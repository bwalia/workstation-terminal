//! OpsAPI task bridge.
//!
//! - **Launch links.** OpsAPI opens `https://<gateway>/#launch=<ticket>` from a task page. The ticket
//!   is `base64url(json).hex(hmac_sha256(secret, base64url(json)))`. The page posts it to
//!   `/api/launch` once the user has signed in with their SSH key; the gateway verifies it, checks the
//!   folder against `local.allowed_roots` and the agent against `opsapi.agents`, and the next `open`
//!   with that launch id starts a shell there.
//! - **Auto sign-in.** A link may also carry a `login` claim (an OpsAPI user who confirmed a step-up
//!   code). When `opsapi.autologin` is on and maps that email to a terminal user,
//!   `/api/launch/login` signs the person in through that user's key, once per link. Without it a
//!   launch link never signs anyone in.
//! - **Report.** A `report` claim gives the agent a URL and token to tell OpsAPI about its pull
//!   request (`OPSAPI_REPORT_URL`, `OPSAPI_REPORT_TOKEN`).
//! - **Webhook.** When a launched session starts or ends, an HMAC-signed POST tells OpsAPI.
//!
//! See docs/OPSAPI.md for the full contract.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::auth::keys::{
    Access, AuthorizedKey, AuthorizedKeys, check_key_strength, fingerprint, valid_user,
};
use crate::config::{AgentConfig, AutologinConfig, Config, OpsapiConfig};
use ssh_key::PublicKey;

/// Longest lifetime OpsAPI may give a link (it uses 15 minutes).
pub const MAX_LINK_LIFETIME_SECS: u64 = 3600;
/// Longest lifetime of a link that signs someone in (OpsAPI uses exactly this).
pub const MAX_LOGIN_LINK_LIFETIME_SECS: u64 = 120;
/// Allowed clock difference between OpsAPI and this machine.
const CLOCK_SKEW_SECS: u64 = 300;
const MAX_TICKET_BYTES: usize = 24 * 1024;
pub const MAX_PROMPT_CHARS: usize = 8000;

pub fn valid_agent_id(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn valid_uuidish(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// A canonical UUID: 8-4-4-4-12 hex digits.
pub fn valid_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups
            .iter()
            .all(|g| g.chars().all(|c| c.is_ascii_hexdigit()))
}

fn valid_report_token(s: &str) -> bool {
    (32..=128).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// An email as OpsAPI sends it: one line, at most 254 characters, `local@domain`.
fn valid_email(s: &str) -> bool {
    s.len() <= 254
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
        && matches!(s.split_once('@'), Some((l, d)) if !l.is_empty() && !d.is_empty())
}

/// A verified launch link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub id: String,
    pub task: String,
    pub num: Option<i64>,
    pub title: String,
    pub path: String,
    pub agent: String,
    pub prompt: String,
    pub by: String,
    pub return_url: String,
    pub workspace: Option<String>,
    pub iat: u64,
    pub exp: u64,
    /// OpsAPI asks to sign this person in (§8 of the OpsAPI doc).
    pub login: Option<LoginClaim>,
    /// Where the agent reports its pull request.
    pub report: Option<Report>,
}

/// The OpsAPI user a link may sign in, and when they last confirmed a step-up code.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LoginClaim {
    pub email: String,
    pub user: String,
    pub stepup: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Report {
    pub url: String,
    pub token: String,
}

impl Launch {
    /// Tab name: `#12 Fix the header` (at most 64 characters, see session::normalize_name).
    pub fn tab_name(&self) -> String {
        let base = match self.num {
            Some(n) => format!("#{n} {}", self.title),
            None => self.title.clone(),
        };
        let name: String = base.chars().take(crate::session::MAX_NAME_CHARS).collect();
        name.trim().to_string()
    }
}

#[derive(Deserialize)]
struct Claims {
    v: u32,
    id: String,
    iat: u64,
    exp: u64,
    task: String,
    #[serde(default)]
    num: Option<i64>,
    title: String,
    path: String,
    agent: String,
    #[serde(default)]
    prompt: String,
    #[serde(default)]
    by: String,
    #[serde(rename = "return", default)]
    return_url: String,
    #[serde(default)]
    ws: Option<String>,
    #[serde(default)]
    login: Option<LoginClaim>,
    #[serde(default)]
    report: Option<Report>,
    // Claims this terminal doesn't know are ignored (no deny_unknown_fields), so a newer OpsAPI
    // works with an older terminal.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    #[error("this link isn't valid; open it again from OpsAPI")]
    Invalid,
    #[error("this link has expired; open it again from OpsAPI")]
    Expired,
    #[error("task links aren't set up on this terminal")]
    NotConfigured,
    #[error(
        "this task's text starts with \"-\", which the agent would take as an option; \
         change the start of the task text in OpsAPI and open it again"
    )]
    PromptIsOption,
}

/// One line of text: no control characters, at most `max` characters.
fn one_line(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    (t.chars().count() <= max && !t.chars().any(char::is_control)).then(|| t.to_string())
}

/// Keep newlines and tabs, drop other control characters (escape sequences, NUL).
fn clean_prompt(s: &str) -> String {
    s.replace("\r\n", "\n")
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

fn valid_url(u: &str, max: usize) -> bool {
    let ok_scheme = u.starts_with("https://")
        || u.starts_with("http://localhost")
        || u.starts_with("http://127.0.0.1");
    ok_scheme
        && u.len() <= max
        && !u
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '<' || c == '>')
}

/// Verify a launch ticket's signature, lifetime and fields.
pub fn verify_ticket(secret: &str, ticket: &str, now: u64) -> Result<Launch, LinkError> {
    if secret.is_empty() {
        return Err(LinkError::NotConfigured);
    }
    if ticket.len() > MAX_TICKET_BYTES {
        return Err(LinkError::Invalid);
    }
    let (payload, sig) = ticket.rsplit_once('.').ok_or(LinkError::Invalid)?;
    let want = hmac_sha256_hex(secret, payload.as_bytes());
    if !crate::security::ct_eq(want.as_bytes(), sig.to_ascii_lowercase().as_bytes()) {
        return Err(LinkError::Invalid);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| LinkError::Invalid)?;
    let c: Claims = serde_json::from_slice(&raw).map_err(|_| LinkError::Invalid)?;
    if c.v != 1 {
        return Err(LinkError::Invalid);
    }
    if c.exp <= now {
        return Err(LinkError::Expired);
    }
    if c.exp < c.iat || c.exp - c.iat > MAX_LINK_LIFETIME_SECS || c.iat > now + CLOCK_SKEW_SECS {
        return Err(LinkError::Invalid);
    }
    let bad = |ok: bool| if ok { Ok(()) } else { Err(LinkError::Invalid) };
    bad(valid_uuidish(&c.id) && valid_uuidish(&c.task))?;
    bad(valid_agent_id(&c.agent))?;
    bad(c.path.starts_with('/') && c.path.len() <= 1024 && !c.path.chars().any(char::is_control))?;
    bad(c.return_url.is_empty() || valid_url(&c.return_url, 2048))?;
    bad(c.prompt.chars().count() <= MAX_PROMPT_CHARS)?;
    let title = one_line(&c.title, 200).ok_or(LinkError::Invalid)?;
    let by = one_line(&c.by, 120).ok_or(LinkError::Invalid)?;
    let workspace = match c.ws {
        Some(w) => Some(one_line(&w, 120).ok_or(LinkError::Invalid)?),
        None => None,
    };
    if let Some(l) = &c.login {
        bad(valid_email(&l.email) && valid_uuid(&l.user))?;
    }
    if let Some(r) = &c.report {
        bad(valid_url(&r.url, 512) && valid_report_token(&r.token))?;
    }
    // Agents get the prompt as an argument. The documented run lines put `--` before it, but a
    // line without one would read a prompt like `--settings=…` as an option.
    let prompt = clean_prompt(&c.prompt);
    if prompt.trim_start().starts_with('-') {
        return Err(LinkError::PromptIsOption);
    }
    Ok(Launch {
        id: c.id.to_ascii_lowercase(),
        task: c.task.to_ascii_lowercase(),
        num: c.num,
        title,
        path: c.path,
        agent: c.agent,
        prompt,
        by,
        return_url: c.return_url,
        workspace,
        iat: c.iat,
        exp: c.exp,
        login: c.login.map(|l| LoginClaim {
            user: l.user.to_ascii_lowercase(),
            ..l
        }),
        report: c.report,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AutologinError {
    #[error("{0}")]
    Link(LinkError),
    #[error("automatic sign-in is off on this terminal; sign in with your SSH key")]
    Off,
    #[error("automatic sign-in isn't set up for you on this terminal; sign in with your SSH key")]
    NotAllowed,
    #[error(
        "your OpsAPI confirmation code is too old for this terminal; sign in with your SSH key"
    )]
    StepupStale,
}

impl AutologinError {
    pub fn code(&self) -> &'static str {
        match self {
            AutologinError::Link(e) => e.code(),
            AutologinError::Off => "autologin_off",
            AutologinError::NotAllowed => "autologin_not_allowed",
            AutologinError::StepupStale => "stepup_stale",
        }
    }
}

impl LinkError {
    pub fn code(&self) -> &'static str {
        match self {
            LinkError::Expired => "expired",
            LinkError::NotConfigured => "not_configured",
            LinkError::Invalid => "invalid_link",
            LinkError::PromptIsOption => "prompt_starts_with_dash",
        }
    }
}

/// The terminal user a verified link may sign in (§8), before the key check: the link carries
/// `login` and lives at most 120 s, auto sign-in is on, the email is mapped, and the step-up is
/// no later than the link and no older than `max_stepup_age_secs`.
pub fn autologin_user(
    cfg: &AutologinConfig,
    keys: &AuthorizedKeys,
    launch: &Launch,
    now: u64,
) -> Result<String, AutologinError> {
    if !cfg.enabled {
        return Err(AutologinError::Off);
    }
    let login = launch.login.as_ref().ok_or(AutologinError::NotAllowed)?;
    if launch.exp - launch.iat > MAX_LOGIN_LINK_LIFETIME_SECS || login.stepup > launch.iat {
        return Err(AutologinError::Link(LinkError::Invalid));
    }
    // The config's own list first, then the people OpsAPI issued keys to (by their email).
    let user = cfg
        .user_for(&login.email)
        .or_else(|| keys.user_for_email(&login.email))
        .ok_or(AutologinError::NotAllowed)?
        .to_string();
    if now.saturating_sub(login.stepup) > cfg.max_stepup_age_secs {
        return Err(AutologinError::StepupStale);
    }
    Ok(user)
}

// ---------------------------------------------------------------------------------------------
// Keys issued in OpsAPI (`opsapi.keys`, §10 of the OpsAPI doc)
// ---------------------------------------------------------------------------------------------

/// Largest key list accepted from OpsAPI.
const MAX_KEYS_BODY: usize = 1024 * 1024;

#[derive(Deserialize)]
struct KeysAnswer {
    terminal: String,
    generated_at: u64,
    keys: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct KeyEntry {
    user: String,
    public_key: String,
    expires_unix: u64,
    #[serde(default)]
    email: Option<String>,
    /// The person's name (newer OpsAPI); one line, at most 120 characters.
    #[serde(default)]
    name: Option<String>,
}

/// Check OpsAPI's answer and turn it into keys: it must be signed with the shared secret
/// (`X-Opsapi-Signature: sha256=<hex HMAC of the body>`), name this terminal and be recent.
/// Entries that aren't valid, or have expired, are left out. Keys get `local` access only.
pub fn parse_keys_answer(
    secret: &str,
    terminal_id: &str,
    body: &[u8],
    signature: &str,
    now: u64,
    min_rsa_bits: usize,
) -> Result<(u64, Vec<AuthorizedKey>), String> {
    let sig = signature
        .strip_prefix("sha256=")
        .unwrap_or("")
        .to_ascii_lowercase();
    if !crate::security::ct_eq(hmac_sha256_hex(secret, body).as_bytes(), sig.as_bytes()) {
        return Err("the key list isn't signed with this terminal's secret".into());
    }
    let a: KeysAnswer = serde_json::from_slice(body).map_err(|e| format!("bad key list: {e}"))?;
    if !a.terminal.eq_ignore_ascii_case(terminal_id) {
        return Err("the key list is for another terminal".into());
    }
    if a.generated_at.abs_diff(now) > CLOCK_SKEW_SECS {
        return Err("the key list is too old (or this machine's clock is off)".into());
    }
    let mut keys: Vec<AuthorizedKey> = Vec::new();
    for v in a.keys {
        let Ok(e) = serde_json::from_value::<KeyEntry>(v) else {
            warn!("opsapi key list: an entry isn't valid; skipped");
            continue;
        };
        let email = e.email.map(|m| m.to_ascii_lowercase());
        // Only shown to the person's shells, so a bad one is left out rather than the key.
        let name = e.name.as_deref().and_then(|n| {
            let n = one_line(n, 120);
            if n.is_none() {
                warn!(user = %e.user, "opsapi key list: a name isn't valid; left out");
            }
            n.filter(|n| !n.is_empty())
        });
        let key = match PublicKey::from_openssh(&e.public_key) {
            Ok(k) if check_key_strength(k.key_data(), min_rsa_bits).is_ok() => k,
            _ => {
                warn!(user = %e.user, "opsapi key list: a key isn't valid; skipped");
                continue;
            }
        };
        let fingerprint = fingerprint(&key);
        if !valid_user(&e.user)
            || e.expires_unix <= now
            || email.as_deref().is_some_and(|m| !valid_email(m))
            || keys.iter().any(|k| k.user == e.user || k.fingerprint == fingerprint)
        {
            warn!(user = %e.user, "opsapi key list: an entry isn't valid; skipped");
            continue;
        }
        keys.push(AuthorizedKey {
            user: e.user,
            access: Access {
                local: true,
                ..Access::default()
            },
            key,
            fingerprint,
            line: 0,
            email,
            name,
            expires_unix: Some(e.expires_unix),
        });
    }
    Ok((a.generated_at, keys))
}

/// Fetch this terminal's keys from OpsAPI. The request is signed:
/// `X-Opsapi-Signature: sha256=<hex HMAC of "keys\n<terminal id>\n<X-Opsapi-Timestamp>">`.
pub async fn fetch_keys(cfg: &Config, now: u64) -> Result<(u64, Vec<AuthorizedKey>), String> {
    let k = &cfg.opsapi.keys;
    let (Some(url), Some(term), Some(secret)) = (
        k.url.as_deref(),
        k.terminal_id.as_deref().map(str::to_ascii_lowercase),
        cfg.opsapi.webhook_secret.as_deref(),
    ) else {
        return Err("opsapi.keys isn't configured".into());
    };
    let ts = now.to_string();
    let sig = hmac_sha256_hex(secret, format!("keys\n{term}\n{ts}").as_bytes());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let res = client
        .get(url)
        .header("X-Opsapi-Terminal", &term)
        .header("X-Opsapi-Timestamp", &ts)
        .header("X-Opsapi-Signature", format!("sha256={sig}"))
        .header("User-Agent", "sshweb-opsapi-keys")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("status {}", res.status()));
    }
    if res.content_length().is_some_and(|n| n > MAX_KEYS_BODY as u64) {
        return Err("key list too large".into());
    }
    let signature = res
        .headers()
        .get("x-opsapi-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = res.bytes().await.map_err(|e| e.to_string())?;
    if body.len() > MAX_KEYS_BODY {
        return Err("key list too large".into());
    }
    parse_keys_answer(secret, &term, &body, &signature, now, cfg.auth.min_rsa_bits)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FolderError {
    #[error("opening a folder isn't allowed on this terminal (no local.allowed_roots)")]
    NoRoots,
    #[error("folder {0} doesn't exist on this machine")]
    NotFound(String),
    #[error("{0} isn't one of the folders this terminal may open")]
    NotAllowed(String),
}

/// Resolve a requested folder: it must exist, be a directory, and (after resolving symlinks)
/// lie inside one of `local.allowed_roots`.
pub fn resolve_folder(roots: &[PathBuf], requested: &str) -> Result<PathBuf, FolderError> {
    if roots.is_empty() {
        return Err(FolderError::NoRoots);
    }
    let p = Path::new(requested);
    if !p.is_absolute() || requested.chars().any(char::is_control) {
        return Err(FolderError::NotAllowed(requested.to_string()));
    }
    let real =
        std::fs::canonicalize(p).map_err(|_| FolderError::NotFound(requested.to_string()))?;
    if !real.is_dir() {
        return Err(FolderError::NotFound(requested.to_string()));
    }
    let inside = roots.iter().any(|r| {
        std::fs::canonicalize(r)
            .map(|root| real.starts_with(&root))
            .unwrap_or(false)
    });
    if inside {
        Ok(real)
    } else {
        Err(FolderError::NotAllowed(requested.to_string()))
    }
}

/// The agent a launch asks for. `shell` means none.
pub fn find_agent<'a>(cfg: &'a OpsapiConfig, id: &str) -> Result<Option<&'a AgentConfig>, String> {
    if id == "shell" {
        return Ok(None);
    }
    cfg.agents
        .iter()
        .find(|a| a.id == id)
        .map(Some)
        .ok_or_else(|| format!("the agent {id:?} isn't set up on this terminal"))
}

/// Ties a session to the OpsAPI launch it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchTag {
    pub id: String,
    pub task: String,
    /// The agent id from the link (`shell` for none).
    pub agent: String,
}

/// What `/api/launch` accepted, waiting for (or used by) a terminal session.
#[derive(Debug, Clone)]
pub struct Pending {
    pub user: String,
    pub launch: Launch,
    pub cwd: PathBuf,
    pub agent: Option<AgentConfig>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClaimError {
    #[error("this link was already used by someone else")]
    OtherUser,
}

/// Accepted launches, kept until shortly after they expire so each link works once.
#[derive(Default)]
pub struct LaunchStore {
    map: Mutex<HashMap<String, Pending>>,
    /// Launch ids that already signed someone in (`/api/launch/login`), with their expiry.
    logins: Mutex<HashMap<String, u64>>,
}

impl LaunchStore {
    fn purge(map: &mut HashMap<String, Pending>, now: u64) {
        map.retain(|_, p| p.launch.exp + MAX_LINK_LIFETIME_SECS > now);
    }

    /// Record a verified launch for `user`. The same user posting the same link again gets the
    /// existing entry back (a page reload); another user is refused.
    pub fn accept(&self, p: Pending, now: u64) -> Result<Pending, ClaimError> {
        let mut map = self.map.lock().unwrap();
        Self::purge(&mut map, now);
        match map.get(&p.launch.id) {
            Some(existing) if existing.user != p.user => Err(ClaimError::OtherUser),
            Some(existing) => Ok(existing.clone()),
            None => {
                map.insert(p.launch.id.clone(), p.clone());
                Ok(p)
            }
        }
    }

    /// Claim an accepted, unused launch for `user` to open a session (atomically, so two tabs
    /// can't both use one link). None when it is unknown, someone else's or already used.
    /// Follow with [`Self::mark_used`] or, if opening failed, [`Self::release`].
    pub fn take_for_open(&self, id: &str, user: &str) -> Option<Pending> {
        let mut map = self.map.lock().unwrap();
        let p = map
            .get_mut(id)
            .filter(|p| p.user == user && p.session_id.is_none())?;
        p.session_id = Some(String::new()); // opening
        Some(p.clone())
    }

    pub fn mark_used(&self, id: &str, session_id: &str) {
        if let Some(p) = self.map.lock().unwrap().get_mut(id) {
            p.session_id = Some(session_id.to_string());
        }
    }

    /// Use a link to sign someone in. True the first time for each launch id; kept as long as
    /// accepted launches (an hour past expiry, longer than any link lives).
    pub fn claim_login(&self, launch: &Launch, now: u64) -> bool {
        let mut used = self.logins.lock().unwrap();
        used.retain(|_, exp| *exp + MAX_LINK_LIFETIME_SECS > now);
        used.insert(launch.id.clone(), launch.exp).is_none()
    }

    pub fn release(&self, id: &str) {
        if let Some(p) = self.map.lock().unwrap().get_mut(id)
            && p.session_id.as_deref() == Some("")
        {
            p.session_id = None;
        }
    }
}

/// Environment for a launched shell. The prompt reaches the agent only through these variables,
/// so its text is never parsed as shell syntax.
pub fn launch_env(l: &Launch) -> Vec<(String, String)> {
    let mut env = vec![
        ("OPSAPI_LAUNCH".into(), l.id.clone()),
        ("OPSAPI_TASK".into(), l.task.clone()),
        (
            "OPSAPI_TASK_NUMBER".into(),
            l.num.map(|n| n.to_string()).unwrap_or_default(),
        ),
        ("OPSAPI_TASK_TITLE".into(), l.title.clone()),
        ("OPSAPI_TASK_URL".into(), l.return_url.clone()),
        ("OPSAPI_TASK_PROMPT".into(), l.prompt.clone()),
    ];
    if let Some(r) = &l.report {
        env.push(("OPSAPI_REPORT_URL".into(), r.url.clone()));
        env.push(("OPSAPI_REPORT_TOKEN".into(), r.token.clone()));
    }
    env
}

/// Fire-and-forget HMAC-signed POST to OpsAPI for a launched session (a few retries).
/// No-op when the webhook isn't configured.
pub fn notify(
    cfg: &Config,
    event: &str,
    tag: &LaunchTag,
    session_id: &str,
    user: &str,
    exit_code: Option<u32>,
    reason: Option<&str>,
) {
    let o = &cfg.opsapi;
    let (Some(url), Some(secret)) = (
        o.webhook_url.as_deref().filter(|u| !u.is_empty()),
        o.webhook_secret.as_deref().filter(|s| !s.is_empty()),
    ) else {
        debug!("opsapi webhook not configured; skip");
        return;
    };
    let body = json!({
        "event": event,
        "launch": tag.id,
        "session_id": session_id,
        "user": user,
        "ts": unix_now(),
        "exit_code": exit_code,
        "reason": reason,
    })
    .to_string();
    let sig = hmac_sha256_hex(secret, body.as_bytes());
    let url = url.to_string();
    tokio::spawn(async move {
        for (attempt, wait) in [0u64, 2, 10].into_iter().enumerate() {
            if wait > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            }
            match post(&url, &body, &sig).await {
                Ok(()) => return,
                Err(e) => warn!(error = %e, attempt = attempt + 1, "opsapi webhook failed"),
            }
        }
    });
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// HMAC-SHA256 (RFC 2104) as lowercase hex.
pub fn hmac_sha256_hex(secret: &str, body: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut key = secret.as_bytes().to_vec();
    if key.len() > BLOCK {
        key = Sha256::digest(&key).to_vec();
    }
    key.resize(BLOCK, 0);
    let mut inner = Sha256::new();
    inner.update(key.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(body);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(key.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(inner_hash);
    hex::encode(outer.finalize())
}

async fn post(url: &str, body: &str, sig_hex: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Opsapi-Signature", format!("sha256={sig_hex}"))
        .header("User-Agent", "sshweb-opsapi-webhook")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("status {}", res.status()));
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const SECRET: &str = "0123456789abcdef0123456789abcdef-test-secret";

    /// Mint a ticket the way OpsAPI does.
    pub fn mint(secret: &str, claims: serde_json::Value) -> String {
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let sig = hmac_sha256_hex(secret, payload.as_bytes());
        format!("{payload}.{sig}")
    }

    pub fn claims(now: u64, path: &str) -> serde_json::Value {
        json!({
            "v": 1, "id": "6f1c2a9e-1111-4c4c-9d9d-0123456789ab", "iat": now, "exp": now + 900,
            "task": "0b6c0e7e-2222-4c4c-9d9d-0123456789ab", "num": 12, "title": "Fix the header",
            "path": path, "agent": "claude", "prompt": "Do it\r\nwell\u{1b}[31m",
            "by": "Jane Doe", "return": "https://ops.example/dashboard/projects/p/tasks/t", "ws": "Acme"
        })
    }

    #[test]
    fn hmac_known_vectors() {
        assert_eq!(
            hmac_sha256_hex("", b""),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
        // RFC 4231 test case 2.
        assert_eq!(
            hmac_sha256_hex("Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn valid_ticket_verifies_and_is_cleaned() {
        let now = 1_800_000_000;
        let l = verify_ticket(SECRET, &mint(SECRET, claims(now, "/srv/x")), now).unwrap();
        assert_eq!(l.agent, "claude");
        assert_eq!(l.num, Some(12));
        assert_eq!(
            l.prompt, "Do it\nwell[31m",
            "CR and ESC dropped, newline kept"
        );
        assert_eq!(l.tab_name(), "#12 Fix the header");
        assert_eq!(l.workspace.as_deref(), Some("Acme"));
    }

    #[test]
    fn tampered_wrong_key_expired_and_long_lived_links_are_refused() {
        let now = 1_800_000_000;
        let t = mint(SECRET, claims(now, "/srv/x"));
        assert_eq!(
            verify_ticket("another-secret-another-secret-xx", &t, now),
            Err(LinkError::Invalid)
        );
        let (payload, sig) = t.rsplit_once('.').unwrap();
        let mut c = claims(now, "/srv/x");
        c["path"] = json!("/etc");
        let forged = format!("{}.{sig}", URL_SAFE_NO_PAD.encode(c.to_string()));
        assert_eq!(verify_ticket(SECRET, &forged, now), Err(LinkError::Invalid));
        assert_eq!(
            verify_ticket(SECRET, &format!("{payload}.00"), now),
            Err(LinkError::Invalid)
        );
        assert_eq!(
            verify_ticket(SECRET, &t, now + 901),
            Err(LinkError::Expired)
        );
        let mut long = claims(now, "/srv/x");
        long["exp"] = json!(now + MAX_LINK_LIFETIME_SECS + 1);
        assert_eq!(
            verify_ticket(SECRET, &mint(SECRET, long), now),
            Err(LinkError::Invalid)
        );
        let mut future = claims(now + 3000, "/srv/x");
        future["exp"] = json!(now + 3500);
        assert_eq!(
            verify_ticket(SECRET, &mint(SECRET, future), now),
            Err(LinkError::Invalid)
        );
        assert_eq!(verify_ticket("", &t, now), Err(LinkError::NotConfigured));
    }

    #[test]
    fn return_link_is_optional() {
        let now = 1_800_000_000;
        let mut c = claims(now, "/srv/x");
        c.as_object_mut().unwrap().remove("return");
        let l = verify_ticket(SECRET, &mint(SECRET, c), now).unwrap();
        assert_eq!(l.return_url, "");
    }

    #[test]
    fn bad_fields_are_refused() {
        let now = 1_800_000_000;
        for (k, v) in [
            ("v", json!(2)),
            ("agent", json!("rm -rf /")),
            ("agent", json!("Claude")),
            ("path", json!("relative/path")),
            ("path", json!("/tmp/a\nb")),
            ("return", json!("javascript:alert(1)")),
            ("return", json!("https://x/\"><img src=x>")),
            ("title", json!("two\nlines")),
            ("id", json!("not a uuid!")),
            ("prompt", json!("x".repeat(MAX_PROMPT_CHARS + 1))),
        ] {
            let mut c = claims(now, "/srv/x");
            c[k] = v;
            assert_eq!(
                verify_ticket(SECRET, &mint(SECRET, c), now),
                Err(LinkError::Invalid),
                "{k}"
            );
        }
    }

    #[test]
    fn prompts_that_start_with_a_dash_are_refused() {
        let now = 1_800_000_000;
        let with = |p: &str| {
            let mut c = claims(now, "/srv/x");
            c["prompt"] = json!(p);
            verify_ticket(SECRET, &mint(SECRET, c), now)
        };
        for p in ["-p", "--settings=/tmp/evil.json", "  \n\t--model x", "\u{1b}-x"] {
            assert_eq!(with(p), Err(LinkError::PromptIsOption), "{p:?}");
        }
        assert_eq!(with("-p").unwrap_err().code(), "prompt_starts_with_dash");
        for p in ["", "Fix the --verbose flag", "— a dash of style", "x -y"] {
            assert!(with(p).is_ok(), "{p:?}");
        }
    }

    #[test]
    fn folders_must_be_real_directories_inside_a_root() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("projects");
        let site = root.join("site");
        std::fs::create_dir_all(site.join("src")).unwrap();
        std::fs::write(root.join("notes.txt"), "x").unwrap();
        let outside = base.path().join("secret");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        let roots = vec![root.clone()];
        let real_site = std::fs::canonicalize(&site).unwrap();
        assert_eq!(
            resolve_folder(&roots, site.to_str().unwrap()),
            Ok(real_site.clone())
        );
        assert_eq!(
            resolve_folder(&roots, &format!("{}/src/..", site.display())),
            Ok(real_site)
        );
        assert!(matches!(
            resolve_folder(&roots, root.join("escape").to_str().unwrap()),
            Err(FolderError::NotAllowed(_))
        ));
        assert!(matches!(
            resolve_folder(&roots, &format!("{}/../secret", root.display())),
            Err(FolderError::NotAllowed(_))
        ));
        assert!(matches!(
            resolve_folder(&roots, root.join("notes.txt").to_str().unwrap()),
            Err(FolderError::NotFound(_))
        ));
        assert!(matches!(
            resolve_folder(&roots, root.join("missing").to_str().unwrap()),
            Err(FolderError::NotFound(_))
        ));
        assert!(matches!(
            resolve_folder(&roots, "relative"),
            Err(FolderError::NotAllowed(_))
        ));
        assert_eq!(resolve_folder(&[], "/tmp"), Err(FolderError::NoRoots));
    }

    #[test]
    fn launches_are_single_use_per_user() {
        let now = 1_800_000_000;
        let l = verify_ticket(SECRET, &mint(SECRET, claims(now, "/srv/x")), now).unwrap();
        let store = LaunchStore::default();
        let p = Pending {
            user: "alice".into(),
            launch: l.clone(),
            cwd: "/srv/x".into(),
            agent: None,
            session_id: None,
        };
        store.accept(p.clone(), now).unwrap();
        assert_eq!(
            store
                .accept(
                    Pending {
                        user: "bob".into(),
                        ..p.clone()
                    },
                    now
                )
                .err(),
            Some(ClaimError::OtherUser)
        );
        assert!(store.take_for_open(&l.id, "bob").is_none());
        assert!(store.take_for_open(&l.id, "alice").is_some());
        assert!(
            store.take_for_open(&l.id, "alice").is_none(),
            "claimed while opening"
        );
        store.release(&l.id);
        assert!(
            store.take_for_open(&l.id, "alice").is_some(),
            "released after a failed open"
        );
        store.mark_used(&l.id, "abc123");
        assert!(store.take_for_open(&l.id, "alice").is_none(), "used once");
        let again = store.accept(p, now).unwrap();
        assert_eq!(
            again.session_id.as_deref(),
            Some("abc123"),
            "reload finds the session"
        );
        // Purged an hour after expiry.
        let later = l.exp + MAX_LINK_LIFETIME_SECS + 1;
        store
            .accept(
                Pending {
                    user: "carol".into(),
                    launch: l,
                    cwd: "/srv/x".into(),
                    agent: None,
                    session_id: None,
                },
                later,
            )
            .unwrap();
    }

    #[test]
    fn env_carries_the_task() {
        let now = 1_800_000_000;
        let l = verify_ticket(SECRET, &mint(SECRET, claims(now, "/srv/x")), now).unwrap();
        let env: HashMap<_, _> = launch_env(&l).into_iter().collect();
        assert_eq!(env["OPSAPI_TASK_NUMBER"], "12");
        assert_eq!(env["OPSAPI_TASK_PROMPT"], "Do it\nwell[31m");
        assert_eq!(
            env["OPSAPI_TASK_URL"],
            "https://ops.example/dashboard/projects/p/tasks/t"
        );
    }
    fn login_claims(now: u64) -> serde_json::Value {
        let mut c = claims(now, "/srv/x");
        c["exp"] = json!(now + 120);
        c["login"] = json!({
            "email": "Alice@Example.com", "user": "9A8B7C6D-1111-4C4C-9D9D-0123456789AB",
            "stepup": now - 600
        });
        c["report"] = json!({
            "url": "https://ops.example/api/v2/ai-runner/public/terminal/report",
            "token": "tok_0123456789abcdefghijklmnopqrstuvwxyz-ABC"
        });
        c
    }

    fn autologin_cfg() -> AutologinConfig {
        AutologinConfig {
            enabled: true,
            max_stepup_age_secs: 43200,
            users: [("alice@example.com".to_string(), "alice".to_string())].into(),
        }
    }

    #[test]
    fn login_and_report_claims_are_read_and_unknown_claims_ignored() {
        let now = 1_800_000_000;
        let mut c = login_claims(now);
        c["future_claim"] = json!({"anything": [1, 2]});
        c["login"]["future_field"] = json!(true);
        let l = verify_ticket(SECRET, &mint(SECRET, c), now).unwrap();
        let who = l.login.as_ref().unwrap();
        assert_eq!(who.email, "Alice@Example.com");
        assert_eq!(who.user, "9a8b7c6d-1111-4c4c-9d9d-0123456789ab");
        assert_eq!(who.stepup, now - 600);
        assert_eq!(l.report.as_ref().unwrap().token.len(), 44);
        // An ordinary link has neither.
        let plain = verify_ticket(SECRET, &mint(SECRET, claims(now, "/srv/x")), now).unwrap();
        assert_eq!((plain.login, plain.report), (None, None));
    }

    #[test]
    fn bad_login_and_report_claims_are_refused() {
        let now = 1_800_000_000;
        for (path, v) in [
            (["login", "email"], json!("no-at-sign")),
            (
                ["login", "email"],
                json!(format!("{}@example.com", "a".repeat(250))),
            ),
            (["login", "email"], json!("a b@example.com")),
            (["login", "user"], json!("not-a-uuid")),
            (["login", "user"], json!("6f1c2a9e11114c4c9d9d0123456789ab")),
            (["login", "stepup"], json!(-1)),
            (["login", "stepup"], json!("1800000000")),
            (["report", "url"], json!("http://ops.example/report")),
            (
                ["report", "url"],
                json!(format!("https://ops.example/{}", "x".repeat(500))),
            ),
            (["report", "token"], json!("short")),
            (["report", "token"], json!("x".repeat(129))),
            (["report", "token"], json!(format!("{}!", "x".repeat(40)))),
        ] {
            let mut c = login_claims(now);
            c[path[0]][path[1]] = v;
            let r = verify_ticket(SECRET, &mint(SECRET, c), now);
            assert_eq!(r, Err(LinkError::Invalid), "{path:?}");
        }
        let mut c = login_claims(now);
        c["login"] = json!({"email": "alice@example.com"});
        assert_eq!(
            verify_ticket(SECRET, &mint(SECRET, c), now),
            Err(LinkError::Invalid)
        );
        // Local OpsAPI for development.
        let mut c = login_claims(now);
        c["report"]["url"] = json!("http://127.0.0.1:4010/report");
        assert!(verify_ticket(SECRET, &mint(SECRET, c), now).is_ok());
    }

    #[test]
    fn autologin_needs_config_mapping_short_link_and_fresh_stepup() {
        let now = 1_800_000_000;
        let cfg = autologin_cfg();
        let check = |c: serde_json::Value, cfg: &AutologinConfig, at: u64| {
            let l = verify_ticket(SECRET, &mint(SECRET, c), now).unwrap();
            autologin_user(cfg, &AuthorizedKeys::default(), &l, at)
        };
        assert_eq!(
            check(login_claims(now), &cfg, now),
            Ok("alice".into()),
            "email in any case"
        );
        let off = AutologinConfig {
            enabled: false,
            ..autologin_cfg()
        };
        assert_eq!(
            check(login_claims(now), &off, now),
            Err(AutologinError::Off)
        );
        assert_eq!(
            check(claims(now, "/srv/x"), &cfg, now),
            Err(AutologinError::NotAllowed)
        );
        let mut c = login_claims(now);
        c["login"]["email"] = json!("mallory@example.com");
        assert_eq!(check(c, &cfg, now), Err(AutologinError::NotAllowed));
        let mut c = login_claims(now);
        c["exp"] = json!(now + 121);
        assert_eq!(
            check(c, &cfg, now),
            Err(AutologinError::Link(LinkError::Invalid))
        );
        let mut c = login_claims(now);
        c["login"]["stepup"] = json!(now + 1);
        assert_eq!(
            check(c, &cfg, now),
            Err(AutologinError::Link(LinkError::Invalid))
        );
        let mut c = login_claims(now);
        c["login"]["stepup"] = json!(now - 43_201);
        assert_eq!(check(c, &cfg, now), Err(AutologinError::StepupStale));
        let strict = AutologinConfig {
            max_stepup_age_secs: 300,
            ..autologin_cfg()
        };
        assert_eq!(
            check(login_claims(now), &strict, now),
            Err(AutologinError::StepupStale)
        );
        assert_eq!(AutologinError::StepupStale.code(), "stepup_stale");
        assert_eq!(AutologinError::Link(LinkError::Expired).code(), "expired");
    }

    #[test]
    fn a_link_signs_in_once() {
        let now = 1_800_000_000;
        let l = verify_ticket(SECRET, &mint(SECRET, login_claims(now)), now).unwrap();
        let store = LaunchStore::default();
        assert!(store.claim_login(&l, now));
        assert!(!store.claim_login(&l, now + 60));
        // Remembered until long after the link stopped working.
        assert!(!store.claim_login(&l, l.exp + MAX_LINK_LIFETIME_SECS - 1));
    }

    #[test]
    fn env_carries_the_report_link_when_given() {
        let now = 1_800_000_000;
        let l = verify_ticket(SECRET, &mint(SECRET, login_claims(now)), now).unwrap();
        let env: HashMap<_, _> = launch_env(&l).into_iter().collect();
        assert_eq!(
            env["OPSAPI_REPORT_URL"],
            "https://ops.example/api/v2/ai-runner/public/terminal/report"
        );
        assert_eq!(
            env["OPSAPI_REPORT_TOKEN"],
            "tok_0123456789abcdefghijklmnopqrstuvwxyz-ABC"
        );
        let plain = verify_ticket(SECRET, &mint(SECRET, claims(now, "/srv/x")), now).unwrap();
        let env: HashMap<_, _> = launch_env(&plain).into_iter().collect();
        assert!(!env.contains_key("OPSAPI_REPORT_URL") && !env.contains_key("OPSAPI_REPORT_TOKEN"));
    }

    const TERM: &str = "6f1c2a9e-1111-4c4c-9d9d-0123456789ab";

    fn ed_line(seed: u8) -> String {
        PublicKey::from(ssh_key::public::KeyData::Ed25519(
            ssh_key::public::Ed25519PublicKey([seed; 32]),
        ))
        .to_openssh()
        .unwrap()
    }

    fn keys_answer(generated_at: u64, keys: serde_json::Value) -> (Vec<u8>, String) {
        let body = json!({"terminal": TERM, "generated_at": generated_at, "keys": keys})
            .to_string()
            .into_bytes();
        let sig = format!("sha256={}", hmac_sha256_hex(SECRET, &body));
        (body, sig)
    }

    #[test]
    fn opsapi_key_list_must_be_signed_for_this_terminal_and_recent() {
        let now = 1_800_000_000;
        let (body, sig) = keys_answer(
            now,
            json!([
                {"user": "priya", "public_key": ed_line(1), "expires_unix": now + 3600, "email": "Priya@Example.com"},
                {"user": "Bad User", "public_key": ed_line(2), "expires_unix": now + 3600},
                {"user": "gone", "public_key": ed_line(3), "expires_unix": now - 1},
                {"user": "junk", "public_key": "ssh-ed25519 not-a-key", "expires_unix": now + 3600},
                {"user": "priya", "public_key": ed_line(4), "expires_unix": now + 3600},
                {"oops": true}
            ]),
        );
        let (at, keys) = parse_keys_answer(SECRET, TERM, &body, &sig, now, 2048).unwrap();
        assert_eq!(at, now);
        assert_eq!(keys.len(), 1, "only the valid, unexpired, first entry for a user");
        let k = &keys[0];
        assert_eq!(
            (k.user.as_str(), k.email.as_deref(), k.expires_unix),
            ("priya", Some("priya@example.com"), Some(now + 3600))
        );
        assert!(k.access.local && !k.access.allows_any_remote(), "local only");
        assert!(parse_keys_answer(SECRET, &TERM.to_uppercase(), &body, &sig, now, 2048).is_ok());

        let tampered = String::from_utf8(body.clone())
            .unwrap()
            .replace("1800003600", "1800999999")
            .into_bytes();
        let other_secret = "another-secret-0123456789abcdef0123456789";
        for (secret, term, body, sig, at) in [
            (SECRET, TERM, &body, "sha256=00", now),
            (SECRET, TERM, &body, "", now),
            (other_secret, TERM, &body, sig.as_str(), now),
            (SECRET, TERM, &tampered, sig.as_str(), now),
            (SECRET, "00000000-0000-4000-8000-000000000000", &body, sig.as_str(), now),
            (SECRET, TERM, &body, sig.as_str(), now + 3600),
        ] {
            assert!(parse_keys_answer(secret, term, body, sig, at, 2048).is_err());
        }
    }

    #[test]
    fn opsapi_keys_carry_an_optional_name() {
        let now = 1_800_000_000;
        let (body, sig) = keys_answer(
            now,
            json!([
                {"user": "priya", "public_key": ed_line(1), "expires_unix": now + 3600,
                 "email": "priya@example.com", "name": "  Priya Patel "},
                {"user": "sam", "public_key": ed_line(2), "expires_unix": now + 3600,
                 "name": "Sam\nEvil"},
                {"user": "old", "public_key": ed_line(3), "expires_unix": now + 3600}
            ]),
        );
        let (_, keys) = parse_keys_answer(SECRET, TERM, &body, &sig, now, 2048).unwrap();
        let names: Vec<_> = keys
            .iter()
            .map(|k| (k.user.as_str(), k.name.as_deref()))
            .collect();
        assert_eq!(
            names,
            [("priya", Some("Priya Patel")), ("sam", None), ("old", None)],
            "a bad name is left out, the key kept"
        );
    }

    #[test]
    fn autologin_finds_people_opsapi_issued_keys_to_by_email() {
        let now = 1_800_000_000;
        let cfg = AutologinConfig {
            enabled: true,
            max_stepup_age_secs: 43200,
            users: Default::default(),
        };
        let (body, sig) = keys_answer(
            now,
            json!([{"user": "alice", "public_key": ed_line(1), "expires_unix": now + 3600,
                    "email": "alice@example.com"}]),
        );
        let keys = AuthorizedKeys {
            keys: parse_keys_answer(SECRET, TERM, &body, &sig, now, 2048).unwrap().1,
        };
        let l = verify_ticket(SECRET, &mint(SECRET, login_claims(now)), now).unwrap();
        assert_eq!(autologin_user(&cfg, &keys, &l, now), Ok("alice".into()));
        assert_eq!(
            autologin_user(&cfg, &AuthorizedKeys::default(), &l, now),
            Err(AutologinError::NotAllowed)
        );
    }
}
