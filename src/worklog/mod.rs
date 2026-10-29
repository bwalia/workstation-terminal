//! Work log for OpsAPI (`opsapi.work_log`, §11 of the OpsAPI doc).
//!
//! - **Tabs.** Every session (a "tab", local or remote) is reported: who opened it and how, the
//!   task and folder, how it ended, active seconds, bytes in/out, the last input and whether a
//!   browser is attached. Open tabs are re-sent once a minute, so OpsAPI can show them as live.
//! - **Claude Code telemetry.** Each local tab's shell gets a random token and Claude's
//!   OpenTelemetry settings pointing at a loopback-only receiver ([`otlp`]); the token names the
//!   tab. Prompts, model requests, tool results and decisions, API errors and four metrics are
//!   kept; everything else is dropped, and so is anything without a tab's token (Claude outside
//!   sshweb tabs), which is only counted.
//! - **Screen.** Each local tab's output (never its input) is recorded as asciicast v2 parts
//!   ([`recorder`]), kept gzipped in `<state_dir>/recordings` (0600) until uploaded.
//!
//! [`forward`] sends tabs and events to `{url}/activity` every 10 s and the parts to
//! `{url}/recordings`, both HMAC-signed with the shared secret.

pub mod forward;
pub mod otlp;
pub mod recorder;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tracing::warn;

use crate::audit::{Audit, AuditEvent};
use crate::auth::sessions::{Login, unix_now};
use crate::config::Config;
use crate::session::Target;
use crate::terminal::PtySpec;

/// Events kept while OpsAPI can't be reached; when full the oldest go first.
const MAX_QUEUED_EVENTS: usize = 20_000;
/// A single event larger than this is dropped (a batch must stay under 5 MiB).
const MAX_EVENT_BYTES: usize = 1024 * 1024;
/// A tab is active in a tick when it had input or output in the last 60 s.
const ACTIVE_WINDOW_SECS: u64 = 60;
/// An open tab is re-sent this long after OpsAPI last took it, changed or not (a heartbeat, so
/// OpsAPI can tell a live tab from one whose gateway went away). With the 10 s tick that is once a
/// minute; changes wait for it too.
const HEARTBEAT: Duration = Duration::from_secs(50);
pub const TICK: Duration = Duration::from_secs(10);
/// Dropped unattributed posts are audited at most this often.
const UNATTRIBUTED_AUDIT_EVERY: Duration = Duration::from_secs(60);

pub struct WorkLog {
    url: String,
    terminal: String,
    secret: String,
    otlp_port: u16,
    record: bool,
    tabs: Mutex<HashMap<String, Arc<Tab>>>,
    /// SHA-256 of each live local tab's token -> tab id.
    tokens: Mutex<HashMap<[u8; 32], String>>,
    events: Mutex<EventQueue>,
    pub uploads: Arc<recorder::Uploads>,
    /// Telemetry posts without a tab's token, not yet audited, and when they last were.
    unattributed: Mutex<(u64, Option<Instant>)>,
    audit: Arc<Audit>,
}

struct EventQueue {
    /// (seq, event JSON) in seq order.
    items: VecDeque<(u64, String)>,
    next_seq: u64,
    /// Events lost since the last good send (queue full or too large).
    dropped: u64,
}

struct End {
    closed_at: u64,
    reason: String,
    exit_code: Option<u32>,
}

/// What the work log knows about one session.
pub struct Tab {
    pub id: String,
    user: String,
    key: String,
    via: &'static str,
    ip: String,
    launch: Option<String>,
    kind: &'static str,
    cwd: Option<String>,
    agent: Option<String>,
    opened_at: u64,
    started: Instant,
    token_hash: Option<[u8; 32]>,
    input_bytes: AtomicU64,
    output_bytes: AtomicU64,
    active_secs: AtomicU64,
    /// Seconds after `started` of the last input or output, plus one (0: none yet).
    last_active: AtomicU64,
    /// Unix seconds of the last input (0: none yet).
    last_input_at: AtomicU64,
    /// A browser is attached to the session.
    attached: AtomicBool,
    end: Mutex<Option<End>>,
    /// The state OpsAPI last acknowledged, and when.
    acked: Mutex<Option<(String, Instant)>>,
    recorder: Option<Mutex<recorder::Recorder>>,
}

impl Tab {
    fn touch(&self) {
        self.last_active
            .store(self.started.elapsed().as_secs() + 1, Ordering::Relaxed);
    }

    pub fn input(&self, n: usize) {
        self.input_bytes.fetch_add(n as u64, Ordering::Relaxed);
        self.last_input_at.store(unix_now(), Ordering::Relaxed);
        self.touch();
    }

    /// A browser attached to the session (true) or went away (false).
    pub fn set_attached(&self, attached: bool) {
        self.attached.store(attached, Ordering::Relaxed);
    }

    /// PTY output, whether or not a browser is attached.
    pub fn output(&self, data: &[u8]) {
        self.output_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        self.touch();
        if let Some(r) = &self.recorder {
            r.lock().unwrap().output(data);
        }
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        if let Some(r) = &self.recorder {
            let (cols, rows) = crate::terminal::clamp_size(cols, rows);
            r.lock().unwrap().resize(cols, rows);
        }
    }

    fn is_closed(&self) -> bool {
        self.end.lock().unwrap().is_some()
    }

    /// The tab's whole current state, as OpsAPI upserts it.
    fn state(&self) -> Value {
        let end = self.end.lock().unwrap();
        json!({
            "id": self.id,
            "user": self.user,
            "key": self.key,
            "via": self.via,
            "ip": self.ip,
            "launch": self.launch,
            "kind": self.kind,
            "cwd": self.cwd,
            "agent": self.agent,
            "opened_at": self.opened_at,
            "closed_at": end.as_ref().map(|e| e.closed_at),
            "end_reason": end.as_ref().map(|e| e.reason.as_str()),
            "exit_code": end.as_ref().and_then(|e| e.exit_code),
            "active_secs": self.active_secs.load(Ordering::Relaxed),
            "input_bytes": self.input_bytes.load(Ordering::Relaxed),
            "output_bytes": self.output_bytes.load(Ordering::Relaxed),
            "last_input_at": match self.last_input_at.load(Ordering::Relaxed) {
                0 => None,
                t => Some(t),
            },
            "attached": self.attached.load(Ordering::Relaxed),
        })
    }

    /// Send at open, at close, and once a minute while open (changed or not).
    fn due(&self, state: &str) -> bool {
        match &*self.acked.lock().unwrap() {
            None => true,
            Some((s, _)) if self.is_closed() => s != state,
            Some((_, at)) => at.elapsed() >= HEARTBEAT,
        }
    }
}

/// A random per-tab token: 32 bytes, hex.
fn new_token() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS random number generator unavailable");
    hex::encode(b)
}

/// The shell environment that sends Claude Code's telemetry to this tab's receiver.
fn telemetry_env(port: u16, token: &str) -> Vec<(String, String)> {
    let base = format!("http://127.0.0.1:{port}");
    let logs = format!("{base}/v1/logs");
    let metrics = format!("{base}/v1/metrics");
    let auth = format!("Authorization=Bearer {token}");
    [
        ("SSHWEB_TAB_TOKEN", token.to_string()),
        ("CLAUDE_CODE_ENABLE_TELEMETRY", "1".into()),
        ("OTEL_LOGS_EXPORTER", "otlp".into()),
        ("OTEL_METRICS_EXPORTER", "otlp".into()),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json".into()),
        ("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", logs),
        ("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", metrics),
        ("OTEL_EXPORTER_OTLP_HEADERS", auth),
        ("OTEL_LOG_USER_PROMPTS", "1".into()),
        ("OTEL_LOG_TOOL_DETAILS", "1".into()),
        ("OTEL_LOGS_EXPORT_INTERVAL", "5000".into()),
        ("OTEL_METRIC_EXPORT_INTERVAL", "30000".into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

/// A batch for `{url}/activity`: the body and what to mark as sent once OpsAPI takes it.
pub struct Batch {
    pub body: String,
    tabs: Vec<(Arc<Tab>, String)>,
    last_seq: Option<u64>,
}

impl WorkLog {
    /// None unless `opsapi.work_log.enabled`. `otlp_port` must be the port actually bound.
    pub fn new(cfg: &Config, audit: Arc<Audit>) -> Option<Arc<Self>> {
        let w = &cfg.opsapi.work_log;
        if !w.enabled {
            return None;
        }
        let micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        let uploads = Arc::new(recorder::Uploads::new(
            cfg.server.state_dir.join("recordings"),
            w.max_pending_mb.saturating_mul(1024 * 1024),
            audit.clone(),
        ));
        uploads.load_leftovers();
        Some(Arc::new(Self {
            url: w.url.as_deref().unwrap_or("").trim_end_matches('/').into(),
            terminal: cfg
                .opsapi
                .keys
                .terminal_id
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase(),
            secret: cfg.opsapi.webhook_secret.clone().unwrap_or_default(),
            otlp_port: w.otlp_port,
            record: w.record,
            tabs: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
            // Starting from the clock keeps `<tab>:<seq>` ids unique across restarts (tab ids
            // already are; this is belt and braces), as long as < 1M events a second arrive.
            events: Mutex::new(EventQueue {
                items: VecDeque::new(),
                next_seq: micros,
                dropped: 0,
            }),
            uploads,
            unattributed: Mutex::new((0, None)),
            audit,
        }))
    }

    /// A tab for a session about to start, and the environment to add to a local tab's shell.
    /// It counts once [`WorkLog::register`]ed (after the process started).
    pub fn new_tab(
        &self,
        id: &str,
        login: &Login,
        target: &Target,
        spec: &PtySpec,
        launch: Option<&crate::opsapi::LaunchTag>,
    ) -> (Arc<Tab>, Vec<(String, String)>) {
        let local = matches!(target, Target::Local { .. });
        let opened_at = unix_now();
        let token = local.then(new_token);
        let recorder = (local && self.record).then(|| {
            Mutex::new(recorder::Recorder::new(
                self.uploads.clone(),
                id,
                spec.cols,
                spec.rows,
                opened_at,
            ))
        });
        let tab = Arc::new(Tab {
            id: id.to_string(),
            user: login.user.clone(),
            key: login.key_fingerprint.clone(),
            via: if login.via == "opsapi_launch" {
                "opsapi_launch"
            } else {
                "key"
            },
            ip: login.ip.clone(),
            launch: launch.map(|l| l.id.clone()),
            kind: target.kind(),
            cwd: local.then(|| spec.cwd.to_string_lossy().into_owned()),
            agent: launch.map(|l| l.agent.clone()),
            opened_at,
            started: Instant::now(),
            token_hash: token.as_deref().map(crate::security::hash_secret),
            input_bytes: AtomicU64::new(0),
            output_bytes: AtomicU64::new(0),
            active_secs: AtomicU64::new(0),
            last_active: AtomicU64::new(0),
            last_input_at: AtomicU64::new(0),
            attached: AtomicBool::new(false),
            end: Mutex::new(None),
            acked: Mutex::new(None),
            recorder,
        });
        let env = token
            .map(|t| telemetry_env(self.otlp_port, &t))
            .unwrap_or_default();
        (tab, env)
    }

    pub fn register(&self, tab: &Arc<Tab>) {
        if let Some(h) = tab.token_hash {
            self.tokens.lock().unwrap().insert(h, tab.id.clone());
        }
        self.tabs
            .lock()
            .unwrap()
            .insert(tab.id.clone(), tab.clone());
    }

    /// The session ended: its token stops naming it and its recording gets its last part. The
    /// tab is forgotten once OpsAPI has its final state.
    pub fn close_tab(&self, tab: &Tab, reason: &str, exit_code: Option<u32>) {
        *tab.end.lock().unwrap() = Some(End {
            closed_at: unix_now(),
            reason: reason.to_string(),
            exit_code,
        });
        tab.set_attached(false);
        if let Some(h) = tab.token_hash {
            self.tokens.lock().unwrap().remove(&h);
        }
        if let Some(r) = &tab.recorder {
            r.lock().unwrap().finish();
        }
    }

    /// The live tab a bearer token names.
    pub fn tab_for_token(&self, token: &str) -> Option<String> {
        let h = crate::security::hash_secret(token);
        self.tokens.lock().unwrap().get(&h).cloned()
    }

    /// A telemetry post without a tab's token: discarded unread, only counted.
    pub fn drop_unattributed(&self) {
        self.unattributed.lock().unwrap().0 += 1;
    }

    /// Queue telemetry events for the tab.
    pub fn push_events(&self, tab: &str, drafts: Vec<otlp::Draft>) {
        let mut q = self.events.lock().unwrap();
        for d in drafts {
            let seq = q.next_seq;
            q.next_seq += 1;
            let mut e = json!({
                "id": format!("{tab}:{seq}"),
                "tab": tab,
                "at": d.at,
                "type": d.kind,
                "attrs": d.attrs,
            });
            if let Some(s) = d.session {
                e["session"] = s.into();
            }
            if let Some(p) = d.prompt_id {
                e["prompt_id"] = p.into();
            }
            let line = e.to_string();
            if line.len() > MAX_EVENT_BYTES {
                q.dropped += 1;
                continue;
            }
            if q.items.len() >= MAX_QUEUED_EVENTS {
                q.items.pop_front();
                if q.dropped == 0 {
                    warn!("work log queue full (OpsAPI unreachable?); dropping the oldest events");
                }
                q.dropped += 1;
            }
            q.items.push_back((seq, line));
        }
    }

    /// Every 10 s: count active time, close recording parts older than 60 s, and audit dropped
    /// unattributed posts (at most once a minute).
    pub fn tick(&self) {
        let mut u = self.unattributed.lock().unwrap();
        if u.0 > 0 && u.1.is_none_or(|t| t.elapsed() >= UNATTRIBUTED_AUDIT_EVERY) {
            let ev = AuditEvent::new("work_log_unattributed_dropped");
            self.audit.log(ev.num("count", u.0 as i64));
            *u = (0, Some(Instant::now()));
        }
        drop(u);
        let tabs: Vec<_> = self.tabs.lock().unwrap().values().cloned().collect();
        for t in tabs.iter().filter(|t| !t.is_closed()) {
            let last = t.last_active.load(Ordering::Relaxed);
            let now = t.started.elapsed().as_secs() + 1;
            if last > 0 && now.saturating_sub(last) <= ACTIVE_WINDOW_SECS {
                t.active_secs.fetch_add(TICK.as_secs(), Ordering::Relaxed);
            }
            if let Some(r) = &t.recorder {
                r.lock().unwrap().rotate_if_older(recorder::MAX_PART_AGE);
            }
        }
    }

    /// The next `/activity` body: tabs that are due and the oldest queued events, at most
    /// [`forward::MAX_BATCH_EVENTS`] and [`forward::MAX_BODY`] bytes. None when nothing is new.
    pub fn batch(&self, now: u64) -> Option<Batch> {
        let tabs: Vec<(Arc<Tab>, Value, String)> = self
            .tabs
            .lock()
            .unwrap()
            .values()
            .filter_map(|t| {
                let v = t.state();
                let s = v.to_string();
                t.due(&s).then(|| (t.clone(), v, s))
            })
            .collect();
        let head = json!({
            "terminal": self.terminal,
            "sent_at": now,
            "tabs": tabs.iter().map(|(_, v, _)| v).collect::<Vec<_>>(),
        })
        .to_string();
        let budget = forward::MAX_BODY.saturating_sub(head.len() + 16);
        let q = self.events.lock().unwrap();
        let mut events = String::new();
        let mut last_seq = None;
        for (n, (seq, e)) in q.items.iter().enumerate() {
            if n == forward::MAX_BATCH_EVENTS || events.len() + e.len() + 1 > budget {
                break;
            }
            if n > 0 {
                events.push(',');
            }
            events.push_str(e);
            last_seq = Some(*seq);
        }
        drop(q);
        if tabs.is_empty() && last_seq.is_none() {
            return None;
        }
        // `head` is a JSON object; add the events (already JSON) before its closing brace.
        let body = format!("{},\"events\":[{events}]}}", &head[..head.len() - 1]);
        Some(Batch {
            body,
            tabs: tabs.into_iter().map(|(t, _, s)| (t, s)).collect(),
            last_seq,
        })
    }

    /// OpsAPI took the batch: drop its events, remember the tab states, forget closed tabs.
    /// Returns how many events were lost since the previous good send.
    pub fn ack(&self, b: &Batch) -> u64 {
        let mut q = self.events.lock().unwrap();
        if let Some(last) = b.last_seq {
            while q.items.front().is_some_and(|(seq, _)| *seq <= last) {
                q.items.pop_front();
            }
        }
        let dropped = std::mem::take(&mut q.dropped);
        drop(q);
        let mut tabs = self.tabs.lock().unwrap();
        for (t, state) in &b.tabs {
            *t.acked.lock().unwrap() = Some((state.clone(), Instant::now()));
            let final_state = serde_json::from_str::<Value>(state)
                .is_ok_and(|v| v["closed_at"].is_u64());
            if final_state {
                tabs.remove(&t.id);
            }
        }
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::keys::Access;

    fn work_log(dir: &std::path::Path) -> Arc<WorkLog> {
        work_log_with(dir, Audit::disabled())
    }

    fn work_log_with(dir: &std::path::Path, audit: Audit) -> Arc<WorkLog> {
        let mut cfg = Config::default();
        cfg.server.state_dir = dir.to_path_buf();
        cfg.opsapi.work_log.enabled = true;
        cfg.opsapi.work_log.url = Some("https://ops.example/terminal/".into());
        cfg.opsapi.webhook_secret = Some(crate::opsapi::tests::SECRET.into());
        cfg.opsapi.keys.terminal_id = Some("6F1C2A9E-1111-4C4C-9D9D-0123456789AB".into());
        WorkLog::new(&cfg, Arc::new(audit)).unwrap()
    }

    fn login() -> Login {
        Login {
            id: "l".into(),
            user: "priya".into(),
            key_fingerprint: "SHA256:abc".into(),
            access: Access::parse("local").unwrap(),
            ip: "203.0.113.4".into(),
            created_unix: 0,
            expires_unix: 0,
            via: "websocket",
        }
    }

    fn spec() -> PtySpec {
        PtySpec {
            program: "/bin/sh".into(),
            args: vec![],
            env: vec![],
            cwd: "/srv/site".into(),
            cols: 80,
            rows: 24,
            run_as: None,
            sandbox: None,
        }
    }

    fn draft(kind: &str) -> otlp::Draft {
        otlp::Draft {
            at: 1.5,
            kind: kind.into(),
            session: Some("s1".into()),
            prompt_id: None,
            attrs: Default::default(),
        }
    }

    #[test]
    fn local_tabs_get_a_token_and_telemetry_settings() {
        let dir = tempfile::tempdir().unwrap();
        let w = work_log(dir.path());
        let local = Target::Local {
            shell: "/bin/sh".into(),
        };
        let (tab, env) = w.new_tab("t1", &login(), &local, &spec(), None);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let token = get("SSHWEB_TAB_TOKEN").unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            get("OTEL_EXPORTER_OTLP_HEADERS").unwrap(),
            format!("Authorization=Bearer {token}")
        );
        assert_eq!(
            get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT").unwrap(),
            "http://127.0.0.1:7683/v1/logs"
        );
        assert_eq!(get("CLAUDE_CODE_ENABLE_TELEMETRY").unwrap(), "1");
        assert_eq!(w.tab_for_token(&token), None, "counts once registered");
        w.register(&tab);
        assert_eq!(w.tab_for_token(&token).as_deref(), Some("t1"));
        w.close_tab(&tab, "closed by user", Some(0));
        assert_eq!(
            w.tab_for_token(&token),
            None,
            "a closed tab's token names nothing"
        );
    }

    #[test]
    fn tabs_are_sent_until_their_final_state_is_taken_and_events_until_acked() {
        let dir = tempfile::tempdir().unwrap();
        let w = work_log(dir.path());
        assert!(w.batch(1).is_none(), "nothing new");
        let local = Target::Local {
            shell: "/bin/sh".into(),
        };
        let (tab, _) = w.new_tab("t1", &login(), &local, &spec(), None);
        w.register(&tab);
        tab.input(3);
        let two = vec![draft("user_prompt"), draft("api_request")];
        w.push_events("t1", two);
        w.push_events("t1", vec![draft("api_error")]);

        let b = w.batch(1792828054).unwrap();
        let v: Value = serde_json::from_str(&b.body).unwrap();
        assert_eq!(v["terminal"], "6f1c2a9e-1111-4c4c-9d9d-0123456789ab");
        assert_eq!(v["sent_at"], 1792828054);
        let t = &v["tabs"][0];
        assert_eq!(t["id"], "t1");
        assert_eq!(t["via"], "key");
        assert_eq!(t["cwd"], "/srv/site");
        assert_eq!(t["input_bytes"], 3);
        assert!(t["closed_at"].is_null() && t["launch"].is_null());
        let ev = v["events"].as_array().unwrap();
        assert_eq!(ev.len(), 3);
        assert!(ev[0]["id"].as_str().unwrap().starts_with("t1:"));
        assert_eq!(ev[0]["session"], "s1");
        assert!(ev[0].get("prompt_id").is_none());
        assert_eq!(ev[2]["tab"], "t1");
        let seq = |e: &Value| -> u64 {
            let id = e["id"].as_str().unwrap();
            id[id.find(':').unwrap() + 1..].parse().unwrap()
        };
        assert!(seq(&ev[0]) < seq(&ev[1]) && seq(&ev[1]) < seq(&ev[2]));

        // Not taken yet: the same again.
        assert_eq!(w.batch(1792828054).unwrap().body, b.body);
        assert_eq!(w.ack(&b), 0);
        assert!(w.batch(2).is_none(), "an open tab isn't re-sent within the minute");
        tab.output(b"x");
        assert!(w.batch(2).is_none(), "nor when it changed");

        w.close_tab(&tab, "process exited", Some(3));
        let b = w.batch(3).unwrap();
        let v: Value = serde_json::from_str(&b.body).unwrap();
        assert_eq!(v["tabs"][0]["end_reason"], "process exited");
        assert_eq!(v["tabs"][0]["exit_code"], 3);
        assert_eq!(v["tabs"][0]["output_bytes"], 1);
        assert_eq!(v["events"], json!([]));
        w.ack(&b);
        assert!(w.tabs.lock().unwrap().is_empty(), "closed tab forgotten");
        assert!(w.batch(4).is_none());
    }

    #[test]
    fn open_tabs_are_re_sent_every_minute_with_their_last_input_and_attachment() {
        let dir = tempfile::tempdir().unwrap();
        let w = work_log(dir.path());
        let local = Target::Local {
            shell: "/bin/sh".into(),
        };
        let (tab, _) = w.new_tab("t1", &login(), &local, &spec(), None);
        w.register(&tab);
        let tab_state = |b: &Batch| -> Value {
            let v: Value = serde_json::from_str(&b.body).unwrap();
            v["tabs"][0].clone()
        };
        // Pretend OpsAPI took the tab a minute ago.
        let a_minute_ago = |t: &Tab| {
            let mut acked = t.acked.lock().unwrap();
            let at = &mut acked.as_mut().unwrap().1;
            *at = at.checked_sub(HEARTBEAT).unwrap();
        };
        let b = w.batch(1).unwrap();
        let first = tab_state(&b);
        assert!(first["last_input_at"].is_null(), "{first}");
        assert_eq!(first["attached"], false);
        w.ack(&b);
        assert!(w.batch(2).is_none());

        // Unchanged, but still open: sent again, so OpsAPI knows it is live.
        a_minute_ago(&tab);
        let b = w.batch(3).unwrap();
        assert_eq!(tab_state(&b), first);
        w.ack(&b);

        let before = unix_now();
        tab.set_attached(true);
        tab.input(2);
        a_minute_ago(&tab);
        let b = w.batch(4).unwrap();
        let t = tab_state(&b);
        assert_eq!(t["attached"], true);
        assert!(t["last_input_at"].as_u64().unwrap() >= before, "{t}");
        w.ack(&b);

        w.close_tab(&tab, "closed by user", None);
        let b = w.batch(5).unwrap();
        assert_eq!(tab_state(&b)["attached"], false, "a closed tab has no browser");
        w.ack(&b);
        assert!(w.batch(6).is_none(), "closed tabs aren't re-sent");
    }

    #[test]
    fn unattributed_posts_are_only_counted_and_audited_once_a_minute() {
        use crate::config::{AuditConfig, AuditDestination};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let audit = Audit::open(&AuditConfig {
            destination: AuditDestination::File,
            path: path.clone(),
        })
        .unwrap();
        let w = work_log_with(dir.path(), audit);
        w.tick();
        for _ in 0..3 {
            w.drop_unattributed();
        }
        w.tick();
        w.drop_unattributed();
        w.tick();
        assert!(w.batch(1).is_none(), "nothing is forwarded");
        let log = std::fs::read_to_string(&path).unwrap();
        assert_eq!(log.matches("work_log_unattributed_dropped").count(), 1);
        assert!(log.contains("\"count\":3"), "{log}");
        assert_eq!(
            w.unattributed.lock().unwrap().0,
            1,
            "waits for the next minute"
        );
    }

    #[test]
    fn the_queue_is_bounded_and_batches_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        let w = work_log(dir.path());
        let n = MAX_QUEUED_EVENTS + 5;
        w.push_events("t1", (0..n).map(|_| draft("api_request")).collect());
        assert_eq!(w.events.lock().unwrap().items.len(), MAX_QUEUED_EVENTS);
        let b = w.batch(1).unwrap();
        let v: Value = serde_json::from_str(&b.body).unwrap();
        assert_eq!(
            v["events"].as_array().unwrap().len(),
            forward::MAX_BATCH_EVENTS
        );
        assert_eq!(w.ack(&b), 5, "the dropped count is reported once");
        assert_eq!(
            w.events.lock().unwrap().items.len(),
            MAX_QUEUED_EVENTS - forward::MAX_BATCH_EVENTS
        );
        assert_eq!(w.ack(&b), 0);
    }
}
