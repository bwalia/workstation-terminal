//! Typed configuration: loading, path resolution, environment overrides and validation.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::security::perms;

pub const DEFAULT_PORT: u16 = 7681;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub local: LocalConfig,
    pub remote: RemoteConfig,
    pub sessions: SessionConfig,
    pub limits: LimitsConfig,
    pub rate_limit: RateLimitConfig,
    pub audit: AuditConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
    /// Optional OpsAPI task bridge: launch links from task pages, and a webhook when they start/end.
    pub opsapi: OpsapiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpsapiConfig {
    /// e.g. https://int-opsapi.workstation.co.uk/api/v2/ai-runner/public/terminal/webhook
    pub webhook_url: Option<String>,
    /// Secret shared with OpsAPI (it generates it). Verifies launch links and signs webhooks
    /// (`X-Opsapi-Signature: sha256=<hmac-hex>`). Launch links need it and `local.allowed_roots`.
    pub webhook_secret: Option<String>,
    /// Agents a launch link may start, by id. The link names an id; the command line is only
    /// ever taken from here. `shell` (no agent) is always available.
    pub agents: Vec<AgentConfig>,
    /// Task sessions close after this long with neither input nor output. 0 disables.
    pub idle_timeout_secs: u64,
    /// Task sessions keep running this long after their browser disconnects.
    pub detach_grace_secs: u64,
    /// Let OpsAPI sign chosen people in with a launch link (off by default).
    pub autologin: AutologinConfig,
    /// Keys managers issue people in OpsAPI, fetched from it (off unless `url` is set).
    pub keys: OpsapiKeysConfig,
    /// Work log sent to OpsAPI: tabs, Claude Code telemetry, screen recordings (off by default).
    pub work_log: WorkLogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkLogConfig {
    pub enabled: bool,
    /// Base URL; `/activity` and `/recordings` are appended.
    /// e.g. https://int-opsapi.workstation.co.uk/api/v2/ai-runner/public/terminal
    pub url: Option<String>,
    /// Loopback-only plain-HTTP receiver for Claude Code's telemetry (0 picks a free port).
    pub otlp_port: u16,
    /// Record each local tab's output (never its input).
    pub record: bool,
    /// New recording parts are skipped (a gap) while this much waits for upload.
    pub max_pending_mb: u64,
}

impl Default for WorkLogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            otlp_port: 7683,
            record: true,
            max_pending_mb: 2048,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpsapiKeysConfig {
    /// e.g. https://int-opsapi.workstation.co.uk/api/v2/ai-runner/public/terminal/keys
    pub url: Option<String>,
    /// This terminal's id in OpsAPI (shown in its config block).
    pub terminal_id: Option<String>,
    /// How often to fetch the list.
    pub interval_secs: u64,
    /// Without a good fetch for this long, the keys from OpsAPI stop working (fail closed); keys in
    /// `authorized_keys` keep working.
    pub max_stale_secs: u64,
}

impl Default for OpsapiKeysConfig {
    fn default() -> Self {
        Self {
            url: None,
            terminal_id: None,
            interval_secs: 30,
            max_stale_secs: 900,
        }
    }
}

impl OpsapiKeysConfig {
    pub fn enabled(&self) -> bool {
        self.url.as_deref().is_some_and(|u| !u.is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AutologinConfig {
    pub enabled: bool,
    /// The OpsAPI step-up (emailed code) may be at most this old.
    pub max_stepup_age_secs: u64,
    /// OpsAPI email (any case) -> terminal user. The user signs in through their authorized key
    /// that allows `local`; nobody else can be signed in by a link.
    pub users: std::collections::BTreeMap<String, String>,
}

impl Default for AutologinConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_stepup_age_secs: 12 * 3600,
            users: Default::default(),
        }
    }
}

impl AutologinConfig {
    /// The terminal user mapped to an OpsAPI email, compared case-insensitively.
    pub fn user_for(&self, email: &str) -> Option<&str> {
        let email = email.to_lowercase();
        self.users
            .iter()
            .find(|(e, _)| e.to_lowercase() == email)
            .map(|(_, u)| u.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Shell command line run in the task folder, e.g. `claude -- "$OPSAPI_TASK_PROMPT"` (`--` so
    /// the prompt is never read as an option). The task text is only available through the
    /// OPSAPI_* environment variables.
    pub run: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address. Loopback by default.
    pub bind: IpAddr,
    pub port: u16,
    /// Must be true to bind a non-loopback address. TLS is then mandatory.
    pub allow_remote_access: bool,
    /// Extra origins (scheme://host[:port]) browsers may use, e.g. a DNS name for remote access.
    pub allowed_origins: Vec<String>,
    /// Reverse proxies (exact IPs) whose X-Forwarded-For header is trusted for the client IP
    /// used in rate limiting, lockouts and the audit log. Empty = use the TCP peer address.
    pub trusted_proxies: Vec<IpAddr>,
    pub tls: TlsConfig,
    /// Directory for runtime state (admin socket). Created with mode 0700.
    pub state_dir: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Administrator-managed authorisation file (see docs/AUTHENTICATION.md).
    pub authorized_keys: PathBuf,
    pub challenge_ttl_secs: u64,
    /// Absolute lifetime of a browser login.
    pub session_ttl_secs: u64,
    /// A login expires after this long without any activity.
    pub session_idle_timeout_secs: u64,
    /// Minimum RSA modulus size accepted in the authorisation file.
    pub min_rsa_bits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalConfig {
    pub enabled: bool,
    /// Shell started when the client does not request one. Defaults to $SHELL, then /bin/zsh.
    pub default_shell: Option<PathBuf>,
    /// Shells a client may request. Each must also be listed in /etc/shells.
    pub allowed_shells: Vec<PathBuf>,
    /// Start the shell as a login shell (`-l`).
    pub login_shell: bool,
    /// Working directory; defaults to $HOME.
    pub working_dir: Option<PathBuf>,
    /// Folders a tab may be opened in (and their subfolders), e.g. `~/projects`. Empty: tabs
    /// always start in `working_dir` and launch links are refused.
    pub allowed_roots: Vec<PathBuf>,
    /// Run local shells as this account (through sudo) instead of the gateway's own, so what they
    /// run can't read the gateway's config, secrets, TLS key or logs. Needs the sudoers rule in
    /// packaging/sshweb.sudoers; `config validate` checks it. Unset: shells run as the gateway.
    pub run_as: Option<String>,
    /// macOS only: run local shells inside this sandbox profile (`sandbox-exec`), e.g.
    /// packaging/sshweb-shell.sb, which keeps them to their account's folder and the web. It gets
    /// `HOME` (the shells' home) and `OTLP_PORT` (the work log's receiver) as parameters. Must be
    /// owned by root (or the gateway) and not writable by others; `config validate` tries it.
    pub sandbox_profile: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteConfig {
    pub enabled: bool,
    pub ssh_binary: PathBuf,
    pub ssh_keyscan_binary: PathBuf,
    /// Managed known_hosts file. The only source of trusted host keys.
    pub known_hosts: PathBuf,
    pub connect_timeout_secs: u64,
    pub keepalive_interval_secs: u64,
    pub keepalive_count_max: u32,
    /// Pass SSH_AUTH_SOCK of the gateway process to ssh.
    pub use_agent: bool,
    /// Allow connecting to hosts not listed as profiles (still constrained by the allowlists).
    pub allow_adhoc: bool,
    pub allowed_hosts: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub allowed_users: Vec<String>,
    pub profiles: Vec<RemoteProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteProfile {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub user: String,
    /// Private key on the gateway host used for this profile (never sent to browsers).
    #[serde(default)]
    pub identity_file: Option<PathBuf>,
}

fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionConfig {
    pub max_total: usize,
    pub max_per_user: usize,
    /// Close a terminal session after this long without keyboard input. 0 disables.
    pub idle_timeout_secs: u64,
    /// Keep a session alive this long after its browser disconnects, so it can be resumed.
    pub detach_grace_secs: u64,
    /// Output kept for replay when a browser re-attaches.
    pub scrollback_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub ws_max_message_bytes: usize,
    pub max_websockets: usize,
    /// A WebSocket that hasn't signed in this long after connecting is closed.
    pub ws_auth_timeout_secs: u64,
    /// WebSockets not signed in yet, per client IP, so one client can't take every slot.
    pub max_unauthenticated_websockets_per_ip: usize,
    pub input_bytes_per_sec: u64,
    pub input_burst_bytes: u64,
    pub max_http_body_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    pub challenges_per_minute: u32,
    pub max_failures: u32,
    pub failure_window_secs: u64,
    pub lockout_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditDestination {
    File,
    Stderr,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    pub destination: AuditDestination,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// Expose /metrics on the HTTP listener (loopback clients only). Always on the admin socket.
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub format: LogFormat,
    pub level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            auth: AuthConfig::default(),
            local: LocalConfig::default(),
            remote: RemoteConfig::default(),
            sessions: SessionConfig::default(),
            limits: LimitsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            audit: AuditConfig::default(),
            metrics: MetricsConfig { enabled: false },
            logging: LoggingConfig::default(),
            opsapi: OpsapiConfig::default(),
        }
    }
}

impl Default for OpsapiConfig {
    fn default() -> Self {
        Self {
            webhook_url: None,
            webhook_secret: None,
            agents: Vec::new(),
            idle_timeout_secs: 4 * 3600,
            detach_grace_secs: 4 * 3600,
            autologin: AutologinConfig::default(),
            keys: OpsapiKeysConfig::default(),
            work_log: WorkLogConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_PORT,
            allow_remote_access: false,
            allowed_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            tls: TlsConfig::default(),
            state_dir: PathBuf::from("run"),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            authorized_keys: PathBuf::from("authorized_keys"),
            challenge_ttl_secs: 120,
            session_ttl_secs: 8 * 3600,
            session_idle_timeout_secs: 30 * 60,
            min_rsa_bits: 2048,
        }
    }
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_shell: None,
            allowed_shells: vec![
                PathBuf::from("/bin/zsh"),
                PathBuf::from("/bin/bash"),
                PathBuf::from("/bin/sh"),
            ],
            login_shell: true,
            working_dir: None,
            allowed_roots: Vec::new(),
            run_as: None,
            sandbox_profile: None,
        }
    }
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ssh_binary: PathBuf::from("/usr/bin/ssh"),
            ssh_keyscan_binary: PathBuf::from("/usr/bin/ssh-keyscan"),
            known_hosts: PathBuf::from("known_hosts"),
            connect_timeout_secs: 10,
            keepalive_interval_secs: 30,
            keepalive_count_max: 3,
            use_agent: false,
            allow_adhoc: false,
            allowed_hosts: Vec::new(),
            allowed_ports: vec![22],
            allowed_users: Vec::new(),
            profiles: Vec::new(),
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_total: 16,
            max_per_user: 8,
            idle_timeout_secs: 3600,
            detach_grace_secs: 1800,
            scrollback_bytes: 256 * 1024,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            ws_max_message_bytes: 64 * 1024,
            max_websockets: 64,
            ws_auth_timeout_secs: 30,
            max_unauthenticated_websockets_per_ip: 8,
            input_bytes_per_sec: 256 * 1024,
            input_burst_bytes: 1024 * 1024,
            max_http_body_bytes: 32 * 1024,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            challenges_per_minute: 20,
            max_failures: 5,
            failure_window_secs: 300,
            lockout_secs: 900,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            destination: AuditDestination::File,
            path: PathBuf::from("audit.log"),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Pretty,
            level: "info".into(),
        }
    }
}

/// Default config directory: `$SSHWEB_HOME` or `~/.sshweb`.
pub fn default_config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SSHWEB_HOME") {
        return PathBuf::from(dir);
    }
    home_dir().join(".sshweb")
}

pub fn default_config_path() -> PathBuf {
    default_config_dir().join("config.yaml")
}

/// A local account from the user database.
#[derive(Debug, Clone)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub home: PathBuf,
}

/// Look an account up by name (getpwnam_r). None if it doesn't exist.
pub fn lookup_account(name: &str) -> Option<Account> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: an all-zero passwd is a valid out-parameter; getpwnam_r fills it and points its
    // strings into `buf`, which outlives every use below. `out` is checked before reading.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwnam_r(cname.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    Some(Account {
        name: name.to_string(),
        uid: pwd.pw_uid,
        home: PathBuf::from(home.to_string_lossy().into_owned()),
    })
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Expand `~/` and make relative paths relative to `base`.
pub fn resolve_path(p: &Path, base: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if s == "~" {
        return home_dir();
    }
    if let Some(rest) = s.strip_prefix("~/") {
        return home_dir().join(rest);
    }
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

impl Config {
    /// Load from YAML, apply environment overrides, resolve paths. Does not validate.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| {
            format!(
                "cannot read config file {} (create one with `sshweb config init`)",
                path.display()
            )
        })?;
        let mut cfg = Self::from_yaml(&text)
            .with_context(|| format!("invalid config file {}", path.display()))?;
        cfg.apply_env_overrides()?;
        let base = path
            .parent()
            .map(|p| {
                if p.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    p.to_path_buf()
                }
            })
            .unwrap_or_else(|| PathBuf::from("."));
        let base = std::fs::canonicalize(&base).unwrap_or(base);
        cfg.resolve_paths(&base);
        Ok(cfg)
    }

    pub fn from_yaml(text: &str) -> Result<Self> {
        let cfg: Config = serde_yaml_ng::from_str(text)?;
        Ok(cfg)
    }

    pub fn apply_env_overrides(&mut self) -> Result<()> {
        fn var(name: &str) -> Option<String> {
            std::env::var(name).ok().filter(|v| !v.is_empty())
        }
        if let Some(v) = var("SSHWEB_BIND") {
            self.server.bind = v.parse().context("SSHWEB_BIND is not an IP address")?;
        }
        if let Some(v) = var("SSHWEB_PORT") {
            self.server.port = v.parse().context("SSHWEB_PORT is not a port number")?;
        }
        if let Some(v) = var("SSHWEB_ALLOW_REMOTE_ACCESS") {
            self.server.allow_remote_access = matches!(v.as_str(), "1" | "true" | "yes");
        }
        if let Some(v) = var("SSHWEB_TLS_CERT") {
            self.server.tls.cert = Some(v.into());
        }
        if let Some(v) = var("SSHWEB_TLS_KEY") {
            self.server.tls.key = Some(v.into());
        }
        if let Some(v) = var("SSHWEB_STATE_DIR") {
            self.server.state_dir = v.into();
        }
        if let Some(v) = var("SSHWEB_AUTHORIZED_KEYS") {
            self.auth.authorized_keys = v.into();
        }
        if let Some(v) = var("SSHWEB_KNOWN_HOSTS") {
            self.remote.known_hosts = v.into();
        }
        if let Some(v) = var("SSHWEB_AUDIT_LOG") {
            self.audit.path = v.into();
        }
        if let Some(v) = var("SSHWEB_LOG_LEVEL") {
            self.logging.level = v;
        }
        if let Some(v) = var("SSHWEB_OPSAPI_WEBHOOK_URL") {
            self.opsapi.webhook_url = Some(v);
        }
        if let Some(v) = var("SSHWEB_OPSAPI_WEBHOOK_SECRET") {
            self.opsapi.webhook_secret = Some(v);
        }
        Ok(())
    }

    pub fn resolve_paths(&mut self, base: &Path) {
        let r = |p: &mut PathBuf| *p = resolve_path(p, base);
        r(&mut self.server.state_dir);
        if let Some(p) = self.server.tls.cert.as_mut() {
            r(p);
        }
        if let Some(p) = self.server.tls.key.as_mut() {
            r(p);
        }
        r(&mut self.auth.authorized_keys);
        r(&mut self.remote.known_hosts);
        r(&mut self.audit.path);
        if let Some(p) = self.local.working_dir.as_mut() {
            r(p);
        }
        for p in &mut self.local.allowed_roots {
            r(p);
        }
        for prof in &mut self.remote.profiles {
            if let Some(p) = prof.identity_file.as_mut() {
                r(p);
            }
        }
    }

    pub fn tls_enabled(&self) -> bool {
        self.server.tls.cert.is_some() && self.server.tls.key.is_some()
    }

    pub fn admin_socket_path(&self) -> PathBuf {
        self.server.state_dir.join("admin.sock")
    }

    /// Static validation (no filesystem access).
    pub fn validate_static(&self) -> Vec<String> {
        let mut errs = Vec::new();
        let s = &self.server;
        if s.port == 0 {
            errs.push("server.port must be non-zero".into());
        }
        if !s.bind.is_loopback() && !s.allow_remote_access {
            errs.push(format!(
                "server.bind is {} (not loopback) but server.allow_remote_access is false; \
                 set it to true explicitly to expose the gateway",
                s.bind
            ));
        }
        if let Some(u) = &self.local.run_as {
            let ok = !u.is_empty()
                && u.len() <= 32
                && u.bytes().enumerate().all(|(i, b)| {
                    b == b'_' || b.is_ascii_lowercase() || (i > 0 && (b.is_ascii_digit() || b == b'-' || b == b'.'))
                });
            if !ok {
                errs.push(format!("local.run_as {u:?} is not an account name sshweb can run shells as"));
            }
        }
        if s.tls.cert.is_some() != s.tls.key.is_some() {
            errs.push("server.tls.cert and server.tls.key must be set together".into());
        }
        if !s.bind.is_loopback() && !self.tls_enabled() {
            errs.push(
                "remote access requires TLS: set server.tls.cert and server.tls.key \
                 (or SSHWEB_TLS_CERT / SSHWEB_TLS_KEY)"
                    .into(),
            );
        }
        if s.bind.is_unspecified() && s.allowed_origins.is_empty() {
            errs.push(format!(
                "server.bind is {} (all interfaces): list the origin(s) browsers will use in \
                 server.allowed_origins, e.g. \"https://mac.example.net:{}\"",
                s.bind, s.port
            ));
        }
        for o in &s.allowed_origins {
            if crate::security::origin::parse_origin(o).is_none() {
                errs.push(format!(
                    "server.allowed_origins entry {o:?} must look like https://host[:port]"
                ));
            } else if !self.tls_enabled() && o.starts_with("https://") {
                errs.push(format!(
                    "server.allowed_origins entry {o:?} uses https but TLS is not configured"
                ));
            }
        }
        let a = &self.auth;
        if !(10..=900).contains(&a.challenge_ttl_secs) {
            errs.push("auth.challenge_ttl_secs must be between 10 and 900".into());
        }
        if a.session_ttl_secs < 60 || a.session_ttl_secs > 7 * 24 * 3600 {
            errs.push("auth.session_ttl_secs must be between 60 and 604800".into());
        }
        if a.session_idle_timeout_secs < 60 {
            errs.push("auth.session_idle_timeout_secs must be at least 60".into());
        }
        if a.min_rsa_bits < 2048 {
            errs.push("auth.min_rsa_bits must be at least 2048".into());
        }
        if !self.local.enabled && !self.remote.enabled {
            errs.push("at least one of local.enabled or remote.enabled must be true".into());
        }
        for sh in &self.local.allowed_shells {
            if !sh.is_absolute() {
                errs.push(format!(
                    "local.allowed_shells entry {} must be absolute",
                    sh.display()
                ));
            }
        }
        if let Some(sh) = &self.local.default_shell
            && !self.local.allowed_shells.contains(sh)
        {
            errs.push(format!(
                "local.default_shell {} is not in local.allowed_shells",
                sh.display()
            ));
        }
        let r = &self.remote;
        if r.connect_timeout_secs == 0 || r.connect_timeout_secs > 120 {
            errs.push("remote.connect_timeout_secs must be between 1 and 120".into());
        }
        if r.known_hosts.to_string_lossy().contains(['"', '\n']) {
            errs.push("remote.known_hosts path must not contain quotes or newlines".into());
        }
        let mut ids = std::collections::HashSet::new();
        for p in &r.profiles {
            if !crate::ssh::valid_profile_id(&p.id) {
                errs.push(format!(
                    "remote.profiles id {:?} must start with a letter or digit and match [A-Za-z0-9_-]{{1,64}}",
                    p.id
                ));
            }
            if !ids.insert(p.id.clone()) {
                errs.push(format!("duplicate remote profile id {:?}", p.id));
            }
            if !crate::ssh::valid_host(&p.host) {
                errs.push(format!(
                    "remote profile {:?}: invalid host {:?}",
                    p.id, p.host
                ));
            }
            if !crate::ssh::valid_remote_user(&p.user) {
                errs.push(format!(
                    "remote profile {:?}: invalid user {:?}",
                    p.id, p.user
                ));
            }
            if p.port == 0 {
                errs.push(format!("remote profile {:?}: port must be non-zero", p.id));
            }
        }
        for h in &r.allowed_hosts {
            if !crate::ssh::valid_host(h) {
                errs.push(format!("remote.allowed_hosts entry {h:?} is invalid"));
            }
        }
        for u in &r.allowed_users {
            if !crate::ssh::valid_remote_user(u) {
                errs.push(format!("remote.allowed_users entry {u:?} is invalid"));
            }
        }
        if r.allow_adhoc && (r.allowed_hosts.is_empty() || r.allowed_users.is_empty()) {
            errs.push(
                "remote.allow_adhoc requires non-empty remote.allowed_hosts and remote.allowed_users \
                 (arbitrary-host proxying is not supported)"
                    .into(),
            );
        }
        let o = &self.opsapi;
        if let Some(sec) = &o.webhook_secret
            && sec.len() < 32
        {
            errs.push(
                "opsapi.webhook_secret must be at least 32 characters (paste the one OpsAPI generated)"
                    .into(),
            );
        }
        if let Some(u) = &o.webhook_url
            && !(u.starts_with("https://") || u.starts_with("http://"))
        {
            errs.push("opsapi.webhook_url must be an http(s) URL".into());
        }
        let mut agent_ids = std::collections::HashSet::new();
        for a in &o.agents {
            if !crate::opsapi::valid_agent_id(&a.id) || a.id == "shell" {
                errs.push(format!(
                    "opsapi.agents id {:?} must match [a-z0-9_-]{{1,32}} and not be \"shell\"",
                    a.id
                ));
            }
            if !agent_ids.insert(a.id.clone()) {
                errs.push(format!("duplicate opsapi agent id {:?}", a.id));
            }
            if a.run.trim().is_empty()
                || a.run.len() > 1024
                || a.run.chars().any(|c| c.is_control())
            {
                errs.push(format!(
                    "opsapi agent {:?}: run must be one line of at most 1024 characters",
                    a.id
                ));
            }
        }
        let k = &o.keys;
        if k.enabled() {
            // Keys grant shells: only over TLS, except to OpsAPI on this machine for development.
            if !tls_or_this_machine(k.url.as_deref().unwrap_or("")) {
                errs.push("opsapi.keys.url must be https (or http://localhost / 127.0.0.1)".into());
            }
            if !k
                .terminal_id
                .as_deref()
                .is_some_and(crate::opsapi::valid_uuid)
            {
                errs.push("opsapi.keys.terminal_id must be the terminal's id from OpsAPI".into());
            }
            if o.webhook_secret.as_deref().unwrap_or("").is_empty() {
                errs.push("opsapi.keys needs opsapi.webhook_secret".into());
            }
            if k.interval_secs == 0 || k.max_stale_secs < k.interval_secs.saturating_mul(2) {
                errs.push(
                    "opsapi.keys: interval_secs must be positive and max_stale_secs at least twice it"
                        .into(),
                );
            }
        }
        let w = &o.work_log;
        if w.enabled {
            if !w.url.as_deref().is_some_and(tls_or_this_machine) {
                errs.push(
                    "opsapi.work_log.url must be https (or http://localhost / 127.0.0.1)".into(),
                );
            }
            if !k
                .terminal_id
                .as_deref()
                .is_some_and(crate::opsapi::valid_uuid)
            {
                errs.push("opsapi.work_log needs opsapi.keys.terminal_id".into());
            }
            if o.webhook_secret.as_deref().unwrap_or("").is_empty() {
                errs.push("opsapi.work_log needs opsapi.webhook_secret".into());
            }
            if w.max_pending_mb == 0 {
                errs.push("opsapi.work_log.max_pending_mb must be positive".into());
            }
        }
        let al = &o.autologin;
        if al.enabled && o.webhook_secret.as_deref().unwrap_or("").is_empty() {
            errs.push("opsapi.autologin needs opsapi.webhook_secret".into());
        }
        if al.max_stepup_age_secs == 0 {
            errs.push("opsapi.autologin.max_stepup_age_secs must be positive".into());
        }
        let mut emails = std::collections::HashSet::new();
        for (email, user) in &al.users {
            let at = email.split_once('@');
            if email.len() > 254
                || email.chars().any(|c| c.is_whitespace() || c.is_control())
                || !matches!(at, Some((l, d)) if !l.is_empty() && !d.is_empty())
            {
                errs.push(format!(
                    "opsapi.autologin.users: {email:?} isn't an email address"
                ));
            }
            if !emails.insert(email.to_lowercase()) {
                errs.push(format!("opsapi.autologin.users: {email:?} is listed twice"));
            }
            if !crate::auth::keys::valid_user(user) {
                errs.push(format!(
                    "opsapi.autologin.users: {user:?} (for {email:?}) isn't a valid user name"
                ));
            }
        }
        for r in &self.local.allowed_roots {
            if !r.is_absolute() {
                errs.push(format!(
                    "local.allowed_roots entry {} must be absolute",
                    r.display()
                ));
            }
        }
        for sh in &self.local.allowed_shells {
            if sh.to_string_lossy().contains(['\'', '"', '\\']) {
                errs.push(format!(
                    "local.allowed_shells: {} must not contain quotes",
                    sh.display()
                ));
            }
        }
        let ss = &self.sessions;
        if ss.max_total == 0 || ss.max_per_user == 0 {
            errs.push("sessions.max_total and sessions.max_per_user must be positive".into());
        }
        if ss.scrollback_bytes > 16 * 1024 * 1024 {
            errs.push("sessions.scrollback_bytes must be at most 16 MiB".into());
        }
        let l = &self.limits;
        if !(1024..=1024 * 1024).contains(&l.ws_max_message_bytes) {
            errs.push("limits.ws_max_message_bytes must be between 1024 and 1048576".into());
        }
        if l.input_bytes_per_sec == 0 || l.input_burst_bytes < l.ws_max_message_bytes as u64 {
            errs.push(
                "limits.input_bytes_per_sec must be positive and limits.input_burst_bytes \
                 at least limits.ws_max_message_bytes"
                    .into(),
            );
        }
        if l.max_websockets == 0 {
            errs.push("limits.max_websockets must be positive".into());
        }
        if l.ws_auth_timeout_secs == 0 || l.max_unauthenticated_websockets_per_ip == 0 {
            errs.push(
                "limits.ws_auth_timeout_secs and limits.max_unauthenticated_websockets_per_ip \
                 must be positive"
                    .into(),
            );
        }
        let rl = &self.rate_limit;
        if rl.challenges_per_minute == 0 || rl.max_failures == 0 {
            errs.push(
                "rate_limit.challenges_per_minute and rate_limit.max_failures must be positive"
                    .into(),
            );
        }
        if tracing_subscriber::EnvFilter::try_new(&self.logging.level).is_err() {
            errs.push(format!("logging.level {:?} is invalid", self.logging.level));
        }
        errs
    }

    /// Checks that need the filesystem: files exist and have safe permissions.
    pub fn validate_files(&self) -> Vec<String> {
        let mut errs = Vec::new();
        // macOS limits Unix socket paths to 104 bytes including the terminator.
        let sock = self.admin_socket_path();
        if sock.as_os_str().len() >= 104 {
            errs.push(format!(
                "admin socket path {} is too long for a Unix socket ({} bytes, max 103); \
                 set server.state_dir (or SSHWEB_STATE_DIR) to a shorter directory",
                sock.display(),
                sock.as_os_str().len()
            ));
        }
        match perms::check_admin_file(&self.auth.authorized_keys) {
            Ok(()) => {}
            Err(e) => errs.push(format!("auth.authorized_keys: {e}")),
        }
        if let (Some(cert), Some(key)) = (&self.server.tls.cert, &self.server.tls.key) {
            if !cert.is_file() {
                errs.push(format!("server.tls.cert {} does not exist", cert.display()));
            }
            if let Err(e) = perms::check_private_file(key) {
                errs.push(format!("server.tls.key: {e}"));
            }
        }
        if self.local.enabled {
            let shells = std::fs::read_to_string("/etc/shells").unwrap_or_default();
            for sh in &self.local.allowed_shells {
                if !sh.is_file() {
                    errs.push(format!("local.allowed_shells: {} not found", sh.display()));
                } else if !shells.lines().any(|l| l.trim() == sh.to_string_lossy()) {
                    errs.push(format!(
                        "local.allowed_shells: {} is not listed in /etc/shells",
                        sh.display()
                    ));
                }
            }
        }
        if self.local.enabled
            && let Some(u) = &self.local.run_as
        {
            match lookup_account(u) {
                None => errs.push(format!("local.run_as: there is no account {u:?}")),
                Some(a) if a.uid == 0 => errs.push("local.run_as must not be root".into()),
                // SAFETY: geteuid has no preconditions.
                Some(a) if a.uid == unsafe { libc::geteuid() } => errs.push(format!(
                    "local.run_as: {u:?} is the gateway's own account; run the gateway as another \
                     account (that is the point) or remove run_as"
                )),
                Some(a) => {
                    if let Err(e) = crate::terminal::check_run_as(&a) {
                        errs.push(format!("local.run_as: {e}"));
                    }
                }
            }
        }
        if self.local.enabled
            && let Some(p) = &self.local.sandbox_profile
        {
            if let Err(e) = perms::check_admin_file(p) {
                errs.push(format!("local.sandbox_profile: {e}"));
            } else if !Path::new(crate::terminal::SANDBOX_EXEC).is_file() {
                errs.push(format!(
                    "local.sandbox_profile needs {} (macOS)",
                    crate::terminal::SANDBOX_EXEC
                ));
            } else if let Err(e) = crate::terminal::check_sandbox(self) {
                errs.push(format!("local.sandbox_profile: {e}"));
            }
        }
        for r in &self.local.allowed_roots {
            match std::fs::metadata(r) {
                Ok(m) if m.is_dir() => {}
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => errs.push(format!(
                    "local.allowed_roots: the gateway's account can't reach {} (permission denied); \
                     with run_as, give it search access to the folders above it, e.g. \
                     `chmod +a \"user:<gateway account> allow search\" <home folder>`",
                    r.display()
                )),
                _ => errs.push(format!(
                    "local.allowed_roots: {} is not a folder",
                    r.display()
                )),
            }
        }
        if self.remote.enabled {
            if !self.remote.ssh_binary.is_file() {
                errs.push(format!(
                    "remote.ssh_binary {} not found (OpenSSH client is required for remote mode)",
                    self.remote.ssh_binary.display()
                ));
            }
            if let Err(e) = perms::check_admin_file(&self.remote.known_hosts) {
                errs.push(format!(
                    "remote.known_hosts: {e} (create it and add hosts with `sshweb hosts trust`)"
                ));
            }
            for p in &self.remote.profiles {
                if let Some(id) = &p.identity_file
                    && let Err(e) = perms::check_private_file(id)
                {
                    errs.push(format!("remote profile {:?} identity_file: {e}", p.id));
                }
            }
        }
        if self.audit.destination == AuditDestination::File
            && let Some(dir) = self.audit.path.parent()
            && !dir.is_dir()
        {
            errs.push(format!(
                "audit.path directory {} does not exist",
                dir.display()
            ));
        }
        errs
    }

    pub fn validate(&self) -> Result<()> {
        let mut errs = self.validate_static();
        errs.extend(self.validate_files());
        if errs.is_empty() {
            Ok(())
        } else {
            bail!("configuration is invalid:\n  - {}", errs.join("\n  - "))
        }
    }

    pub fn shell_allowed(&self, shell: &Path) -> bool {
        self.local.allowed_shells.iter().any(|s| s == shell)
    }

    /// The shell used when none is requested.
    pub fn effective_default_shell(&self) -> PathBuf {
        if let Some(s) = &self.local.default_shell {
            return s.clone();
        }
        if let Some(env) = std::env::var_os("SHELL") {
            let p = PathBuf::from(env);
            if self.shell_allowed(&p) {
                return p;
            }
        }
        self.local
            .allowed_shells
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("/bin/zsh"))
    }
}

/// An https URL, or plain http to OpsAPI on this machine (development).
fn tls_or_this_machine(url: &str) -> bool {
    [
        "https://",
        "http://localhost:",
        "http://localhost/",
        "http://127.0.0.1:",
        "http://127.0.0.1/",
    ]
    .iter()
    .any(|p| url.starts_with(p))
}

/// The sample configuration written by `sshweb config init`.
pub const SAMPLE_CONFIG: &str = include_str!("../config.example.yaml");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe_and_valid() {
        let c = Config::default();
        assert!(c.server.bind.is_loopback());
        assert!(!c.server.allow_remote_access);
        assert!(!c.remote.enabled);
        assert!(!c.remote.allow_adhoc);
        assert!(!c.metrics.enabled);
        assert!(c.validate_static().is_empty(), "{:?}", c.validate_static());
    }

    #[test]
    fn sample_config_parses() {
        let c = Config::from_yaml(SAMPLE_CONFIG).unwrap();
        assert!(c.validate_static().is_empty(), "{:?}", c.validate_static());
        assert_eq!(c.server.port, DEFAULT_PORT);
    }

    #[test]
    fn autologin_is_off_by_default_and_validated() {
        let c = Config::default();
        assert!(!c.opsapi.autologin.enabled);
        assert_eq!(c.opsapi.autologin.max_stepup_age_secs, 43200);
        let c = Config::from_yaml(
            "opsapi:\n  webhook_secret: \"0123456789abcdef0123456789abcdef\"\n  autologin:\n    \
             enabled: true\n    users:\n      \"Alice@Example.com\": alice\n",
        )
        .unwrap();
        assert!(c.validate_static().is_empty(), "{:?}", c.validate_static());
        assert_eq!(
            c.opsapi.autologin.user_for("alice@EXAMPLE.com"),
            Some("alice")
        );
        assert_eq!(c.opsapi.autologin.user_for("bob@example.com"), None);
        let bad = Config::from_yaml(
            "opsapi:\n  autologin:\n    enabled: true\n    max_stepup_age_secs: 0\n    users:\n      \
             \"a@x.io\": Root\n      \"A@X.io\": bob\n      \"nobody\": carol\n",
        )
        .unwrap();
        let errs = bad.validate_static().join("\n");
        for want in [
            "needs opsapi.webhook_secret",
            "max_stepup_age_secs",
            "\"Root\"",
            "listed twice",
            "\"nobody\"",
        ] {
            assert!(errs.contains(want), "{want}: {errs}");
        }
        assert!(Config::from_yaml("opsapi:\n  autologin:\n    enable: true\n").is_err());
    }

    #[test]
    fn work_log_is_off_by_default_and_validated() {
        let c = Config::default();
        assert!(!c.opsapi.work_log.enabled);
        assert_eq!(c.opsapi.work_log.otlp_port, 7683);
        assert!(c.opsapi.work_log.record);
        assert_eq!(c.opsapi.work_log.max_pending_mb, 2048);
        let c = Config::from_yaml(
            "opsapi:\n  webhook_secret: \"0123456789abcdef0123456789abcdef\"\n  keys:\n    \
             terminal_id: 6f1c2a9e-1111-4c4c-9d9d-0123456789ab\n  work_log:\n    \
             enabled: true\n    url: https://ops.example/api/v2/ai-runner/public/terminal\n",
        )
        .unwrap();
        assert!(c.validate_static().is_empty(), "{:?}", c.validate_static());
        let bad = Config::from_yaml(
            "opsapi:\n  work_log:\n    enabled: true\n    url: http://ops.example/terminal\n    \
             max_pending_mb: 0\n",
        )
        .unwrap();
        let errs = bad.validate_static().join("\n");
        for want in [
            "work_log.url must be https",
            "terminal_id",
            "webhook_secret",
            "max_pending_mb",
        ] {
            assert!(errs.contains(want), "{want}: {errs}");
        }
        assert!(Config::from_yaml("opsapi:\n  work_log:\n    recrd: true\n").is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        assert!(Config::from_yaml("server:\n  bindd: 1.2.3.4\n").is_err());
        assert!(Config::from_yaml("server:\n  port: 99999\n").is_err());
        assert!(Config::from_yaml("server:\n  bind: not-an-ip\n").is_err());
    }

    #[test]
    fn remote_exposure_requires_opt_in_tls_and_origins() {
        let mut c = Config::default();
        c.server.bind = "0.0.0.0".parse().unwrap();
        let e = c.validate_static().join("\n");
        assert!(e.contains("allow_remote_access"));
        assert!(e.contains("requires TLS"));
        assert!(e.contains("allowed_origins"));
        c.server.allow_remote_access = true;
        c.server.tls.cert = Some("/c.pem".into());
        c.server.tls.key = Some("/k.pem".into());
        c.server.allowed_origins = vec!["https://mac.example.net:7681".into()];
        assert!(c.validate_static().is_empty(), "{:?}", c.validate_static());
    }

    #[test]
    fn validation_catches_bad_limits_and_profiles() {
        let mut c = Config::default();
        c.auth.challenge_ttl_secs = 5;
        c.sessions.max_total = 0;
        c.remote.allow_adhoc = true;
        c.remote.profiles.push(RemoteProfile {
            id: "-bad".into(),
            name: None,
            host: "-oProxyCommand=x".into(),
            port: 22,
            user: "root;rm".into(),
            identity_file: None,
        });
        let e = c.validate_static().join("\n");
        for needle in [
            "challenge_ttl_secs",
            "max_total",
            "allow_adhoc",
            "id \"-bad\"",
            "invalid host",
            "invalid user",
        ] {
            assert!(e.contains(needle), "missing {needle}: {e}");
        }
        let mut c = Config::default();
        c.local.enabled = false;
        assert!(c.validate_static().join("").contains("at least one"));
    }

    #[test]
    fn paths_resolve_relative_to_config_dir() {
        let mut c = Config::default();
        c.resolve_paths(Path::new("/etc/sshweb"));
        assert_eq!(
            c.auth.authorized_keys,
            PathBuf::from("/etc/sshweb/authorized_keys")
        );
        assert_eq!(
            c.admin_socket_path(),
            PathBuf::from("/etc/sshweb/run/admin.sock")
        );
        assert_eq!(
            resolve_path(Path::new("~/x"), Path::new("/b")),
            home_dir().join("x")
        );
        assert_eq!(
            resolve_path(Path::new("/abs"), Path::new("/b")),
            PathBuf::from("/abs")
        );
    }

    #[test]
    fn env_overrides() {
        // SAFETY: tests touching env run in this single test.
        unsafe {
            std::env::set_var("SSHWEB_PORT", "9999");
            std::env::set_var("SSHWEB_TLS_CERT", "/x/cert.pem");
        }
        let mut c = Config::default();
        c.apply_env_overrides().unwrap();
        unsafe {
            std::env::remove_var("SSHWEB_PORT");
            std::env::remove_var("SSHWEB_TLS_CERT");
        }
        assert_eq!(c.server.port, 9999);
        assert_eq!(c.server.tls.cert, Some(PathBuf::from("/x/cert.pem")));
    }
}
