//! Terminal session lifecycle: creation, attach/detach for reconnects, limits and reaping.
//!
//! A session owns one PTY process (a local shell or the OpenSSH client). At most one WebSocket
//! is attached at a time. When the browser disconnects the session is *detached* and kept for
//! `detach_grace_secs`, so a reconnecting browser can resume it; recent output is replayed
//! from a bounded scrollback buffer. Input is never replayed.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::audit::{Audit, AuditEvent};
use crate::auth::sessions::{Login, unix_now};
use crate::config::Config;
use crate::metrics::Metrics;
use crate::ssh::RemoteTarget;
use crate::terminal::{PtyProcess, PtySpec};

const TERMINATE_GRACE: Duration = Duration::from_secs(3);
const OUTBOUND_QUEUE: usize = 32;

#[derive(Debug, Clone)]
pub enum Target {
    Local { shell: std::path::PathBuf },
    Remote(RemoteTarget),
}

impl Target {
    pub fn kind(&self) -> &'static str {
        match self {
            Target::Local { .. } => "local",
            Target::Remote(_) => "remote",
        }
    }

    pub fn title(&self) -> String {
        match self {
            Target::Local { shell } => {
                let user = std::env::var("USER").unwrap_or_else(|_| "local".into());
                let host = hostname();
                format!("{user}@{host} ({})", shell.display())
            }
            Target::Remote(t) => t.label(),
        }
    }
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buffer is valid for its length; gethostname NUL-terminates on success.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    if !ok {
        return "localhost".into();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Events delivered to the attached WebSocket.
#[derive(Debug)]
pub enum SessionEvent {
    Output(Bytes),
    /// Another connection attached; this one no longer owns the session.
    Detached,
    Closed {
        reason: String,
        exit_code: Option<u32>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub user: String,
    pub login_id: String,
    pub kind: &'static str,
    pub title: String,
    /// User-chosen label; None until renamed.
    pub name: Option<String>,
    pub profile: Option<String>,
    pub state: &'static str,
    pub created_unix: u64,
    pub idle_secs: u64,
    pub cols: u16,
    pub rows: u16,
}

struct Attachment {
    conn_id: u64,
    tx: mpsc::Sender<SessionEvent>,
}

struct Scrollback {
    buf: VecDeque<u8>,
    cap: usize,
}

impl Scrollback {
    fn push(&mut self, data: &[u8]) {
        if self.cap == 0 {
            return;
        }
        if data.len() >= self.cap {
            self.buf.clear();
            self.buf.extend(&data[data.len() - self.cap..]);
            return;
        }
        let overflow = (self.buf.len() + data.len()).saturating_sub(self.cap);
        self.buf.drain(..overflow);
        self.buf.extend(data);
    }

    fn snapshot(&mut self) -> Bytes {
        Bytes::copy_from_slice(self.buf.make_contiguous())
    }
}

struct Owner {
    login_id: String,
    key_fingerprint: String,
}

pub struct TerminalSession {
    pub id: String,
    pub user: String,
    /// Login and key currently responsible for the session. Rebound when the same user
    /// re-attaches after logging in again, so a detached shell can outlive the browser login.
    owner: Mutex<Owner>,
    pub target: Target,
    pub title: String,
    pub created_unix: u64,
    /// The OpsAPI launch this session was opened from. Task sessions follow the `opsapi`
    /// keep-alive limits and report start/end to OpsAPI.
    pub launch: Option<crate::opsapi::LaunchTag>,
    /// This session in the OpsAPI work log (`opsapi.work_log`).
    work: Option<Arc<crate::worklog::Tab>>,
    pty: PtyProcess,
    name: Mutex<Option<String>>,
    scrollback: Mutex<Scrollback>,
    attached: Mutex<Option<Attachment>>,
    detached_since: Mutex<Option<Instant>>,
    last_input: Mutex<Instant>,
    last_output: Mutex<Instant>,
    closed: CancellationToken,
    close_reason: Mutex<Option<String>>,
    metrics: Arc<Metrics>,
}

impl TerminalSession {
    pub fn info(&self) -> SessionInfo {
        let (cols, rows) = self.pty.size().unwrap_or((0, 0));
        SessionInfo {
            id: self.id.clone(),
            user: self.user.clone(),
            login_id: self.login_id(),
            kind: self.target.kind(),
            title: self.title.clone(),
            name: self.name.lock().unwrap().clone(),
            profile: match &self.target {
                Target::Remote(t) => t.profile.clone(),
                Target::Local { .. } => None,
            },
            state: if self.closed.is_cancelled() {
                "closed"
            } else if self.attached.lock().unwrap().is_some() {
                "attached"
            } else {
                "detached"
            },
            created_unix: self.created_unix,
            idle_secs: self.last_input.lock().unwrap().elapsed().as_secs(),
            cols,
            rows,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    /// Send keyboard input to the process. Applies backpressure if the process is not reading.
    pub async fn input(&self, data: Bytes) -> Result<(), ()> {
        if self.is_closed() {
            return Err(());
        }
        *self.last_input.lock().unwrap() = Instant::now();
        self.metrics.add(&self.metrics.bytes_in, data.len() as u64);
        if let Some(t) = &self.work {
            t.input(data.len());
        }
        self.pty.write(data).await
    }

    pub fn resize(&self, cols: u16, rows: u16) -> anyhow::Result<()> {
        self.pty.resize(cols, rows)?;
        if let Some(t) = &self.work {
            t.resize(cols, rows);
        }
        Ok(())
    }

    pub fn pid(&self) -> Option<i32> {
        self.pty.pid()
    }

    pub fn login_id(&self) -> String {
        self.owner.lock().unwrap().login_id.clone()
    }

    pub fn key_fingerprint(&self) -> String {
        self.owner.lock().unwrap().key_fingerprint.clone()
    }

    /// Make `login` (same user, freshly authenticated) the owner of this session.
    pub fn rebind(&self, login: &Login) {
        debug_assert_eq!(login.user, self.user);
        let mut o = self.owner.lock().unwrap();
        o.login_id = login.id.clone();
        o.key_fingerprint = login.key_fingerprint.clone();
    }

    pub fn name(&self) -> Option<String> {
        self.name.lock().unwrap().clone()
    }

    /// Set or clear (None) the user-chosen label. Validate with [`normalize_name`] first.
    pub fn set_name(&self, name: Option<String>) {
        *self.name.lock().unwrap() = name;
    }

    /// Does `access` (as currently granted in the authorisation file) cover this session?
    pub fn permitted_by(&self, access: &crate::auth::keys::Access) -> bool {
        match &self.target {
            Target::Local { .. } => access.local,
            Target::Remote(t) => match &t.profile {
                Some(p) => access.allows_remote(p),
                None => access.remote_all,
            },
        }
    }

    async fn deliver(&self, target: Option<(u64, mpsc::Sender<SessionEvent>)>, ev: SessionEvent) {
        let Some((conn_id, tx)) = target else {
            return;
        };
        tokio::select! {
            r = tx.send(ev) => {
                if r.is_err() {
                    self.detach(conn_id);
                }
            }
            _ = self.closed.cancelled() => {}
        }
    }

    /// Detach `conn_id` if it is the current attachment.
    pub fn detach(&self, conn_id: u64) -> bool {
        let mut a = self.attached.lock().unwrap();
        if a.as_ref().is_some_and(|x| x.conn_id == conn_id) {
            *a = None;
            *self.detached_since.lock().unwrap() = Some(Instant::now());
            if let Some(t) = &self.work {
                t.set_attached(false);
            }
            true
        } else {
            false
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpenError {
    #[error("session limit reached ({0} sessions)")]
    TotalLimit(usize),
    #[error("per-user session limit reached ({0} sessions)")]
    UserLimit(usize),
    #[error("server is shutting down")]
    ShuttingDown,
    #[error("failed to start terminal: {0}")]
    Spawn(String),
}

pub struct SessionManager {
    cfg: Arc<Config>,
    sessions: Mutex<HashMap<String, Arc<TerminalSession>>>,
    audit: Arc<Audit>,
    metrics: Arc<Metrics>,
    shutting_down: CancellationToken,
    next_conn: AtomicU64,
    /// The OpsAPI work log, when `opsapi.work_log.enabled`.
    pub work_log: Option<Arc<crate::worklog::WorkLog>>,
}

impl SessionManager {
    pub fn new(cfg: Arc<Config>, audit: Arc<Audit>, metrics: Arc<Metrics>) -> Arc<Self> {
        Arc::new(Self {
            work_log: crate::worklog::WorkLog::new(&cfg, audit.clone()),
            cfg,
            sessions: Mutex::new(HashMap::new()),
            audit,
            metrics,
            shutting_down: CancellationToken::new(),
            next_conn: AtomicU64::new(1),
        })
    }

    pub fn next_conn_id(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    pub fn count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn open(
        self: &Arc<Self>,
        login: &Login,
        target: Target,
        mut spec: PtySpec,
        name: Option<String>,
        launch: Option<crate::opsapi::LaunchTag>,
    ) -> Result<Arc<TerminalSession>, OpenError> {
        if self.shutting_down.is_cancelled() {
            return Err(OpenError::ShuttingDown);
        }
        let mut map = self.sessions.lock().unwrap();
        let s = &self.cfg.sessions;
        if map.len() >= s.max_total {
            return Err(OpenError::TotalLimit(s.max_total));
        }
        if map.values().filter(|x| x.user == login.user).count() >= s.max_per_user {
            return Err(OpenError::UserLimit(s.max_per_user));
        }
        let id = crate::security::random_id();
        // A local tab's shell gets its work log token and Claude's telemetry settings.
        let work = self.work_log.as_ref().map(|w| {
            let (tab, env) = w.new_tab(&id, login, &target, &spec, launch.as_ref());
            spec.env.extend(env);
            tab
        });
        let (pty, out_rx) = PtyProcess::spawn(&spec).map_err(|e| {
            self.metrics.inc(&self.metrics.session_open_failures);
            OpenError::Spawn(format!("{e:#}"))
        })?;
        let sess = Arc::new(TerminalSession {
            id,
            user: login.user.clone(),
            owner: Mutex::new(Owner {
                login_id: login.id.clone(),
                key_fingerprint: login.key_fingerprint.clone(),
            }),
            title: target.title(),
            target,
            created_unix: unix_now(),
            launch,
            work,
            pty,
            scrollback: Mutex::new(Scrollback {
                buf: VecDeque::new(),
                cap: s.scrollback_bytes,
            }),
            attached: Mutex::new(None),
            detached_since: Mutex::new(Some(Instant::now())),
            last_input: Mutex::new(Instant::now()),
            last_output: Mutex::new(Instant::now()),
            closed: CancellationToken::new(),
            close_reason: Mutex::new(None),
            name: Mutex::new(name),
            metrics: self.metrics.clone(),
        });
        map.insert(sess.id.clone(), sess.clone());
        drop(map);
        if let (Some(w), Some(t)) = (&self.work_log, &sess.work) {
            w.register(t);
        }

        match &sess.target {
            Target::Local { .. } => self.metrics.inc(&self.metrics.sessions_opened_local),
            Target::Remote(_) => self.metrics.inc(&self.metrics.sessions_opened_remote),
        }
        self.metrics.gauge_add(&self.metrics.sessions_active, 1);
        let mut ev = AuditEvent::new("session_open")
            .user(&sess.user)
            .field("session_id", &sess.id)
            .field("login_id", &sess.login_id())
            .field("kind", sess.target.kind())
            .num("pid", sess.pid().unwrap_or(-1) as i64);
        if let Target::Remote(t) = &sess.target {
            ev = ev
                .field("remote_host", &t.host)
                .num("remote_port", t.port as i64)
                .field("remote_user", &t.user)
                .field("profile", t.profile.as_deref().unwrap_or("adhoc"));
        }
        if let Some(t) = &sess.launch {
            ev = ev
                .field("opsapi_launch", &t.id)
                .field("opsapi_task", &t.task);
        }
        self.audit.log(ev);

        if let Some(t) = &sess.launch {
            crate::opsapi::notify(
                &self.cfg,
                "session_start",
                t,
                &sess.id,
                &sess.user,
                None,
                None,
            );
        }

        let mgr = self.clone();
        let s2 = sess.clone();
        tokio::spawn(async move { mgr.pump(s2, out_rx).await });
        Ok(sess)
    }

    /// Move PTY output to the attached socket and scrollback until the process ends.
    async fn pump(self: Arc<Self>, sess: Arc<TerminalSession>, mut out_rx: mpsc::Receiver<Bytes>) {
        let mut exit_code = None;
        loop {
            tokio::select! {
                _ = sess.closed.cancelled() => break,
                exit = sess.pty.wait_exit() => {
                    exit_code = exit.code;
                    // Drain output still buffered after the process exited.
                    let deadline = tokio::time::sleep(Duration::from_millis(300));
                    tokio::pin!(deadline);
                    loop {
                        tokio::select! {
                            _ = &mut deadline => break,
                            chunk = out_rx.recv() => match chunk {
                                Some(b) => self.forward_output(&sess, b).await,
                                None => break,
                            }
                        }
                    }
                    break;
                }
                chunk = out_rx.recv() => match chunk {
                    Some(b) => self.forward_output(&sess, b).await,
                    None => {
                        exit_code = tokio::time::timeout(Duration::from_secs(1), sess.pty.wait_exit())
                            .await
                            .ok()
                            .and_then(|e| e.code);
                        break;
                    }
                }
            }
        }
        let reason = sess
            .close_reason
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "process exited".into());
        sess.closed.cancel();
        let exit = sess.pty.terminate(TERMINATE_GRACE).await;
        let exit_code = exit_code.or(exit.code);
        self.finish(&sess, reason, exit_code).await;
    }

    async fn forward_output(&self, sess: &TerminalSession, b: Bytes) {
        self.metrics.add(&self.metrics.bytes_out, b.len() as u64);
        *sess.last_output.lock().unwrap() = Instant::now();
        // Recorded whether or not a browser is attached.
        if let Some(t) = &sess.work {
            t.output(&b);
        }
        // Lock order (attached, then scrollback) matches attach(), so a re-attach sees each
        // chunk exactly once: either in the snapshot or as a live event.
        let target = {
            let a = sess.attached.lock().unwrap();
            sess.scrollback.lock().unwrap().push(&b);
            a.as_ref().map(|a| (a.conn_id, a.tx.clone()))
        };
        sess.deliver(target, SessionEvent::Output(b)).await;
    }

    async fn finish(&self, sess: &Arc<TerminalSession>, reason: String, exit_code: Option<u32>) {
        if let (Some(w), Some(t)) = (&self.work_log, &sess.work) {
            w.close_tab(t, &reason, exit_code);
        }
        self.sessions.lock().unwrap().remove(&sess.id);
        self.metrics.gauge_add(&self.metrics.sessions_active, -1);
        if matches!(sess.target, Target::Remote(_)) && exit_code == Some(255) {
            self.metrics.inc(&self.metrics.remote_connect_failures);
        }
        let tx = sess.attached.lock().unwrap().take().map(|a| a.tx);
        if let Some(tx) = tx {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                tx.send(SessionEvent::Closed {
                    reason: reason.clone(),
                    exit_code,
                }),
            )
            .await;
        }
        self.audit.log(
            AuditEvent::new("session_close")
                .user(&sess.user)
                .field("session_id", &sess.id)
                .field("kind", sess.target.kind())
                .field("reason", &reason)
                .num("exit_code", exit_code.map(i64::from).unwrap_or(-1))
                .num(
                    "duration_secs",
                    unix_now().saturating_sub(sess.created_unix) as i64,
                ),
        );
        if let Some(t) = &sess.launch {
            crate::opsapi::notify(
                &self.cfg,
                "session_end",
                t,
                &sess.id,
                &sess.user,
                exit_code,
                Some(&reason),
            );
        }
    }

    /// Attach a connection, replacing any previous attachment. Returns the event stream and
    /// the scrollback snapshot to replay.
    pub fn attach(
        &self,
        sess: &TerminalSession,
        conn_id: u64,
    ) -> (mpsc::Receiver<SessionEvent>, Bytes) {
        let (tx, rx) = mpsc::channel(OUTBOUND_QUEUE);
        let mut a = sess.attached.lock().unwrap();
        if let Some(old) = a.take() {
            let _ = old.tx.try_send(SessionEvent::Detached);
        }
        // Snapshot under the attachment lock so no output is lost or duplicated.
        let snapshot = sess.scrollback.lock().unwrap().snapshot();
        *a = Some(Attachment { conn_id, tx });
        *sess.detached_since.lock().unwrap() = None;
        if let Some(t) = &sess.work {
            t.set_attached(true);
        }
        (rx, snapshot)
    }

    pub fn get(&self, id: &str) -> Option<Arc<TerminalSession>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }

    pub fn list(&self) -> Vec<SessionInfo> {
        let mut v: Vec<_> = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .map(|s| s.info())
            .collect();
        v.sort_by_key(|s| s.created_unix);
        v
    }

    pub fn list_for_user(&self, user: &str) -> Vec<SessionInfo> {
        self.list().into_iter().filter(|s| s.user == user).collect()
    }

    /// Request closure; the pump terminates the process and notifies the client.
    pub fn close(&self, id: &str, reason: &str) -> bool {
        let Some(s) = self.get(id) else {
            return false;
        };
        request_close(&s, reason);
        true
    }

    pub fn close_where(&self, reason: &str, f: impl Fn(&TerminalSession) -> bool) -> usize {
        let targets: Vec<_> = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| f(s))
            .cloned()
            .collect();
        for s in &targets {
            request_close(s, reason);
        }
        targets.len()
    }

    /// Periodic policy enforcement: detach grace and idle timeout. Authorisation (revoked or
    /// narrowed keys) is enforced separately by the server against the key fingerprint.
    /// Task sessions (opened from an OpsAPI launch) use the `opsapi` limits, and their output
    /// counts as activity, so an agent working on its own isn't closed for lack of typing.
    pub fn reap(&self) {
        let all: Vec<_> = self.sessions.lock().unwrap().values().cloned().collect();
        for s in all {
            if s.is_closed() {
                continue;
            }
            let (grace, idle) = if s.launch.is_some() {
                (
                    self.cfg.opsapi.detach_grace_secs,
                    self.cfg.opsapi.idle_timeout_secs,
                )
            } else {
                (
                    self.cfg.sessions.detach_grace_secs,
                    self.cfg.sessions.idle_timeout_secs,
                )
            };
            if let Some(t) = *s.detached_since.lock().unwrap()
                && t.elapsed() >= Duration::from_secs(grace)
            {
                request_close(&s, "disconnected for too long");
                continue;
            }
            let quiet = if s.launch.is_some() {
                s.last_input
                    .lock()
                    .unwrap()
                    .elapsed()
                    .min(s.last_output.lock().unwrap().elapsed())
            } else {
                s.last_input.lock().unwrap().elapsed()
            };
            if idle > 0 && quiet >= Duration::from_secs(idle) {
                request_close(&s, "idle timeout");
            }
        }
    }

    /// Close every session and wait (bounded) for processes to exit.
    pub async fn shutdown(&self) {
        self.shutting_down.cancel();
        self.close_where("server shutting down", |_| true);
        let deadline = Instant::now() + TERMINATE_GRACE + Duration::from_secs(3);
        while self.count() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

pub const MAX_NAME_CHARS: usize = 64;

/// Validate a session label: trimmed, at most 64 characters, no control characters.
/// `Ok(None)` means "clear the name".
pub fn normalize_name(raw: &str) -> Result<Option<String>, &'static str> {
    let t = raw.trim();
    if t.is_empty() {
        return Ok(None);
    }
    if t.chars().count() > MAX_NAME_CHARS {
        return Err("name must be at most 64 characters");
    }
    if t.chars().any(|c| c.is_control()) {
        return Err("name must not contain control characters");
    }
    Ok(Some(t.to_string()))
}

fn request_close(s: &TerminalSession, reason: &str) {
    let mut r = s.close_reason.lock().unwrap();
    if r.is_none() {
        *r = Some(reason.to_string());
    }
    drop(r);
    s.closed.cancel();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::keys::Access;
    use crate::terminal::base_env;

    fn login(user: &str) -> Login {
        Login {
            id: crate::security::random_id(),
            user: user.into(),
            key_fingerprint: "SHA256:x".into(),
            access: Access::parse("local").unwrap(),
            ip: "127.0.0.1".into(),
            created_unix: 0,
            expires_unix: 0,
            via: "test",
        }
    }

    fn spec(script: &str) -> PtySpec {
        PtySpec {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: base_env(),
            cwd: std::env::temp_dir(),
            cols: 80,
            rows: 24,
            run_as: None,
            sandbox: None,
        }
    }

    fn mgr(cfg: Config) -> Arc<SessionManager> {
        SessionManager::new(
            Arc::new(cfg),
            Arc::new(Audit::disabled()),
            Arc::new(Metrics::default()),
        )
    }

    fn local() -> Target {
        Target::Local {
            shell: "/bin/sh".into(),
        }
    }

    async fn next_closed(rx: &mut mpsc::Receiver<SessionEvent>) -> (String, Option<u32>) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(ev) = rx.recv().await {
                if let SessionEvent::Closed { reason, exit_code } = ev {
                    return (reason, exit_code);
                }
            }
            panic!("stream ended without Closed")
        })
        .await
        .expect("timeout")
    }

    #[test]
    fn session_names_are_validated() {
        assert_eq!(
            normalize_name("  build box  "),
            Ok(Some("build box".into()))
        );
        assert_eq!(normalize_name("   "), Ok(None));
        assert_eq!(normalize_name("prod 🚀"), Ok(Some("prod 🚀".into())));
        assert!(normalize_name(&"x".repeat(65)).is_err());
        assert!(
            normalize_name(&"é".repeat(64)).is_ok(),
            "limit counts characters, not bytes"
        );
        assert!(normalize_name("a\x1b[31mb").is_err());
        assert!(normalize_name("a\nb").is_err());
    }

    #[test]
    fn scrollback_is_bounded() {
        let mut s = Scrollback {
            buf: VecDeque::new(),
            cap: 5,
        };
        s.push(b"abc");
        s.push(b"defg");
        assert_eq!(&s.snapshot()[..], b"cdefg");
        s.push(b"0123456789");
        assert_eq!(&s.snapshot()[..], b"56789");
    }

    #[tokio::test]
    async fn exit_closes_session_and_reports_code() {
        let m = mgr(Config::default());
        let s = m
            .open(&login("a"), local(), spec("echo hi; exit 4"), None, None)
            .unwrap();
        let (mut rx, _) = m.attach(&s, 1);
        let (reason, code) = next_closed(&mut rx).await;
        assert_eq!(reason, "process exited");
        assert_eq!(code, Some(4));
        assert_eq!(m.count(), 0);
    }

    #[tokio::test]
    async fn limits_enforced() {
        let mut cfg = Config::default();
        cfg.sessions.max_per_user = 1;
        cfg.sessions.max_total = 2;
        let m = mgr(cfg);
        let a = login("a");
        let _s1 = m.open(&a, local(), spec("sleep 30"), None, None).unwrap();
        assert_eq!(
            m.open(&a, local(), spec("sleep 30"), None, None).err(),
            Some(OpenError::UserLimit(1))
        );
        let _s2 = m
            .open(&login("b"), local(), spec("sleep 30"), None, None)
            .unwrap();
        assert_eq!(
            m.open(&login("c"), local(), spec("sleep 30"), None, None)
                .err(),
            Some(OpenError::TotalLimit(2))
        );
        m.shutdown().await;
        assert_eq!(m.count(), 0);
        assert_eq!(
            m.open(&login("d"), local(), spec("true"), None, None).err(),
            Some(OpenError::ShuttingDown)
        );
    }

    #[tokio::test]
    async fn reattach_replays_output_and_detaches_old() {
        let m = mgr(Config::default());
        let s = m
            .open(
                &login("a"),
                local(),
                spec("echo MARKER; sleep 30"),
                None,
                None,
            )
            .unwrap();
        let (mut rx1, _) = m.attach(&s, 1);
        // Wait for output on the first connection.
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(ev) = rx1.recv().await {
                if matches!(&ev, SessionEvent::Output(b) if String::from_utf8_lossy(b).contains("MARKER")) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        let (_rx2, snap) = m.attach(&s, 2);
        assert!(String::from_utf8_lossy(&snap).contains("MARKER"));
        assert!(matches!(rx1.recv().await, Some(SessionEvent::Detached)));
        assert!(!s.detach(1), "stale connection cannot detach the new one");
        assert!(s.detach(2));
        m.close(&s.id, "test");
        m.shutdown().await;
    }

    #[tokio::test]
    async fn reaper_closes_detached_and_idle() {
        let mut cfg = Config::default();
        cfg.sessions.detach_grace_secs = 0;
        let m = mgr(cfg);
        let s = m
            .open(&login("a"), local(), spec("sleep 30"), None, None)
            .unwrap();
        m.reap();
        assert!(s.is_closed());

        let mut cfg = Config::default();
        cfg.sessions.idle_timeout_secs = 1;
        let m2 = mgr(cfg);
        let s2 = m2
            .open(&login("a"), local(), spec("sleep 30"), None, None)
            .unwrap();
        let (mut rx, _) = m2.attach(&s2, 1);
        m2.reap();
        assert!(!s2.is_closed(), "attached and recently active");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        m2.reap();
        let (reason, _) = next_closed(&mut rx).await;
        assert_eq!(reason, "idle timeout");
        m.shutdown().await;
    }

    #[tokio::test]
    async fn task_sessions_count_output_as_activity_and_outlive_the_browser() {
        let mut cfg = Config::default();
        cfg.sessions.idle_timeout_secs = 1;
        cfg.sessions.detach_grace_secs = 0;
        cfg.opsapi.idle_timeout_secs = 1;
        cfg.opsapi.detach_grace_secs = 3600;
        let m = mgr(cfg);
        let tag = || {
            Some(crate::opsapi::LaunchTag {
                id: "l1".into(),
                task: "t1".into(),
                agent: "shell".into(),
            })
        };
        let a = login("a");
        // An agent printing on its own, with nobody typing and no browser attached.
        let busy = m
            .open(
                &a,
                local(),
                spec("while true; do echo working; sleep 0.2; done"),
                None,
                tag(),
            )
            .unwrap();
        let quiet = m.open(&a, local(), spec("sleep 30"), None, tag()).unwrap();
        let plain = m.open(&a, local(), spec("sleep 30"), None, None).unwrap();
        m.reap();
        assert!(
            plain.is_closed(),
            "ordinary sessions keep the normal detach limit"
        );
        assert!(
            !busy.is_closed() && !quiet.is_closed(),
            "task sessions survive a closed browser"
        );
        tokio::time::sleep(Duration::from_millis(1300)).await;
        m.reap();
        assert!(!busy.is_closed(), "output counts as activity");
        assert!(quiet.is_closed(), "no input and no output: idle");
        m.shutdown().await;
    }

    #[tokio::test]
    async fn named_open_and_rebind_to_new_login() {
        let m = mgr(Config::default());
        let first = login("a");
        let s = m
            .open(
                &first,
                local(),
                spec("sleep 30"),
                Some("build".into()),
                None,
            )
            .unwrap();
        assert_eq!(s.info().name.as_deref(), Some("build"));
        assert_eq!(s.login_id(), first.id);
        let mut second = login("a");
        second.key_fingerprint = "SHA256:other".into();
        s.rebind(&second);
        assert_eq!(s.login_id(), second.id);
        assert_eq!(s.key_fingerprint(), "SHA256:other");
        m.shutdown().await;
    }

    #[tokio::test]
    async fn explicit_close_kills_process() {
        let m = mgr(Config::default());
        let s = m
            .open(&login("a"), local(), spec("sleep 300"), None, None)
            .unwrap();
        let pid = s.pid().unwrap();
        let (mut rx, _) = m.attach(&s, 1);
        assert!(m.close(&s.id, "closed by user"));
        let (reason, _) = next_closed(&mut rx).await;
        assert_eq!(reason, "closed by user");
        // SAFETY: probe only.
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "process still alive");
    }
}
