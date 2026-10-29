//! WebSocket endpoint: origin-checked upgrade, authentication, and terminal streaming.

pub mod protocol;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use crate::audit::AuditEvent;
use crate::auth::sessions::Login;
use crate::security::rate_limit::{Slot, TokenBucket};
use crate::server::{App, session_token_from_headers};
use crate::session::{SessionEvent, Target, TerminalSession};
use protocol::{ClientMsg, OpenTarget, PROTOCOL_VERSION, ServerMsg};

const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const PING_INTERVAL: Duration = Duration::from_secs(20);
const DEAD_PEER: Duration = Duration::from_secs(65);
const MAX_PROTOCOL_ERRORS: u32 = 10;

pub async fn ws_handler(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let ip = crate::server::client_ip(&app.cfg, peer, &headers).to_string();
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if !app.origin.origin_allowed(origin) {
        app.metrics.inc(&app.metrics.ws_rejected_origin);
        app.audit.log(
            AuditEvent::new("ws_rejected")
                .ip(&ip)
                .field("reason", "origin not allowed")
                .field("origin", origin.unwrap_or("-")),
        );
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }
    let origin = origin.unwrap_or_default().to_string();
    // An existing browser login (cookie) authenticates the socket; otherwise the client must
    // complete the challenge over the socket before anything else is allowed.
    let login = session_token_from_headers(&app, &headers)
        .and_then(|tok| app.auth.validate(&tok).map(|l| (tok, l)));
    // Until it signs in, a socket also takes one of its IP's few places, so one client can't
    // hold every connection slot with sockets that never sign in.
    let unauthenticated = match login {
        Some(_) => None,
        None => match app.ws_unauthenticated.try_take(&ip) {
            Some(slot) => Some(slot),
            None => {
                return (StatusCode::TOO_MANY_REQUESTS, "too many connections").into_response();
            }
        },
    };
    let Ok(permit) = app.ws_slots.clone().try_acquire_owned() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "too many connections").into_response();
    };
    let max = app.cfg.limits.ws_max_message_bytes;
    ws.max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| async move {
            run(app, socket, ip, origin, login, unauthenticated, permit).await;
        })
}

struct Conn {
    app: App,
    id: u64,
    ip: String,
    origin: String,
    binding: String,
    hello: bool,
    login: Option<(String, Login)>,
    /// The IP's place for a socket that hasn't signed in; given back when it does.
    unauthenticated: Option<Slot>,
    session: Option<Arc<TerminalSession>>,
    events: Option<mpsc::Receiver<SessionEvent>>,
    bucket: TokenBucket,
    protocol_errors: u32,
}

enum Flow {
    Continue,
    Close,
}

async fn recv_event(rx: &mut Option<mpsc::Receiver<SessionEvent>>) -> Option<SessionEvent> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

async fn run(
    app: App,
    socket: WebSocket,
    ip: String,
    origin: String,
    login: Option<(String, Login)>,
    unauthenticated: Option<Slot>,
    _permit: OwnedSemaphorePermit,
) {
    let (mut sink, mut stream) = socket.split();
    let limits = &app.cfg.limits;
    let mut c = Conn {
        id: app.sessions.next_conn_id(),
        ip,
        origin,
        binding: crate::security::random_token(32),
        hello: false,
        login,
        unauthenticated,
        session: None,
        events: None,
        bucket: TokenBucket::new(limits.input_bytes_per_sec, limits.input_burst_bytes),
        protocol_errors: 0,
        app: app.clone(),
    };
    app.metrics.inc(&app.metrics.ws_connections_total);
    app.metrics.gauge_add(&app.metrics.ws_connections_active, 1);
    app.audit.log(
        AuditEvent::new("ws_connect")
            .ip(&c.ip)
            .field("conn", &c.id.to_string())
            .field(
                "user",
                c.login.as_ref().map(|l| l.1.user.as_str()).unwrap_or("-"),
            ),
    );

    let started = Instant::now();
    let auth_timeout = Duration::from_secs(limits.ws_auth_timeout_secs);
    let mut last_seen = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let mut last_ping = Instant::now();
    let shutdown = app.shutdown.clone();
    let mut close_reason = "client disconnected";

    loop {
        let mut out: Vec<Message> = Vec::new();
        let flow = tokio::select! {
            _ = shutdown.cancelled() => {
                out.push(text(ServerMsg::error("server_shutdown", "server is shutting down", true)));
                close_reason = "server shutdown";
                Flow::Close
            }
            msg = stream.next() => match msg {
                None | Some(Err(_)) => Flow::Close,
                Some(Ok(m)) => {
                    last_seen = Instant::now();
                    match m {
                        Message::Text(t) => c.handle_text(t.as_str(), &mut out).await,
                        Message::Binary(_) => c.protocol_error("binary frames are not accepted", &mut out),
                        Message::Ping(_) | Message::Pong(_) => Flow::Continue,
                        Message::Close(_) => Flow::Close,
                    }
                }
            },
            ev = recv_event(&mut c.events) => {
                c.handle_event(ev, &mut out);
                Flow::Continue
            }
            _ = tick.tick() => {
                if !c.hello && started.elapsed() > HELLO_TIMEOUT {
                    out.push(text(ServerMsg::error("hello_timeout", "no hello received", true)));
                    close_reason = "hello timeout";
                    Flow::Close
                } else if c.login.is_none() && started.elapsed() > auth_timeout {
                    // Counted from connecting, so pings and pongs don't keep it open.
                    out.push(text(ServerMsg::error("auth_timeout", "not signed in in time", true)));
                    close_reason = "auth timeout";
                    Flow::Close
                } else if last_seen.elapsed() > DEAD_PEER {
                    close_reason = "keepalive timeout";
                    Flow::Close
                } else if let Some((tok, _)) = &c.login {
                    if !c.app.auth.check_still_valid(tok) {
                        out.push(text(ServerMsg::error("session_expired", "login expired or was revoked", true)));
                        close_reason = "login expired or revoked";
                        Flow::Close
                    } else {
                        Flow::Continue
                    }
                } else {
                    Flow::Continue
                }
            }
        };
        if last_ping.elapsed() >= PING_INTERVAL {
            last_ping = Instant::now();
            out.push(Message::Ping(Default::default()));
        }
        let mut send_failed = false;
        for m in out {
            if sink.send(m).await.is_err() {
                send_failed = true;
                break;
            }
        }
        if send_failed {
            break;
        }
        if let Flow::Close = flow {
            let _ = sink
                .send(Message::Close(Some(CloseFrame {
                    code: axum::extract::ws::close_code::NORMAL,
                    reason: Utf8Bytes::from_static("bye"),
                })))
                .await;
            break;
        }
    }

    if let Some(s) = c.session.take() {
        s.detach(c.id);
    }
    app.metrics
        .gauge_add(&app.metrics.ws_connections_active, -1);
    app.audit.log(
        AuditEvent::new("ws_disconnect")
            .ip(&c.ip)
            .field("conn", &c.id.to_string())
            .field("reason", close_reason),
    );
}

fn text(m: ServerMsg) -> Message {
    Message::Text(m.to_json().into())
}

impl Conn {
    fn protocol_error(&mut self, msg: &str, out: &mut Vec<Message>) -> Flow {
        self.app.metrics.inc(&self.app.metrics.ws_protocol_errors);
        self.protocol_errors += 1;
        let fatal = self.protocol_errors >= MAX_PROTOCOL_ERRORS;
        out.push(text(ServerMsg::error("bad_message", msg, fatal)));
        if fatal { Flow::Close } else { Flow::Continue }
    }

    fn handle_event(&mut self, ev: Option<SessionEvent>, out: &mut Vec<Message>) {
        match ev {
            Some(SessionEvent::Output(b)) => out.push(Message::Binary(b)),
            Some(SessionEvent::Detached) => {
                out.push(text(ServerMsg::Status {
                    state: "detached",
                    message: "session was attached from another window".into(),
                }));
                self.session = None;
                self.events = None;
            }
            Some(SessionEvent::Closed { reason, exit_code }) => {
                if let Some(s) = self.session.take() {
                    out.push(text(ServerMsg::SessionClosed {
                        session_id: s.id.clone(),
                        reason,
                        exit_code,
                    }));
                }
                self.events = None;
            }
            None => {
                if let Some(s) = self.session.take() {
                    out.push(text(ServerMsg::SessionClosed {
                        session_id: s.id.clone(),
                        reason: "session ended".into(),
                        exit_code: None,
                    }));
                }
                self.events = None;
            }
        }
    }

    async fn handle_text(&mut self, t: &str, out: &mut Vec<Message>) -> Flow {
        let max = self.app.cfg.limits.ws_max_message_bytes;
        let msg = match protocol::decode(t, max) {
            Ok(m) => m,
            Err(e) => return self.protocol_error(&e.to_string(), out),
        };
        if !self.hello {
            return match msg {
                ClientMsg::Hello { version } if version == PROTOCOL_VERSION => {
                    self.hello = true;
                    out.push(text(ServerMsg::Hello {
                        version: PROTOCOL_VERSION,
                        server: concat!("sshweb/", env!("CARGO_PKG_VERSION")),
                        authenticated: self.login.is_some(),
                        user: self.login.as_ref().map(|l| l.1.user.clone()),
                    }));
                    Flow::Continue
                }
                ClientMsg::Hello { .. } => {
                    out.push(text(ServerMsg::error(
                        "unsupported_version",
                        format!("server speaks protocol version {PROTOCOL_VERSION}"),
                        true,
                    )));
                    Flow::Close
                }
                _ => {
                    out.push(text(ServerMsg::error(
                        "hello_required",
                        "send hello first",
                        true,
                    )));
                    Flow::Close
                }
            };
        }
        match msg {
            ClientMsg::Hello { .. } => self.protocol_error("duplicate hello", out),
            ClientMsg::Ping { ts } => {
                out.push(text(ServerMsg::Pong { ts }));
                Flow::Continue
            }
            ClientMsg::AuthRequest { user } => {
                if self.login.is_some() {
                    return self.protocol_error("already authenticated", out);
                }
                match self
                    .app
                    .auth
                    .issue_challenge(&user, &self.origin, &self.binding, &self.ip)
                {
                    Ok(ch) => out.push(text(ServerMsg::AuthChallenge {
                        challenge_id: ch.id,
                        namespace: crate::auth::challenge::NAMESPACE,
                        message: ch.message,
                        expires_unix: ch.expires_unix,
                    })),
                    Err(e) => out.push(text(ServerMsg::AuthFailed {
                        code: e.code(),
                        message: e.to_string(),
                    })),
                }
                Flow::Continue
            }
            ClientMsg::AuthResponse {
                challenge_id,
                signature,
            } => {
                if self.login.is_some() {
                    return self.protocol_error("already authenticated", out);
                }
                match self.app.auth.verify(
                    &challenge_id,
                    &signature,
                    &self.binding,
                    &self.ip,
                    "websocket",
                ) {
                    Ok((tok, login)) => {
                        out.push(text(ServerMsg::AuthOk {
                            user: login.user.clone(),
                            expires_unix: login.expires_unix,
                        }));
                        self.login = Some((tok, login));
                        self.unauthenticated = None;
                    }
                    Err(e) => out.push(text(ServerMsg::AuthFailed {
                        code: e.code(),
                        message: e.to_string(),
                    })),
                }
                Flow::Continue
            }
            other => {
                // Everything below requires an authenticated, still-valid login.
                let login = match &self.login {
                    Some((tok, _)) => match self.app.auth.validate(tok) {
                        Some(l) => l,
                        None => {
                            out.push(text(ServerMsg::error(
                                "session_expired",
                                "login expired or was revoked",
                                true,
                            )));
                            return Flow::Close;
                        }
                    },
                    None => {
                        self.app.metrics.inc(&self.app.metrics.ws_protocol_errors);
                        out.push(text(ServerMsg::error(
                            "unauthenticated",
                            "authentication required",
                            true,
                        )));
                        return Flow::Close;
                    }
                };
                self.handle_terminal(other, login, out).await
            }
        }
    }

    async fn handle_terminal(
        &mut self,
        msg: ClientMsg,
        login: Login,
        out: &mut Vec<Message>,
    ) -> Flow {
        let app = self.app.clone();
        match msg {
            ClientMsg::Open {
                target,
                cols,
                rows,
                name,
                launch,
            } => {
                if self.session.is_some() {
                    return self.protocol_error("this connection already has a session", out);
                }
                let local_ok = app.cfg.local.enabled && login.access.local;
                // A launch decides the folder, agent and task; nothing in this message can.
                let mut claimed: Option<crate::opsapi::Pending> = None;
                let built = match (launch, target) {
                    (Some(_), _) if !local_ok => {
                        Err("local terminal access is not permitted".to_string())
                    }
                    (Some(id), OpenTarget::Local { .. }) => {
                        match app.launches.take_for_open(&id, &login.user) {
                            None => Err("this task link was already used or has expired; \
                                         open it again from OpsAPI"
                                .to_string()),
                            Some(p) => {
                                let run = p.agent.as_ref().map(|a| a.run.clone());
                                let spec = crate::terminal::task_shell_spec(
                                    &app.cfg,
                                    p.cwd.clone(),
                                    crate::opsapi::launch_env(&p.launch),
                                    run.as_deref(),
                                    cols,
                                    rows,
                                );
                                if spec.is_err() {
                                    app.launches.release(&p.launch.id);
                                }
                                claimed = Some(p);
                                spec.map(|spec| {
                                    (
                                        Target::Local {
                                            shell: spec.program.clone(),
                                        },
                                        spec,
                                    )
                                })
                            }
                        }
                    }
                    (Some(_), _) => Err("a task link opens a local terminal".to_string()),
                    (None, OpenTarget::Local { shell, cwd }) => {
                        if !local_ok {
                            Err("local terminal access is not permitted".to_string())
                        } else {
                            let shell = shell.as_deref().map(std::path::Path::new);
                            crate::terminal::local_shell_spec(&app.cfg, shell, cols, rows).and_then(
                                |mut spec| {
                                    if let Some(c) = cwd {
                                        spec.cwd = crate::opsapi::resolve_folder(
                                            &app.cfg.local.allowed_roots,
                                            &c,
                                        )
                                        .map_err(|e| e.to_string())?;
                                    }
                                    Ok((
                                        Target::Local {
                                            shell: spec.program.clone(),
                                        },
                                        spec,
                                    ))
                                },
                            )
                        }
                    }
                    (None, OpenTarget::Remote { profile }) => {
                        crate::ssh::resolve_profile(&app.cfg, &login.access, &profile)
                            .map_err(|e| e.to_string())
                            .map(|t| {
                                let spec = crate::ssh::ssh_spec(&app.cfg, &t, cols, rows);
                                (Target::Remote(t), spec)
                            })
                    }
                    (None, OpenTarget::Adhoc { host, port, user }) => {
                        crate::ssh::resolve_adhoc(&app.cfg, &login.access, &host, port, &user)
                            .map_err(|e| e.to_string())
                            .map(|t| {
                                let spec = crate::ssh::ssh_spec(&app.cfg, &t, cols, rows);
                                (Target::Remote(t), spec)
                            })
                    }
                };
                let (target, mut spec) = match built {
                    Ok(x) => x,
                    Err(msg) => {
                        app.audit.log(
                            AuditEvent::new("session_denied")
                                .ip(&self.ip)
                                .user(&login.user)
                                .field("reason", &msg),
                        );
                        out.push(text(ServerMsg::error("forbidden", msg, false)));
                        return Flow::Continue;
                    }
                };
                if let Target::Local { .. } = &target {
                    let keys = app.auth.keys.current().ok();
                    let key = keys
                        .as_ref()
                        .and_then(|k| k.by_fingerprint(&login.key_fingerprint));
                    spec.env
                        .extend(crate::terminal::identity_env(&login.user, key));
                }
                let name = name
                    .and_then(|n| crate::session::normalize_name(&n).ok().flatten())
                    .or_else(|| claimed.as_ref().map(|p| p.launch.tab_name()));
                let tag = claimed.as_ref().map(|p| crate::opsapi::LaunchTag {
                    id: p.launch.id.clone(),
                    task: p.launch.task.clone(),
                    agent: p.launch.agent.clone(),
                });
                match app.sessions.open(&login, target, spec, name, tag) {
                    Ok(s) => {
                        if let Some(p) = &claimed {
                            app.launches.mark_used(&p.launch.id, &s.id);
                        }
                        let (rx, _) = app.sessions.attach(&s, self.id);
                        out.push(text(ServerMsg::SessionOpened {
                            session_id: s.id.clone(),
                            kind: s.target.kind(),
                            title: s.title.clone(),
                            name: s.name(),
                            resumed: false,
                        }));
                        self.session = Some(s);
                        self.events = Some(rx);
                    }
                    Err(e) => {
                        if let Some(p) = &claimed {
                            app.launches.release(&p.launch.id);
                        }
                        out.push(text(ServerMsg::error("open_failed", e.to_string(), false)))
                    }
                }
                Flow::Continue
            }
            ClientMsg::Attach {
                session_id,
                cols,
                rows,
            } => {
                if self.session.is_some() {
                    return self.protocol_error("this connection already has a session", out);
                }
                // Same error for "missing" and "someone else's" so ids cannot be probed.
                let Some(s) = app
                    .sessions
                    .get(&session_id)
                    .filter(|s| s.user == login.user && !s.is_closed())
                else {
                    out.push(text(ServerMsg::error(
                        "no_such_session",
                        "session not found or already closed",
                        false,
                    )));
                    return Flow::Continue;
                };
                if !s.permitted_by(&login.access) {
                    out.push(text(ServerMsg::error("forbidden", "not permitted", false)));
                    return Flow::Continue;
                }
                // The user re-authenticated with a currently authorised key: they now own it.
                s.rebind(&login);
                let (rx, snapshot) = app.sessions.attach(&s, self.id);
                let _ = s.resize(cols, rows);
                out.push(text(ServerMsg::SessionOpened {
                    session_id: s.id.clone(),
                    kind: s.target.kind(),
                    title: s.title.clone(),
                    name: s.name(),
                    resumed: true,
                }));
                if !snapshot.is_empty() {
                    out.push(Message::Binary(snapshot));
                }
                app.audit.log(
                    AuditEvent::new("session_attach")
                        .ip(&self.ip)
                        .user(&login.user)
                        .field("session_id", &s.id),
                );
                self.session = Some(s);
                self.events = Some(rx);
                Flow::Continue
            }
            ClientMsg::Input { data, binary } => {
                let Some(s) = self.session.clone() else {
                    out.push(text(ServerMsg::error(
                        "no_session",
                        "no session is open",
                        false,
                    )));
                    return Flow::Continue;
                };
                let bytes = protocol::input_bytes(data, binary);
                match self.bucket.take(bytes.len() as u64) {
                    None => return self.protocol_error("input message too large", out),
                    Some(wait) if !wait.is_zero() => tokio::time::sleep(wait).await,
                    Some(_) => {}
                }
                app.auth.logins.touch_id(&login.id);
                if s.input(bytes).await.is_err() {
                    out.push(text(ServerMsg::error(
                        "session_closed",
                        "session is closed",
                        false,
                    )));
                }
                Flow::Continue
            }
            ClientMsg::Resize { cols, rows } => {
                if let Some(s) = &self.session
                    && let Err(e) = s.resize(cols, rows)
                {
                    out.push(text(ServerMsg::error(
                        "resize_failed",
                        e.to_string(),
                        false,
                    )));
                }
                Flow::Continue
            }
            ClientMsg::Detach => {
                if let Some(s) = self.session.take() {
                    s.detach(self.id);
                    self.events = None;
                    out.push(text(ServerMsg::Status {
                        state: "detached",
                        message: "detached; the session stays alive for a short grace period"
                            .into(),
                    }));
                }
                Flow::Continue
            }
            ClientMsg::Close => {
                if let Some(s) = &self.session {
                    app.sessions.close(&s.id, "closed by user");
                }
                Flow::Continue
            }
            ClientMsg::Hello { .. }
            | ClientMsg::Ping { .. }
            | ClientMsg::AuthRequest { .. }
            | ClientMsg::AuthResponse { .. } => Flow::Continue,
        }
    }
}
