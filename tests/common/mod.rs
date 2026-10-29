//! Shared integration-test harness: disposable config, keys and a server on an ephemeral port.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use sshweb::audit::Audit;
use sshweb::config::{AuditConfig, AuditDestination, Config};
use sshweb::server::Running;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{self, Message};

pub const USER: &str = "alice";

pub struct Env {
    pub dir: tempfile::TempDir,
    pub cfg: Config,
    pub key: PrivateKey,
    pub listener: Option<std::net::TcpListener>,
}

pub fn new_key() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
}

pub fn write_file(path: &Path, text: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub fn authorized_line(user: &str, access: &str, key: &PrivateKey) -> String {
    format!(
        "user=\"{user}\",access=\"{access}\" {}\n",
        key.public_key().to_openssh().unwrap()
    )
}

/// Build a disposable environment. The key for `alice` has access `local,remote:*`.
pub fn env() -> Env {
    let dir = tempfile::Builder::new().prefix("sw").tempdir().unwrap();
    let key = new_key();
    let p = dir.path();
    write_file(
        &p.join("authorized_keys"),
        &authorized_line(USER, "local,remote:*", &key),
        0o600,
    );
    write_file(&p.join("known_hosts"), "", 0o600);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut cfg = Config::default();
    cfg.server.port = listener.local_addr().unwrap().port();
    cfg.server.state_dir = p.join("run");
    cfg.auth.authorized_keys = p.join("authorized_keys");
    cfg.remote.known_hosts = p.join("known_hosts");
    cfg.audit = AuditConfig {
        destination: AuditDestination::File,
        path: p.join("audit.log"),
    };
    cfg.local.default_shell = Some("/bin/sh".into());
    cfg.local.login_shell = false;
    cfg.local.working_dir = Some(p.to_path_buf());
    Env {
        dir,
        cfg,
        key,
        listener: Some(listener),
    }
}

impl Env {
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.cfg.server.port)
    }

    pub async fn start(&mut self) -> Running {
        let audit = Audit::open(&self.cfg.audit).unwrap();
        sshweb::server::start(self.cfg.clone(), audit, self.listener.take().unwrap())
            .await
            .expect("server starts")
    }

    pub fn audit_log(&self) -> String {
        std::fs::read_to_string(&self.cfg.audit.path).unwrap_or_default()
    }

    /// HTTP client with a cookie jar that sends our Origin on every request.
    pub fn client(&self) -> Client {
        self.client_via(None)
    }

    /// Like [`client`](Self::client), and with `X-Forwarded-For: <ip>` (a client behind a proxy
    /// in `server.trusted_proxies`).
    pub fn client_via(&self, forwarded_for: Option<&str>) -> Client {
        let jar = Arc::new(reqwest::cookie::Jar::default());
        let mut h = reqwest::header::HeaderMap::new();
        h.insert("origin", self.base().parse().unwrap());
        if let Some(ip) = forwarded_for {
            h.insert("x-forwarded-for", ip.parse().unwrap());
        }
        let http = reqwest::Client::builder()
            .cookie_provider(jar.clone())
            .default_headers(h)
            .build()
            .unwrap();
        Client {
            http,
            jar,
            base: self.base(),
        }
    }
}

pub struct Client {
    pub http: reqwest::Client,
    pub jar: Arc<reqwest::cookie::Jar>,
    pub base: String,
}

pub fn sign(key: &PrivateKey, message: &str) -> String {
    key.sign("sshweb-auth", HashAlg::Sha512, message.as_bytes())
        .unwrap()
        .to_pem(LineEnding::LF)
        .unwrap()
}

impl Client {
    pub fn url(&self, p: &str) -> String {
        format!("{}{}", self.base, p)
    }

    pub async fn challenge(&self, user: &str) -> reqwest::Response {
        self.http
            .post(self.url("/api/auth/challenge"))
            .json(&json!({ "user": user }))
            .send()
            .await
            .unwrap()
    }

    pub async fn verify(&self, challenge_id: &str, signature: &str) -> reqwest::Response {
        self.http
            .post(self.url("/api/auth/verify"))
            .json(&json!({ "challenge_id": challenge_id, "signature": signature }))
            .send()
            .await
            .unwrap()
    }

    /// Full login; panics on failure.
    pub async fn login(&self, user: &str, key: &PrivateKey) {
        let r = self.challenge(user).await;
        assert_eq!(r.status(), 200, "challenge failed");
        let ch: Value = r.json().await.unwrap();
        let sig = sign(key, ch["message"].as_str().unwrap());
        let r = self
            .verify(ch["challenge_id"].as_str().unwrap(), &sig)
            .await;
        assert_eq!(
            r.status(),
            200,
            "verify failed: {}",
            r.text().await.unwrap()
        );
    }

    pub fn cookie_header(&self) -> Option<String> {
        use reqwest::cookie::CookieStore;
        self.jar
            .cookies(&self.base.parse().unwrap())
            .map(|v| v.to_str().unwrap().to_string())
    }
}

pub struct Ws {
    pub inner: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    pub output: String,
}

pub async fn ws_connect(
    port: u16,
    origin: Option<&str>,
    cookie: Option<&str>,
) -> Result<Ws, tungstenite::Error> {
    let mut req = format!("ws://127.0.0.1:{port}/ws")
        .into_client_request()
        .unwrap();
    if let Some(o) = origin {
        req.headers_mut()
            .insert("origin", HeaderValue::from_str(o).unwrap());
    }
    if let Some(c) = cookie {
        req.headers_mut()
            .insert("cookie", HeaderValue::from_str(c).unwrap());
    }
    let (inner, _) = tokio_tungstenite::connect_async(req).await?;
    Ok(Ws {
        inner,
        output: String::new(),
    })
}

pub const WAIT: Duration = Duration::from_secs(15);

impl Ws {
    pub async fn send(&mut self, v: Value) {
        self.inner
            .send(Message::Text(v.to_string().into()))
            .await
            .unwrap();
    }

    pub async fn send_raw(&mut self, m: Message) -> Result<(), tungstenite::Error> {
        self.inner.send(m).await
    }

    /// Next frame (JSON or output); None when the socket is closed.
    pub async fn next_frame(&mut self) -> Option<Frame> {
        loop {
            let m = tokio::time::timeout(WAIT, self.inner.next())
                .await
                .expect("timed out waiting for a frame");
            match m {
                None | Some(Err(_)) => return None,
                Some(Ok(Message::Text(t))) => {
                    return Some(Frame::Json(serde_json::from_str(&t).unwrap()));
                }
                Some(Ok(Message::Binary(b))) => {
                    let s = String::from_utf8_lossy(&b).into_owned();
                    self.output.push_str(&s);
                    return Some(Frame::Output(s));
                }
                Some(Ok(Message::Close(_))) => return None,
                Some(Ok(_)) => continue,
            }
        }
    }

    /// Wait for a JSON message of `ty`, collecting output along the way.
    pub async fn expect_type(&mut self, ty: &str) -> Value {
        loop {
            match self.next_frame().await {
                Some(Frame::Json(v)) if v["type"] == ty => return v,
                Some(_) => continue,
                None => panic!(
                    "socket closed while waiting for {ty}; output so far: {}",
                    self.output
                ),
            }
        }
    }

    /// Wait until accumulated output contains `needle`.
    pub async fn expect_output(&mut self, needle: &str) {
        while !self.output.contains(needle) {
            match self.next_frame().await {
                Some(Frame::Json(v)) if v["type"] == "session_closed" => {
                    panic!(
                        "session closed waiting for {needle:?}: {v}; output: {}",
                        self.output
                    )
                }
                Some(_) => {}
                None => panic!(
                    "socket closed waiting for {needle:?}; output: {}",
                    self.output
                ),
            }
        }
    }

    pub async fn input(&mut self, s: &str) {
        self.send(json!({"type": "input", "data": s})).await;
    }

    /// hello → authenticated; returns the hello reply.
    pub async fn hello(&mut self) -> Value {
        self.send(json!({"type": "hello", "version": 1})).await;
        self.expect_type("hello").await
    }

    pub async fn open_local(&mut self) -> String {
        self.send(json!({"type": "open", "target": {"kind": "local"}, "cols": 80, "rows": 24}))
            .await;
        let v = self.expect_type("session_opened").await;
        v["session_id"].as_str().unwrap().to_string()
    }

    /// Drain until the socket closes; returns all JSON messages seen.
    pub async fn drain(&mut self) -> Vec<Value> {
        let mut out = Vec::new();
        while let Some(f) = self.next_frame().await {
            if let Frame::Json(v) = f {
                out.push(v);
            }
        }
        out
    }
}

#[derive(Debug)]
pub enum Frame {
    Json(Value),
    Output(String),
}

pub async fn logged_in_ws(env: &Env) -> (Client, Ws) {
    let c = env.client();
    c.login(USER, &env.key).await;
    let cookie = c.cookie_header().expect("session cookie");
    let mut ws = ws_connect(env.cfg.server.port, Some(&env.base()), Some(&cookie))
        .await
        .unwrap();
    let hello = ws.hello().await;
    assert_eq!(hello["authenticated"], true);
    (c, ws)
}

pub fn pid_alive(pid: i32) -> bool {
    // SAFETY: probe only.
    unsafe { libc::kill(pid, 0) == 0 }
}

pub fn find_bin(p: &str) -> Option<PathBuf> {
    let p = PathBuf::from(p);
    p.is_file().then_some(p)
}
