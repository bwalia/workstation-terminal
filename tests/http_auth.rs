//! HTTP-level integration tests: assets, health, origin/host checks, SSH-key login flow,
//! replay prevention, rate limiting, lockout, logout and key revocation.

mod common;

use common::*;
use serde_json::{Value, json};

#[tokio::test]
async fn serves_embedded_frontend_with_security_headers() {
    let mut env = env();
    let srv = env.start().await;
    let c = env.client();
    let r = c.http.get(c.url("/")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let csp = r.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(csp.contains("script-src 'self'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert_eq!(r.headers()["x-frame-options"], "DENY");
    let body = r.text().await.unwrap();
    assert!(body.contains("/assets/vendor/xterm.js"));
    let js = c
        .http
        .get(c.url("/assets/vendor/xterm.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(js.status(), 200);
    assert!(
        js.headers()["content-type"]
            .to_str()
            .unwrap()
            .contains("javascript")
    );
    assert_eq!(
        c.http
            .get(c.url("/assets/../Cargo.toml"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        c.http
            .get(c.url("/assets/nope.js"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    srv.shutdown().await;
}

#[tokio::test]
async fn health_readiness_and_metrics_restricted() {
    let mut env = env();
    let srv = env.start().await;
    let c = env.client();
    let h: Value = c
        .http
        .get(c.url("/healthz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(h["status"], "ok");
    let r = c.http.get(c.url("/readyz")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    // Metrics are disabled on the HTTP port by default.
    assert_eq!(
        c.http.get(c.url("/metrics")).send().await.unwrap().status(),
        404
    );
    // ...but available on the private admin socket.
    let (st, body) =
        sshweb::admin_client::request(&env.cfg.admin_socket_path(), hyper::Method::GET, "/metrics")
            .await
            .unwrap();
    assert_eq!(st, 200);
    assert!(body.contains("sshweb_auth_failure_total"));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(env.cfg.admin_socket_path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "admin socket must be private");
    srv.shutdown().await;
}

#[tokio::test]
async fn readiness_fails_when_keys_file_invalid() {
    let mut env = env();
    let srv = env.start().await;
    write_file(
        &env.cfg.auth.authorized_keys,
        "this is not a key line at all\n",
        0o600,
    );
    let c = env.client();
    assert_eq!(
        c.http.get(c.url("/readyz")).send().await.unwrap().status(),
        503
    );
    srv.shutdown().await;
}

#[tokio::test]
async fn rejects_foreign_host_header() {
    let mut env = env();
    let srv = env.start().await;
    let c = env.client();
    let r = c
        .http
        .get(c.url("/healthz"))
        .header("host", "evil.example:80")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 421);
    srv.shutdown().await;
}

#[tokio::test]
async fn state_changing_requests_require_origin() {
    let mut env = env();
    let srv = env.start().await;
    let plain = reqwest::Client::new();
    let url = format!("{}/api/auth/challenge", env.base());
    let r = plain
        .post(&url)
        .json(&json!({"user": USER}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "no Origin");
    let r = plain
        .post(&url)
        .header("origin", "http://evil.example")
        .json(&json!({"user": USER}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "foreign Origin");
    srv.shutdown().await;
}

#[tokio::test]
async fn full_login_flow_and_replay_prevention() {
    let mut env = env();
    let srv = env.start().await;
    let c = env.client();
    assert_eq!(
        c.http.get(c.url("/api/me")).send().await.unwrap().status(),
        401
    );

    let ch: Value = c.challenge(USER).await.json().await.unwrap();
    let msg = ch["message"].as_str().unwrap();
    assert!(msg.starts_with("sshweb-auth-v1 "));
    assert!(msg.contains(&format!("origin={}", env.base())));
    assert!(msg.contains("user=alice"));
    let sig = sign(&env.key, msg);
    let id = ch["challenge_id"].as_str().unwrap();
    let r = c.verify(id, &sig).await;
    assert_eq!(r.status(), 200);
    let cookie = r.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));

    let me: Value = c
        .http
        .get(c.url("/api/me"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["user"], USER);
    assert_eq!(me["local"]["enabled"], true);

    // Replaying the same signed challenge fails, even from the same client.
    let r = c.verify(id, &sig).await;
    assert_eq!(r.status(), 401);
    srv.shutdown().await;

    let log = env.audit_log();
    assert!(log.contains("\"event\":\"auth_success\""));
    assert!(log.contains("\"event\":\"auth_failure\""));
    assert!(
        !log.contains("BEGIN SSH SIGNATURE"),
        "signatures must not be logged"
    );
}

#[tokio::test]
async fn signature_from_unauthorised_key_or_other_user_rejected() {
    let mut env = env();
    let srv = env.start().await;
    let c = env.client();

    let ch: Value = c.challenge(USER).await.json().await.unwrap();
    let wrong = new_key();
    let r = c
        .verify(
            ch["challenge_id"].as_str().unwrap(),
            &sign(&wrong, ch["message"].as_str().unwrap()),
        )
        .await;
    assert_eq!(r.status(), 401);

    // A valid key, but the challenge was issued for another user.
    let ch: Value = c.challenge("bob").await.json().await.unwrap();
    let r = c
        .verify(
            ch["challenge_id"].as_str().unwrap(),
            &sign(&env.key, ch["message"].as_str().unwrap()),
        )
        .await;
    assert_eq!(r.status(), 401);

    // A public key pasted instead of a signature is not proof of possession.
    let ch: Value = c.challenge(USER).await.json().await.unwrap();
    let pubkey = env.key.public_key().to_openssh().unwrap();
    let r = c
        .verify(ch["challenge_id"].as_str().unwrap(), &pubkey)
        .await;
    assert_eq!(r.status(), 401);
    srv.shutdown().await;
}

#[tokio::test]
async fn challenge_bound_to_requesting_browser() {
    let mut env = env();
    let srv = env.start().await;
    let a = env.client();
    let b = env.client();
    let ch: Value = a.challenge(USER).await.json().await.unwrap();
    let sig = sign(&env.key, ch["message"].as_str().unwrap());
    // Another browser (different binding cookie) cannot redeem the signature.
    let r = b.verify(ch["challenge_id"].as_str().unwrap(), &sig).await;
    assert_eq!(r.status(), 401);
    // And the challenge is burned for the original browser too.
    let r = a.verify(ch["challenge_id"].as_str().unwrap(), &sig).await;
    assert_eq!(r.status(), 401);
    srv.shutdown().await;
}

#[tokio::test]
async fn malformed_and_oversized_requests() {
    let mut env = env();
    let srv = env.start().await;
    let c = env.client();
    let r = c
        .http
        .post(c.url("/api/auth/challenge"))
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = c
        .http
        .post(c.url("/api/auth/challenge"))
        .json(&json!({"user": "Robert'); DROP"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = c
        .http
        .post(c.url("/api/auth/challenge"))
        .json(&json!({"user": "alice", "extra": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422, "unknown fields rejected");
    let big = "A".repeat(64 * 1024);
    let r = c
        .http
        .post(c.url("/api/auth/verify"))
        .json(&json!({"challenge_id": "x", "signature": big}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);
    srv.shutdown().await;
}

#[tokio::test]
async fn challenge_rate_limit() {
    let mut env = env();
    env.cfg.rate_limit.challenges_per_minute = 3;
    let srv = env.start().await;
    let c = env.client();
    for _ in 0..3 {
        assert_eq!(c.challenge(USER).await.status(), 200);
    }
    let r = c.challenge(USER).await;
    assert_eq!(r.status(), 429);
    assert!(r.headers().contains_key("retry-after"));
    srv.shutdown().await;
}

#[tokio::test]
async fn lockout_after_repeated_failures() {
    let mut env = env();
    env.cfg.rate_limit.max_failures = 3;
    env.cfg.server.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
    let srv = env.start().await;
    let c = env.client_via(Some("203.0.113.5"));
    let wrong = new_key();
    for _ in 0..3 {
        let ch: Value = c.challenge(USER).await.json().await.unwrap();
        let r = c
            .verify(
                ch["challenge_id"].as_str().unwrap(),
                &sign(&wrong, ch["message"].as_str().unwrap()),
            )
            .await;
        assert_eq!(r.status(), 401);
    }
    // Locked out: even the correct key is refused from that address for now.
    let r = c.challenge(USER).await;
    assert_eq!(r.status(), 429);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"], "locked_out");
    // The user name isn't locked: from anywhere else they sign in as usual, so nobody can lock
    // a named person out by sending bad signatures for them.
    env.client_via(Some("203.0.113.6"))
        .login(USER, &env.key)
        .await;
    srv.shutdown().await;
    assert!(env.audit_log().contains("\"event\":\"auth_lockout\""));
}

#[tokio::test]
async fn background_polls_do_not_keep_a_login_alive() {
    let mut env = env();
    env.cfg.auth.session_idle_timeout_secs = 2;
    let srv = env.start().await;
    let (left_open, in_use) = (env.client(), env.client());
    left_open.login(USER, &env.key).await;
    in_use.login(USER, &env.key).await;
    let sessions = |c: &Client, poll: bool| {
        let mut r = c.http.get(c.url("/api/sessions"));
        if poll {
            r = r.header("x-sshweb-poll", "1");
        }
        async move { r.send().await.unwrap().status().as_u16() }
    };
    let (mut polled, mut used) = (Vec::new(), Vec::new());
    for _ in 0..6 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        polled.push(sessions(&left_open, true).await);
        used.push(sessions(&in_use, false).await);
    }
    // A page that only polls goes idle; one that is used stays signed in.
    assert_eq!(polled.first(), Some(&200), "{polled:?}");
    assert_eq!(polled.last(), Some(&401), "{polled:?}");
    assert!(used.iter().all(|s| *s == 200), "{used:?}");
    srv.shutdown().await;
}

#[tokio::test]
async fn logout_and_key_revocation_end_access() {
    let mut env = env();
    let srv = env.start().await;
    let c = env.client();
    c.login(USER, &env.key).await;
    assert_eq!(
        c.http.get(c.url("/api/me")).send().await.unwrap().status(),
        200
    );
    let r = c.http.post(c.url("/api/auth/logout")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        c.http.get(c.url("/api/me")).send().await.unwrap().status(),
        401
    );

    // Log in again, then revoke the key by editing the file (as `sshweb keys revoke` does).
    let c2 = env.client();
    c2.login(USER, &env.key).await;
    let other = new_key();
    write_file(
        &env.cfg.auth.authorized_keys,
        &format!("# revoked\n{}", authorized_line("bob", "local", &other)),
        0o600,
    );
    assert_eq!(
        c2.http
            .get(c2.url("/api/me"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    srv.shutdown().await;
}

#[tokio::test]
async fn access_rights_follow_authorisation_file() {
    let mut env = env();
    // alice may only use remote profiles; there are none, and local is not granted.
    write_file(
        &env.cfg.auth.authorized_keys,
        &authorized_line(USER, "remote:web1", &env.key),
        0o600,
    );
    let srv = env.start().await;
    let c = env.client();
    c.login(USER, &env.key).await;
    let me: Value = c
        .http
        .get(c.url("/api/me"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["local"]["enabled"], false);
    assert_eq!(me["remote"]["enabled"], false, "remote disabled in config");
    srv.shutdown().await;
}

#[tokio::test]
async fn same_origin_requests_with_withheld_origin_are_accepted() {
    let mut env = env();
    let srv = env.start().await;
    let plain = reqwest::Client::new();
    let url = format!("{}/api/auth/challenge", env.base());
    let send = |origin: Option<&'static str>, site: Option<&'static str>| {
        let mut rb = plain.post(&url).json(&json!({"user": USER}));
        if let Some(o) = origin {
            rb = rb.header("origin", o);
        }
        if let Some(s) = site {
            rb = rb.header("sec-fetch-site", s);
        }
        rb.send()
    };
    // Browsers under some referrer policies send `Origin: null` for same-origin POSTs.
    assert_eq!(
        send(Some("null"), Some("same-origin"))
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(send(None, Some("same-origin")).await.unwrap().status(), 200);
    // ...but not for cross-site requests, and a foreign origin is never rescued.
    assert_eq!(
        send(Some("null"), Some("cross-site"))
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(send(Some("null"), None).await.unwrap().status(), 403);
    assert_eq!(
        send(Some("https://evil.example"), Some("same-origin"))
            .await
            .unwrap()
            .status(),
        403
    );
    let r = send(Some("https://evil.example"), None).await.unwrap();
    assert!(
        r.text()
            .await
            .unwrap()
            .contains("origin https://evil.example")
    );
    srv.shutdown().await;
    assert!(env.audit_log().contains("\"event\":\"csrf_rejected\""));
}

#[tokio::test]
async fn reverse_proxy_origin_and_forwarded_client_ip() {
    let mut env = env();
    env.cfg.server.allowed_origins = vec!["https://dev.example.net".into()];
    env.cfg.server.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
    env.cfg.rate_limit.challenges_per_minute = 1;
    let srv = env.start().await;
    let plain = reqwest::Client::new();
    let url = format!("{}/api/auth/challenge", env.base());
    let req = |xff: &'static str| {
        plain
            .post(&url)
            .header("origin", "https://dev.example.net")
            .header("x-forwarded-for", xff)
            .json(&json!({"user": USER}))
            .send()
    };
    // The proxy's public origin is accepted, and its Host (proxy may preserve it) too.
    assert_eq!(req("203.0.113.5").await.unwrap().status(), 200);
    // Rate limits are per real client, not per proxy.
    assert_eq!(req("203.0.113.6").await.unwrap().status(), 200);
    assert_eq!(req("203.0.113.5").await.unwrap().status(), 429);
    let r = plain
        .get(format!("{}/healthz", env.base()))
        .header("host", "dev.example.net")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    srv.shutdown().await;
    assert!(env.audit_log().contains("\"ip\":\"203.0.113.5\""));
}
