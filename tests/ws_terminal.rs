//! WebSocket + PTY integration tests: browser-equivalent client to a real local shell.

mod common;

use std::time::Duration;

use common::*;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn rejects_cross_site_websocket() {
    let mut env = env();
    let srv = env.start().await;
    let port = env.cfg.server.port;
    assert!(
        ws_connect(port, Some("http://evil.example"), None)
            .await
            .is_err()
    );
    assert!(
        ws_connect(port, None, None).await.is_err(),
        "missing Origin"
    );
    assert!(
        ws_connect(port, Some(&format!("http://127.0.0.1:{}", port + 1)), None)
            .await
            .is_err(),
        "wrong port"
    );
    // Even with a valid login cookie, a foreign origin is refused.
    let c = env.client();
    c.login(USER, &env.key).await;
    let cookie = c.cookie_header().unwrap();
    assert!(
        ws_connect(port, Some("http://evil.example"), Some(&cookie))
            .await
            .is_err()
    );
    srv.shutdown().await;
}

#[tokio::test]
async fn unauthenticated_socket_cannot_open_terminal() {
    let mut env = env();
    let srv = env.start().await;
    let mut ws = ws_connect(env.cfg.server.port, Some(&env.base()), None)
        .await
        .unwrap();
    let hello = ws.hello().await;
    assert_eq!(hello["authenticated"], false);
    ws.send(json!({"type": "open", "target": {"kind": "local"}, "cols": 80, "rows": 24}))
        .await;
    let msgs = ws.drain().await;
    assert!(
        msgs.iter()
            .any(|m| m["code"] == "unauthenticated" && m["fatal"] == true),
        "{msgs:?}"
    );
    assert_eq!(srv.app.sessions.count(), 0);

    // Raw input before authentication is rejected too, and nothing reaches a PTY.
    let mut ws = ws_connect(env.cfg.server.port, Some(&env.base()), None)
        .await
        .unwrap();
    ws.hello().await;
    ws.input("touch /tmp/should-not-exist\r").await;
    let msgs = ws.drain().await;
    assert!(msgs.iter().any(|m| m["code"] == "unauthenticated"));
    srv.shutdown().await;
}

#[tokio::test]
async fn sockets_must_sign_in_in_time_and_few_may_wait_per_address() {
    let mut env = env();
    env.cfg.limits.ws_auth_timeout_secs = 1;
    env.cfg.limits.max_unauthenticated_websockets_per_ip = 2;
    let srv = env.start().await;
    let (port, base) = (env.cfg.server.port, env.base());
    // Two sockets that haven't signed in may wait per address; a third is refused.
    let mut a = ws_connect(port, Some(&base), None).await.unwrap();
    let mut b = ws_connect(port, Some(&base), None).await.unwrap();
    assert!(ws_connect(port, Some(&base), None).await.is_err());
    // A signed-in browser doesn't count.
    let (_c, mut browser) = logged_in_ws(&env).await;
    // Signing in over the socket gives its place back.
    a.hello().await;
    a.send(json!({"type": "auth_request", "user": USER})).await;
    let ch = a.expect_type("auth_challenge").await;
    let sig = sign(&env.key, ch["message"].as_str().unwrap());
    a.send(json!({"type": "auth_response", "challenge_id": ch["challenge_id"], "signature": sig}))
        .await;
    a.expect_type("auth_ok").await;
    let _waiting = ws_connect(port, Some(&base), None).await.unwrap();
    assert!(ws_connect(port, Some(&base), None).await.is_err());

    // One that doesn't sign in is closed after the deadline, even while it keeps pinging.
    b.hello().await;
    let started = std::time::Instant::now();
    let mut pinged = started - Duration::from_secs(1);
    let mut seen = Vec::new();
    loop {
        assert!(started.elapsed() < Duration::from_secs(12), "still open: {seen:?}");
        if pinged.elapsed() >= Duration::from_millis(500) {
            pinged = std::time::Instant::now();
            let _ = b.send_raw(Message::Ping(Default::default())).await;
            let ping = json!({"type": "ping", "ts": 1}).to_string();
            let _ = b.send_raw(Message::Text(ping.into())).await;
        }
        match tokio::time::timeout(Duration::from_millis(100), b.inner.next()).await {
            Err(_) | Ok(Some(Ok(Message::Pong(_) | Message::Ping(_)))) => {}
            Ok(Some(Ok(Message::Text(t)))) => seen.push(serde_json::from_str::<Value>(&t).unwrap()),
            Ok(_) => break,
        }
    }
    assert!(seen.iter().any(|m| m["type"] == "pong"), "pings were answered");
    assert!(
        seen.iter()
            .any(|m| m["code"] == "auth_timeout" && m["fatal"] == true),
        "{seen:?}"
    );
    // The signed-in ones stay.
    for ws in [&mut a, &mut browser] {
        ws.send(json!({"type": "ping", "ts": 2})).await;
        assert_eq!(ws.expect_type("pong").await["ts"], 2);
    }
    srv.shutdown().await;
}

#[tokio::test]
async fn shells_say_whose_they_are() {
    use sshweb::auth::keys::{Access, AuthorizedKey, fingerprint};
    let mut env = env();
    let srv = env.start().await;
    let who = r#"printf 'WHO<%s|%s|%s>\n' "$SSHWEB_USER" "$SSHWEB_USER_EMAIL" "$SSHWEB_USER_NAME""#;
    // A key from the authorised keys file: only the user name is known.
    let (_c, mut ws) = logged_in_ws(&env).await;
    ws.open_local().await;
    ws.input(&format!("{who}\r")).await;
    ws.expect_output("WHO<alice||>").await;

    // A key from OpsAPI with the person's email and name.
    let key = new_key();
    let now = sshweb::opsapi::unix_now();
    let priya = AuthorizedKey {
        user: "priya".into(),
        access: Access {
            local: true,
            ..Access::default()
        },
        key: key.public_key().clone(),
        fingerprint: fingerprint(key.public_key()),
        line: 0,
        email: Some("priya@example.com".into()),
        name: Some("Priya Patel".into()),
        expires_unix: Some(now + 3600),
    };
    srv.app.auth.keys.set_synced(vec![priya], now, now).unwrap();
    let c = env.client();
    c.login("priya", &key).await;
    let cookie = c.cookie_header().unwrap();
    let mut ws = ws_connect(env.cfg.server.port, Some(&env.base()), Some(&cookie))
        .await
        .unwrap();
    ws.hello().await;
    ws.open_local().await;
    ws.input(&format!("{who}\r")).await;
    ws.expect_output("WHO<priya|priya@example.com|Priya Patel>").await;
    srv.shutdown().await;
}

#[tokio::test]
async fn hello_is_required_and_versioned() {
    let mut env = env();
    let srv = env.start().await;
    let mut ws = ws_connect(env.cfg.server.port, Some(&env.base()), None)
        .await
        .unwrap();
    ws.send(json!({"type": "ping"})).await;
    let msgs = ws.drain().await;
    assert!(msgs.iter().any(|m| m["code"] == "hello_required"));

    let mut ws = ws_connect(env.cfg.server.port, Some(&env.base()), None)
        .await
        .unwrap();
    ws.send(json!({"type": "hello", "version": 99})).await;
    let msgs = ws.drain().await;
    assert!(msgs.iter().any(|m| m["code"] == "unsupported_version"));
    srv.shutdown().await;
}

#[tokio::test]
async fn websocket_native_challenge_login_and_interactive_shell() {
    let mut env = env();
    let srv = env.start().await;
    let mut ws = ws_connect(env.cfg.server.port, Some(&env.base()), None)
        .await
        .unwrap();
    assert_eq!(ws.hello().await["authenticated"], false);
    ws.send(json!({"type": "auth_request", "user": USER})).await;
    let ch = ws.expect_type("auth_challenge").await;
    assert_eq!(ch["namespace"], "sshweb-auth");
    // Wrong signature first: fails, challenge is burned.
    let bad = sign(&new_key(), ch["message"].as_str().unwrap());
    ws.send(json!({"type": "auth_response", "challenge_id": ch["challenge_id"], "signature": bad}))
        .await;
    assert_eq!(ws.expect_type("auth_failed").await["code"], "auth_failed");
    let good = sign(&env.key, ch["message"].as_str().unwrap());
    ws.send(
        json!({"type": "auth_response", "challenge_id": ch["challenge_id"], "signature": good}),
    )
    .await;
    assert_eq!(
        ws.expect_type("auth_failed").await["code"],
        "auth_failed",
        "replay rejected"
    );

    ws.send(json!({"type": "auth_request", "user": USER})).await;
    let ch = ws.expect_type("auth_challenge").await;
    let good = sign(&env.key, ch["message"].as_str().unwrap());
    ws.send(
        json!({"type": "auth_response", "challenge_id": ch["challenge_id"], "signature": good}),
    )
    .await;
    assert_eq!(ws.expect_type("auth_ok").await["user"], USER);

    ws.open_local().await;
    ws.input("echo calc=$((6*7))\r").await;
    ws.expect_output("calc=42").await;
    ws.input("exit 5\r").await;
    let closed = ws.expect_type("session_closed").await;
    assert_eq!(closed["exit_code"], 5);
    assert_eq!(closed["reason"], "process exited");
    srv.shutdown().await;
}

#[tokio::test]
async fn resize_ctrl_c_and_tty_behaviour() {
    let mut env = env();
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    ws.open_local().await;
    ws.input("stty size; tty\r").await;
    ws.expect_output("24 80").await;
    ws.expect_output("/dev/ttys").await;

    ws.send(json!({"type": "resize", "cols": 120, "rows": 40}))
        .await;
    ws.input("stty size\r").await;
    ws.expect_output("40 120").await;

    // Ctrl+C interrupts a foreground program; the shell survives.
    let t0 = std::time::Instant::now();
    ws.input("sleep 100\r").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    ws.input("\x03").await;
    ws.input("echo after=$((3*3))\r").await;
    ws.expect_output("after=9").await;
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "sleep was not interrupted"
    );
    assert!(ws.output.contains("^C"), "tty echoed the interrupt");

    // Ctrl+Z suspends a job; it can be resumed and finished.
    ws.input("sleep 100\r").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    ws.input("\x1a").await;
    ws.input("jobs; kill %1; echo jobs=$((5+5))\r").await;
    ws.expect_output("jobs=10").await;

    // Invalid resize is refused without killing the connection.
    ws.send(json!({"type": "resize", "cols": 0, "rows": 0}))
        .await;
    let e = ws.expect_type("error").await;
    assert_eq!(e["fatal"], false);

    // Ctrl+D at the prompt ends the shell.
    ws.input("\x04").await;
    let closed = ws.expect_type("session_closed").await;
    assert_eq!(closed["reason"], "process exited");
    srv.shutdown().await;
}

#[tokio::test]
async fn full_screen_application_uses_alternate_screen() {
    let Some(vim) = find_bin("/usr/bin/vim") else {
        eprintln!("skipping: /usr/bin/vim not found");
        return;
    };
    let mut env = env();
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    ws.open_local().await;
    ws.input(&format!(
        "{} -u NONE -N -n {}/note.txt\r",
        vim.display(),
        env.path().display()
    ))
    .await;
    // xterm alternate screen enable.
    ws.expect_output("\x1b[?1049h").await;
    ws.input("ihello from vim\x1b:wq\r").await;
    ws.expect_output("\x1b[?1049l").await;
    ws.input("cat note.txt\r").await;
    ws.expect_output("hello from vim\r\n").await;
    srv.shutdown().await;
}

#[tokio::test]
async fn malformed_messages_are_recoverable_errors() {
    let mut env = env();
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    ws.send_raw(Message::Text("{oops".into())).await.unwrap();
    let e = ws.expect_type("error").await;
    assert_eq!(e["code"], "bad_message");
    assert_eq!(e["fatal"], false);
    ws.send(json!({"type": "rm_rf"})).await;
    assert_eq!(ws.expect_type("error").await["fatal"], false);
    ws.send_raw(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert_eq!(ws.expect_type("error").await["code"], "bad_message");
    // Input without an open session is refused.
    ws.input("ls\r").await;
    assert_eq!(ws.expect_type("error").await["code"], "no_session");
    // Still usable afterwards.
    ws.send(json!({"type": "ping", "ts": 7})).await;
    assert_eq!(ws.expect_type("pong").await["ts"], 7);
    srv.shutdown().await;
}

#[tokio::test]
async fn too_many_protocol_errors_close_the_socket() {
    let mut env = env();
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    for _ in 0..10 {
        let _ = ws.send_raw(Message::Text("garbage".into())).await;
    }
    let msgs = ws.drain().await;
    assert!(msgs.iter().any(|m| m["fatal"] == true));
    srv.shutdown().await;
}

#[tokio::test]
async fn oversized_message_closes_connection() {
    let mut env = env();
    env.cfg.limits.ws_max_message_bytes = 4096;
    env.cfg.limits.input_burst_bytes = 8192;
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    let big = json!({"type": "input", "data": "x".repeat(10_000)});
    let _ = ws.send_raw(Message::Text(big.to_string().into())).await;
    ws.drain().await; // returns once the server drops the connection
    srv.shutdown().await;
}

#[tokio::test]
async fn reconnect_resumes_session_without_replaying_input() {
    let mut env = env();
    let srv = env.start().await;
    let (c, mut ws) = logged_in_ws(&env).await;
    let id = ws.open_local().await;
    ws.input("echo counter=$((40+2))\r").await;
    ws.expect_output("counter=42").await;
    // Simulate a network drop.
    drop(ws);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let s = srv
        .app
        .sessions
        .get(&id)
        .expect("session survives disconnect");
    assert_eq!(s.info().state, "detached");

    let cookie = c.cookie_header().unwrap();
    let mut ws2 = ws_connect(env.cfg.server.port, Some(&env.base()), Some(&cookie))
        .await
        .unwrap();
    ws2.hello().await;
    ws2.send(json!({"type": "attach", "session_id": id, "cols": 100, "rows": 30}))
        .await;
    let opened = ws2.expect_type("session_opened").await;
    assert_eq!(opened["resumed"], true);
    // Scrollback is replayed (output), but the earlier command is not re-executed.
    ws2.expect_output("counter=42").await;
    ws2.input("echo second=$((1+1)); stty size\r").await;
    ws2.expect_output("30 100").await;
    assert_eq!(
        ws2.output.matches("counter=42").count(),
        1,
        "input must not be replayed"
    );
    ws2.send(json!({"type": "close"})).await;
    ws2.expect_type("session_closed").await;
    srv.shutdown().await;
}

#[tokio::test]
async fn sessions_are_bound_to_their_owner() {
    let mut env = env();
    let bob = new_key();
    write_file(
        &env.cfg.auth.authorized_keys,
        &format!(
            "{}{}",
            authorized_line(USER, "local", &env.key),
            authorized_line("bob", "local", &bob)
        ),
        0o600,
    );
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    let id = ws.open_local().await;

    let cb = env.client();
    cb.login("bob", &bob).await;
    let mut wb = ws_connect(
        env.cfg.server.port,
        Some(&env.base()),
        Some(&cb.cookie_header().unwrap()),
    )
    .await
    .unwrap();
    wb.hello().await;
    wb.send(json!({"type": "attach", "session_id": id, "cols": 80, "rows": 24}))
        .await;
    assert_eq!(wb.expect_type("error").await["code"], "no_such_session");
    // bob cannot close alice's session over HTTP either.
    let r = cb
        .http
        .delete(cb.url(&format!("/api/sessions/{id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let list: Value = cb
        .http
        .get(cb.url("/api/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["sessions"].as_array().unwrap().len(), 0);
    srv.shutdown().await;
}

#[tokio::test]
async fn session_limit_per_user() {
    let mut env = env();
    env.cfg.sessions.max_per_user = 1;
    let srv = env.start().await;
    let (c, mut ws) = logged_in_ws(&env).await;
    ws.open_local().await;
    let mut ws2 = ws_connect(
        env.cfg.server.port,
        Some(&env.base()),
        Some(&c.cookie_header().unwrap()),
    )
    .await
    .unwrap();
    ws2.hello().await;
    ws2.send(json!({"type": "open", "target": {"kind": "local"}, "cols": 80, "rows": 24}))
        .await;
    let e = ws2.expect_type("error").await;
    assert_eq!(e["code"], "open_failed");
    srv.shutdown().await;
}

#[tokio::test]
async fn disallowed_shell_and_local_access_refused() {
    let mut env = env();
    write_file(
        &env.cfg.auth.authorized_keys,
        &authorized_line(USER, "remote:*", &env.key),
        0o600,
    );
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    ws.send(json!({"type": "open", "target": {"kind": "local"}, "cols": 80, "rows": 24}))
        .await;
    assert_eq!(ws.expect_type("error").await["code"], "forbidden");
    srv.shutdown().await;

    let mut env = common::env();
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    ws.send(json!({"type": "open", "target": {"kind": "local", "shell": "/usr/bin/python3"}, "cols": 80, "rows": 24}))
        .await;
    let e = ws.expect_type("error").await;
    assert_eq!(e["code"], "forbidden");
    assert!(e["message"].as_str().unwrap().contains("not permitted"));
    srv.shutdown().await;
}

#[tokio::test]
async fn revoked_login_terminates_terminal() {
    let mut env = env();
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    let id = ws.open_local().await;
    let pid = srv.app.sessions.get(&id).unwrap().pid().unwrap();
    // Administrator revokes the key.
    write_file(&env.cfg.auth.authorized_keys, "# all keys revoked\n", 0o600);
    let msgs = ws.drain().await;
    assert!(
        msgs.iter()
            .any(|m| m["code"] == "session_expired" || m["type"] == "session_closed"),
        "{msgs:?}"
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(srv.app.sessions.get(&id).is_none());
    assert!(!pid_alive(pid), "shell must be terminated");
    srv.shutdown().await;
}

#[tokio::test]
async fn admin_can_list_and_revoke_sessions() {
    let mut env = env();
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    let id = ws.open_local().await;
    let sock = env.cfg.admin_socket_path();
    let (st, body) = sshweb::admin_client::request(&sock, hyper::Method::GET, "/admin/sessions")
        .await
        .unwrap();
    assert_eq!(st, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["sessions"][0]["id"], id);
    assert_eq!(v["logins"][0]["user"], USER);
    let (st, _) = sshweb::admin_client::request(
        &sock,
        hyper::Method::DELETE,
        &format!("/admin/sessions/{id}"),
    )
    .await
    .unwrap();
    assert_eq!(st, 200);
    let closed = ws.expect_type("session_closed").await;
    assert_eq!(closed["reason"], "revoked by administrator");
    srv.shutdown().await;
    assert!(env.audit_log().contains("admin_revoke"));
}

#[tokio::test]
async fn graceful_shutdown_closes_sessions_and_sockets() {
    let mut env = env();
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    let id = ws.open_local().await;
    let pid = srv.app.sessions.get(&id).unwrap().pid().unwrap();
    let sock = env.cfg.admin_socket_path();
    let started = std::time::Instant::now();
    let shut = tokio::spawn(srv.shutdown());
    let msgs = ws.drain().await;
    shut.await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(12));
    assert!(
        msgs.iter()
            .any(|m| m["type"] == "session_closed" || m["code"] == "server_shutdown"),
        "{msgs:?}"
    );
    assert!(!pid_alive(pid), "shell must be terminated on shutdown");
    assert!(!sock.exists(), "admin socket removed");
    assert!(env.audit_log().contains("server_stop"));
}

#[tokio::test]
async fn narrowing_access_closes_running_sessions() {
    let mut env = env();
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    ws.open_local().await;
    // Same key stays authorised, but no longer for local terminals.
    write_file(
        &env.cfg.auth.authorized_keys,
        &authorized_line(USER, "remote:*", &env.key),
        0o600,
    );
    let closed = ws.expect_type("session_closed").await;
    assert_eq!(closed["reason"], "access revoked");
    srv.shutdown().await;
}

#[tokio::test]
async fn sessions_can_be_renamed_by_their_owner() {
    let mut env = env();
    let bob = new_key();
    write_file(
        &env.cfg.auth.authorized_keys,
        &format!(
            "{}{}",
            authorized_line(USER, "local", &env.key),
            authorized_line("bob", "local", &bob)
        ),
        0o600,
    );
    let srv = env.start().await;
    let (c, mut ws) = logged_in_ws(&env).await;
    let id = ws.open_local().await;
    let url = c.url(&format!("/api/sessions/{id}"));

    let r = c
        .http
        .patch(&url)
        .json(&json!({"name": "  build box  "}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.json::<Value>().await.unwrap()["name"], "build box");
    let list: Value = c
        .http
        .get(c.url("/api/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["sessions"][0]["name"], "build box");

    // Invalid names are refused and leave the name unchanged.
    for bad in ["x".repeat(65), "a\u{1b}[31mb".to_string()] {
        let r = c
            .http
            .patch(&url)
            .json(&json!({ "name": bad }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
    }
    // Cross-site rename is blocked by the Origin check.
    let r = reqwest::Client::new()
        .patch(&url)
        .header("cookie", c.cookie_header().unwrap())
        .json(&json!({"name": "pwned"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // Another user cannot rename it (and cannot tell it exists).
    let cb = env.client();
    cb.login("bob", &bob).await;
    let r = cb
        .http
        .patch(&url)
        .json(&json!({"name": "mine"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // The name survives a reconnect and is sent with session_opened.
    drop(ws);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut ws2 = ws_connect(
        env.cfg.server.port,
        Some(&env.base()),
        Some(&c.cookie_header().unwrap()),
    )
    .await
    .unwrap();
    ws2.hello().await;
    ws2.send(json!({"type": "attach", "session_id": id, "cols": 80, "rows": 24}))
        .await;
    assert_eq!(ws2.expect_type("session_opened").await["name"], "build box");

    // Empty name resets to the default title.
    let r = c
        .http
        .patch(&url)
        .json(&json!({"name": ""}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["name"], Value::Null);
    srv.shutdown().await;
    assert!(env.audit_log().contains("\"event\":\"session_rename\""));
}
