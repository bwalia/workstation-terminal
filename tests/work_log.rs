//! Work log: a local tab's telemetry token, the loopback OTLP receiver, and the signed
//! `/activity` and `/recordings` posts to OpsAPI.

mod common;

use std::io::Read;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, Uri};
use common::*;
use serde_json::{Value, json};
use sshweb::opsapi::hmac_sha256_hex;
use tokio::sync::mpsc;

const SECRET: &str = "work-log-test-secret-0123456789abcdef0123456789";
const TERMINAL: &str = "6f1c2a9e-1111-4c4c-9d9d-0123456789ab";

struct Hit {
    path: String,
    headers: HeaderMap,
    body: Bytes,
}

impl Hit {
    fn header(&self, k: &str) -> &str {
        self.headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

/// A local HTTP server standing in for OpsAPI's work log endpoints.
async fn fake_opsapi() -> (String, mpsc::UnboundedReceiver<Hit>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let handler = move |uri: Uri, headers: HeaderMap, body: Bytes| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Hit {
                path: uri.path().to_string(),
                headers,
                body,
            });
            axum::Json(json!({"stored": true}))
        }
    };
    let app = axum::Router::new()
        .route("/terminal/activity", axum::routing::post(handler.clone()))
        .route("/terminal/recordings", axum::routing::post(handler));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/terminal", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, rx)
}

async fn next_hit(rx: &mut mpsc::UnboundedReceiver<Hit>) -> Hit {
    tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("OpsAPI hears from the terminal")
        .unwrap()
}

/// The value printed as `<tag><value>>` by the shell (not the echoed `%s` of the command).
fn printed(out: &str, tag: &str) -> Option<String> {
    out.match_indices(tag).find_map(|(i, _)| {
        let rest = &out[i + tag.len()..];
        let v = &rest[..rest.find('>')?];
        (!v.contains('%')).then(|| v.to_string())
    })
}

fn otlp_logs(records: Vec<Value>) -> Value {
    json!({"resourceLogs": [{"scopeLogs": [{"logRecords": records}]}]})
}

fn record(name: &str, extra: Value) -> Value {
    let mut attrs = vec![
        json!({"key": "event.name", "value": {"stringValue": name}}),
        json!({"key": "session.id", "value": {"stringValue": "claude-sess"}}),
        json!({"key": "prompt.id", "value": {"stringValue": "prompt-1"}}),
        json!({"key": "user.email", "value": {"stringValue": "priya@example.com"}}),
    ];
    for (k, v) in extra.as_object().unwrap() {
        attrs.push(json!({"key": k, "value": v}));
    }
    json!({"timeUnixNano": "1792828050123000000", "attributes": attrs})
}

#[tokio::test]
async fn a_local_tab_reports_claude_telemetry_and_its_screen_to_opsapi() {
    let (url, mut hits) = fake_opsapi().await;
    let mut env = env();
    env.cfg.opsapi.webhook_secret = Some(SECRET.into());
    env.cfg.opsapi.keys.terminal_id = Some(TERMINAL.into());
    let w = &mut env.cfg.opsapi.work_log;
    w.enabled = true;
    w.url = Some(url);
    w.otlp_port = 0;
    let recordings = env.cfg.server.state_dir.join("recordings");
    let _srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    let sid = ws.open_local().await;

    // The shell has the tab's token and where to send Claude's telemetry.
    ws.input(r#"printf 'TOK<%s> EP<%s>\n' "$SSHWEB_TAB_TOKEN" "$OTEL_EXPORTER_OTLP_LOGS_ENDPOINT""#)
        .await;
    ws.input("\r").await;
    ws.expect_output("EP<http://127.0.0.1:").await;
    let token = printed(&ws.output, "TOK<").unwrap();
    let endpoint = printed(&ws.output, "EP<").unwrap();
    assert_eq!(token.len(), 64);

    // What Claude Code would post, plus an event it doesn't need: first without a tab's token
    // (Claude outside sshweb) and with a wrong one, then with the tab's. The tick that sends the
    // tab's events has counted the others by then.
    let http = reqwest::Client::new();
    let body = otlp_logs(vec![
        record("hook_registered", json!({})),
        record(
            "user_prompt",
            json!({
                "prompt": {"stringValue": "fix the header"},
                "prompt_length": {"intValue": "14"}
            }),
        ),
        record(
            "api_request",
            json!({
                "model": {"stringValue": "claude-opus-5-5"},
                "input_tokens": {"intValue": "2"},
                "cost_usd": {"doubleValue": 0.13839}
            }),
        ),
    ]);
    let wrong = "0".repeat(64);
    for auth in [None, Some(wrong.as_str()), Some(token.as_str())] {
        let mut req = http.post(&endpoint).json(&body);
        if let Some(t) = auth {
            req = req.bearer_auth(t);
        }
        let r = req.send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.json::<Value>().await.unwrap(), json!({}));
    }

    // Within a tick OpsAPI gets the tab and the events, signed.
    let mut events: Vec<Value> = Vec::new();
    let mut tab = Value::Null;
    while events.len() < 2 || tab.is_null() {
        let h = next_hit(&mut hits).await;
        assert_eq!(h.path, "/terminal/activity", "only activity before the tab closes");
        assert!(!String::from_utf8_lossy(&h.body).contains("\"tab\":null"));
        assert_eq!(h.header("x-opsapi-terminal"), TERMINAL);
        assert_eq!(
            h.header("x-opsapi-signature"),
            format!("sha256={}", hmac_sha256_hex(SECRET, &h.body))
        );
        let v: Value = serde_json::from_slice(&h.body).unwrap();
        assert_eq!(v["terminal"], TERMINAL);
        assert!(v["sent_at"].is_u64());
        let tabs = v["tabs"].as_array().unwrap();
        if let Some(t) = tabs.iter().find(|t| t["id"] == sid.as_str()) {
            tab = t.clone();
        }
        events.extend(v["events"].as_array().unwrap().iter().cloned());
    }
    assert_eq!(tab["user"], USER);
    assert_eq!(tab["kind"], "local");
    assert_eq!(tab["via"], "key");
    assert!(tab["key"].as_str().unwrap().starts_with("SHA256:"));
    assert!(tab["launch"].is_null() && tab["closed_at"].is_null());
    assert_eq!(tab["attached"], true, "the browser is connected: {tab}");
    assert!(tab.get("last_input_at").is_some(), "{tab}");
    assert_eq!(events.len(), 2, "only the tab's own posts: {events:?}");
    let mine: Vec<&Value> = events
        .iter()
        .filter(|e| e["tab"] == sid.as_str())
        .collect();
    assert_eq!(mine.len(), 2);
    let prompt = mine.iter().find(|e| e["type"] == "user_prompt").unwrap();
    let prefix = format!("{sid}:");
    assert!(prompt["id"].as_str().unwrap().starts_with(&prefix));
    assert_eq!(prompt["session"], "claude-sess");
    assert_eq!(prompt["prompt_id"], "prompt-1");
    assert_eq!(prompt["at"], 1792828050.123);
    assert_eq!(
        prompt["attrs"],
        json!({"prompt": "fix the header", "prompt_length": 14})
    );
    let req = mine.iter().find(|e| e["type"] == "api_request").unwrap();
    assert_eq!(req["attrs"]["model"], "claude-opus-5-5");
    assert_eq!(req["attrs"]["input_tokens"], 2);
    assert!(!json!(events).to_string().contains("priya@"));
    // The two posts without a tab's token were only counted.
    let audit = env.audit_log();
    let dropped: Vec<Value> = audit
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|v| v["event"] == "work_log_unattributed_dropped")
        .collect();
    assert_eq!(dropped.len(), 1, "{audit}");
    assert_eq!(dropped[0]["count"], 2);
    assert!(
        !audit.contains("fix the header"),
        "no content in the audit log"
    );

    // Closing the tab uploads the screen recording's last part.
    ws.input("echo RECORDED_$((6*7))\r").await;
    ws.expect_output("RECORDED_42").await;
    ws.send(json!({"type": "close"})).await;
    let mut cast = Vec::new();
    loop {
        let h = next_hit(&mut hits).await;
        if h.path != "/terminal/recordings" {
            continue;
        }
        assert_eq!(h.header("x-opsapi-terminal"), TERMINAL);
        assert_eq!(h.header("x-opsapi-tab"), sid);
        let part = h.header("x-opsapi-part").to_string();
        let mut signed = format!("{sid}\n{part}\n").into_bytes();
        signed.extend_from_slice(&h.body);
        assert_eq!(
            h.header("x-opsapi-signature"),
            format!("sha256={}", hmac_sha256_hex(SECRET, &signed))
        );
        flate2::read::GzDecoder::new(&h.body[..])
            .read_to_end(&mut cast)
            .unwrap();
        if h.header("x-opsapi-final") == "1" {
            break;
        }
        assert_eq!(h.header("x-opsapi-final"), "0");
    }
    let cast = String::from_utf8(cast).unwrap();
    let lines: Vec<Value> = cast
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines[0]["version"], 2);
    assert_eq!(lines[0]["width"], 80);
    assert_eq!(lines[0]["height"], 24);
    for l in &lines[1..] {
        assert!(
            l[0].is_f64() && (l[1] == "o" || l[1] == "r") && l[2].is_string(),
            "{l}"
        );
    }
    let screen: String = lines[1..]
        .iter()
        .filter(|l| l[1] == "o")
        .map(|l| l[2].as_str().unwrap())
        .collect();
    assert!(screen.contains("RECORDED_42"), "{screen}");

    // Uploaded parts are deleted.
    for _ in 0..50 {
        if std::fs::read_dir(&recordings).unwrap().next().is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("uploaded recording parts are deleted");
}
