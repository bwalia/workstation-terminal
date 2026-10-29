//! Sending the work log to OpsAPI (§11.2 of the OpsAPI doc).
//!
//! - `POST {url}/activity` every 10 s while there is something new (an open tab is, once a minute):
//!   `{terminal, sent_at, tabs, events}`, `X-Opsapi-Signature: sha256=<hex HMAC of the body>`.
//! - `POST {url}/recordings` for each part as it is written: `X-Opsapi-Tab`, `X-Opsapi-Part`,
//!   `X-Opsapi-Final`, signature over `"<tab>\n<part>\n" + body`.
//!
//! Both carry `X-Opsapi-Terminal` and retry with backoff (up to 5 min) until OpsAPI takes them.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::warn;

use super::WorkLog;
use super::recorder::Part;
use crate::audit::AuditEvent;
use crate::opsapi::hmac_sha256_hex;
use crate::server::App;

pub const MAX_BODY: usize = 5 * 1024 * 1024;
pub const MAX_BATCH_EVENTS: usize = 2000;
const MAX_BACKOFF: Duration = Duration::from_secs(300);

pub fn activity_signature(secret: &str, body: &[u8]) -> String {
    format!("sha256={}", hmac_sha256_hex(secret, body))
}

pub fn recording_signature(secret: &str, tab: &str, part: u64, body: &[u8]) -> String {
    let mut msg = format!("{tab}\n{part}\n").into_bytes();
    msg.extend_from_slice(body);
    format!("sha256={}", hmac_sha256_hex(secret, &msg))
}

fn client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client")
}

enum SendError {
    /// Worth retrying (network, 5xx, 401: a config being fixed).
    Retry(String),
    /// OpsAPI won't ever take it (400, 413): drop it rather than block everything behind it.
    Refused(String),
}

fn outcome(r: reqwest::Result<reqwest::Response>) -> Result<(), SendError> {
    let res = r.map_err(|e| SendError::Retry(e.to_string()))?;
    match res.status().as_u16() {
        200..=299 => Ok(()),
        s @ (400 | 413) => Err(SendError::Refused(format!("status {s}"))),
        s => Err(SendError::Retry(format!("status {s}"))),
    }
}

/// One `/activity` post of what is due (nothing when nothing is new). Returns how many events
/// were lost since the previous good send.
async fn send_activity(http: &reqwest::Client, wl: &WorkLog) -> Result<u64, String> {
    let Some(batch) = wl.batch(crate::opsapi::unix_now()) else {
        return Ok(0);
    };
    let r = http
        .post(format!("{}/activity", wl.url))
        .header("Content-Type", "application/json")
        .header("X-Opsapi-Terminal", &wl.terminal)
        .header(
            "X-Opsapi-Signature",
            activity_signature(&wl.secret, batch.body.as_bytes()),
        )
        .header("User-Agent", "sshweb-work-log")
        .body(batch.body.clone())
        .send()
        .await;
    match outcome(r) {
        Ok(()) => Ok(wl.ack(&batch)),
        Err(SendError::Refused(e)) => {
            warn!(error = %e, "OpsAPI refused a work log batch; it is dropped");
            Ok(wl.ack(&batch))
        }
        Err(SendError::Retry(e)) => Err(e),
    }
}

/// Every 10 s: count active time, close old recording parts, and send what is new. On
/// shutdown, one last send once the sessions have closed, so their final state goes out.
pub async fn activity_loop(app: App, wl: Arc<WorkLog>) {
    let http = client(Duration::from_secs(10));
    let mut tick = tokio::time::interval(super::TICK);
    let mut next_send = Instant::now();
    let mut backoff = super::TICK;
    let mut failing = false;
    loop {
        tokio::select! {
            _ = app.shutdown.cancelled() => {
                let deadline = Instant::now() + Duration::from_secs(8);
                while app.sessions.count() > 0 && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let _ = send_activity(&http, &wl).await;
                break;
            }
            _ = tick.tick() => {}
        }
        wl.tick();
        if Instant::now() < next_send {
            continue;
        }
        match send_activity(&http, &wl).await {
            Ok(dropped) => {
                failing = false;
                backoff = super::TICK;
                if dropped > 0 {
                    let ev = AuditEvent::new("work_log_events_dropped");
                    app.audit.log(ev.num("count", dropped as i64));
                }
            }
            Err(e) => {
                warn!(error = %e, retry_secs = backoff.as_secs(), "couldn't send the work log");
                if !failing {
                    app.audit.log(
                        AuditEvent::new("work_log_send_failed")
                            .field("what", "activity")
                            .field("error", &e),
                    );
                    failing = true;
                }
                next_send = Instant::now() + backoff;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

async fn upload(http: &reqwest::Client, wl: &WorkLog, p: &Part) -> Result<(), SendError> {
    let body = match std::fs::read(&p.path) {
        Ok(b) => b,
        // Gone (removed by hand): nothing to send.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(SendError::Retry(e.to_string())),
    };
    let r = http
        .post(format!("{}/recordings", wl.url))
        .header("Content-Type", "application/gzip")
        .header("X-Opsapi-Terminal", &wl.terminal)
        .header("X-Opsapi-Tab", &p.tab)
        .header("X-Opsapi-Part", p.part.to_string())
        .header("X-Opsapi-Final", if p.last { "1" } else { "0" })
        .header(
            "X-Opsapi-Signature",
            recording_signature(&wl.secret, &p.tab, p.part, &body),
        )
        .header("User-Agent", "sshweb-work-log")
        .body(body)
        .send()
        .await;
    outcome(r)
}

/// Upload recording parts in order as they are written; delete each once OpsAPI has it.
pub async fn upload_loop(app: App, wl: Arc<WorkLog>) {
    let http = client(Duration::from_secs(60));
    let mut backoff = super::TICK;
    let mut failing = false;
    loop {
        let Some(part) = wl.uploads.front() else {
            tokio::select! {
                _ = app.shutdown.cancelled() => break,
                _ = wl.uploads.ready.notified() => continue,
            }
        };
        match upload(&http, &wl, &part).await {
            done @ (Ok(()) | Err(SendError::Refused(_))) => {
                if let Err(SendError::Refused(e)) = done {
                    warn!(error = %e, tab = %part.tab, part = part.part,
                        "OpsAPI refused a recording part; it is deleted");
                }
                let _ = std::fs::remove_file(&part.path);
                wl.uploads.pop_front();
                failing = false;
                backoff = super::TICK;
            }
            Err(SendError::Retry(e)) => {
                warn!(error = %e, retry_secs = backoff.as_secs(), "couldn't upload a recording");
                if !failing {
                    app.audit.log(
                        AuditEvent::new("work_log_send_failed")
                            .field("what", "recordings")
                            .field("error", &e),
                    );
                    failing = true;
                }
                tokio::select! {
                    _ = app.shutdown.cancelled() => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opsapi::tests::SECRET;

    #[test]
    fn signatures_cover_the_body_and_for_recordings_the_tab_and_part() {
        let body = br#"{"terminal":"t"}"#;
        assert_eq!(
            activity_signature(SECRET, body),
            format!("sha256={}", hmac_sha256_hex(SECRET, body))
        );
        let gz = [0x1f, 0x8b, 0, 1];
        let mut msg = b"ab12\n3\n".to_vec();
        msg.extend_from_slice(&gz);
        assert_eq!(
            recording_signature(SECRET, "ab12", 3, &gz),
            format!("sha256={}", hmac_sha256_hex(SECRET, &msg))
        );
        assert_ne!(
            recording_signature(SECRET, "ab12", 3, &gz),
            recording_signature(SECRET, "ab12", 4, &gz)
        );
    }
}
