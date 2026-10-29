//! STD-008 UI capture and validation. Needs Google Chrome and PostgreSQL:
//! `cargo test -p flyw8t-server --test ui_capture -- --ignored`.
//!
//! Signs in, builds real state (an enrolled agent, verified, queued, cancelled and
//! outcome-unknown jobs), then renders every console page at desktop, tablet and phone widths
//! in light and dark. Fails on horizontal page overflow or any browser error. Screenshots go to
//! `target/ui-capture/`; with `FLYW8T_PUBLISH_SCREENSHOTS=1` a selection is copied to `docs/img/`.

mod common;

use base64::Engine;
use common::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

const SIZES: [(u32, u32, &str); 3] = [
    (1280, 860, "desktop"),
    (820, 1100, "tablet"),
    (390, 844, "phone"),
];
const THEMES: [&str; 2] = ["light", "dark"];

struct Cdp {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next: u64,
    errors: Vec<String>,
}

impl Cdp {
    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        self.ws
            .send(Message::text(
                json!({"id": id, "method": method, "params": params}).to_string(),
            ))
            .await
            .unwrap();
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(20), self.ws.next())
                .await
                .expect("CDP timeout")
                .unwrap()
                .unwrap();
            let v: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
            match v["method"].as_str() {
                Some("Runtime.exceptionThrown") => self
                    .errors
                    .push(v["params"]["exceptionDetails"].to_string()),
                Some("Runtime.consoleAPICalled") if v["params"]["type"] == "error" => {
                    self.errors.push(v["params"]["args"].to_string())
                }
                Some("Log.entryAdded") if v["params"]["entry"]["level"] == "error" => {
                    self.errors.push(v["params"]["entry"]["text"].to_string())
                }
                _ => {}
            }
            if v["id"] == id {
                return v["result"].clone();
            }
        }
    }

    async fn eval(&mut self, expr: &str) -> Value {
        self.call(
            "Runtime.evaluate",
            json!({"expression": expr, "returnByValue": true, "awaitPromise": true}),
        )
        .await["result"]["value"]
            .clone()
    }
}

async fn http_json(port: u16, path: &str) -> Value {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    text.split_once("\r\n\r\n")
        .and_then(|(_, b)| serde_json::from_str(b).ok())
        .unwrap_or(Value::Null)
}

fn find_chrome() -> PathBuf {
    let candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ];
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("Google Chrome")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "launches Google Chrome and needs PostgreSQL"]
async fn console_renders_cleanly_everywhere() {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/ui-capture");
    std::fs::create_dir_all(&out_dir).unwrap();
    let publish = std::env::var("FLYW8T_PUBLISH_SCREENSHOTS").as_deref() == Ok("1");
    let docs_img = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/img");

    // Real state to look at.
    let server = start_fresh().await;
    let (admin, org, agent) = enrolled(&server).await;
    let (stop, task) = agent.connect(&server.url());
    wait_connected(&server, agent.device_id).await;
    let ok = admin
        .run(&server, agent.device_id, &[("action", "net.ipconfig")])
        .await;
    wait_state(&server, ok, "completed", Duration::from_secs(30)).await;
    let info = admin
        .run(&server, agent.device_id, &[("action", "system.info")])
        .await;
    wait_state(&server, info, "completed", Duration::from_secs(30)).await;
    let ping = admin
        .run(
            &server,
            agent.device_id,
            &[("action", "net.ping"), ("target", "127.0.0.1")],
        )
        .await;
    wait_state(&server, ping, "completed", Duration::from_secs(30)).await;
    stop.cancel();
    task.await.unwrap().unwrap();
    wait_for("disconnect", Duration::from_secs(10), || {
        let st = server.state.clone();
        let id = agent.device_id;
        async move { st.registry.connected_since(id).is_none() }
    })
    .await;
    let queued = admin
        .run(
            &server,
            agent.device_id,
            &[("action", "process.top"), ("limit", "10")],
        )
        .await;
    let cancelled = admin
        .run(&server, agent.device_id, &[("action", "net.ipconfig")])
        .await;
    admin
        .post(&server, &format!("/jobs/{cancelled}/cancel"), &[])
        .await;
    // An unknown outcome, as the sweeper would leave it.
    let unknown = admin
        .run(&server, agent.device_id, &[("action", "system.info")])
        .await;
    sqlx::query("UPDATE jobs SET state = 'dispatched', dispatch_count = 1, first_dispatched_at = now() WHERE id = $1")
        .bind(unknown)
        .execute(&server.state.db)
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET deliver_by = now() WHERE id = $1")
        .bind(unknown)
        .execute(&server.state.db)
        .await
        .unwrap();
    wait_state(&server, unknown, "outcome_unknown", Duration::from_secs(10)).await;
    let org_b = admin
        .create_org(&server, "Contoso Dental — Northside Clinic")
        .await;
    let _ = admin.enrollment_token(&server, org_b, "60", "5").await;

    let session_value = admin.cookie.split_once('=').unwrap().1.to_string();
    let pages: Vec<(String, &str)> = vec![
        ("/".into(), "overview"),
        ("/devices".into(), "devices"),
        (format!("/devices/{}", agent.device_id), "device"),
        ("/jobs".into(), "jobs"),
        (format!("/jobs/{ok}"), "job-succeeded"),
        (format!("/jobs/{info}"), "job-structured"),
        (format!("/jobs/{queued}"), "job-queued"),
        (format!("/jobs/{cancelled}"), "job-cancelled"),
        (format!("/jobs/{unknown}"), "job-unknown"),
        ("/organizations".into(), "organizations"),
        (format!("/organizations/{org}"), "organization"),
        ("/audit".into(), "audit"),
        ("/admin".into(), "admin"),
        ("/support".into(), "support"),
        (
            "/devices/00000000-0000-0000-0000-000000000000".into(),
            "not-found",
        ),
    ];

    let profile = tempfile::tempdir().unwrap();
    let mut child = tokio::process::Command::new(find_chrome())
        .arg("--headless=new")
        .arg("--remote-debugging-port=0")
        .arg("--hide-scrollbars")
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg("about:blank")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut port = None;
    for _ in 0..100 {
        if let Ok(t) = std::fs::read_to_string(profile.path().join("DevToolsActivePort")) {
            port = t.lines().next().and_then(|l| l.trim().parse::<u16>().ok());
            if port.is_some() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let port = port.expect("DevTools port");
    let mut ws_url = None;
    for _ in 0..50 {
        ws_url = http_json(port, "/json/list")
            .await
            .as_array()
            .and_then(|a| a.iter().find(|t| t["type"] == "page").cloned())
            .and_then(|t| t["webSocketDebuggerUrl"].as_str().map(str::to_owned));
        if ws_url.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (ws, _) = tokio_tungstenite::connect_async(ws_url.unwrap())
        .await
        .unwrap();
    let mut cdp = Cdp {
        ws,
        next: 0,
        errors: Vec::new(),
    };
    cdp.call("Runtime.enable", json!({})).await;
    cdp.call("Log.enable", json!({})).await;
    cdp.call("Page.enable", json!({})).await;
    cdp.call("Network.enable", json!({})).await;

    let base = server.url();
    let mut failures = Vec::new();
    let mut shots = 0;

    let save = |cdp_errors: Vec<String>,
                name: String,
                overflow: Value,
                png: Value|
     -> (bool, Vec<String>) {
        let mut problems = Vec::new();
        let mut saved = false;
        if let Some(b64) = png["data"].as_str() {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap();
            std::fs::write(out_dir.join(format!("{name}.png")), &bytes).unwrap();
            if publish && name.ends_with("-desktop-light") || publish && name == "device-phone-dark"
            {
                std::fs::create_dir_all(&docs_img).unwrap();
                std::fs::write(docs_img.join(format!("{name}.png")), &bytes).unwrap();
            }
            saved = true;
        }
        if overflow.as_bool() != Some(false) {
            problems.push(format!("{name}: horizontal overflow ({overflow})"));
        }
        for e in cdp_errors {
            problems.push(format!("{name}: browser error {e}"));
        }
        (saved, problems)
    };

    // The sign-in page, signed out.
    for theme in THEMES {
        for (w, h, size) in SIZES {
            cdp.call(
                "Emulation.setDeviceMetricsOverride",
                json!({"width": w, "height": h, "deviceScaleFactor": 1, "mobile": w < 600}),
            )
            .await;
            cdp.call(
                "Emulation.setEmulatedMedia",
                json!({"features": [{"name": "prefers-color-scheme", "value": theme}]}),
            )
            .await;
            cdp.call("Page.navigate", json!({"url": format!("{base}/login")}))
                .await;
            tokio::time::sleep(Duration::from_millis(400)).await;
            let overflow = cdp
                .eval("document.documentElement.scrollWidth > window.innerWidth")
                .await;
            let png = cdp
                .call("Page.captureScreenshot", json!({"format": "png"}))
                .await;
            let errs = std::mem::take(&mut cdp.errors);
            let (saved, problems) = save(errs, format!("login-{size}-{theme}"), overflow, png);
            shots += usize::from(saved);
            failures.extend(problems);
        }
    }

    cdp.call("Network.setCookie", json!({"name": "flyw8t_session", "value": session_value, "url": base, "httpOnly": true, "sameSite": "Strict"})).await;
    for (path, name) in &pages {
        for theme in THEMES {
            for (w, h, size) in SIZES {
                cdp.call(
                    "Emulation.setDeviceMetricsOverride",
                    json!({"width": w, "height": h, "deviceScaleFactor": 1, "mobile": w < 600}),
                )
                .await;
                cdp.call(
                    "Emulation.setEmulatedMedia",
                    json!({"features": [{"name": "prefers-color-scheme", "value": theme}]}),
                )
                .await;
                cdp.call("Page.navigate", json!({"url": format!("{base}{path}")}))
                    .await;
                tokio::time::sleep(Duration::from_millis(400)).await;
                let signed_in = cdp.eval("!!document.querySelector('header.top')").await;
                if signed_in != Value::Bool(true) {
                    failures.push(format!("{name}: rendered without the signed-in frame"));
                }
                let overflow = cdp
                    .eval("document.documentElement.scrollWidth > window.innerWidth")
                    .await;
                let png = cdp
                    .call(
                        "Page.captureScreenshot",
                        json!({"format": "png", "captureBeyondViewport": true}),
                    )
                    .await;
                let mut errs = std::mem::take(&mut cdp.errors);
                // The deliberate 404 page logs the failed load; that is the page working.
                if *name == "not-found" {
                    errs.retain(|e| !e.contains("404"));
                }
                let (saved, problems) = save(errs, format!("{name}-{size}-{theme}"), overflow, png);
                shots += usize::from(saved);
                failures.extend(problems);
            }
        }
    }

    let _ = child.kill().await;
    server.stop().await;
    println!("captured {shots} screenshots in {}", out_dir.display());
    assert!(
        failures.is_empty(),
        "UI validation failures:\n{}",
        failures.join("\n")
    );
    assert_eq!(shots, (pages.len() + 1) * SIZES.len() * THEMES.len());
}
