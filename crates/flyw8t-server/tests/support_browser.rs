//! Attended support in a real browser: two Chrome tabs (technician and participant) pair,
//! consent, and stream a third tab over WebRTC. Needs Google Chrome and PostgreSQL:
//! `cargo test -p flyw8t-server --test support_browser -- --ignored`.
//!
//! Chrome is told to auto-select the tab titled `flyw8t-share-target` in the screen picker;
//! the participant's Allow click is a trusted input event, as browsers require.

mod common;

use axum::http::StatusCode;
use base64::Engine;
use common::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

struct Cdp {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next: u64,
}

impl Cdp {
    async fn call(&mut self, session: Option<&str>, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        self.ws.send(Message::text(msg.to_string())).await.unwrap();
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(20), self.ws.next())
                .await
                .expect("CDP timeout")
                .unwrap()
                .unwrap();
            let v: Value = serde_json::from_str(frame.to_text().unwrap()).unwrap();
            if v["id"] == id {
                assert!(v.get("error").is_none(), "{method}: {}", v["error"]);
                return v["result"].clone();
            }
        }
    }

    async fn eval(&mut self, session: &str, expr: &str) -> Value {
        self.call(
            Some(session),
            "Runtime.evaluate",
            json!({"expression": expr, "returnByValue": true, "awaitPromise": true}),
        )
        .await["result"]["value"]
            .clone()
    }

    async fn open(&mut self, url: &str) -> String {
        let target = self
            .call(None, "Target.createTarget", json!({"url": url}))
            .await["targetId"]
            .as_str()
            .unwrap()
            .to_string();
        let session = self
            .call(
                None,
                "Target.attachToTarget",
                json!({"targetId": target, "flatten": true}),
            )
            .await["sessionId"]
            .as_str()
            .unwrap()
            .to_string();
        self.call(Some(&session), "Runtime.enable", json!({})).await;
        self.call(Some(&session), "Page.enable", json!({})).await;
        session
    }

    async fn wait_for(&mut self, session: &str, what: &str, expr: &str, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.eval(session, expr).await == Value::Bool(true) {
                return;
            }
            if tokio::time::Instant::now() > deadline {
                let state = self.eval(session, "JSON.stringify({url: location.href, state: document.getElementById('state')?.textContent, error: document.getElementById('error')?.textContent, data: document.getElementById('support')?.dataset.state, body: document.body?.innerText.slice(0, 300)})").await;
                panic!("timed out waiting for {what}: {state}");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Click an element as a person would: the page's own handler runs with transient user
    /// activation (CDP `userGesture`), which `getDisplayMedia` requires. Coordinate-based
    /// `Input.dispatchMouseEvent` did not reach the page in headless mode.
    async fn click(&mut self, session: &str, selector: &str) {
        self.call(Some(session), "Page.bringToFront", json!({}))
            .await;
        self.call(
            Some(session),
            "Runtime.evaluate",
            json!({"expression": format!("document.querySelector('{selector}').click()"), "userGesture": true}),
        )
        .await;
    }

    async fn screenshot(&mut self, session: &str, path: PathBuf) {
        let png = self
            .call(
                Some(session),
                "Page.captureScreenshot",
                json!({"format": "png"}),
            )
            .await;
        std::fs::write(
            path,
            base64::engine::general_purpose::STANDARD
                .decode(png["data"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "launches Google Chrome and needs PostgreSQL"]
async fn two_browsers_pair_consent_and_share_a_tab() {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/ui-capture");
    std::fs::create_dir_all(&out_dir).unwrap();
    let server = start_fresh().await;
    let admin = server.admin().await;
    let org = admin
        .create_org(&server, "Contoso Dental")
        .await
        .to_string();
    let r = admin
        .post(
            &server,
            "/support",
            &[("organization", org.as_str()), ("note", "Demo")],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let session_id = extract(&r.body, r#"href="/support/([0-9a-f-]{36})""#).unwrap();
    let link_token = extract(&r.body, r"/s/([A-Za-z0-9_-]{43})").unwrap();
    let base = server.url();

    let chrome = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
    .expect("Google Chrome");
    let profile = tempfile::tempdir().unwrap();
    let mut chrome = tokio::process::Command::new(chrome);
    // A Linux runner has no display, so no real tab or screen can be captured
    // ("NotReadableError: Could not start video source"). There, Chrome's fake capture
    // device stands in. Windows keeps capturing a real tab.
    if cfg!(target_os = "linux") {
        chrome.arg("--use-fake-device-for-media-stream");
    }
    let mut child = chrome
        .arg("--headless=new")
        .arg("--remote-debugging-port=0")
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg("--use-fake-ui-for-media-stream")
        .arg("--auto-select-tab-capture-source-by-title=flyw8t-share-target")
        .arg("--auto-select-desktop-capture-source=flyw8t-share-target")
        .arg("--auto-accept-this-tab-capture")
        .arg("--autoplay-policy=no-user-gesture-required")
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
    let version = http_json(port.expect("DevTools port"), "/json/version").await;
    let (ws, _) =
        tokio_tungstenite::connect_async(version["webSocketDebuggerUrl"].as_str().unwrap())
            .await
            .unwrap();
    let mut cdp = Cdp { ws, next: 0 };

    // The technician signs in through the real form: a browser's own form post must pass the
    // cross-origin check (a `no-referrer` policy once made Chrome send `Origin: null` and every
    // console post was refused; only a real browser shows that).
    let tech = cdp.open(&format!("{base}/login")).await;
    cdp.wait_for(
        &tech,
        "sign-in form",
        "!!document.querySelector('input[name=password]')",
        Duration::from_secs(15),
    )
    .await;
    cdp.eval(
        &tech,
        &format!(
            "document.querySelector('input[name=email]').value = '{ADMIN_EMAIL}'; \
             document.querySelector('input[name=password]').value = '{ADMIN_PASSWORD}'; \
             document.querySelector('form[action=\"/login\"]').submit(); true"
        ),
    )
    .await;
    cdp.wait_for(
        &tech,
        "the console after sign-in",
        "location.pathname === '/' && !!document.querySelector('header.top')",
        Duration::from_secs(15),
    )
    .await;
    cdp.call(
        Some(&tech),
        "Page.navigate",
        json!({"url": format!("{base}/support/{session_id}")}),
    )
    .await;
    cdp.wait_for(
        &tech,
        "technician page",
        "document.getElementById('support')?.dataset.state === 'waiting'",
        Duration::from_secs(15),
    )
    .await;

    // The tab that will be shared.
    let _target = cdp.open("data:text/html,<title>flyw8t-share-target</title><body style='margin:0;background:%23c0392b;color:white;font:bold 72px sans-serif'><p style='padding:40px'>Shared tab</p></body>").await;

    // The participant follows the link, sees who is asking, and allows.
    let part = cdp.open(&format!("{base}/s/{link_token}")).await;
    // Opening the link spends nothing; the person continues on purpose.
    cdp.wait_for(
        &part,
        "link page",
        "!!document.querySelector('form[action^=\"/s/\"] button')",
        Duration::from_secs(15),
    )
    .await;
    cdp.click(&part, "form[action^=\"/s/\"] button").await;
    cdp.wait_for(
        &part,
        "consent screen",
        "!document.getElementById('decide').hidden",
        Duration::from_secs(15),
    )
    .await;
    let consent_text = cdp.eval(&part, "document.body.innerText").await;
    assert!(consent_text
        .as_str()
        .unwrap()
        .contains("wants to see your screen"));
    cdp.screenshot(&part, out_dir.join("support-consent.png"))
        .await;
    cdp.click(&part, "#allow").await;

    // If media never connects, say what the participant's page shows (the picker is the
    // usual suspect on a new platform).
    for _ in 0..150 {
        if cdp
            .eval(
                &tech,
                "document.getElementById('support').dataset.state === 'connected'",
            )
            .await
            == json!(true)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let seen = cdp.eval(&part, "JSON.stringify({state: document.getElementById('state')?.textContent, error: document.getElementById('error')?.textContent, data: document.getElementById('support')?.dataset.state})").await;
    eprintln!("participant after Allow: {seen}");
    if seen
        .as_str()
        .is_some_and(|s| s.contains("Nothing was shared"))
    {
        let probe = cdp
            .call(Some(&part), "Runtime.evaluate", json!({"expression": "navigator.mediaDevices.getDisplayMedia({video: true}).then(s => 'ok ' + s.getTracks().length, e => e.name + ': ' + e.message)", "awaitPromise": true, "userGesture": true}))
            .await;
        eprintln!("direct getDisplayMedia: {}", probe["result"]["value"]);
    }
    cdp.wait_for(
        &tech,
        "media to connect",
        "document.getElementById('support').dataset.state === 'connected'",
        Duration::from_secs(30),
    )
    .await;
    // Everything that states the session's condition must agree with the live state.
    assert_eq!(
        cdp.eval(&tech, "document.getElementById('state-badge').textContent")
            .await,
        json!("Connected"),
        "the header badge must not keep showing the load-time state"
    );
    cdp.wait_for(
        &tech,
        "video frames",
        "document.getElementById('remote').videoWidth > 0",
        Duration::from_secs(30),
    )
    .await;
    cdp.wait_for(
        &part,
        "security code",
        "!document.getElementById('sas-box').hidden",
        Duration::from_secs(15),
    )
    .await;
    cdp.wait_for(
        &tech,
        "security code",
        "!document.getElementById('sas-box').hidden",
        Duration::from_secs(15),
    )
    .await;
    let sas_tech = cdp
        .eval(&tech, "document.getElementById('sas').textContent")
        .await;
    let sas_part = cdp
        .eval(&part, "document.getElementById('sas').textContent")
        .await;
    assert_eq!(
        sas_tech, sas_part,
        "both sides derive the same security code"
    );
    assert!(
        sas_tech.as_str().is_some_and(|s| s.len() == 7),
        "a six-digit code on both pages: {sas_tech}"
    );
    // The code came from the certificates in use, and the participant checked the technician's
    // commitment (a mismatch ends the session instead; tests/support.test.mjs).
    for tab in [&tech, &part] {
        assert_eq!(
            cdp.eval(tab, "document.getElementById('support').dataset.sas")
                .await,
            json!("shown")
        );
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    cdp.screenshot(&tech, out_dir.join("support-technician-connected.png"))
        .await;
    cdp.screenshot(&part, out_dir.join("support-participant-connected.png"))
        .await;

    // The participant ends it; the technician's view goes dark and says so.
    cdp.click(&part, "#end").await;
    cdp.wait_for(
        &tech,
        "session end",
        "document.getElementById('support').dataset.state === 'ended'",
        Duration::from_secs(15),
    )
    .await;
    let after = cdp
        .eval(&tech, "JSON.stringify([document.getElementById('state-badge').textContent, document.getElementById('peer').textContent, document.getElementById('sas-box').hidden, document.getElementById('viewer').hidden])")
        .await;
    assert_eq!(
        after,
        json!(r#"["Ended","",true,true]"#),
        "nothing on an ended session may still read as live"
    );
    let (state,): (String,) =
        sqlx::query_as("SELECT state FROM support_sessions WHERE id = $1::uuid")
            .bind(&session_id)
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(state, "closed");
    cdp.screenshot(&tech, out_dir.join("support-technician-ended.png"))
        .await;

    let _ = child.kill().await;
    server.stop().await;
}
