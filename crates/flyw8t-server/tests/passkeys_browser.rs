//! Passkeys in a real browser: Chrome's virtual authenticator (DevTools `WebAuthn` domain) answers the ceremonies that
//! `/static/passkey.js` starts, so the script, the page's options, the browser's own checks and the form posts are all
//! the real ones. Needs Google Chrome and PostgreSQL:
//! `cargo test -p flyw8t-server --test passkeys_browser -- --ignored`.
//!
//! WebAuthn binds a credential to the page's origin, so the console is served at `http://localhost:<port>` with the
//! same URL as its public URL (browsers refuse an IP address as the relying party).

mod common;

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

    async fn navigate(&mut self, session: &str, url: &str) {
        self.call(Some(session), "Page.navigate", json!({ "url": url }))
            .await;
    }

    async fn wait_for(&mut self, session: &str, what: &str, expr: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if self.eval(session, expr).await == Value::Bool(true) {
                return;
            }
            if tokio::time::Instant::now() > deadline {
                let state = self
                    .eval(
                        session,
                        "JSON.stringify({url: location.href, status: document.getElementById('webauthn-status')?.textContent, error: document.querySelector('.flash.bad')?.textContent, body: document.body?.innerText.slice(0, 400)})",
                    )
                    .await;
                panic!("timed out waiting for {what}: {state}");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Submit the ceremony form with a trusted click, as a person would.
    async fn submit(&mut self, session: &str) {
        self.call(
            Some(session),
            "Runtime.evaluate",
            json!({"expression": "document.querySelector('#webauthn button[type=submit]').click()", "userGesture": true}),
        )
        .await;
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
async fn a_browser_adds_a_passkey_and_confirms_sudo_mode_with_it() {
    // Choose the port first, so the public URL can name it.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let base = format!("http://localhost:{port}");
    let server = start(flyw8t_server::config::Config {
        bind: format!("127.0.0.1:{port}").parse().unwrap(),
        public_url: base.clone(),
        ..test_config(&fresh_database().await)
    })
    .await;

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
    let mut child = tokio::process::Command::new(chrome)
        .arg("--headless=new")
        .arg("--remote-debugging-port=0")
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg("about:blank")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut devtools = None;
    for _ in 0..100 {
        if let Ok(t) = std::fs::read_to_string(profile.path().join("DevToolsActivePort")) {
            devtools = t.lines().next().and_then(|l| l.trim().parse::<u16>().ok());
            if devtools.is_some() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let version = http_json(devtools.expect("DevTools port"), "/json/version").await;
    let (ws, _) =
        tokio_tungstenite::connect_async(version["webSocketDebuggerUrl"].as_str().unwrap())
            .await
            .unwrap();
    let mut cdp = Cdp { ws, next: 0 };

    let target = cdp
        .call(
            None,
            "Target.createTarget",
            json!({"url": format!("{base}/login")}),
        )
        .await["targetId"]
        .as_str()
        .unwrap()
        .to_string();
    let tab = cdp
        .call(
            None,
            "Target.attachToTarget",
            json!({"targetId": target, "flatten": true}),
        )
        .await["sessionId"]
        .as_str()
        .unwrap()
        .to_string();
    cdp.call(Some(&tab), "Runtime.enable", json!({})).await;
    cdp.call(Some(&tab), "Page.enable", json!({})).await;
    // A platform authenticator that verifies its user (as Windows Hello or Touch ID would) and is touched at once.
    cdp.call(Some(&tab), "WebAuthn.enable", json!({})).await;
    let authenticator = cdp
        .call(
            Some(&tab),
            "WebAuthn.addVirtualAuthenticator",
            json!({"options": {
                "protocol": "ctap2",
                "transport": "internal",
                "hasResidentKey": true,
                "hasUserVerification": true,
                "isUserVerified": true,
                "automaticPresenceSimulation": true,
            }}),
        )
        .await["authenticatorId"]
        .as_str()
        .unwrap()
        .to_string();

    cdp.wait_for(
        &tab,
        "sign-in form",
        "!!document.querySelector('input[name=password]')",
    )
    .await;
    cdp.eval(
        &tab,
        &format!(
            "document.querySelector('input[name=email]').value = '{ADMIN_EMAIL}'; \
             document.querySelector('input[name=password]').value = '{ADMIN_PASSWORD}'; \
             document.querySelector('form[action=\"/login\"]').submit(); true"
        ),
    )
    .await;
    cdp.wait_for(
        &tab,
        "the console",
        "location.pathname === '/' && !!document.querySelector('header.top')",
    )
    .await;

    // Add a first passkey: name and password, then the browser's ceremony.
    cdp.navigate(&tab, &format!("{base}/account/passkeys/new"))
        .await;
    cdp.wait_for(
        &tab,
        "the passkey form",
        "!!document.querySelector('#webauthn button:enabled')",
    )
    .await;
    cdp.eval(
        &tab,
        &format!(
            "document.querySelector('#webauthn input[name=name]').value = 'Virtual key'; \
             document.querySelector('#webauthn input[name=password]').value = '{ADMIN_PASSWORD}'; true"
        ),
    )
    .await;
    cdp.submit(&tab).await;
    cdp.wait_for(
        &tab,
        "the passkey to be added",
        "location.pathname === '/account' && location.search === '?m=passkey-added'",
    )
    .await;
    let stored: (String, i64) = sqlx::query_as("SELECT name, sign_count FROM webauthn_credentials")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(stored.0, "Virtual key");
    // Sudo mode: the browser signs the server's challenge and is sent on to where it was going.
    cdp.navigate(&tab, &format!("{base}/sudo?next=/admin"))
        .await;
    cdp.wait_for(
        &tab,
        "the sudo page",
        "!!document.querySelector('#webauthn button:enabled')",
    )
    .await;
    cdp.submit(&tab).await;
    cdp.wait_for(
        &tab,
        "sudo mode and the admin page",
        "location.pathname === '/admin'",
    )
    .await;
    let (in_sudo, used): (bool, bool) = sqlx::query_as(
        "SELECT bool_or(s.sudo_until > now()), bool_and(w.last_used_at IS NOT NULL)
           FROM sessions s, webauthn_credentials w",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert!(
        in_sudo && used,
        "sudo mode recorded and the key marked used"
    );

    // A ceremony the person does not complete (here, the key fails to verify them) says so and changes nothing.
    cdp.call(
        Some(&tab),
        "WebAuthn.setUserVerified",
        json!({ "authenticatorId": authenticator, "isUserVerified": false }),
    )
    .await;
    sqlx::query("UPDATE sessions SET sudo_until = NULL")
        .execute(&server.state.db)
        .await
        .unwrap();
    cdp.navigate(&tab, &format!("{base}/sudo?next=/admin"))
        .await;
    cdp.wait_for(
        &tab,
        "the sudo page",
        "!!document.querySelector('#webauthn button:enabled')",
    )
    .await;
    cdp.call(
        Some(&tab),
        "Runtime.evaluate",
        json!({"expression": "document.querySelector('#webauthn button[type=submit]').click()", "userGesture": true}),
    )
    .await;
    cdp.wait_for(
        &tab,
        "the ceremony to fail",
        "/Cancelled|did not work/.test(document.getElementById('webauthn-status').textContent)",
    )
    .await;
    let in_sudo: bool =
        sqlx::query_scalar("SELECT coalesce(bool_or(sudo_until > now()), false) FROM sessions")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert!(!in_sudo);

    // Sign out, then sign back in with the passkey alone: the browser offers the key it holds for this console.
    cdp.call(
        Some(&tab),
        "WebAuthn.setUserVerified",
        json!({ "authenticatorId": authenticator, "isUserVerified": true }),
    )
    .await;
    cdp.eval(
        &tab,
        "document.querySelector('form[action=\"/logout\"]').submit(); true",
    )
    .await;
    cdp.wait_for(
        &tab,
        "the sign-in page",
        "location.pathname === '/login' && !!document.querySelector('a[href=\"/login/passkey\"]')",
    )
    .await;
    cdp.eval(
        &tab,
        "document.querySelector('a[href=\"/login/passkey\"]').click(); true",
    )
    .await;
    cdp.wait_for(
        &tab,
        "the passkey sign-in page",
        "location.pathname === '/login/passkey' && !!document.querySelector('#webauthn button:enabled')",
    )
    .await;
    cdp.submit(&tab).await;
    cdp.wait_for(
        &tab,
        "the console, signed in with the passkey",
        "location.pathname === '/' && !!document.querySelector('header.top')",
    )
    .await;
    let method: String = sqlx::query_scalar(
        "SELECT detail->>'method' FROM audit_events WHERE action = 'user.login' AND outcome = 'success' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(method, "passkey");

    let _ = child.kill().await;
    server.stop().await;
}
