//! Exercise the shipped stdio executable across an authenticated, attended browser session.
use super::{common::*, Cdp};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{ffi::OsString, path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdout, Command},
};
use uuid::Uuid;

struct Mcp {
    child: Child,
    replies: Lines<BufReader<ChildStdout>>,
    id: u32,
}

impl Mcp {
    async fn start(binary: OsString, server: &TestServer) -> Self {
        let admin = server.admin_sudo().await;
        let reveal = admin
            .post(
                server,
                "/admin/tokens",
                &[
                    ("name", "Support assistant"),
                    ("scope", "support:screenshot"),
                    ("ttl_days", "1"),
                ],
            )
            .await;
        assert_eq!(
            reveal.status.as_u16(),
            200,
            "could not issue fixture credential"
        );
        let token =
            extract(&reveal.body, r"(fw8_[A-Za-z0-9_-]{43})").expect("new fixture credential");
        let mut child = Command::new(binary)
            .env("FLYW8T_SERVER_URL", server.url())
            .env("FLYW8T_MCP_TOKEN", token)
            .env_remove("FLYW8T_MCP_TOKEN_FILE")
            .env_remove("FLYW8T_MCP_CA_FILE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("start flyw8t-mcp");
        let replies = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut client = Self {
            child,
            replies,
            id: 0,
        };
        let init = client
            .call(
                "initialize",
                json!({
                    "protocolVersion":"2025-11-25", "capabilities":{},
                    "clientInfo":{"name":"flyw8t-browser-test","version":"1"}
                }),
            )
            .await;
        assert_eq!(init["serverInfo"]["name"], "flyw8t-mcp");
        client
            .send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        let list = client.call("tools/list", json!({})).await;
        assert!(list["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "support_screenshot"));
        client
    }

    async fn send(&mut self, message: Value) {
        let stdin = self.child.stdin.as_mut().unwrap();
        stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .unwrap();
        stdin.flush().await.unwrap();
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        self.send(json!({"jsonrpc":"2.0","id":self.id,"method":method,"params":params}))
            .await;
        let line = tokio::time::timeout(Duration::from_secs(35), self.replies.next_line())
            .await
            .expect("MCP reply timeout")
            .unwrap()
            .expect("adapter exited");
        let reply: Value = serde_json::from_str(&line).expect("JSON-RPC response");
        assert_eq!(reply["id"], self.id);
        assert!(
            reply["result"].is_object(),
            "missing tool result for {method}"
        );
        reply["result"].clone()
    }

    async fn shot(&mut self, session_id: &str, request_id: Uuid) -> Value {
        self.call(
            "tools/call",
            json!({"name":"support_screenshot","arguments":{
                "session_id":session_id,"request_id":request_id,
                "crop":{"x":0.75,"y":0.75,"width":0.25,"height":0.25}
            }}),
        )
        .await
    }
}

fn assert_no_image(result: &Value) {
    assert_eq!(result["isError"], true);
    assert!(result["content"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["type"] != "image"));
}

pub(super) async fn exercise(
    server: &TestServer,
    cdp: &mut Cdp,
    tech: &str,
    part: &str,
    session_id: &str,
    out: &Path,
    binary: OsString,
) {
    let mut mcp = Mcp::start(binary, server).await;
    let request = Uuid::new_v4();
    assert_no_image(&mcp.shot(session_id, request).await);

    cdp.call(
        Some(part),
        "Emulation.setDeviceMetricsOverride",
        json!({"width":390,"height":844,"deviceScaleFactor":1,"mobile":true}),
    )
    .await;
    cdp.wait_for(part, "named assistant consent",
        "!!document.getElementById('screenshot-allow')?.getClientRects().length && document.getElementById('screenshot-recipient')?.textContent.includes('Support assistant')", Duration::from_secs(10)).await;
    assert_eq!(
        cdp.eval(part, "document.documentElement.scrollWidth <= innerWidth")
            .await,
        true
    );
    cdp.eval(
        part,
        "document.getElementById('screenshot-panel').scrollIntoView({block:'center'}); true",
    )
    .await;
    cdp.screenshot(part, out.join("mcp-participant-consent.png"))
        .await;
    cdp.click(part, "#screenshot-allow").await;
    cdp.wait_for(
        part,
        "active revocation control",
        "!!document.getElementById('screenshot-revoke')?.getClientRects().length",
        Duration::from_secs(10),
    )
    .await;

    cdp.call(Some(tech), "Page.bringToFront", json!({})).await;
    cdp.eval(
        tech,
        "document.getElementById('remote').scrollIntoView({block:'center'}); true",
    )
    .await;
    let result = mcp.shot(session_id, request).await;
    let content = result["content"].as_array().expect("tool content");
    let images: Vec<_> = content.iter().filter(|c| c["type"] == "image").collect();
    if images.len() != 1 {
        let reason = content
            .iter()
            .find_map(|c| c["text"].as_str())
            .unwrap_or("no explanation");
        panic!(
            "expected a single screenshot, got {}: {}",
            images.len(),
            reason.chars().take(240).collect::<String>()
        );
    }
    assert_eq!(images[0]["mimeType"], "image/png");
    let encoded = images[0]["data"].as_str().unwrap();
    let png = STANDARD.decode(encoded).unwrap();
    assert!(png.len() <= 512 * 1024);
    std::fs::write(out.join("mcp-returned-crop.png"), &png).unwrap();

    // Decode the actual MCP result. The selected corner contains a rust-red rectangle over blue.
    // Both colors survive WebRTC compression; wrong crops and capturing browser chrome fail here.
    let probe = format!(
        r#"(async () => {{
        const bytes = Uint8Array.from(atob('{encoded}'), c => c.charCodeAt(0));
        const bitmap = await createImageBitmap(new Blob([bytes], {{type:'image/png'}}));
        const ctx = new OffscreenCanvas(bitmap.width, bitmap.height).getContext('2d');
        ctx.drawImage(bitmap, 0, 0);
        const pixel = (fraction) => [...ctx.getImageData(Math.floor(bitmap.width * fraction), Math.floor(bitmap.height / 2), 1, 1).data];
        return [bitmap.width, bitmap.height, pixel(0.25), pixel(0.75)];
    }})()"#
    );
    let pixel = cdp.eval(tech, &probe).await;
    assert_eq!(pixel[0], 160);
    assert_eq!(pixel[1], 90);
    assert!(
        pixel[2][0].as_u64().unwrap() > 160 && pixel[2][2].as_u64().unwrap() < 125,
        "missing red landmark"
    );
    assert!(
        pixel[3][0].as_u64().unwrap() < 70 && pixel[3][2].as_u64().unwrap() > 50,
        "missing blue background"
    );

    assert_no_image(&mcp.shot(session_id, request).await);
    cdp.click(part, "#screenshot-revoke").await;
    cdp.wait_for(
        part,
        "screenshot access turned off",
        "!document.getElementById('screenshot-revoke')?.getClientRects().length",
        Duration::from_secs(10),
    )
    .await;
    assert_no_image(&mcp.shot(session_id, Uuid::new_v4()).await);
    drop(mcp.child.stdin.take());
    let exit = tokio::time::timeout(Duration::from_secs(5), mcp.child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(exit.success());
}
