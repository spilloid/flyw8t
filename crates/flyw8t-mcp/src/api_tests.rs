use super::*;
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    thread::JoinHandle,
};

const DEVICE: &str = "2ceeefa0-25cf-433d-a18f-492de7d29396";
const REQUEST: &str = "7305c303-ebf3-4dd4-94f9-8f9a1b0f3bb8";
const JOB: &str = "a7ca3516-d4e0-4fe8-ac08-a56b518544e4";

fn fixture(
    enabled: bool,
    status: &'static str,
    body: Value,
    check: impl FnOnce(String, String) + Send + 'static,
) -> (crate::Server, JoinHandle<()>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let api = Api {
        client: Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(4))
            .build()
            .unwrap(),
        origin: Url::parse(&format!("http://{address}")).unwrap(),
        bearer: HeaderValue::from_static("Bearer fixture"),
        device_diagnostics: enabled,
    };
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            headers.push_str(&line);
        }
        assert!(headers.contains("authorization: Bearer fixture\r\n"));
        let length = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .map_or(0, |len| len.parse().unwrap());
        let mut request = vec![0; length];
        reader.read_exact(&mut request).unwrap();
        check(headers, String::from_utf8(request).unwrap());
        let body = body.to_string();
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    (
        crate::Server {
            api: Ok(api),
            version: Some("2025-11-25"),
        },
        thread,
    )
}

async fn call(server: &mut crate::Server, name: &str, arguments: Value) -> Value {
    server
        .handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}}))
        .await
        .unwrap()
}

#[test]
fn cli_accepts_connection_settings_and_keeps_raw_tokens_off_argv() {
    let settings = Settings::try_parse_from([
        "flyw8t-mcp",
        "--server",
        "https://example.test",
        "--token-file",
        "operator.token",
        "--ca-cert",
        "lab.pem",
    ])
    .unwrap();
    assert_eq!(settings.server.as_deref(), Some("https://example.test"));
    assert_eq!(
        settings.token_file.as_deref(),
        Some(Path::new("operator.token"))
    );
    assert_eq!(settings.ca_cert.as_deref(), Some(Path::new("lab.pem")));
    assert!(Settings::try_parse_from(["flyw8t-mcp", "--token", "test"]).is_err());
}

#[test]
fn rejects_remote_cleartext_userinfo_and_url_overrides() {
    for url in [
        "https://name:secret@example.test",
        "http://localhost.example.test",
        "http://10.0.0.2",
        "https://example.test/device",
        "https://example.test/?token=secret",
        "file:///local",
    ] {
        assert!(parse_origin(url).is_err(), "{url}");
    }
    for url in [
        "http://127.0.0.1:4930",
        "http://[::1]:8000",
        "https://rmm.example.test",
    ] {
        assert!(parse_origin(url).is_ok(), "{url}");
    }
}

#[test]
fn refusals_do_not_echo_untrusted_server_text() {
    assert!(!refusal(StatusCode::CONFLICT, "secret here").contains("secret here"));
    assert!(refusal(StatusCode::CONFLICT, "consent_required").contains("participant"));
}

#[test]
fn servers_with_only_the_screenshot_capability_still_work() {
    let capabilities: Capabilities =
        serde_json::from_value(json!({"support_screenshot":true})).unwrap();
    assert!(capabilities.support_screenshot);
    assert!(!capabilities.support_session_status);
    assert!(!capabilities.background_terminal_status);
}

#[tokio::test]
async fn advertises_diagnostics_only_after_opt_in() {
    for (enabled, status, body, expected) in [
        (
            false,
            "200 OK",
            json!({"support_screenshot":true}),
            vec!["support_screenshot"],
        ),
        (
            true,
            "404 Not Found",
            json!({}),
            vec![
                "device_list",
                "device_system_info",
                "device_system_info_status",
                "device_terminal_handoff",
            ],
        ),
        (
            true,
            "200 OK",
            json!({"support_screenshot":false,"background_terminal_status":true}),
            vec![
                "device_list",
                "device_system_info",
                "device_system_info_status",
                "device_terminal_handoff",
                "device_terminal_status",
            ],
        ),
    ] {
        let (mut server, thread) = fixture(enabled, status, body, |headers, _| {
            assert!(headers.starts_with("GET /api/v1/mcp/capabilities "));
        });
        let response = server
            .handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
            .await
            .unwrap();
        thread.join().unwrap();
        let names: Vec<_> = response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, expected);
        if !enabled {
            assert_eq!(
                call(&mut server, "device_list", json!({})).await["error"]["code"],
                -32602
            );
            assert_eq!(
                call(
                    &mut server,
                    "device_terminal_handoff",
                    json!({"device_id": DEVICE}),
                )
                .await["error"]["code"],
                -32602
            );
        }
    }
}

#[tokio::test]
async fn terminal_status_only_reads_matching_lifecycle_metadata() {
    for returned_device in [DEVICE, JOB] {
        let (mut server, thread) = fixture(
            true,
            "200 OK",
            json!({
                "device_id": returned_device, "session_id": REQUEST, "state": "ended",
                "account": "local_system", "reason": "closed", "observed_at": "2026-11-28T04:25:00Z",
                "output": "fixture-terminal-content"
            }),
            |headers, body| {
                assert!(headers.starts_with(&format!(
                    "GET /api/v1/devices/{DEVICE}/background-terminal/sessions/{REQUEST}/status "
                )));
                assert!(body.is_empty());
            },
        );
        let invalid = call(
            &mut server,
            "device_terminal_status",
            json!({"device_id":DEVICE,"session_id":REQUEST,"input":"forbidden"}),
        )
        .await;
        assert_eq!(invalid["result"]["isError"], true);
        let response = call(
            &mut server,
            "device_terminal_status",
            json!({"device_id":DEVICE,"session_id":REQUEST}),
        )
        .await;
        thread.join().unwrap();
        assert!(!response.to_string().contains("fixture-terminal-content"));
        if returned_device == DEVICE {
            assert_eq!(response["result"]["structuredContent"]["state"], "ended");
        } else {
            assert_eq!(response["result"]["isError"], true);
        }
    }
}

#[tokio::test]
async fn terminal_handoff_links_only_to_the_checked_device_on_the_configured_origin() {
    let (mut server, thread) = fixture(
        true,
        "200 OK",
        json!({"id": DEVICE, "retired": false, "console_url": "https://elsewhere.test"}),
        |headers, body| {
            assert!(headers.starts_with(&format!("GET /api/v1/devices/{DEVICE} ")));
            assert!(body.is_empty());
        },
    );
    let mut expected = server.api.as_ref().unwrap().origin.clone();
    expected.set_path(&format!("/devices/{DEVICE}"));
    expected.set_fragment(Some("device-connection-options"));

    let invalid = call(
        &mut server,
        "device_terminal_handoff",
        json!({"device_id": DEVICE, "command": "fixture-input"}),
    )
    .await;
    assert_eq!(invalid["result"]["isError"], true);
    let response = call(
        &mut server,
        "device_terminal_handoff",
        json!({"device_id": DEVICE}),
    )
    .await;
    thread.join().unwrap();
    assert_eq!(
        response["result"]["structuredContent"],
        json!({"device_id": DEVICE, "console_url": expected.as_str()})
    );
}

#[tokio::test]
async fn terminal_handoff_rejects_retired_inaccessible_and_mismatched_devices() {
    for (status, body) in [
        ("200 OK", json!({"id": DEVICE, "retired": true})),
        ("200 OK", json!({"id": JOB, "retired": false})),
        ("404 Not Found", json!({"error": "unknown device"})),
    ] {
        let (mut server, thread) = fixture(true, status, body, |headers, body| {
            assert!(headers.starts_with(&format!("GET /api/v1/devices/{DEVICE} ")));
            assert!(body.is_empty());
        });
        let response = call(
            &mut server,
            "device_terminal_handoff",
            json!({"device_id": DEVICE}),
        )
        .await;
        thread.join().unwrap();
        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"].get("structuredContent").is_none());
    }
}

#[tokio::test]
async fn device_list_uses_scoped_search_and_limits_delivered_rows() {
    let row = json!({
        "id":DEVICE, "hostname":"workstation", "organization":{"id":REQUEST,"name":"Fixture"},
        "site":"Lab", "connection":{"state":"connected","since":"2026-11-26T20:00:00Z"},
        "retired":false, "tags":["not exported"]
    });
    let (mut server, thread) = fixture(true, "200 OK", json!(vec![row; 41]), |headers, _| {
        assert!(headers.starts_with("GET /api/v1/devices?q=WIN%26EDGE "));
    });
    let response = call(&mut server, "device_list", json!({"query":"WIN&EDGE"})).await;
    thread.join().unwrap();
    let data = &response["result"]["structuredContent"];
    assert_eq!(data["truncated"], true);
    assert_eq!(data["devices"].as_array().unwrap().len(), 40);
    assert_eq!(data["devices"][0]["id"], DEVICE);
    assert_eq!(data["devices"][0]["organization"]["name"], "Fixture");
    assert!(data["devices"][0].get("tags").is_none());
}

#[tokio::test]
async fn queues_only_system_info_using_the_callers_idempotency_key() {
    let (mut server, thread) = fixture(
        true,
        "202 Accepted",
        json!({"job_id":JOB}),
        |headers, body| {
            assert!(headers.starts_with(&format!("POST /api/v1/devices/{DEVICE}/jobs ")));
            assert!(headers.contains(&format!("idempotency-key: {REQUEST}\r\n")));
            assert_eq!(
                serde_json::from_str::<Value>(&body).unwrap(),
                json!({"action":"system.info"})
            );
        },
    );
    let invalid = call(
        &mut server,
        "device_system_info",
        json!({"device_id":DEVICE, "request_id":REQUEST, "action":"other"}),
    )
    .await;
    assert_eq!(invalid["result"]["isError"], true);
    let accepted = call(
        &mut server,
        "device_system_info",
        json!({"device_id":DEVICE, "request_id":REQUEST}),
    )
    .await;
    thread.join().unwrap();
    assert_eq!(accepted["result"]["structuredContent"]["job_id"], JOB);
}

#[tokio::test]
async fn status_only_exposes_system_info_evidence() {
    for action in ["system.info", "other"] {
        let job = json!({
            "id":JOB, "device_id":DEVICE, "action":action, "state":"completed",
            "verification":"verified", "outcome":{"label":"Succeeded"},
            "deliver_by":"2026-11-26T20:00:00Z", "result":{"os":"Windows"},
            "stdout":{"data":"fixture-private","truncated":false}
        });
        let (mut server, thread) = fixture(true, "200 OK", job, |headers, _| {
            assert!(headers.starts_with(&format!("GET /api/v1/jobs/{JOB} ")));
        });
        let response = call(
            &mut server,
            "device_system_info_status",
            json!({"job_id":JOB}),
        )
        .await;
        thread.join().unwrap();
        assert!(!response.to_string().contains("fixture-private"));
        if action == "system.info" {
            assert_eq!(
                response["result"]["structuredContent"]["job"]["result"]["os"],
                "Windows"
            );
        } else {
            assert_eq!(response["result"]["isError"], true);
            assert!(!response.to_string().contains("Windows"));
        }
    }
}
