use super::*;

#[test]
fn skips_oversize_lines_and_recovers_the_following_request() {
    let mut input = vec![b' '; MAX_LINE + 100];
    input.extend_from_slice(b"\n{}\n");
    let mut cursor = io::BufReader::with_capacity(31, input.as_slice());
    assert!(matches!(next_line(&mut cursor).unwrap(), Line::TooLong));
    assert!(matches!(next_line(&mut cursor).unwrap(),Line::Bytes(b) if b==b"{}\n"));
    assert!(matches!(next_line(&mut cursor).unwrap(), Line::End));
}

#[tokio::test]
async fn initializes_and_withholds_tools_on_missing_config() {
    let mut server = Server {
        api: Err(anyhow::anyhow!("missing profile")),
        version: None,
    };
    let list = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
    assert!(server.handle(list.clone()).await.unwrap()["error"].is_object());
    let init = json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25"}});
    assert_eq!(
        server.handle(init).await.unwrap()["result"]["protocolVersion"],
        "2025-11-25"
    );
    assert!(server
        .handle(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .await
        .is_none());
    assert_eq!(server.handle(list).await.unwrap()["error"]["code"], -32000);
    let invalid = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"support_screenshot","arguments":{"session_id":"bogus","request_id":"x"}}});
    assert_eq!(
        server.handle(invalid).await.unwrap()["error"]["code"],
        -32602
    );
    let nil_status = json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
        "name":"support_session_status","arguments":{"session_id":Uuid::nil()}
    }});
    assert_eq!(
        server.handle(nil_status).await.unwrap()["error"]["code"],
        -32602
    );
}
