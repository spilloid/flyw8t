use super::*;

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
