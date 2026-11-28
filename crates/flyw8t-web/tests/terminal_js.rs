//! Runs the hardware-independent browser terminal checks under Node.js.

#[test]
#[ignore = "needs Node.js 18 or later on PATH"]
fn terminal_js() {
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/terminal.test.mjs");
    let output = std::process::Command::new("node")
        .args(["--test", file])
        .output()
        .expect("Node.js on PATH");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
