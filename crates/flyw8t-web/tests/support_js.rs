//! Runs the `support.js` unit tests (`support.test.mjs`) under Node.js.

#[test]
#[ignore = "needs Node.js 18 or later on PATH"]
fn support_js() {
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support.test.mjs");
    let out = std::process::Command::new("node")
        .args(["--test", file])
        .output()
        .expect("Node.js on PATH");
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
