# Windows H.264 feasibility probe

The Rust program generates 32 NV12 frames, encodes them with Media Foundation, reopens the temporary MP4, checks the negotiated H.264 subtype and decodes every frame. It checks presentation times and the four alternating luma bands. The optional browser test seeks into each band and samples its decoded pixel in the installed Microsoft Edge. Neither test needs an enrolled machine or desktop capture.

From this directory on Windows with Media Foundation installed:

```powershell
cargo run --locked
npm ci --ignore-scripts
node browser.mjs ./target/x86_64-pc-windows-msvc/debug/flyw8t-windows-media-probe.exe
```

With a custom Cargo target directory, pass the corresponding executable path to the browser check. The fixture uses a private temporary directory and removes the generated clip when it exits. `--emit-mp4` writes the validated clip to standard output for the browser process.

This establishes OS encode and browser decode compatibility for a 320×180 synthetic clip. The sink writer selects the encoder. This check does not identify a hardware MFT, measure live performance, transport media over WebRTC or exercise remote input. It changes no release binaries.

The Rust dependency lock is separate from the production workspace. The browser tooling uses Playwright Core under Apache-2.0 and the installed Edge. No browser is downloaded.
