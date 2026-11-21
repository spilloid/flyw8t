# Windows Graphics Capture feasibility probe

Run `cargo run --locked --manifest-path scripts/windows-capture-probe/Cargo.toml` from the repository root in an interactive Windows login. A small test window briefly alternates black and white. Close the window to end the test early.

The only capture target is the window this process creates. The probe accepts no handles or monitor choices. It creates a WGC item for that window, requests BGRA frames, copies one center texel into CPU-readable staging memory, and checks four expected transitions. A timeout, window closure or unsupported API fails the run. It writes no image and uses no networking or input injection.

This proves WGC capture on the interactive Windows configuration that ran it. Real multi-monitor geometry, console/RDP login selection, secure desktop, GPU-to-encoder transfer and session revocation require separate tests. [Microsoft CreateForWindow documentation](https://learn.microsoft.com/en-us/windows/win32/api/windows.graphics.capture.interop/nf-windows-graphics-capture-interop-igraphicscaptureiteminterop-createforwindow)
