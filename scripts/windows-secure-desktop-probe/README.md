# Windows sign-in frame probe

This development probe checks whether the Windows sign-in desktop provides a DXGI frame to a process already running on that desktop. Build it from the repository root with `cargo build --locked --manifest-path scripts/windows-secure-desktop-probe/Cargo.toml --target x86_64-pc-windows-msvc`.

From an ordinary Windows terminal, run `cargo test --locked --manifest-path scripts/windows-secure-desktop-probe/Cargo.toml --target x86_64-pc-windows-msvc` to check desktop refusal.

Use a disposable Windows pilot and the authorized agent-supervised test process for the physical trial. Run once at the actual Windows sign-in screen, with no user signed in. Expect one line with the dimensions of an acquired frame. An ordinary desktop, Session 0, and a desktop that no longer receives input are refusal cases. The program checks the active desktop before and after frame acquisition and releases the frame without reading its pixels. Make a separate observation at sign-in to establish that the Winlogon desktop was showing the sign-in screen.

The probe only reports dimensions and errors. It has no network or input path. The Windows beta also requires a browser stream, scoped input, revocation and a safe transition to the signed-in desktop. [Microsoft DXGI desktop duplication documentation](https://learn.microsoft.com/en-us/windows/desktop/api/DXGI1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput) · [Windows stable beta gate](../../docs/roadmap.md#windows-stable-beta-gate)
