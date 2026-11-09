//! Link the agent's VC runtime in, so it never loads `VCRUNTIME140.dll` ("hybrid CRT": static VC runtime, system
//! UCRT). An administrator often runs the agent from a download folder other accounts can write to, and Windows
//! looks for that DLL next to the program first, so a planted copy would run elevated (dev-process row 36). The UCRT
//! is reached through `api-ms-win-crt-*` API sets, which Windows resolves itself and never from the program folder.
//! The program's other imports are resolved from System32 only (`/DEPENDENTLOADFLAG`).

fn main() {
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if msvc {
        for arg in [
            "/NODEFAULTLIB:vcruntime.lib",
            "/DEFAULTLIB:libvcruntime.lib",
            // Resolve every other import (pdh, iphlpapi, powrprof, psapi, bcrypt, ... which are not KnownDLLs)
            // from System32 only, never the program's folder: LOAD_LIBRARY_SEARCH_SYSTEM32.
            "/DEPENDENTLOADFLAG:0x800",
        ] {
            println!("cargo:rustc-link-arg-bins={arg}");
        }
    }
}
