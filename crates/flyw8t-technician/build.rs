fn main() {
    println!("cargo:rerun-if-changed=src/rdp_host.cpp");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let system32 = std::path::PathBuf::from(
        std::env::var_os("SystemRoot").expect("building the RDP host requires Windows"),
    )
    .join("System32");
    cc::Build::new()
        .cpp(true)
        .file("src/rdp_host.cpp")
        .include(system32)
        .flag("/std:c++17")
        .flag("/EHsc")
        .compile("flyw8t_rdp_host");
    for library in ["ole32", "oleaut32", "user32", "uuid"] {
        println!("cargo:rustc-link-lib={library}");
    }
}
