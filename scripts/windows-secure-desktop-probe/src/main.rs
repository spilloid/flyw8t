//! Observe a DXGI frame on the active Windows sign-in desktop without reading its pixels.

#[cfg(windows)]
mod windows_probe;

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (width, height) = windows_probe::observe_frame()?;
    println!("The active Windows secure desktop returned a {width}x{height} DXGI frame.");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This probe requires Windows.");
    std::process::exit(1);
}
