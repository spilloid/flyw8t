fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().len() != 1 {
        return Err("this fixture takes no window, display or other arguments".into());
    }
    flyw8t_windows_capture_probe::verify_window()?;
    println!("Windows Graphics Capture verified four black/white transitions on the fixture's own window.");
    Ok(())
}
