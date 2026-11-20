#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod assist;
#[cfg(windows)]
#[path = "../../flyw8t-protocol/src/desktop_link.rs"]
mod desktop_link;
#[cfg(windows)]
mod launch;
#[cfg(windows)]
mod rdp;
#[cfg(windows)]
mod registration;
#[cfg(any(windows, test))]
mod sessions;
#[cfg(any(windows, test))]
mod target;
#[cfg(windows)]
mod ui;

#[cfg(windows)]
fn main() {
    use launch::Intent;
    use std::ffi::OsString;
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [] => ui::run(None, Intent::Assist, false),
        [flag] if flag == "--register-protocol" => registration::configure(true),
        [flag] if flag == "--unregister-protocol" => registration::configure(false),
        [flag, rest @ ..] if flag == "--open-uri" => launch::parse_link(rest)
            .and_then(|(intent, host)| ui::run(host, intent, false)),
        [flag, host] if flag == "--assist" || flag == "--share" || flag == "--console" => {
            let mode = if flag == "--console" { assist::Mode::Console }
                else if flag == "--share" { assist::Mode::Share }
                else { assist::Mode::Attend };
            target::Target::parse(&host.to_string_lossy()).and_then(|t| assist::run(t, mode))
        }
        [host] if !host.to_string_lossy().starts_with('-') => {
            ui::run(Some(host.to_string_lossy().into_owned()), Intent::Assist, false)
        }
        [flag, host] if flag == "--connect" => match target::Target::parse(&host.to_string_lossy()) {
            Ok(_) => ui::run(Some(host.to_string_lossy().into_owned()), Intent::SignIn, true),
            Err(error) => Err(error),
        },
        _ => Err("Open flyw8t-technician with an optional host, or use --connect HOST[:PORT] to start a session.".into()),
    };
    if let Err(error) = result {
        if matches!(args.as_slice(), [flag] if flag == "--register-protocol" || flag == "--unregister-protocol")
        {
            eprintln!("{error}");
            std::process::exit(1);
        }
        let message: Vec<u16> = error.encode_utf16().chain([0]).collect();
        let title: Vec<u16> = "flyw8t technician".encode_utf16().chain([0]).collect();
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            )
        };
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The flyw8t technician RDP preview runs on Windows.");
    std::process::exit(1);
}
