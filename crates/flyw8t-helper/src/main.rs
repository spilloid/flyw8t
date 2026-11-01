//! `flyw8t-helper.exe`: run by the person being helped, from the support page's download.
//! Installs nothing and stores nothing; it exits when the session ends (ADR-0012).

use flyw8t_helper::{launch_from_file_name, Consent, ConsentRequest, Outcome};
use std::sync::Arc;

fn main() {
    let name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default();
    let launch = match launch_from_file_name(&name) {
        Ok(l) => l,
        Err(e) => {
            notify(&format!(
                "This copy of the flyw8t helper cannot be used: {e}.\n\nGo back to the support page and download the helper again."
            ));
            return;
        }
    };
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return notify(&format!("The flyw8t helper could not start: {e}")),
    };
    let message = match rt.block_on(flyw8t_helper::run(&launch, Arc::new(Dialog))) {
        Ok(Outcome::Declined) => "You declined. Nothing was shared.".to_string(),
        Ok(Outcome::Ended { label, .. }) => format!("The support session has ended: {label}."),
        Ok(Outcome::Lost) => {
            "The connection to the support server was lost, so the helper stopped.".to_string()
        }
        Err(e) => format!("The flyw8t helper could not connect: {e:#}."),
    };
    notify(&message);
}

/// The consent question, in the system's own dialog.
struct Dialog;

impl Consent for Dialog {
    fn ask(&self, r: &ConsentRequest) -> bool {
        let what = if r.control {
            "see your screen and use your mouse and keyboard"
        } else {
            "see your screen"
        };
        let org = if r.organization.is_empty() {
            String::new()
        } else {
            format!(" for {}", r.organization)
        };
        let text = format!(
            "{name} ({email}){org} wants to {what}.\n\n\
             This request comes from the server: {host}\n\
             Only allow it if you were expecting help from that server.\n\n\
             You can stop at any time. Nothing is installed.\n\n\
             Allow?",
            name = r.technician_name,
            email = r.technician_email,
            host = r.server_host,
        );
        ask_yes_no("flyw8t: allow remote help?", &text)
    }
}

#[cfg(windows)]
fn ask_yes_no(title: &str, text: &str) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONQUESTION, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO,
    };
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (t, b) = (wide(title), wide(text));
    // No is the default button: pressing Enter by accident must not grant anything.
    let flags = MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_TOPMOST | MB_SETFOREGROUND;
    unsafe { MessageBoxW(std::ptr::null_mut(), b.as_ptr(), t.as_ptr(), flags) == IDYES }
}

#[cfg(not(windows))]
fn ask_yes_no(title: &str, text: &str) -> bool {
    use std::io::{BufRead, Write};
    print!("{title}\n\n{text} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    line.trim().eq_ignore_ascii_case("y")
}

#[cfg(windows)]
fn notify(text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (t, b) = (wide("flyw8t helper"), wide(text));
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            b.as_ptr(),
            t.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

#[cfg(not(windows))]
fn notify(text: &str) {
    println!("{text}");
}
