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
    let message = match rt.block_on(flyw8t_helper::run(&launch, Arc::new(Dialog::default()))) {
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
#[derive(Default)]
struct Dialog {
    #[cfg(windows)]
    open: windows::Open,
}

impl Consent for Dialog {
    fn ask(&self, r: &ConsentRequest) -> bool {
        let (title, text) = r.dialog();
        #[cfg(windows)]
        return self.open.ask_yes_no(&title, &text);
        #[cfg(not(windows))]
        return ask_yes_no(&title, &text);
    }

    fn cancel(&self) {
        #[cfg(windows)]
        self.open.cancel();
    }
}

#[cfg(windows)]
mod windows {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use windows_sys::core::BOOL;
    use windows_sys::Win32::Foundation::{HWND, LPARAM};
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumThreadWindows, MessageBoxW, PostMessageW, IDNO, IDYES, MB_DEFBUTTON2, MB_ICONQUESTION,
        MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE, WM_COMMAND,
    };

    /// No is the default button: pressing Enter by accident must not grant anything.
    pub(crate) const QUESTION: MESSAGEBOX_STYLE =
        MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_TOPMOST | MB_SETFOREGROUND;

    /// Only an explicit Yes allows. No, a closed dialog, or a failure to show it does not.
    pub(crate) fn allowed(result: MESSAGEBOX_RESULT) -> bool {
        result == IDYES
    }

    pub(crate) fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// The open question, so it can be taken away when the session ends first.
    #[derive(Default)]
    pub(crate) struct Open {
        /// The thread showing the dialog, or 0.
        thread: Arc<AtomicU32>,
        cancelled: AtomicBool,
    }

    impl Open {
        pub(crate) fn ask_yes_no(&self, title: &str, text: &str) -> bool {
            self.thread
                .store(unsafe { GetCurrentThreadId() }, Ordering::SeqCst);
            // Cancelled before the dialog appeared: never show it.
            if self.cancelled.load(Ordering::SeqCst) {
                self.thread.store(0, Ordering::SeqCst);
                return false;
            }
            let (t, b) = (wide(title), wide(text));
            let result =
                unsafe { MessageBoxW(std::ptr::null_mut(), b.as_ptr(), t.as_ptr(), QUESTION) };
            self.thread.store(0, Ordering::SeqCst);
            allowed(result) && !self.cancelled.load(Ordering::SeqCst)
        }

        /// Answer the open dialog with No, as if the person had. Keeps trying until the asking
        /// thread is done, however long the dialog takes to appear. (`ask_yes_no` records its
        /// thread before checking `cancelled`, and this sets `cancelled` before reading the
        /// thread, so either the question is never shown or this sees it and waits it out.)
        pub(crate) fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
            let thread = self.thread.clone();
            std::thread::spawn(move || loop {
                let id = thread.load(Ordering::SeqCst);
                if id == 0 {
                    return;
                }
                unsafe { EnumThreadWindows(id, Some(answer_no), 0) };
                std::thread::sleep(Duration::from_millis(50));
            });
        }
    }

    unsafe extern "system" fn answer_no(window: HWND, _: LPARAM) -> BOOL {
        unsafe { PostMessageW(window, WM_COMMAND, IDNO as usize, 0) };
        1
    }
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
    let (t, b) = (windows::wide("flyw8t helper"), windows::wide(text));
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

#[cfg(all(test, windows))]
mod tests {
    use super::windows::*;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDCANCEL, IDNO, IDYES, MB_DEFBUTTON2, MB_DEFMASK, MB_TYPEMASK, MB_YESNO,
    };

    #[test]
    fn only_an_explicit_yes_allows_and_no_is_the_default() {
        assert!(allowed(IDYES));
        for other in [IDNO, IDCANCEL, 0] {
            assert!(!allowed(other), "{other}");
        }
        assert_eq!(QUESTION & MB_DEFMASK, MB_DEFBUTTON2, "Enter must mean No");
        assert_eq!(QUESTION & MB_TYPEMASK, MB_YESNO);
    }

    /// Shows a real dialog on this desktop for a moment, so it is not run by default.
    #[test]
    #[ignore = "shows a dialog on the desktop"]
    fn cancelling_takes_the_question_away() {
        let open = std::sync::Arc::new(Open::default());
        let asking = {
            let open = open.clone();
            std::thread::spawn(move || open.ask_yes_no("flyw8t test", "Closing by itself..."))
        };
        std::thread::sleep(Duration::from_millis(700));
        let started = Instant::now();
        open.cancel();
        assert!(!asking.join().unwrap(), "a cancelled question is No");
        assert!(started.elapsed() < Duration::from_secs(2));
        // Cancelled before it appears: it never appears.
        assert!(!open.ask_yes_no("flyw8t test", "should not be shown"));
    }
}
