//! Session selection runs in its own short-lived UI process. Windows RPC
//! discovery may block. Closing this window cancels the pending local request.
use crate::sessions::{self, ConsoleAccess, Session, ShadowMode, ShadowRequest};
use crate::target::Target;
use std::ptr::{null, null_mut};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const SELECT: usize = 201;
const VIEW: usize = 202;
const CONTROL: usize = 203;
const SHARE: usize = 204;
const OPEN: usize = 205;
const CLOSE: usize = 206;
const COMMAND: u32 = WM_APP + 2;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
unsafe fn label(h: HWND, s: &str) {
    SetWindowTextW(h, wide(s).as_ptr());
}
unsafe fn visible(h: HWND, show: bool) {
    ShowWindow(h, if show { SW_SHOW } else { SW_HIDE });
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND => {
            PostMessageW(hwnd, COMMAND, w, l);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}

enum Reply {
    Sessions(Vec<Session>, Option<ConsoleAccess>),
    Prepared(ShadowRequest),
}
type Work = Receiver<Result<Reply, String>>;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Mode {
    Attend,
    Share,
    Console,
}
fn worker(op: impl FnOnce() -> Result<Reply, String> + Send + 'static) -> Result<Work, String> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("session-lookup".into())
        .spawn(move || {
            let _ = tx.send(op());
        })
        .map_err(|e| format!("Could not start the Windows session query ({e})."))?;
    Ok(rx)
}

struct Picker {
    window: HWND,
    summary: HWND,
    list: HWND,
    view: HWND,
    control: HWND,
    share: HWND,
    url_label: HWND,
    url: HWND,
    open: HWND,
    status: HWND,
    target: Target,
    mode: Mode,
    access: Option<ConsoleAccess>,
    rows: Vec<Session>,
    pending: Option<(Work, Instant)>,
    preparing: bool,
}

impl Picker {
    unsafe fn new(window: HWND, target: Target, mode: Mode) -> Result<Self, String> {
        let dpi = GetDpiForWindow(window).max(96) as i32;
        let px = |v: i32| v * dpi / 96;
        let child =
            |class: &str, text: &str, style: u32, id: usize, x, y, w, h| -> Result<HWND, String> {
                let c = CreateWindowExW(
                    if class == "EDIT" { WS_EX_CLIENTEDGE } else { 0 },
                    wide(class).as_ptr(),
                    wide(text).as_ptr(),
                    WS_CHILD | WS_VISIBLE | style,
                    px(x),
                    px(y),
                    px(w),
                    px(h),
                    window,
                    id as HMENU,
                    GetModuleHandleW(null()),
                    null(),
                );
                if c.is_null() {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                SendMessageW(c, WM_SETFONT, GetStockObject(DEFAULT_GUI_FONT) as usize, 0);
                Ok(c)
            };
        let summary = child(
            "STATIC",
            if mode == Mode::Console {
                "The computer’s Windows policy determines whether you can view or control its physical console."
            } else {
                "Choose the desktop you want to see."
            },
            0,
            0,
            18,
            18,
            590,
            38,
        )?;
        let list = child(
            "COMBOBOX",
            "",
            WS_TABSTOP | CBS_DROPDOWNLIST as u32 | WS_VSCROLL,
            SELECT,
            18,
            60,
            575,
            195,
        )?;
        let view = child(
            "BUTTON",
            if mode == Mode::Console {
                "View console"
            } else {
                "View session"
            },
            WS_TABSTOP,
            VIEW,
            18,
            103,
            126,
            32,
        )?;
        let control = child(
            "BUTTON",
            if mode == Mode::Console {
                "Control console"
            } else {
                "Request control"
            },
            WS_TABSTOP,
            CONTROL,
            152,
            103,
            140,
            32,
        )?;
        let share = child(
            "BUTTON",
            "Share a screen…",
            WS_TABSTOP,
            SHARE,
            300,
            103,
            145,
            32,
        )?;
        let url_label = child("STATIC", "flyw8t server address", 0, 0, 18, 66, 152, 24)?;
        let default_url = std::env::var("FLYW8T_PUBLIC_URL").unwrap_or_default();
        let url = child(
            "EDIT",
            &default_url,
            WS_TABSTOP | ES_AUTOHSCROLL as u32,
            207,
            175,
            59,
            418,
            32,
        )?;
        let open = child(
            "BUTTON",
            "Open flyw8t Support",
            WS_TABSTOP,
            OPEN,
            18,
            103,
            174,
            32,
        )?;
        child("BUTTON", "Close", WS_TABSTOP, CLOSE, 502, 103, 91, 32)?;
        let status = child("STATIC", "", 0, 210, 18, 153, 575, 85)?;
        let picker = Self {
            window,
            summary,
            list,
            view,
            control,
            share,
            url_label,
            url,
            open,
            status,
            target,
            mode,
            access: None,
            rows: vec![],
            pending: None,
            preparing: false,
        };
        picker.select_mode(false);
        picker.update_selection();
        Ok(picker)
    }

    unsafe fn select_mode(&self, share: bool) {
        for h in [self.url_label, self.url, self.open] {
            visible(h, share);
        }
        for h in [self.list, self.view, self.control] {
            visible(h, !share);
        }
        visible(self.share, !share && self.mode != Mode::Console);
    }

    unsafe fn discover(&mut self) -> Result<(), String> {
        let target = self.target.clone();
        let mode = self.mode;
        let rx = worker(move || {
            if mode == Mode::Console {
                sessions::discover_console(&target)
                    .map(|(session, policy)| Reply::Sessions(vec![session], Some(policy)))
            } else {
                sessions::discover(&target).map(|rows| Reply::Sessions(rows, None))
            }
        })?;
        self.watch(rx)
    }

    unsafe fn watch(&mut self, rx: Work) -> Result<(), String> {
        if SetTimer(self.window, 1, 100, None) == 0 {
            return Err("Windows could not monitor the session lookup.".into());
        }
        self.pending = Some((rx, Instant::now()));
        Ok(())
    }

    unsafe fn selected(&self) -> Option<&Session> {
        let index = SendMessageW(self.list, CB_GETCURSEL, 0, 0);
        usize::try_from(index).ok().and_then(|i| self.rows.get(i))
    }

    unsafe fn update_selection(&self) {
        let allowed = self.pending.is_none()
            && self.selected().is_some_and(Session::can_shadow)
            && (self.mode != Mode::Console || self.access.is_some());
        EnableWindow(self.view, allowed.into());
        EnableWindow(
            self.control,
            (allowed
                && (self.mode != Mode::Console || self.access == Some(ConsoleAccess::Control)))
            .into(),
        );
    }

    unsafe fn request(&mut self, mode: ShadowMode) -> Result<(), String> {
        if self.pending.is_some() {
            return Ok(());
        }
        let Some(row) = self.selected().filter(|r| r.can_shadow()).cloned() else {
            return Ok(());
        };
        let target = self.target.clone();
        let console = self.mode == Mode::Console;
        if console && !self.access.is_some_and(|access| access.permits(mode)) {
            return Err("The computer has not authorized this action.".into());
        }
        let rx = worker(move || {
            if console {
                sessions::prepare_console(&target, &row, mode).map(Reply::Prepared)
            } else {
                sessions::prepare_shadow(&target, &row, mode).map(Reply::Prepared)
            }
        })?;
        self.watch(rx)?;
        self.preparing = true;
        EnableWindow(self.list, 0);
        self.update_selection();
        label(self.status, "");
        Ok(())
    }

    unsafe fn tick(&mut self) {
        let Some((rx, since)) = &self.pending else {
            return;
        };
        let result = match rx.try_recv() {
            Ok(r) => r,
            Err(mpsc::TryRecvError::Disconnected) => Err("The Windows session query ended early.".into()),
            Err(mpsc::TryRecvError::Empty) if since.elapsed() >= Duration::from_secs(8) => {
                Err(if self.mode == Mode::Console { "Windows did not return the console and policy checks in time. Check the management connection and permissions." } else { "Windows did not return the session list in time. The remote machine may require additional query permissions or firewall access." }.into())
            }
            Err(mpsc::TryRecvError::Empty) => {
                if since.elapsed() > Duration::from_millis(750) {
                    let text = if self.mode == Mode::Console { "Checking this computer’s shadow policy and physical console…" }
                        else if self.preparing { "Checking that the selected user is still in that session…" }
                        else { "Waiting for Windows to return its desktop sessions…" };
                    if GetWindowTextLengthW(self.status) == 0 { label(self.status,text); }
                }
                return;
            }
        };
        KillTimer(self.window, 1);
        self.pending = None;
        EnableWindow(self.list, 1);
        match result {
            Err(e) => {
                if self.mode == Mode::Console {
                    self.access = None;
                    SendMessageW(self.list, CB_RESETCONTENT, 0, 0);
                    self.rows.clear();
                }
                label(self.status, &e)
            }
            Ok(Reply::Sessions(rows, access)) => {
                self.rows = rows;
                self.access = access;
                for row in &self.rows {
                    SendMessageW(
                        self.list,
                        CB_ADDSTRING,
                        0,
                        wide(&row.to_string()).as_ptr() as isize,
                    );
                }
                if self.rows.len() == 1 {
                    SendMessageW(self.list, CB_SETCURSEL, 0, 0);
                }
                label(
                    self.status,
                    if access == Some(ConsoleAccess::View) {
                        "This computer permits unattended viewing only."
                    } else if access == Some(ConsoleAccess::Control) {
                        "This computer permits unattended viewing and control. Choose how to open the console."
                    } else if self.rows.is_empty() {
                        "Windows returned no user desktops. If someone is at the machine, they can share their screen."
                    } else if self.rows.len() > 1 {
                        "Select the user and desktop. A disconnected session cannot receive a shadow request."
                    } else if self.rows[0].can_shadow() {
                        "Windows will handle the shadow request and the host’s consent policy."
                    } else {
                        "This desktop is unavailable for shadowing. The user can share a screen from their active desktop."
                    },
                );
            }
            Ok(Reply::Prepared(request)) => match request.launch() {
                Ok(()) => label(
                    self.status,
                    if self.mode == Mode::Console {
                        "Windows opened the console request. Its window shows the connection outcome."
                    } else {
                        "Windows opened the shadow request. Its window shows consent and the connection outcome."
                    },
                ),
                Err(e) => label(self.status, &e),
            },
        }
        self.preparing = false;
        self.update_selection();
    }

    unsafe fn share_mode(&mut self) {
        self.pending = None; // Discard any late discovery or prepared shadow request.
        KillTimer(self.window, 1);
        self.preparing = false;
        self.select_mode(true);
        label(
            self.summary,
            &format!(
                "Ask the person on {} to open the invitation inside the desktop you intend to see.",
                self.target.host
            ),
        );
        label(self.status,"Attended, view only. Create an invitation in your flyw8t console. The person chooses the screen and can stop sharing.");
        SetFocus(self.url);
    }

    unsafe fn open_support(&self) -> Result<(), String> {
        let n = GetWindowTextLengthW(self.url);
        let mut buf = vec![0; n as usize + 1];
        let used = GetWindowTextW(self.url, buf.as_mut_ptr(), n + 1);
        let entry = String::from_utf16_lossy(&buf[..used as usize]);
        let address = support_address(&entry)?;
        let rc = ShellExecuteW(
            self.window,
            wide("open").as_ptr(),
            wide(&address).as_ptr(),
            null(),
            null(),
            SW_SHOWNORMAL,
        );
        if rc as isize <= 32 {
            return Err("Windows could not open flyw8t Support in your browser.".into());
        }
        label(self.status,"Support opened in your browser. Create an invitation and have the person open it in the intended desktop.");
        Ok(())
    }
}

fn support_address(raw: &str) -> Result<String, String> {
    let invalid = || {
        "Enter the HTTPS address of your flyw8t server. Local development also accepts HTTP on loopback.".to_owned()
    };
    let mut url = url::Url::parse(raw.trim()).map_err(|_| invalid())?;
    let local = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => return Err(invalid()),
    };
    if !(url.scheme() == "https" || url.scheme() == "http" && local)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "/" | "/support" | "/support/")
    {
        return Err(invalid());
    }
    url.set_path("/support");
    Ok(url.into())
}

pub fn run(target: Target, mode: Mode) -> Result<(), String> {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let name = wide("Flyw8tAssistPicker");
        let class = WNDCLASSW {
            hInstance: GetModuleHandleW(null()),
            lpszClassName: name.as_ptr(),
            lpfnWndProc: Some(window_proc),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
            ..Default::default()
        };
        if RegisterClassW(&class) == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let dpi = GetDpiForSystem().max(96) as i32;
        let title = if mode == Mode::Console {
            format!("{} · Unattended console", target.host)
        } else {
            format!("{} · flyw8t support", target.host)
        };
        let window = CreateWindowExW(
            0,
            name.as_ptr(),
            wide(&title).as_ptr(),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            632 * dpi / 96,
            290 * dpi / 96,
            null_mut(),
            null_mut(),
            class.hInstance,
            null(),
        );
        if window.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut picker = Picker::new(window, target, mode)?;
        ShowWindow(window, SW_SHOW);
        if mode == Mode::Share {
            picker.share_mode();
        } else {
            picker.discover()?;
        }
        let mut msg = MSG::default();
        loop {
            match GetMessageW(&mut msg, null_mut(), 0, 0) {
                0 => break,
                -1 => return Err(std::io::Error::last_os_error().to_string()),
                _ => {}
            }
            if msg.hwnd == window {
                if msg.message == WM_TIMER {
                    picker.tick();
                    continue;
                }
                if msg.message == COMMAND {
                    let id = msg.wParam & 0xffff;
                    let result = match id {
                        VIEW => picker.request(ShadowMode::View),
                        CONTROL => picker.request(ShadowMode::RequestControl),
                        SHARE if mode != Mode::Console => {
                            picker.share_mode();
                            Ok(())
                        }
                        OPEN => picker.open_support(),
                        SELECT => {
                            picker.update_selection();
                            Ok(())
                        }
                        CLOSE => {
                            DestroyWindow(window);
                            Ok(())
                        }
                        _ => Ok(()),
                    };
                    if let Err(e) = result {
                        label(picker.status, &e);
                    }
                    continue;
                }
            }
            if IsDialogMessageW(window, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::support_address;
    #[test]
    fn share_link_always_goes_to_the_configured_console() {
        assert_eq!(
            support_address("https://rmm.example").unwrap(),
            "https://rmm.example/support"
        );
        assert_eq!(
            support_address("http://[::1]:8080").unwrap(),
            "http://[::1]:8080/support"
        );
        for bad in [
            "file:///C:/tool",
            "http://rmm.example",
            "https://a:b@rmm.example",
            "https://rmm.example/s/token",
            "https://rmm.example/?token=abc",
        ] {
            assert!(support_address(bad).is_err(), "{bad}");
        }
    }
}
