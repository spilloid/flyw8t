//! The window owns the RDP control on its STA. Window callbacks only enqueue events:
//! Win32 and OLE can synchronously reenter a callback while a control method is running.
use crate::rdp::{RdpEvent, RdpSession};
use crate::target::{probe, Target};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Ole::{OleInitialize, OleUninitialize};
use windows_sys::Win32::System::SystemServices::SS_NOPREFIX;
use windows_sys::Win32::UI::HiDpi::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetFocus, SetFocus, VK_RETURN,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const CONNECT: usize = 101;
const INTENT: usize = 105;
const RDP_EVENT: u32 = WM_APP + 40;
const WAKE: u32 = WM_APP + 41;
const TIMER: usize = 1;
const DISPLAY_TIMER: usize = 2;
const MIN_CARD_WIDTH: i32 = 572;
const INITIAL_CARD_HEIGHT: i32 = 204;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn last_error(action: &str) -> String {
    format!("{action}: {}", std::io::Error::last_os_error())
}

#[derive(Clone, Copy)]
enum Event {
    Action,
    SelectIntent,
    Resize,
    Dpi,
    Rdp,
    Tick,
    SyncDisplay,
    Close,
}
type Events = RefCell<VecDeque<Event>>;

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if msg == WM_NCCREATE {
        let cs = &*(l as *const CREATESTRUCTW);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, cs.lpCreateParams as isize);
    }
    let queue = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const Events;
    if queue.is_null() {
        return DefWindowProcW(hwnd, msg, w, l);
    }
    let event = match msg {
        WM_CLOSE => Event::Close,
        WM_COMMAND if w & 0xffff == CONNECT && (w >> 16) as u32 == BN_CLICKED => Event::Action,
        WM_COMMAND if w & 0xffff == INTENT && (w >> 16) as u32 == CBN_SELCHANGE => {
            Event::SelectIntent
        }
        WM_SIZE => Event::Resize,
        WM_DPICHANGED => {
            let r = &*(l as *const RECT);
            SetWindowPos(
                hwnd,
                null_mut(),
                r.left,
                r.top,
                r.right - r.left,
                r.bottom - r.top,
                SWP_NOACTIVATE | SWP_NOZORDER,
            );
            Event::Dpi
        }
        WM_GETMINMAXINFO => {
            let dpi = GetDpiForWindow(hwnd).max(96) as i32;
            let limits = &mut *(l as *mut MINMAXINFO);
            limits.ptMinTrackSize = POINT {
                x: MIN_CARD_WIDTH * dpi / 96,
                y: INITIAL_CARD_HEIGHT * dpi / 96,
            };
            return 0;
        }
        WM_TIMER if w == TIMER => Event::Tick,
        WM_TIMER if w == DISPLAY_TIMER => Event::SyncDisplay,
        RDP_EVENT => Event::Rdp,
        WAKE => return 0,
        WM_NCDESTROY => {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return DefWindowProcW(hwnd, msg, w, l);
        }
        _ => return DefWindowProcW(hwnd, msg, w, l),
    };
    let was_empty = (*queue).borrow().is_empty();
    (*queue).borrow_mut().push_back(event);
    if was_empty {
        PostMessageW(hwnd, WAKE, 0, 0);
    }
    0
}

struct Ole;
impl Drop for Ole {
    fn drop(&mut self) {
        unsafe { OleUninitialize() }
    }
}
struct Window(HWND);
impl Drop for Window {
    fn drop(&mut self) {
        unsafe {
            DestroyWindow(self.0);
        }
    }
}

pub fn run(prefill: Option<String>, connect_now: bool) -> Result<(), String> {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let hr = OleInitialize(null());
        if hr < 0 {
            return Err(format!(
                "Windows could not start Remote Desktop (0x{:08X}).",
                hr as u32
            ));
        }
        let _ole = Ole;
        let events = Box::new(Events::default());
        let instance = GetModuleHandleW(null());
        let class_name = wide("Flyw8tTechnicianWindow");
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
            lpszClassName: class_name.as_ptr(),
            ..Default::default()
        };
        if RegisterClassW(&class) == 0 {
            return Err(last_error("Could not register the technician window"));
        }
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            wide("Flyw8t Technician").as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            730 * GetDpiForSystem().max(96) as i32 / 96,
            INITIAL_CARD_HEIGHT * GetDpiForSystem().max(96) as i32 / 96,
            null_mut(),
            null_mut(),
            instance,
            (&*events as *const Events).cast(),
        );
        if hwnd.is_null() {
            return Err(last_error("Could not open the technician window"));
        }
        let _window = Window(hwnd);
        let mut ui = Ui::new(hwnd, prefill.as_deref().unwrap_or_default())?;
        if connect_now {
            SendMessageW(ui.intent, CB_SETCURSEL, 2, 0);
        }
        ui.select_intent();
        ui.update_font();
        ui.layout();
        ShowWindow(hwnd, SW_SHOW);
        SetFocus(ui.address);
        if connect_now {
            events.borrow_mut().push_back(Event::Action);
        }
        loop {
            loop {
                let next = events.borrow_mut().pop_front();
                match next {
                    Some(Event::Close) => return Ok(()),
                    Some(Event::Action) => ui.action(),
                    Some(Event::SelectIntent) => ui.select_intent(),
                    Some(Event::Resize) => ui.layout(),
                    Some(Event::Dpi) => {
                        ui.update_font();
                        ui.layout();
                    }
                    Some(Event::Tick) => ui.tick(),
                    Some(Event::SyncDisplay) => ui.sync_display(),
                    Some(Event::Rdp) => ui.rdp_events(),
                    None => break,
                }
            }
            let mut msg = MSG::default();
            match GetMessageW(&mut msg, null_mut(), 0, 0) {
                -1 => return Err(last_error("Windows message loop failed")),
                0 => return Ok(()),
                _ => {}
            }
            let focus = GetFocus();
            if msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN as usize {
                let closed_choice =
                    focus == ui.intent && SendMessageW(ui.intent, CB_GETDROPPEDSTATE, 0, 0) == 0;
                if focus == ui.address || focus == ui.button || closed_choice {
                    // Holding Enter must not immediately cancel the connection it just started.
                    if msg.lParam & (1 << 30) == 0 {
                        ui.action();
                    }
                    continue;
                }
            }
            if [ui.address, ui.intent, ui.button, ui.clipboard].contains(&focus)
                && IsDialogMessageW(hwnd, &msg) != 0
            {
                continue;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

unsafe fn child(
    hwnd: HWND,
    class: &str,
    text: &str,
    extra: u32,
    style: u32,
    id: usize,
) -> Result<HWND, String> {
    let h = CreateWindowExW(
        extra,
        wide(class).as_ptr(),
        wide(text).as_ptr(),
        style | WS_CHILD | WS_VISIBLE,
        0,
        0,
        10,
        10,
        hwnd,
        id as HMENU,
        GetModuleHandleW(null()),
        null(),
    );
    if h.is_null() {
        Err(last_error("Could not create the Remote Desktop controls"))
    } else {
        Ok(h)
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Intent {
    Assist,
    Share,
    SignIn,
    Console,
}

struct Chooser {
    intent: Intent,
    target: String,
    process: std::process::Child,
}

// Bring an already-open chooser forward without inspecting any of its contents.
unsafe extern "system" fn raise_chooser(hwnd: HWND, pid: LPARAM) -> i32 {
    let mut owner = 0;
    GetWindowThreadProcessId(hwnd, &mut owner);
    if owner != pid as u32 || IsWindowVisible(hwnd) == 0 {
        return 1;
    }
    if IsIconic(hwnd) != 0 {
        ShowWindowAsync(hwnd, SW_RESTORE);
    }
    SetForegroundWindow(hwnd);
    0
}

struct Ui {
    hwnd: HWND,
    intent_label: HWND,
    intent: HWND,
    choosers: Vec<Chooser>,
    label: HWND,
    address: HWND,
    button: HWND,
    clipboard: HWND,
    status: HWND,
    surface: HWND,
    hint: HWND,
    font: HFONT,
    session: Option<RdpSession>,
    active: Option<Target>,
    started: Option<Instant>,
    signed_in: bool,
    // Restore the connection card only when the operator kept the automatic desktop size.
    automatic_size: Option<(RECT, RECT)>,
    generation: Arc<AtomicU64>,
    requests: mpsc::Sender<(u64, Target)>,
    replies: mpsc::Receiver<(u64, Result<(), String>)>,
}

impl Ui {
    unsafe fn new(hwnd: HWND, address: &str) -> Result<Self, String> {
        let label = child(hwnd, "STATIC", "&Computer", 0, 0, 0)?;
        let address = child(
            hwnd,
            "EDIT",
            address,
            WS_EX_CLIENTEDGE,
            WS_TABSTOP | ES_AUTOHSCROLL as u32,
            102,
        )?;
        let intent_label = child(hwnd, "STATIC", "&Session", 0, 0, 0)?;
        let intent = child(
            hwnd,
            "COMBOBOX",
            "",
            0,
            WS_TABSTOP | CBS_DROPDOWNLIST as u32,
            INTENT,
        )?;
        for name in [
            "Help someone",
            "Share a screen",
            "Windows sign-in",
            "Unattended console",
        ] {
            if SendMessageW(intent, CB_ADDSTRING, 0, wide(name).as_ptr() as isize) < 0 {
                return Err("Could not set up the session choices.".into());
            }
        }
        SendMessageW(intent, CB_SETCURSEL, 0, 0);
        let button = child(
            hwnd,
            "BUTTON",
            "Connect",
            0,
            WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
            CONNECT,
        )?;
        let clipboard = child(
            hwnd,
            "BUTTON",
            "Share clipboard",
            0,
            WS_TABSTOP | BS_AUTOCHECKBOX as u32,
            103,
        )?;
        SendMessageW(clipboard, BM_SETCHECK, 1, 0);
        let surface = child(hwnd, "STATIC", "", 0, WS_CLIPCHILDREN, 0)?;
        ShowWindow(surface, SW_HIDE);
        let hint = child(hwnd, "STATIC", "", 0, SS_NOPREFIX, 0)?;
        let status = child(hwnd, "STATIC", "", 0, SS_NOPREFIX, 104)?;
        let generation = Arc::new(AtomicU64::new(0));
        let latest = generation.clone();
        let (requests, jobs) = mpsc::channel::<(u64, Target)>();
        let (results, replies) = mpsc::channel();
        std::thread::Builder::new()
            .name("rdp-connect".into())
            .spawn(move || {
                for (id, target) in jobs {
                    if latest.load(Ordering::Acquire) == id
                        && results.send((id, probe(&target))).is_err()
                    {
                        break;
                    }
                }
            })
            .map_err(|e| format!("Could not start the connection worker: {e}"))?;
        Ok(Self {
            hwnd,
            intent_label,
            intent,
            choosers: Vec::new(),
            label,
            address,
            button,
            clipboard,
            status,
            surface,
            hint,
            font: null_mut(),
            active: None,
            session: None,
            started: None,
            signed_in: false,
            automatic_size: None,
            generation,
            requests,
            replies,
        })
    }

    unsafe fn update_font(&mut self) {
        let dpi = GetDpiForWindow(self.hwnd).max(96) as i32;
        let font = CreateFontW(
            -(14 * dpi / 96),
            0,
            0,
            0,
            FW_NORMAL as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            0,
            0,
            CLEARTYPE_QUALITY as u32,
            0,
            wide("Segoe UI").as_ptr(),
        );
        if font.is_null() {
            return;
        }
        for h in [
            self.intent_label,
            self.intent,
            self.label,
            self.address,
            self.button,
            self.clipboard,
            self.hint,
            self.status,
        ] {
            SendMessageW(h, WM_SETFONT, font as usize, 1);
        }
        if !self.font.is_null() {
            DeleteObject(self.font);
        }
        self.font = font;
    }

    unsafe fn text_height(&self, control: HWND, width: i32, dpi: i32) -> i32 {
        let mut text = vec![0u16; GetWindowTextLengthW(control) as usize + 1];
        let count = GetWindowTextW(control, text.as_mut_ptr(), text.len() as i32);
        if count == 0 {
            return 0;
        }
        let dc = GetDC(control);
        if dc.is_null() {
            return 36 * dpi / 96;
        }
        let old = SelectObject(dc, SendMessageW(control, WM_GETFONT, 0, 0) as HGDIOBJ);
        let mut bounds = RECT {
            right: width,
            ..Default::default()
        };
        let height = DrawTextW(
            dc,
            text.as_mut_ptr(),
            count,
            &mut bounds,
            DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX,
        );
        if !old.is_null() {
            SelectObject(dc, old);
        }
        ReleaseDC(control, dc);
        height.max(18 * dpi / 96)
    }

    unsafe fn layout(&self) {
        let mut r = RECT::default();
        GetClientRect(self.hwnd, &mut r);
        let dpi = GetDpiForWindow(self.hwnd).max(96) as i32;
        let s = |n: i32| (n * dpi + 48) / 96;
        let (w, h) = (r.right, r.bottom);
        MoveWindow(self.label, s(16), s(19), s(77), s(22), 1);
        MoveWindow(self.address, s(96), s(12), (w - s(112)).max(1), s(32), 1);
        MoveWindow(self.intent_label, s(16), s(65), s(76), s(22), 1);
        MoveWindow(self.intent, s(96), s(56), s(166), s(154), 1);
        MoveWindow(self.button, s(274), s(54), s(120), s(34), 1);
        MoveWindow(self.clipboard, s(406), s(55), s(126), s(32), 1);
        let y = s(100);
        let height = (h - y - s(33)).max(1);
        MoveWindow(self.surface, 0, y, w, height, 1);
        let text_width = (w - s(32)).max(1);
        if GetWindowLongW(self.surface, GWL_STYLE) as u32 & WS_VISIBLE != 0 {
            MoveWindow(self.status, s(16), h - s(26), text_width, s(25), 1);
        } else {
            let hint_height = self.text_height(self.hint, text_width, dpi);
            MoveWindow(self.hint, s(16), y, text_width, hint_height, 1);
            let status_y = y + hint_height + s(8);
            MoveWindow(
                self.status,
                s(16),
                status_y,
                text_width,
                (h - status_y - s(12)).max(1),
                1,
            );
        }
        if let Some(session) = &self.session {
            session.resize(0, 0, w.max(1), height);
            if self.signed_in && IsIconic(self.hwnd) == 0 {
                SetTimer(self.hwnd, DISPLAY_TIMER, 240, None);
            }
        }
    }

    unsafe fn sync_display(&self) {
        KillTimer(self.hwnd, DISPLAY_TIMER);
        if self.signed_in && IsIconic(self.hwnd) == 0 {
            if let Some(session) = &self.session {
                // Older session hosts keep the control's locally scaled presentation.
                let _ = session.sync_display();
            }
        }
    }

    // Size a fresh session inside the selected monitor without activating the window.
    // Keep a user-sized window (or a maximized one) at the size the operator chose.
    unsafe fn fit_desktop(&mut self) {
        let mut card = RECT::default();
        GetWindowRect(self.hwnd, &mut card);
        let dpi = GetDpiForWindow(self.hwnd).max(96) as i32;
        if IsZoomed(self.hwnd) != 0
            || IsIconic(self.hwnd) != 0
            || card.bottom - card.top > 350 * dpi / 96
        {
            return;
        }
        let monitor = MonitorFromWindow(self.hwnd, MONITOR_DEFAULTTONEAREST);
        let mut info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if GetMonitorInfoW(monitor, &mut info) == 0 {
            return;
        }
        let work = info.rcWork;
        let width = (1200 * dpi / 96).min(work.right - work.left);
        let height = (800 * dpi / 96).min(work.bottom - work.top);
        let x = card.left.clamp(work.left, work.right - width);
        let y = card.top.clamp(work.top, work.bottom - height);
        if SetWindowPos(
            self.hwnd,
            null_mut(),
            x,
            y,
            width,
            height,
            SWP_NOACTIVATE | SWP_NOZORDER,
        ) != 0
        {
            let mut expanded = RECT::default();
            GetWindowRect(self.hwnd, &mut expanded);
            self.automatic_size = Some((card, expanded));
        }
    }

    unsafe fn restore_card(&mut self) {
        if let Some((card, expanded)) = self.automatic_size.take() {
            let mut current = RECT::default();
            GetWindowRect(self.hwnd, &mut current);
            if [current.left, current.top, current.right, current.bottom]
                == [expanded.left, expanded.top, expanded.right, expanded.bottom]
            {
                SetWindowPos(
                    self.hwnd,
                    null_mut(),
                    card.left,
                    card.top,
                    card.right - card.left,
                    card.bottom - card.top,
                    SWP_NOACTIVATE | SWP_NOZORDER,
                );
            }
        }
    }

    unsafe fn message(&self, text: &str) {
        SetWindowTextW(self.status, wide(text).as_ptr());
        ShowWindow(
            self.status,
            if text.is_empty() { SW_HIDE } else { SW_SHOWNA },
        );
        if text.is_empty()
            || IsZoomed(self.hwnd) != 0
            || IsIconic(self.hwnd) != 0
            || GetWindowLongW(self.surface, GWL_STYLE) as u32 & WS_VISIBLE != 0
        {
            return;
        }
        // Grow the compact card only when an actual status needs more lines.
        let dpi = GetDpiForWindow(self.hwnd).max(96) as i32;
        let mut client = RECT::default();
        GetClientRect(self.hwnd, &mut client);
        let width = (client.right - 32 * dpi / 96).max(1);
        let required = 120 * dpi / 96
            + self.text_height(self.hint, width, dpi)
            + self
                .text_height(self.status, width, dpi)
                .min(150 * dpi / 96);
        if required > client.bottom {
            let mut rect = RECT::default();
            if GetWindowRect(self.hwnd, &mut rect) != 0 {
                SetWindowPos(
                    self.hwnd,
                    null_mut(),
                    0,
                    0,
                    rect.right - rect.left,
                    rect.bottom - rect.top + required - client.bottom,
                    SWP_NOMOVE | SWP_NOACTIVATE | SWP_NOZORDER,
                );
            }
        }
    }

    unsafe fn selected(&self) -> Intent {
        match SendMessageW(self.intent, CB_GETCURSEL, 0, 0) {
            3 => Intent::Console,
            2 => Intent::SignIn,
            1 => Intent::Share,
            _ => Intent::Assist,
        }
    }

    unsafe fn select_intent(&self) {
        let intent = self.selected();
        let (button, hint) = match intent {
            Intent::Assist => ("Find sessions", "Choose the signed-in person whose current Windows session you want to help."),
            Intent::Share => ("Share a screen", "Open flyw8t Support in your browser. The person chooses which screen to share."),
            Intent::SignIn => ("Connect", "Sign in with a Windows account. The person at this computer may see a lock screen."),
            Intent::Console => ("Check console", "Open the signed-in physical console when the computer’s Windows policy permits unattended access."),
        };
        SetWindowTextW(self.button, wide(button).as_ptr());
        SetWindowTextW(self.hint, wide(hint).as_ptr());
        ShowWindow(
            self.clipboard,
            if intent == Intent::SignIn {
                SW_SHOWNA
            } else {
                SW_HIDE
            },
        );
        self.message("");
        self.layout();
    }

    unsafe fn open_chooser(&mut self, intent: Intent, target: &Target) {
        let name = target.to_string();
        self.choosers
            .retain_mut(|item| item.process.try_wait().is_ok_and(|s| s.is_none()));
        if let Some(open) = self
            .choosers
            .iter()
            .find(|item| item.intent == intent && item.target == name)
        {
            EnumWindows(Some(raise_chooser), open.process.id() as isize);
            self.message(&format!("The support window for {name} is already open."));
            return;
        }
        let flag = match intent {
            Intent::Assist => "--assist",
            Intent::Console => "--console",
            Intent::Share => "--share",
            Intent::SignIn => return,
        };
        let launched = std::env::current_exe()
            .and_then(|exe| std::process::Command::new(exe).arg(flag).arg(&name).spawn());
        match launched {
            Ok(process) => {
                self.message(&format!("Opened the support window for {name}."));
                self.choosers.push(Chooser {
                    intent,
                    target: name,
                    process,
                });
            }
            Err(e) => self.message(&format!("Could not open the support window: {e}")),
        }
    }

    unsafe fn action(&mut self) {
        if self.active.is_some() {
            if let Some(s) = self.session.take() {
                let _ = s.disconnect();
            }
            let msg = if self.signed_in {
                "Disconnected"
            } else {
                "Connection canceled"
            };
            self.finish(msg);
            return;
        }
        let len = GetWindowTextLengthW(self.address);
        let mut text = vec![0u16; len as usize + 1];
        let n = GetWindowTextW(self.address, text.as_mut_ptr(), len + 1);
        let target = match Target::parse(&String::from_utf16_lossy(&text[..n as usize])) {
            Ok(t) => t,
            Err(e) => {
                self.message(&e);
                SetFocus(self.address);
                return;
            }
        };
        let intent = self.selected();
        if intent != Intent::SignIn {
            self.open_chooser(intent, &target);
            return;
        }
        let id = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let target_name = target.to_string();
        self.active = Some(target.clone());
        if self.requests.send((id, target)).is_err() {
            self.finish("The connection worker stopped. Reopen the window to try again.");
            return;
        }
        self.started = Some(Instant::now());
        SetFocus(self.button);
        EnableWindow(self.address, 0);
        EnableWindow(self.intent, 0);
        EnableWindow(self.clipboard, 0);
        SetWindowTextW(self.button, wide("Cancel").as_ptr());
        SetWindowTextW(
            self.hwnd,
            wide(&format!("{target_name} · Flyw8t Technician")).as_ptr(),
        );
        self.message("");
        if SetTimer(self.hwnd, TIMER, 75, None) == 0 {
            self.finish("Windows could not monitor the connection.");
        }
    }

    unsafe fn tick(&mut self) {
        if self.active.is_none() {
            return;
        }
        if self
            .started
            .is_some_and(|t| t.elapsed() >= Duration::from_millis(550))
        {
            self.started = None;
            if let Some(target) = &self.active {
                if self.session.is_some() {
                    self.message("Waiting for Windows Remote Desktop…");
                } else {
                    self.message(&format!(
                        "Waiting for {} on port {}…",
                        target.host, target.port
                    ));
                }
            }
        }
        while let Ok((id, result)) = self.replies.try_recv() {
            if id != self.generation.load(Ordering::Acquire) {
                continue;
            }
            if let Err(e) = result {
                self.finish(&e);
                return;
            }
            if self.started.is_none() {
                self.message("Waiting for Windows Remote Desktop…");
            }
            self.fit_desktop();
            ShowWindow(self.hint, SW_HIDE);
            ShowWindow(self.surface, SW_SHOWNA);
            self.layout();
            let target = self.active.as_ref().unwrap();
            let clipboard = SendMessageW(self.clipboard, BM_GETCHECK, 0, 0) == 1;
            let start = RdpSession::new(self.surface as isize, self.hwnd as isize, RDP_EVENT)
                .and_then(|session| {
                    let mut rect = RECT::default();
                    GetClientRect(self.surface, &mut rect);
                    session.resize(0, 0, rect.right.max(1), rect.bottom.max(1));
                    session.connect(&target.host, target.port, clipboard)?;
                    Ok(session)
                });
            match start {
                Ok(s) => self.session = Some(s),
                Err(e) => self.finish(&e),
            }
        }
    }

    unsafe fn rdp_events(&mut self) {
        while let Some(event) = self.session.as_ref().and_then(|s| s.poll()) {
            match event {
                RdpEvent::Connecting => {}
                RdpEvent::TransportConnected => {
                    self.started = None;
                    KillTimer(self.hwnd, TIMER);
                    self.message("Waiting for Windows sign-in…");
                }
                RdpEvent::LoggedIn => {
                    self.signed_in = true;
                    self.sync_display();
                    self.started = None;
                    KillTimer(self.hwnd, TIMER);
                    SetWindowTextW(self.button, wide("Disconnect").as_ptr());
                    if let Some(t) = &self.active {
                        self.message(&format!("Connected to {t}"));
                    }
                    if GetForegroundWindow() == self.hwnd {
                        if let Some(s) = &self.session {
                            s.focus();
                        }
                    }
                }
                RdpEvent::LoginNotice(code) => {
                    self.started = None;
                    // OnLogonError also carries ordinary Winlogon transitions.
                    match code {
                        -1 | -6 => self.message("Windows denied access to this session."),
                        0 | -1_073_741_715 => self.message(
                            "Windows rejected the sign-in. Check your account and password.",
                        ),
                        1 | -1_073_741_276 => {
                            self.message("Windows requires a new password before sign-in.")
                        }
                        -1_073_741_714 => {
                            self.message("An account restriction blocked Windows sign-in.")
                        }
                        2 | 3 | -7 | -5 | -4 => self.message("Check the Windows sign-in prompt."),
                        _ => {}
                    }
                }
                RdpEvent::Disconnected {
                    code,
                    extended,
                    detail,
                } => {
                    let msg = if detail.trim().is_empty() {
                        format!("Disconnected (RDP {code}, extended {extended}).")
                    } else {
                        detail
                    };
                    self.finish(&msg);
                    return;
                }
                RdpEvent::Fatal(code) => {
                    self.finish(&format!("Remote Desktop stopped (RDP error {code})."));
                    return;
                }
            }
        }
    }

    unsafe fn finish(&mut self, reason: &str) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        KillTimer(self.hwnd, DISPLAY_TIMER);
        KillTimer(self.hwnd, TIMER);
        self.started = None;
        self.session.take();
        self.active = None;
        self.signed_in = false;
        ShowWindow(self.surface, SW_HIDE);
        ShowWindow(self.hint, SW_SHOWNA);
        self.restore_card();
        self.layout();
        EnableWindow(self.address, 1);
        EnableWindow(self.intent, 1);
        EnableWindow(self.clipboard, 1);
        SetWindowTextW(self.hwnd, wide("Flyw8t Technician").as_ptr());
        self.select_intent();
        self.message(reason);
        if GetForegroundWindow() == self.hwnd {
            SetFocus(self.address);
        }
    }
}

impl Drop for Ui {
    fn drop(&mut self) {
        unsafe {
            self.generation.fetch_add(1, Ordering::AcqRel);
            KillTimer(self.hwnd, DISPLAY_TIMER);
            KillTimer(self.hwnd, TIMER);
            if let Some(s) = self.session.take() {
                let _ = s.disconnect();
            }
            if !self.font.is_null() {
                for h in [
                    self.intent_label,
                    self.intent,
                    self.label,
                    self.address,
                    self.button,
                    self.clipboard,
                    self.hint,
                    self.status,
                ] {
                    SendMessageW(h, WM_SETFONT, 0, 0);
                }
                DeleteObject(self.font);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_is_the_default_and_only_sign_in_offers_rdp_clipboard() {
        unsafe {
            let host = CreateWindowExW(
                0,
                wide("STATIC").as_ptr(),
                null(),
                WS_OVERLAPPED,
                0,
                0,
                730,
                294,
                null_mut(),
                null_mut(),
                null_mut(),
                null(),
            );
            assert!(!host.is_null());
            let _window = Window(host);
            let mut ui = Ui::new(host, "example.test").unwrap();
            ui.update_font();
            for (index, expected, clipboard) in [
                (0, "Find sessions", false),
                (1, "Share a screen", false),
                (2, "Connect", true),
                (3, "Check console", false),
            ] {
                if index != 0 {
                    SendMessageW(ui.intent, CB_SETCURSEL, index, 0);
                }
                ui.select_intent();
                let mut text = [0u16; 64];
                let n = GetWindowTextW(ui.button, text.as_mut_ptr(), text.len() as i32);
                assert_eq!(String::from_utf16_lossy(&text[..n as usize]), expected);
                assert_eq!(
                    GetWindowTextLengthW(ui.status),
                    0,
                    "an idle card needs no status"
                );
                assert_eq!(
                    (GetWindowLongW(ui.clipboard, GWL_STYLE) as u32 & WS_VISIBLE) != 0,
                    clipboard
                );
            }
            assert!(ui.choosers.is_empty());
            assert!(ui.session.is_none() && ui.active.is_none());
            let dpi = GetDpiForWindow(host).max(96) as i32;
            let rect = |control| {
                let mut bounds = RECT::default();
                assert_ne!(GetWindowRect(control, &mut bounds), 0);
                bounds
            };
            SendMessageW(ui.intent, CB_SETCURSEL, 2, 0);
            for width in [MIN_CARD_WIDTH, 730] {
                SetWindowPos(
                    host,
                    null_mut(),
                    0,
                    0,
                    width * dpi / 96,
                    INITIAL_CARD_HEIGHT * dpi / 96,
                    SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                );
                ui.select_intent();
                assert!(rect(ui.clipboard).right <= rect(ui.address).right);
                let gap = rect(ui.hint).top - rect(ui.button).bottom;
                assert!(
                    gap >= 0 && gap <= 16 * dpi / 96,
                    "guidance follows the actionable controls"
                );
                let reason = "Windows could not reach workstation.example. Check the computer’s network, VPN, and Remote Desktop configuration. Close this session and try again when the computer is available. ";
                ui.message(&reason.repeat(2));
                ui.layout();
                let b = rect(ui.status);
                assert!(b.top >= rect(ui.hint).bottom);
                assert!(b.bottom - b.top >= ui.text_height(ui.status, b.right - b.left, dpi));
            }
        }
    }
}
