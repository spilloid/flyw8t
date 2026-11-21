use super::model::{Board, Phase, COLUMNS, ROWS};
use super::session::BoardSession;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::oneshot;
use windows::{
    core::{w, HSTRING, PCWSTR},
    Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        System::RemoteDesktop::{WTSRegisterSessionNotification, WTSUnRegisterSessionNotification},
        UI::{Accessibility::*, WindowsAndMessaging::*},
    },
};

static SESSION: OnceLock<Arc<Mutex<BoardSession>>> = OnceLock::new();
const ALLOW: usize = 101;
const STOP: usize = 102;
const DISPLAY: i32 = 103;

fn stop() {
    if let Some(session) = SESSION.get() {
        session.lock().expect("board session").stop();
    }
}

extern "system" fn desktop_switched(
    _: HWINEVENTHOOK,
    _: u32,
    _: HWND,
    _: i32,
    _: i32,
    _: u32,
    _: u32,
) {
    // A brief switch away and back must still invalidate this session.
    stop();
}

struct DesktopHook(HWINEVENTHOOK);

impl Drop for DesktopHook {
    fn drop(&mut self) {
        unsafe {
            let _ = UnhookWinEvent(self.0);
        }
    }
}

unsafe extern "system" fn procedure(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND => {
            let id = w.0 & 65535;
            if (id == ALLOW || id == STOP)
                && w.0 >> 16 == BN_CLICKED as usize
                && GetDlgItem(Some(hwnd), id as i32).is_ok_and(|child| child.0 as isize == l.0)
            {
                if id == STOP {
                    stop();
                } else if IsWindowVisible(hwnd).as_bool() {
                    if let Some(session) = SESSION.get() {
                        session.lock().expect("board session").allow();
                    }
                }
            }
            LRESULT(0)
        }
        WM_QUERYENDSESSION | WM_ENDSESSION | WM_WTSSESSION_CHANGE => {
            stop();
            LRESULT(1)
        }
        WM_CLOSE | WM_DESTROY => {
            stop();
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}

fn display_text(board: &Board) -> String {
    let mut text = if board.phase == Phase::Waiting {
        "Waiting for local permission.".to_owned()
    } else {
        "Technician controls this board. Click Stop to end.".to_owned()
    };
    for row in 0..ROWS {
        text.push_str("\r\n");
        for col in 0..COLUMNS {
            text.push_str(if (col, row) == (board.x, board.y) {
                " [X] "
            } else if Some((col, row)) == board.marked {
                " [*] "
            } else {
                " [  ] "
            });
        }
    }
    text.push_str("\r\nTyped here: ");
    text.push_str(&board.text);
    text
}

pub fn run(session: Arc<Mutex<BoardSession>>, ready: oneshot::Sender<()>) -> super::Result<()> {
    SESSION
        .set(session.clone())
        .map_err(|_| "one board per process")?;
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class = w!("Flyw8tOwnedControlFixture");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(procedure),
            hInstance: instance.into(),
            lpszClassName: class,
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH((16usize) as *mut _),
            ..Default::default()
        };
        if RegisterClassW(&wc) == 0 {
            return Err(windows::core::Error::from_thread().into());
        }
        // Initially hidden. Windows can deliver WTS changes before the peer
        // is known. The window becomes visible after the verified code exists.
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST,
            class,
            w!("Flyw8t · Allow control of the practice board?"),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            540,
            350,
            None,
            None,
            Some(instance.into()),
            None,
        )?;
        let registered = WTSRegisterSessionNotification(hwnd, 0);
        let result = match registered {
            Ok(()) => {
                let result = watch(hwnd, session, ready);
                let _ = WTSUnRegisterSessionNotification(hwnd);
                result
            }
            Err(err) => Err(err.into()),
        };
        let _ = DestroyWindow(hwnd);
        result
    }
}

unsafe fn watch(
    hwnd: HWND,
    session: Arc<Mutex<BoardSession>>,
    ready: oneshot::Sender<()>,
) -> super::Result<()> {
    let hook = SetWinEventHook(
        EVENT_SYSTEM_DESKTOPSWITCH,
        EVENT_SYSTEM_DESKTOPSWITCH,
        None,
        Some(desktop_switched),
        0,
        0,
        WINEVENT_OUTOFCONTEXT,
    );
    if hook.is_invalid() {
        return Err("Windows could not monitor desktop switches".into());
    }
    let _hook = DesktopHook(hook);
    session.lock().expect("board session").bind_login()?;

    let child = |class, text, id, x, y, width, height| {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            text,
            WS_VISIBLE | WS_CHILD,
            x,
            y,
            width,
            height,
            Some(hwnd),
            Some(HMENU(id as *mut _)),
            None,
            None,
        )
    };
    let attribution = child(w!("STATIC"), w!(""), 100, 16, 12, 500, 50)?;
    child(
        w!("BUTTON"),
        w!("Allow board control"),
        ALLOW,
        16,
        65,
        165,
        32,
    )?;
    child(w!("BUTTON"), w!("Stop"), STOP, 195, 65, 100, 32)?;
    let display = child(w!("STATIC"), w!(""), DISPLAY as usize, 16, 110, 495, 180)?;
    if SetTimer(Some(hwnd), 1, 50, None) == 0 {
        return Err(windows::core::Error::from_thread().into());
    }
    ready.send(()).map_err(|_| "board supervisor ended")?;
    let mut message = MSG::default();
    let mut visible = false;
    let mut previous = String::new();
    loop {
        match GetMessageW(&mut message, None, 0, 0).0 {
            -1 => return Err(windows::core::Error::from_thread().into()),
            0 => return Ok(()),
            _ => (),
        }
        if message.hwnd == hwnd && message.message == WM_TIMER {
            // Win32 can re-enter a window procedure while showing/updating
            // windows. Snapshot the display data and release the lock first.
            let (code, text) = {
                let state = session.lock().expect("board session");
                if state.board().phase == Phase::Stopped {
                    return Ok(());
                }
                let Some(code) = state.code() else {
                    continue;
                };
                (
                    (!visible).then(|| code.to_owned()),
                    display_text(state.board()),
                )
            };
            if let Some(code) = code {
                let title = HSTRING::from(format!("Compare code {code} with the person using the viewer.\r\nAllow shares control of this practice board for up to two minutes."));
                SetWindowTextW(attribution, PCWSTR(title.as_ptr()))?;
                let _ = ShowWindow(hwnd, SW_SHOW);
                visible = true;
            }
            if previous != text {
                SetWindowTextW(display, &HSTRING::from(text.as_str()))?;
                previous = text;
            }
        }
        let _ = TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };
    use windows::{core::BOOL, Win32::System::Threading::GetCurrentThreadId};

    unsafe extern "system" fn find_board(hwnd: HWND, output: LPARAM) -> BOOL {
        let mut class = [0u16; 64];
        let len = GetClassNameW(hwnd, &mut class) as usize;
        if class[..len]
            .iter()
            .copied()
            .eq("Flyw8tOwnedControlFixture".encode_utf16())
        {
            *(output.0 as *mut HWND) = hwnd;
        }
        true.into()
    }

    #[test]
    fn synthetic_wts_change_stops_our_hidden_observer_before_consent() {
        let session = Arc::new(Mutex::new(BoardSession::with_observer(|| {
            Ok(super::super::login::fixture(3, 100))
        })));
        let observed = session.clone();
        let (id_tx, id_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let worker = thread::spawn(move || {
            id_tx.send(unsafe { GetCurrentThreadId() }).unwrap();
            run(observed, ready_tx).map_err(|e| e.to_string())
        });

        let owner_thread = id_rx.recv().unwrap();
        let mut hwnd = HWND::default();
        let mut sent = false;
        if ready_rx.blocking_recv().is_ok() {
            unsafe {
                // Enumerate only this test's observer thread and only its own
                // board class. No message goes to any other app or Windows session.
                let _ = EnumThreadWindows(
                    owner_thread,
                    Some(find_board),
                    LPARAM((&raw mut hwnd) as isize),
                );
                if !hwnd.is_invalid() && !IsWindowVisible(hwnd).as_bool() {
                    sent = PostMessageW(
                        Some(hwnd),
                        WM_WTSSESSION_CHANGE,
                        WPARAM(WTS_SESSION_LOCK as usize),
                        LPARAM(3),
                    )
                    .is_ok();
                }
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while sent
            && session.lock().unwrap().board().phase != Phase::Stopped
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        let stopped = session.lock().unwrap().board().phase == Phase::Stopped;
        session.lock().unwrap().stop();
        worker
            .join()
            .expect("observer thread")
            .expect("watch a hidden board");
        assert!(
            sent,
            "the registered board should be hidden before verification"
        );
        assert!(
            stopped,
            "a WTS transition must end the existing login binding"
        );
        assert!(session
            .lock()
            .unwrap()
            .peer_verified("123456".into())
            .is_err());
    }
}
