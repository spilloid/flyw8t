use super::model::{Board, Phase};
use std::sync::{Arc, Mutex, OnceLock};
use windows::{
    core::{w, HSTRING, PCWSTR},
    Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        System::RemoteDesktop::{WTSRegisterSessionNotification, WTSUnRegisterSessionNotification},
        UI::WindowsAndMessaging::*,
    },
};

static BOARD: OnceLock<Arc<Mutex<Board>>> = OnceLock::new();
const ALLOW: usize = 101;
const STOP: usize = 102;
const DISPLAY: i32 = 103;

unsafe extern "system" fn procedure(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND => {
            let Some(board) = BOARD.get() else {
                return LRESULT(0);
            };
            // Only the real, local button controls own these handles. No network
            // message can address native controls or post a window message.
            let id = w.0 & 65535;
            if (id == ALLOW || id == STOP)
                && w.0 >> 16 == BN_CLICKED as usize
                && GetDlgItem(Some(hwnd), id as i32).is_ok_and(|child| child.0 as isize == l.0)
            {
                let mut state = board.lock().expect("board");
                if id == ALLOW {
                    state.allow()
                } else {
                    state.stop()
                }
            }
            LRESULT(0)
        }
        WM_CLOSE | WM_ENDSESSION | WM_QUERYENDSESSION | WM_WTSSESSION_CHANGE => {
            if let Some(board) = BOARD.get() {
                board.lock().expect("board").stop();
            }
            if msg == WM_CLOSE {
                let _ = DestroyWindow(hwnd);
            }
            LRESULT(1)
        }
        WM_DESTROY => {
            let _ = WTSUnRegisterSessionNotification(hwnd);
            if let Some(board) = BOARD.get() {
                board.lock().expect("board").stop();
            }
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}

pub fn run(board: Arc<Mutex<Board>>, code: String) -> windows::core::Result<()> {
    BOARD.set(board.clone()).expect("one board per process");
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
            return Err(windows::core::Error::from_thread());
        }
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
        WTSRegisterSessionNotification(hwnd, 0)?;
        let child = |class, text: &str, id, x, y, width, height| {
            let text = HSTRING::from(text);
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class,
                PCWSTR(text.as_ptr()),
                WS_VISIBLE | WS_CHILD,
                x,
                y,
                width,
                height,
                Some(hwnd),
                Some(HMENU(id as *mut _)),
                Some(instance.into()),
                None,
            )
        };
        child(w!("STATIC"),&format!("Compare code {code} with the person using the viewer.\r\nAllow shares control of this practice board for up to two minutes."),100,16,12,500,50)?;
        child(w!("BUTTON"), "Allow board control", ALLOW, 16, 65, 165, 32)?;
        child(w!("BUTTON"), "Stop", STOP, 195, 65, 100, 32)?;
        let display = child(w!("STATIC"), "", DISPLAY as usize, 16, 110, 495, 180)?;
        let _ = ShowWindow(hwnd, SW_SHOW);
        if SetTimer(Some(hwnd), 1, 50, None) == 0 {
            return Err(windows::core::Error::from_thread());
        }
        let mut message = MSG::default();
        let mut previous = String::new();
        while GetMessageW(&mut message, None, 0, 0).0 > 0 {
            if message.message == WM_TIMER {
                let state = board.lock().expect("board");
                if state.phase == Phase::Stopped {
                    drop(state);
                    let _ = DestroyWindow(hwnd);
                    continue;
                }
                let mut shown = if state.phase == Phase::Waiting {
                    "Waiting for local permission.".to_owned()
                } else {
                    "Technician controls this board. Click Stop to end.".to_owned()
                };
                for row in 0..super::model::ROWS {
                    shown.push_str("\r\n");
                    for col in 0..super::model::COLUMNS {
                        shown.push_str(if (col, row) == (state.x, state.y) {
                            " [X] "
                        } else if Some((col, row)) == state.marked {
                            " [*] "
                        } else {
                            " [  ] "
                        });
                    }
                }
                shown.push_str(&format!("\r\nTyped here: {}", state.text));
                if previous != shown {
                    SetWindowTextW(display, &HSTRING::from(shown.as_str()))?;
                    previous = shown;
                }
            }
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    Ok(())
}
