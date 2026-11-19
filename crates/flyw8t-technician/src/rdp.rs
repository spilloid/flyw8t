//! Windows' RDP ActiveX control, owned by the technician window's OLE STA.
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::rc::Rc;

#[derive(Debug)]
pub enum RdpEvent {
    Connecting,
    TransportConnected,
    LoggedIn,
    LoginNotice(i32),
    Disconnected {
        code: i32,
        extended: i32,
        detail: String,
    },
    Fatal(i32),
}

#[repr(C)]
struct Notice {
    kind: i32,
    reason: i32,
    extended: i32,
    detail: [u16; 512],
}

unsafe extern "C" {
    fn rdp_create(parent: isize, notify: isize, message: u32, session: *mut *mut c_void) -> i32;
    fn rdp_connect(session: *mut c_void, host: *const u16, port: u16, clipboard: i32) -> i32;
    fn rdp_resize(session: *mut c_void, x: i32, y: i32, width: i32, height: i32);
    fn rdp_sync_display(session: *mut c_void) -> i32;
    fn rdp_focus(session: *mut c_void);
    fn rdp_disconnect(session: *mut c_void) -> i32;
    fn rdp_destroy(session: *mut c_void);
    fn rdp_poll(session: *mut c_void, notice: *mut Notice) -> i32;
}

fn check(hr: i32, operation: &str) -> Result<(), String> {
    if hr < 0 {
        let message = std::io::Error::from_raw_os_error(hr);
        Err(format!("{operation} (0x{hr:08X}): {message}"))
    } else {
        Ok(())
    }
}

pub struct RdpSession {
    handle: NonNull<c_void>,
    // The ActiveX host and its connection-point sink belong to this STA.
    _thread: PhantomData<Rc<()>>,
}

impl RdpSession {
    pub fn new(parent_hwnd: isize, event_hwnd: isize, notify_message: u32) -> Result<Self, String> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: the bridge validates both window handles and initializes the out-pointer.
        check(
            unsafe { rdp_create(parent_hwnd, event_hwnd, notify_message, &mut raw) },
            "Opening the Windows Remote Desktop control failed",
        )?;
        Ok(Self {
            handle: NonNull::new(raw).ok_or("Windows did not return an RDP control")?,
            _thread: PhantomData,
        })
    }

    pub fn connect(&self, host: &str, port: u16, clipboard: bool) -> Result<(), String> {
        if host.is_empty() || host.contains('\0') || port == 0 {
            return Err("Enter an RDP host and a port from 1 to 65535.".into());
        }
        let host: Vec<u16> = host.encode_utf16().chain(Some(0)).collect();
        // SAFETY: the server name is NUL-terminated and copied by the bridge before returning.
        check(
            unsafe {
                rdp_connect(
                    self.handle.as_ptr(),
                    host.as_ptr(),
                    port,
                    i32::from(clipboard),
                )
            },
            "Starting the Windows RDP connection failed",
        )
    }

    pub fn resize(&self, x: i32, y: i32, width: i32, height: i32) {
        unsafe { rdp_resize(self.handle.as_ptr(), x, y, width, height) }
    }

    pub fn focus(&self) {
        unsafe { rdp_focus(self.handle.as_ptr()) }
    }

    /// Ask a signed-in host to render at the latest viewport dimensions.
    /// Servers without dynamic display support continue with local SmartSizing.
    pub fn sync_display(&self) -> Result<(), String> {
        check(
            unsafe { rdp_sync_display(self.handle.as_ptr()) },
            "Updating the remote display failed",
        )
    }

    pub fn disconnect(&self) -> Result<(), String> {
        check(
            unsafe { rdp_disconnect(self.handle.as_ptr()) },
            "Disconnect failed",
        )
    }

    pub fn poll(&self) -> Option<RdpEvent> {
        let mut raw = std::mem::MaybeUninit::<Notice>::uninit();
        // SAFETY: the bridge fills the whole fixed-size repr(C) record if it returns TRUE.
        if unsafe { rdp_poll(self.handle.as_ptr(), raw.as_mut_ptr()) } == 0 {
            return None;
        }
        let raw = unsafe { raw.assume_init() };
        Some(match raw.kind {
            1 => RdpEvent::Connecting,
            2 => RdpEvent::TransportConnected,
            3 => RdpEvent::LoggedIn,
            4 => RdpEvent::LoginNotice(raw.reason),
            5 => {
                let end = raw
                    .detail
                    .iter()
                    .position(|c| *c == 0)
                    .unwrap_or(raw.detail.len());
                RdpEvent::Disconnected {
                    code: raw.reason,
                    extended: raw.extended,
                    detail: String::from_utf16_lossy(&raw.detail[..end]),
                }
            }
            6 => RdpEvent::Fatal(raw.reason),
            _ => return None,
        })
    }
}

impl Drop for RdpSession {
    fn drop(&mut self) {
        // SAFETY: one owner, on its creating thread. The bridge detaches events before teardown.
        unsafe { rdp_destroy(self.handle.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null_mut;
    use windows_sys::Win32::System::Ole::{OleInitialize, OleUninitialize};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, WM_APP, WS_OVERLAPPED,
    };

    #[test]
    fn windows_control_activates_and_subscribes_without_a_connection() {
        let hr = unsafe { OleInitialize(null_mut()) };
        check(hr, "Initialize OLE apartment").unwrap();
        let class: Vec<u16> = "STATIC".encode_utf16().chain(Some(0)).collect();
        let host = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                std::ptr::null(),
                WS_OVERLAPPED,
                0,
                0,
                640,
                480,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        assert!(!host.is_null(), "create hidden host window");
        let actual = RdpSession::new(host as isize, host as isize, WM_APP + 20);
        if let Ok(session) = &actual {
            session.resize(0, 0, 640, 480);
            assert!(session.poll().is_none());
        }
        let outcome = actual.map(drop);
        unsafe {
            DestroyWindow(host);
            OleUninitialize();
        }
        outcome.unwrap();
    }
}
