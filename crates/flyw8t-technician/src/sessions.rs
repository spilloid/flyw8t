//! Existing Windows interactive sessions on one operator-selected host.
use crate::target::Target;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionKind {
    Console,
    Rdp,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Active,
    Disconnected,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub id: u32,
    pub kind: SessionKind,
    pub state: SessionState,
    pub account: Option<String>,
    target: Target,
    logon_time: Option<i64>,
}

impl Session {
    pub fn can_shadow(&self) -> bool {
        self.id != 0
            && self.kind != SessionKind::Other
            && self.state == SessionState::Active
            && self.account.is_some()
            && self.logon_time.is_some_and(|t| t > 0)
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desktop = match self.kind {
            SessionKind::Console => "Physical console",
            SessionKind::Rdp => "RDP desktop",
            SessionKind::Other => "Unknown desktop",
        };
        let state = match self.state {
            SessionState::Active => "active",
            SessionState::Disconnected => "disconnected",
            SessionState::Other => "inactive or unknown",
        };
        write!(
            f,
            "{desktop} {} · {state} · {}",
            self.id,
            self.account.as_deref().unwrap_or("account unavailable")
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowMode {
    View,
    RequestControl,
}

fn session(
    target: &Target,
    id: u32,
    state: i32,
    protocol: Option<u16>,
    account: Option<String>,
    logon_time: Option<i64>,
) -> Option<Session> {
    // WTS_CONNECTSTATE_CLASS: Active = 0, Disconnected = 4, Listen = 6.
    if id == 0 || state == 6 {
        return None;
    }
    let kind = match protocol {
        Some(0) => SessionKind::Console,
        Some(2) => SessionKind::Rdp,
        _ => SessionKind::Other,
    };
    let state = match state {
        0 => SessionState::Active,
        4 => SessionState::Disconnected,
        _ => SessionState::Other,
    };
    Some(Session {
        id,
        kind,
        state,
        account,
        target: target.clone(),
        logon_time,
    })
}

fn check_target(target: &Target) -> Result<(), String> {
    // WTS identifies a computer via RPC and cannot address the far end of a forwarded RDP port.
    if target.port != 3389 {
        return Err("Windows session discovery needs the computer’s own hostname or IP. A custom RDP port can point to another computer.".into());
    }
    Ok(())
}

fn check_selection(
    target: &Target,
    selected: &Session,
    current: Option<&Session>,
) -> Result<(), String> {
    check_target(target)?;
    if selected.target != *target || !selected.can_shadow() {
        return Err("Choose an active desktop with a verified Windows user session.".into());
    }
    if current != Some(selected) {
        return Err(
            "The selected Windows session changed. Refresh the list and choose the desktop again."
                .into(),
        );
    }
    Ok(())
}

fn shadow_args(target: &Target, id: u32, mode: ShadowMode) -> Vec<String> {
    let host = if target.host.contains(':') {
        format!("[{}]", target.host)
    } else {
        target.host.clone()
    };
    let mut args = vec![format!("/v:{host}"), format!("/shadow:{id}")];
    if mode == ShadowMode::RequestControl {
        args.push("/control".into());
    }
    args
}

#[cfg(windows)]
pub use platform::{discover, prepare_shadow, ShadowRequest};

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::OsString;
    use std::io;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::ptr::{self, NonNull};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::RemoteDesktop::*;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    struct Server(HANDLE);

    impl Server {
        fn open(target: &Target) -> Result<Self, String> {
            check_target(target)?;
            let host: Vec<u16> = target.host.encode_utf16().chain(Some(0)).collect();
            let handle = unsafe { WTSOpenServerW(host.as_ptr()) };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(discovery_error(io::Error::last_os_error()));
            }
            Ok(Self(handle))
        }

        // The information class fixes the output type. Only request fixed-width Windows
        // POD structures here. WTS owns the returned allocation until WTSFreeMemory.
        unsafe fn query<T: Copy>(&self, id: u32, class: WTS_INFO_CLASS) -> Option<T> {
            let mut raw = ptr::null_mut();
            let mut bytes = 0;
            if unsafe { WTSQuerySessionInformationW(self.0, id, class, &mut raw, &mut bytes) } == 0
            {
                return None;
            }
            let owned = Buffer(NonNull::new(raw)?);
            if (bytes as usize) < std::mem::size_of::<T>() {
                return None;
            }
            Some(unsafe { ptr::read_unaligned(owned.0.as_ptr().cast::<T>()) })
        }

        fn session(&self, target: &Target, id: u32, enumerated_state: i32) -> Option<Session> {
            if id == 0 || enumerated_state == WTSListen {
                return None;
            }
            let protocol = unsafe { self.query::<u16>(id, WTSClientProtocolType) };
            let details = unsafe { self.query::<WTSINFOEXW>(id, WTSSessionInfoEx) }
                .filter(|info| info.Level == 1)
                .map(|info| unsafe { info.Data.WTSInfoExLevel1 })
                .filter(|details| details.SessionId == id);
            let state = details
                .as_ref()
                .map_or(enumerated_state, |d| d.SessionState);
            let account = details.as_ref().and_then(|d| {
                let user = field(&d.UserName);
                let domain = field(&d.DomainName);
                if user.is_empty() {
                    None
                } else if domain.is_empty() {
                    Some(user)
                } else {
                    Some(format!("{domain}\\{user}"))
                }
            });
            session(
                target,
                id,
                state,
                protocol,
                account,
                details.map(|d| d.LogonTime),
            )
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            unsafe { WTSCloseServer(self.0) };
        }
    }

    struct Buffer<T>(NonNull<T>);
    impl<T> Drop for Buffer<T> {
        fn drop(&mut self) {
            unsafe { WTSFreeMemory(self.0.as_ptr().cast()) };
        }
    }

    fn field(s: &[u16]) -> String {
        String::from_utf16_lossy(&s[..s.iter().position(|&x| x == 0).unwrap_or(s.len())])
    }

    fn discovery_error(err: io::Error) -> String {
        match err.raw_os_error() {
            Some(5) => "Windows denied permission to list sessions. Use an account with session query permission or ask the user to share their screen.".into(),
            Some(53 | 1722 | 1231) => "Windows session discovery is unreachable. Check the computer name, VPN and Windows Remote Desktop Services RPC access.".into(),
            _ => format!("Windows could not list sessions ({err}). Check the computer name and session query permission."),
        }
    }

    pub fn discover(target: &Target) -> Result<Vec<Session>, String> {
        let server = Server::open(target)?;
        let mut raw = ptr::null_mut();
        let mut count = 0;
        if unsafe { WTSEnumerateSessionsW(server.0, 0, 1, &mut raw, &mut count) } == 0 {
            return Err(discovery_error(io::Error::last_os_error()));
        }
        let Some(buffer) = NonNull::new(raw).map(Buffer) else {
            return if count == 0 {
                Ok(Vec::new())
            } else {
                Err("Windows returned an incomplete session list.".into())
            };
        };
        // WTSEnumerateSessionsW supplies count entries in this allocation.
        let records = unsafe { std::slice::from_raw_parts(buffer.0.as_ptr(), count as usize) };
        let mut sessions: Vec<_> = records
            .iter()
            .filter_map(|r| server.session(target, r.SessionId, r.State))
            .collect();
        sessions.sort_by_key(|s| s.id);
        Ok(sessions)
    }

    /// Prepare on a worker. Only the UI that still owns this particular request can launch it.
    pub fn prepare_shadow(
        target: &Target,
        selected: &Session,
        mode: ShadowMode,
    ) -> Result<ShadowRequest, String> {
        check_selection(target, selected, Some(selected))?;
        let server = Server::open(target)?;
        let current = server.session(target, selected.id, WTSInit);
        check_selection(target, selected, current.as_ref())?;
        Ok(ShadowRequest {
            checked: Instant::now(),
            args: shadow_args(target, selected.id, mode),
        })
    }

    #[derive(Debug)]
    pub struct ShadowRequest {
        checked: Instant,
        args: Vec<String>,
    }

    impl ShadowRequest {
        pub fn launch(self) -> Result<(), String> {
            if self.checked.elapsed() > Duration::from_secs(5) {
                return Err("The session check expired. Select the desktop and try again.".into());
            }
            let mut path = vec![0u16; 32768];
            let n = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
            if n == 0 || n >= path.len() {
                return Err("Windows could not locate its Remote Desktop client.".into());
            }
            let client = PathBuf::from(OsString::from_wide(&path[..n])).join("mstsc.exe");
            // The user interacts with the system client; creating the process only means it opened.
            std::process::Command::new(client)
                .args(self.args)
                .spawn()
                .map(drop)
                .map_err(|e| format!("Windows could not open its Remote Desktop client ({e})."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Target {
        Target::parse("workstation.example").unwrap()
    }
    fn row(id: u32, state: i32, protocol: Option<u16>, user: &str) -> Session {
        session(
            &host(),
            id,
            state,
            protocol,
            Some(user.into()),
            Some(123_000),
        )
        .unwrap()
    }

    #[test]
    fn service_and_listener_are_excluded_and_each_user_keeps_their_desktop() {
        assert!(session(&host(), 0, 0, Some(0), None, None).is_none());
        assert!(session(&host(), 65536, 6, Some(2), None, None).is_none());
        let console = row(1, 0, Some(0), "A");
        let desktop = row(7, 0, Some(2), "B");
        assert_eq!(console.kind, SessionKind::Console);
        assert_eq!(desktop.kind, SessionKind::Rdp);
        assert!(console.can_shadow() && desktop.can_shadow());
        assert!(check_selection(&host(), &desktop, Some(&console)).is_err());
    }

    #[test]
    fn unavailable_or_changed_sessions_do_not_launch() {
        let selected = row(4, 0, Some(2), "B");
        for row in [
            row(4, 4, Some(2), "B"),
            row(4, 1, Some(2), "B"),
            row(4, 0, None, "B"),
            row(4, 0, Some(1), "B"),
            Session {
                logon_time: None,
                ..selected.clone()
            },
            Session {
                account: None,
                ..selected.clone()
            },
        ] {
            assert!(!row.can_shadow());
            assert!(check_selection(&host(), &row, Some(&row)).is_err());
        }
        for current in [
            row(4, 0, Some(2), "C"),
            Session {
                logon_time: Some(123_001),
                ..selected.clone()
            },
        ] {
            assert!(check_selection(&host(), &selected, Some(&current)).is_err());
        }
        assert!(check_selection(&host(), &selected, None).is_err());
        assert!(check_selection(
            &Target::parse("another.example").unwrap(),
            &selected,
            Some(&selected)
        )
        .is_err());
        assert!(check_target(&Target::parse("workstation.example:3390").unwrap()).is_err());
        assert!(check_selection(&host(), &selected, Some(&selected)).is_ok());
    }

    #[test]
    fn shadow_args_use_the_chosen_session_and_only_explicitly_request_input() {
        assert_eq!(
            shadow_args(&host(), 7, ShadowMode::View),
            ["/v:workstation.example", "/shadow:7"]
        );
        assert_eq!(
            shadow_args(&host(), 3, ShadowMode::RequestControl),
            ["/v:workstation.example", "/shadow:3", "/control"]
        );
        assert_eq!(
            shadow_args(&Target::parse("::1").unwrap(), 8, ShadowMode::View),
            ["/v:[::1]", "/shadow:8"]
        );
    }
}
