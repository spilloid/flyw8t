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

/// Explicit computer policy from Microsoft's TerminalServer.admx, TS_RemoteControl_2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleAccess {
    View,
    Control,
}

impl ConsoleAccess {
    fn policy(value: Option<u32>) -> Result<Self, String> {
        match value {
            Some(2) => Ok(Self::Control),
            Some(4) => Ok(Self::View),
            Some(0) => Err("This computer’s Windows policy disables shadow access.".into()),
            Some(1 | 3) => Err("This computer requires the user’s permission. Choose Help someone for an attended request.".into()),
            None => Err("This computer has no explicit Windows policy for unattended shadow access.".into()),
            Some(_) => Err("Windows returned an unrecognized remote-control policy. Unattended access is unavailable.".into()),
        }
    }

    pub fn permits(self, mode: ShadowMode) -> bool {
        self == Self::Control || mode == ShadowMode::View
    }
}

fn physical_console(rows: Vec<Session>) -> Result<Session, String> {
    let mut active = rows
        .into_iter()
        .filter(|s| s.kind == SessionKind::Console && s.state == SessionState::Active);
    let selected = active.next().ok_or("No active physical console was found. Windows sign-in is available as a separate session choice.")?;
    if active.next().is_some() {
        return Err("Windows reported multiple active physical consoles. Unattended access needs one unambiguous console.".into());
    }
    if !selected.can_shadow() {
        return Err("Windows could not verify the signed-in user on the physical console.".into());
    }
    Ok(selected)
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

fn console_args(
    target: &Target,
    selected: &Session,
    current: &Session,
    access: ConsoleAccess,
    mode: ShadowMode,
) -> Result<Vec<String>, String> {
    if current.kind != SessionKind::Console {
        return Err("The selected desktop is no longer the physical console.".into());
    }
    check_selection(target, selected, Some(current))?;
    if !access.permits(mode) {
        return Err("This computer allows unattended viewing only.".into());
    }
    let mut args = shadow_args(target, selected.id, mode);
    args.push("/noConsentPrompt".into());
    Ok(args)
}

#[cfg(windows)]
pub use platform::{discover, discover_console, prepare_console, prepare_shadow, ShadowRequest};

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
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegConnectRegistryW, RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD,
        RRF_SUBKEY_WOW6464KEY,
    };
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

    fn machine_policy(target: &Target) -> Result<ConsoleAccess, String> {
        check_target(target)?;
        // Read only the applied machine-level policy. An unavailable management
        // interface cannot establish the owner's intent. Windows still enforces access on launch.
        let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<_>>();
        let machine = wide(&format!(r"\\{}", target.host));
        let mut key = ptr::null_mut();
        let status = unsafe { RegConnectRegistryW(machine.as_ptr(), HKEY_LOCAL_MACHINE, &mut key) };
        if status != 0 {
            return Err(format!("Could not verify this computer’s Windows policy. Check Remote Registry reachability and read permission (Windows error {status})."));
        }
        let subkey = wide(r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services");
        let name = wide("Shadow");
        let mut value = 0u32;
        let mut bytes = std::mem::size_of::<u32>() as u32;
        let status = unsafe {
            RegGetValueW(
                key,
                subkey.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
                ptr::null_mut(),
                (&mut value as *mut u32).cast(),
                &mut bytes,
            )
        };
        unsafe { RegCloseKey(key) };
        match status {
            0 if bytes == 4 => ConsoleAccess::policy(Some(value)),
            2 | 3 => ConsoleAccess::policy(None),
            code => Err(format!("Could not read this computer’s Windows remote-control policy (Windows error {code}).")),
        }
    }

    pub fn discover_console(target: &Target) -> Result<(Session, ConsoleAccess), String> {
        let policy = machine_policy(target)?;
        Ok((physical_console(discover(target)?)?, policy))
    }

    pub fn prepare_console(
        target: &Target,
        selected: &Session,
        mode: ShadowMode,
    ) -> Result<ShadowRequest, String> {
        let (current, access) = discover_console(target)?;
        let args = console_args(target, selected, &current, access, mode)?;
        Ok(ShadowRequest {
            checked: Instant::now(),
            args,
        })
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

    #[test]
    fn unattended_console_needs_one_known_active_physical_logon() {
        let console = row(1, 0, Some(0), "A");
        let remote = row(2, 0, Some(2), "B");
        let disconnected = row(3, 4, Some(0), "C");
        assert_eq!(
            physical_console(vec![remote.clone(), console.clone(), disconnected.clone()]).unwrap(),
            console
        );
        assert!(physical_console(vec![remote.clone(), disconnected]).is_err());
        let missing_user = Session {
            account: None,
            ..console.clone()
        };
        assert!(physical_console(vec![console.clone(), missing_user.clone()]).is_err());
        assert!(physical_console(vec![missing_user]).is_err());
        for changed in [
            row(1, 0, Some(0), "Other"),
            Session {
                logon_time: Some(999),
                ..console.clone()
            },
            remote,
            row(1, 4, Some(0), "A"),
        ] {
            assert!(console_args(
                &host(),
                &console,
                &changed,
                ConsoleAccess::Control,
                ShadowMode::View
            )
            .is_err());
        }
    }

    #[test]
    fn machine_policy_limits_each_human_console_request() {
        for policy in [None, Some(0), Some(1), Some(3), Some(5)] {
            assert!(ConsoleAccess::policy(policy).is_err());
        }
        let row = row(1, 0, Some(0), "A");
        let args = |policy, mode| {
            console_args(
                &host(),
                &row,
                &row,
                ConsoleAccess::policy(Some(policy)).unwrap(),
                mode,
            )
        };
        for v in [2, 4] {
            assert_eq!(
                args(v, ShadowMode::View).unwrap(),
                ["/v:workstation.example", "/shadow:1", "/noConsentPrompt"]
            );
        }
        assert!(args(4, ShadowMode::RequestControl).is_err());
        assert_eq!(
            args(2, ShadowMode::RequestControl).unwrap(),
            [
                "/v:workstation.example",
                "/shadow:1",
                "/control",
                "/noConsentPrompt"
            ]
        );
    }
}
