//! Local WTS login incarnation and the calling thread's input desktop.
use std::mem::{size_of, size_of_val};
use windows::{
    core::{BOOL, PWSTR},
    Win32::{
        Foundation::HANDLE,
        System::{RemoteDesktop::*, StationsAndDesktops::*, Threading::GetCurrentThreadId},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Login {
    session: u32,
    logon: i64,
    connection: i64,
    protocol: u16,
}

fn active_login(state: &WTSINFOEX_LEVEL1_W, protocol: u16) -> Option<Login> {
    if state.SessionId == 0
        || state.SessionId == WTS_CURRENT_SESSION
        || state.SessionState != WTSActive
        || state.SessionFlags != WTS_SESSIONSTATE_UNLOCK as i32
        || state.LogonTime <= 0
        || state.ConnectTime < 0
        || (u32::from(protocol) == WTS_PROTOCOL_TYPE_RDP && state.ConnectTime == 0)
        || !matches!(
            u32::from(protocol),
            WTS_PROTOCOL_TYPE_CONSOLE | WTS_PROTOCOL_TYPE_RDP
        )
    {
        return None;
    }
    Some(Login {
        session: state.SessionId,
        logon: state.LogonTime,
        connection: state.ConnectTime,
        protocol,
    })
}

struct WtsBuffer {
    ptr: PWSTR,
    bytes: u32,
}

impl WtsBuffer {
    fn current(class: WTS_INFO_CLASS) -> Result<Self, &'static str> {
        let mut ptr = PWSTR::null();
        let mut bytes = 0;
        unsafe {
            WTSQuerySessionInformationW(None, WTS_CURRENT_SESSION, class, &mut ptr, &mut bytes)
        }
        .map_err(|_| "Windows session information is unavailable")?;
        if ptr.is_null() {
            return Err("Windows returned no session information");
        }
        Ok(Self { ptr, bytes })
    }
}
impl Drop for WtsBuffer {
    fn drop(&mut self) {
        unsafe { WTSFreeMemory(self.ptr.0.cast()) };
    }
}

fn is_default_input(receives_input: bool, name: &[u16]) -> bool {
    let Some(name) = name.strip_suffix(&[0]) else {
        return false;
    };
    receives_input
        && name.len() == 7
        && name
            .iter()
            .zip(b"Default")
            .all(|(&a, &b)| u8::try_from(a).is_ok_and(|ch| ch.eq_ignore_ascii_case(&b)))
}

fn check_input_desktop() -> Result<(), &'static str> {
    // GetThreadDesktop returns a borrowed handle for this exact thread. UOI_IO
    // asks whether that same desktop currently receives input in its session.
    let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) }
        .map_err(|_| "Windows could not identify the practice board desktop")?;
    let handle = HANDLE(desktop.0);
    let mut name = [0u16; 8];
    let mut bytes = 0;
    let mut input = BOOL::default();
    unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            Some(name.as_mut_ptr().cast()),
            size_of_val(&name) as u32,
            Some(&mut bytes),
        )
        .map_err(|_| "Windows could not verify the default input desktop")?;
        GetUserObjectInformationW(
            handle,
            UOI_IO,
            Some((&raw mut input).cast()),
            size_of::<BOOL>() as u32,
            None,
        )
        .map_err(|_| "Windows could not verify the active input desktop")?;
    }
    if bytes != size_of_val(&name) as u32 || !is_default_input(input.as_bool(), &name) {
        return Err("The practice board is no longer on the default input desktop");
    }
    Ok(())
}

pub fn current() -> Result<Login, &'static str> {
    let protocol = WtsBuffer::current(WTSClientProtocolType)?;
    if protocol.bytes as usize != size_of::<u16>() {
        return Err("Windows returned an invalid session protocol");
    }
    // WTSClientProtocolType returns a USHORT. Only the local console and RDP
    // can be the source of a practice board under this capability.
    let protocol = unsafe { protocol.ptr.0.read_unaligned() };
    check_input_desktop()?;
    let info = WtsBuffer::current(WTSSessionInfoEx)?;
    if (info.bytes as usize) < size_of::<WTSINFOEXW>() {
        return Err("Windows returned incomplete login information");
    }
    // This class returns a WTSINFOEXW. Its union is tagged by Level.
    let typed = unsafe { &*info.ptr.0.cast::<WTSINFOEXW>() };
    if typed.Level != 1 {
        return Err("Windows returned an unknown login information level");
    }
    active_login(unsafe { &typed.Data.WTSInfoExLevel1 }, protocol)
        .ok_or("Control requires an active, unlocked Windows console or RDP login")
}

#[cfg(test)]
pub(super) fn fixture(session: u32, logon: i64) -> Login {
    Login {
        session,
        logon,
        connection: 0,
        protocol: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires an unlocked foreground Windows desktop"]
    fn observes_the_same_active_windows_login_twice() {
        let first = current().expect("requires an unlocked Windows console or RDP desktop");
        assert!(current().is_ok_and(|next| next == first));
    }

    fn active() -> WTSINFOEX_LEVEL1_W {
        WTSINFOEX_LEVEL1_W {
            SessionId: 1,
            SessionState: WTSActive,
            SessionFlags: WTS_SESSIONSTATE_UNLOCK as i32,
            LogonTime: 12345,
            ConnectTime: 12346,
            ..Default::default()
        }
    }

    #[test]
    fn console_and_rdp_have_distinct_login_incarnations() {
        let current = active();
        let console = active_login(&current, 0).unwrap();
        let rdp = active_login(&current, 2).unwrap();
        assert_ne!(console, rdp);
        let recycled = WTSINFOEX_LEVEL1_W {
            LogonTime: 54321,
            ..current
        };
        assert_ne!(Some(rdp), active_login(&recycled, 2));
        let reconnected = WTSINFOEX_LEVEL1_W {
            ConnectTime: 23456,
            ..current
        };
        assert_ne!(Some(rdp), active_login(&reconnected, 2));
    }

    #[test]
    fn rejects_unknown_or_inactive_login_evidence() {
        let state = active();
        for invalid in [
            WTSINFOEX_LEVEL1_W {
                SessionId: 0,
                ..state
            },
            WTSINFOEX_LEVEL1_W {
                SessionId: WTS_CURRENT_SESSION,
                ..state
            },
            WTSINFOEX_LEVEL1_W {
                LogonTime: 0,
                ..state
            },
            WTSINFOEX_LEVEL1_W {
                SessionState: WTSDisconnected,
                ..state
            },
            WTSINFOEX_LEVEL1_W {
                SessionFlags: WTS_SESSIONSTATE_LOCK as i32,
                ..state
            },
            WTSINFOEX_LEVEL1_W {
                SessionFlags: WTS_SESSIONSTATE_UNKNOWN as i32,
                ..state
            },
        ] {
            assert!(active_login(&invalid, 2).is_none());
        }
        assert!(active_login(&state, 1).is_none());
        assert!(active_login(&state, u16::MAX).is_none());
        let no_connection_time = WTSINFOEX_LEVEL1_W {
            ConnectTime: 0,
            ..state
        };
        assert!(active_login(&no_connection_time, 2).is_none());
        assert!(active_login(&no_connection_time, 0).is_some());
    }

    #[test]
    fn secure_inactive_and_unidentified_desktops_cannot_receive_control() {
        let name = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<_>>();
        assert!(is_default_input(true, &name("Default")));
        assert!(is_default_input(true, &name("default")));
        assert!(!is_default_input(false, &name("Default")));
        assert!(!is_default_input(true, &name("Winlogon")));
        assert!(!is_default_input(true, &name("")));
        assert!(!is_default_input(true, &name("Default")[..7]));
    }
}
