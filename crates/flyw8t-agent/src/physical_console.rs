//! On-demand, read-only presence of a signed-in account on the physical console.
//! WTSActive can include a locked workstation. The result grants no access.
use flyw8t_protocol::PhysicalConsoleState;

#[cfg(not(windows))]
pub(super) async fn check() -> PhysicalConsoleState {
    PhysicalConsoleState::Unavailable
}

#[cfg(windows)]
pub(super) async fn check() -> PhysicalConsoleState {
    use std::time::Duration;
    use tokio::sync::{oneshot, Semaphore};

    // Windows can take longer than the caller's deadline. Keep the permit
    // until the OS call actually returns, even if the socket has gone away.
    static WORKER: Semaphore = Semaphore::const_new(1);
    let Ok(permit) = WORKER.try_acquire() else {
        return PhysicalConsoleState::Unavailable;
    };
    let (reply, received) = oneshot::channel();
    // A stuck OS call must also leave the service free to exit. Tokio joins
    // blocking pool threads when its runtime shuts down.
    if std::thread::Builder::new()
        .name("physical-console-check".into())
        .spawn(move || {
            let _permit = permit;
            let _ = reply.send(windows::snapshot());
        })
        .is_err()
    {
        return PhysicalConsoleState::Unavailable;
    }
    match tokio::time::timeout(Duration::from_secs(1), received).await {
        Ok(Ok(state)) => state,
        _ => PhysicalConsoleState::Unavailable,
    }
}

#[cfg(windows)]
mod windows {
    use super::PhysicalConsoleState;
    use std::{ptr, slice};
    use windows_sys::Win32::System::RemoteDesktop::{
        WTSActive as WTS_ACTIVE, WTSClientProtocolType, WTSConnectState,
        WTSConnected as WTS_CONNECTED, WTSFreeMemory, WTSGetActiveConsoleSessionId,
        WTSQuerySessionInformationW, WTSUserName, WTS_CURRENT_SERVER_HANDLE, WTS_INFO_CLASS,
    };

    #[derive(PartialEq, Eq)]
    struct Evidence {
        state: i32,
        protocol: u16,
        user_present: bool,
    }

    pub(super) fn snapshot() -> PhysicalConsoleState {
        observe(|| unsafe { WTSGetActiveConsoleSessionId() }, evidence)
    }

    fn observe(
        mut attached: impl FnMut() -> u32,
        mut read: impl FnMut(u32) -> Option<Evidence>,
    ) -> PhysicalConsoleState {
        use PhysicalConsoleState::*;
        let id = attached();
        if id == u32::MAX {
            return if attached() == id {
                NoConsole
            } else {
                Unavailable
            };
        }
        // Session zero is reserved for services on supported Windows versions.
        if id == 0 {
            return Unavailable;
        }
        let Some(first) = read(id) else {
            return Unavailable;
        };
        if attached() != id || read(id).as_ref() != Some(&first) || attached() != id {
            return Unavailable;
        }
        match (first.state, first.protocol, first.user_present) {
            (WTS_ACTIVE, 0, true) => ActiveConsole,
            (WTS_ACTIVE | WTS_CONNECTED, 0, false) => NoInteractiveUser,
            _ => Unavailable,
        }
    }

    fn evidence(id: u32) -> Option<Evidence> {
        let state = query(id, WTSConnectState, |bytes| {
            Some(i32::from_ne_bytes(bytes.try_into().ok()?))
        })?;
        let protocol = query(id, WTSClientProtocolType, |bytes| {
            Some(u16::from_ne_bytes(bytes.try_into().ok()?))
        })?;
        let user_present = query(id, WTSUserName, user_present)?;
        Some(Evidence {
            state,
            protocol,
            user_present,
        })
    }

    // Only a presence bit leaves this callback. Do not format or retain WTSUserName.
    fn user_present(bytes: &[u8]) -> Option<bool> {
        let text = bytes.strip_suffix(&[0, 0])?;
        if !text.len().is_multiple_of(2) || text.chunks_exact(2).any(|unit| unit == [0, 0]) {
            return None;
        }
        Some(!text.is_empty())
    }

    fn query<T>(
        id: u32,
        class: WTS_INFO_CLASS,
        decode: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Option<T> {
        let mut raw = ptr::null_mut();
        let mut len = 0;
        // The local API owns the returned allocation until WTSFreeMemory.
        let ok = unsafe {
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, id, class, &mut raw, &mut len)
        };
        if ok == 0 || raw.is_null() {
            return None;
        }
        struct WtsBuffer(*mut u16);
        impl Drop for WtsBuffer {
            fn drop(&mut self) {
                unsafe { WTSFreeMemory(self.0.cast()) }
            }
        }
        let allocation = WtsBuffer(raw);
        if !(1..=65_536).contains(&len) {
            return None;
        }
        let bytes = unsafe { slice::from_raw_parts(allocation.0.cast::<u8>(), len as usize) };
        decode(bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::System::RemoteDesktop::WTSDisconnected;
        use PhysicalConsoleState::*;

        fn evidence(state: i32, protocol: u16, user_present: bool) -> Option<Evidence> {
            Some(Evidence {
                state,
                protocol,
                user_present,
            })
        }

        #[test]
        fn reports_only_consistent_local_console_facts() {
            for (state, protocol, user, expected) in [
                (WTS_ACTIVE, 0, true, ActiveConsole),
                (WTS_ACTIVE, 0, false, NoInteractiveUser),
                (WTS_CONNECTED, 0, false, NoInteractiveUser),
                (WTS_CONNECTED, 0, true, Unavailable),
                (WTSDisconnected, 0, true, Unavailable),
                (WTS_ACTIVE, 2, true, Unavailable),
                (WTS_ACTIVE, 1, true, Unavailable),
            ] {
                assert_eq!(observe(|| 7, |_| evidence(state, protocol, user)), expected);
            }
            assert_eq!(
                observe(|| u32::MAX, |_| panic!("no session to query")),
                NoConsole
            );
            assert_eq!(observe(|| 0, |_| panic!("service session")), Unavailable);
            assert_eq!(observe(|| 7, |_| None), Unavailable);
        }

        #[test]
        fn ambiguous_changing_or_malformed_observations_are_unavailable() {
            for ids in [[7, 8, 8], [7, 7, 8], [u32::MAX, 7, 7]] {
                let mut ids = ids.into_iter();
                assert_eq!(
                    observe(|| ids.next().unwrap(), |_| evidence(WTS_ACTIVE, 0, true)),
                    Unavailable
                );
            }
            let mut users = [true, false].into_iter();
            assert_eq!(
                observe(|| 7, |_| evidence(WTS_ACTIVE, 0, users.next().unwrap())),
                Unavailable
            );
            assert_eq!(user_present(&[0, 0]), Some(false));
            assert_eq!(user_present(&[65, 0, 0, 0]), Some(true));
            for bytes in [&[][..], &[65, 0], &[65, 0, 0], &[0, 0, 65, 0, 0, 0]] {
                assert_eq!(user_present(bytes), None);
            }
        }

        #[test]
        #[ignore = "read-only snapshot of this machine's Windows physical console"]
        fn current_physical_console() {
            println!("Physical console snapshot: {:?}", snapshot());
        }
    }
}
