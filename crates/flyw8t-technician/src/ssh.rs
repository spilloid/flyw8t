//! Launch an interactive Windows OpenSSH session for one validated destination.

use crate::target::Target;

fn ssh_arguments(address: &str, account: &str) -> Result<Vec<String>, String> {
    let mut args = vec!["-t".to_owned()];
    let account = account.trim();
    let address = address.trim();
    let (user, host) = match address.split_once('@') {
        Some(_) if !account.is_empty() => {
            return Err("Enter the computer and SSH account in their separate fields.".into());
        }
        Some((user, host)) => (Some(user), host),
        None => ((!account.is_empty()).then_some(account), address),
    };
    if let Some(user) = user {
        if user.is_empty()
            || user.starts_with('-')
            || user.len() > 128
            || !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-\\".contains(&b))
        {
            return Err("Enter a valid Windows SSH account, such as user or DOMAIN\\user.".into());
        }
        args.extend(["-l".to_owned(), user.to_owned()]);
    }
    let target = Target::parse_with_port(host, 22)?;
    args.extend(["-p".to_owned(), target.port.to_string(), target.host]);
    Ok(args)
}

#[cfg(windows)]
pub fn open(address: &str, account: &str) -> Result<(), String> {
    use std::os::windows::{ffi::OsStringExt, process::CommandExt};
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    use windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE;
    let args = ssh_arguments(address, account)?;
    let mut path = vec![0u16; 32768];
    let n = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    if n == 0 || n >= path.len() {
        return Err("Windows could not locate its system directory.".into());
    }
    let client = std::path::PathBuf::from(std::ffi::OsString::from_wide(&path[..n]))
        .join("OpenSSH")
        .join("ssh.exe");
    std::process::Command::new(client)
        .args(args)
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map(drop)
        .map_err(|e| {
            format!("Could not open Windows OpenSSH Client. Check Windows Optional Features ({e}).")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_mode_accepts_only_an_interactive_destination() {
        assert_eq!(
            ssh_arguments("alice@[::1]:2200", "").unwrap(),
            ["-t", "-l", "alice", "-p", "2200", "::1"]
        );
        assert_eq!(
            ssh_arguments("pc.example", "").unwrap(),
            ["-t", "-p", "22", "pc.example"]
        );
        assert_eq!(
            ssh_arguments("pc.example:2200", r"CORP\alice").unwrap(),
            ["-t", "-l", r"CORP\alice", "-p", "2200", "pc.example"]
        );
        assert!(ssh_arguments("alice@pc.example", "bob").is_err());
        for bad in ["-F", "alice@pc", "alice user", "alice;cmd"] {
            assert!(ssh_arguments("pc.example", bad).is_err(), "{bad}");
        }
        for bad in [
            "-oProxyCommand=x",
            "pc.example cmd",
            "alice@pc:0",
            "@pc",
            "user@-F",
        ] {
            assert!(ssh_arguments(bad, "").is_err(), "{bad}");
        }
    }
}
