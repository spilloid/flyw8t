//! Folders the agent trusts on Windows: created with their final owner and permissions in the same call, and
//! checked rather than repaired when they already exist.
//!
//! "Repairing" a folder another account created does not make it safe: that account may hold open handles
//! (including one that can change permissions back), may have planted a junction or a hard link, or may own its
//! parent. So a folder flyw8t did not create, or that has changed since, is refused with a message to delete it and
//! start again. Locations come from Windows (known folders), not from environment variables the caller controls.

use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ALREADY_EXISTS, ERROR_INVALID_OWNER};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_REPARSE_POINT,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_System, FOLDERID_Windows,
    SHGetKnownFolderPath, KF_FLAG_DEFAULT,
};

/// Owned by Administrators; SYSTEM and Administrators have full control; nothing inherited from above.
pub const PRIVATE: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// As `PRIVATE`, and Users may read and run what is inside (the program folder).
pub const READABLE: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

/// The access mask Users get in `READABLE` (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE), as Windows writes it back.
const USERS_READ: &[&str] = &["0x1200a9", "FRFX", "FXFR"];

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    let mut out: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: valid GUID pointer, null token (current user), out-pointer to a PWSTR; the result is freed below.
    let hr =
        unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT as _, std::ptr::null_mut(), &mut out) };
    if hr != 0 || out.is_null() {
        if !out.is_null() {
            unsafe { CoTaskMemFree(out as _) };
        }
        return None;
    }
    // SAFETY: SHGetKnownFolderPath returned a NUL-terminated string.
    let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
    let path = std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(out, len) });
    unsafe { CoTaskMemFree(out as _) };
    Some(PathBuf::from(path))
}

/// `C:\ProgramData` (or wherever Windows keeps it), not `%ProgramData%`. No fallback: a guessed path is not one
/// Windows protects.
pub fn program_data() -> Result<PathBuf> {
    known_folder(&FOLDERID_ProgramData).context("Windows did not say where ProgramData is")
}

/// The System folder (`C:\Windows\System32`), from Windows, not `%SystemRoot%`.
pub fn system_folder() -> Result<PathBuf> {
    known_folder(&FOLDERID_System).context("Windows did not say where the System folder is")
}

/// The Windows folder, from Windows, not `%windir%`.
pub fn windows_folder() -> Result<PathBuf> {
    known_folder(&FOLDERID_Windows).context("Windows did not say where the Windows folder is")
}

/// `C:\Program Files` (or wherever Windows keeps it), not `%ProgramFiles%`. No fallback, as above.
pub fn program_files() -> Result<PathBuf> {
    known_folder(&FOLDERID_ProgramFiles).context("Windows did not say where Program Files is")
}

/// Write a warning to the Windows Application event log (source `flyw8t-agent`), for what a service cannot say
/// anywhere else. Best effort.
pub fn event_log_warning(message: &str) {
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_WARNING_TYPE,
    };
    let source = wide(OsStr::new("flyw8t-agent"));
    let text = wide(OsStr::new(message));
    // SAFETY: NUL-terminated strings that outlive the calls; the handle is checked and released.
    unsafe {
        let h = RegisterEventSourceW(std::ptr::null(), source.as_ptr());
        if h.is_null() {
            return;
        }
        let strings = [text.as_ptr()];
        ReportEventW(
            h,
            EVENTLOG_WARNING_TYPE,
            0,
            1,
            std::ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            std::ptr::null(),
        );
        DeregisterEventSource(h);
    }
}

/// What happened when creating a folder.
#[derive(Debug, PartialEq, Eq)]
pub enum Created {
    /// Made now, with `sddl` as its security.
    New,
    /// Already there (to be checked with [`check_tree`]).
    Existed,
    /// This process may not make Administrators the owner: it is not elevated.
    NotElevated,
}

/// Create `dir` (not its parents) with `sddl` as its owner and permissions, in one call.
pub fn create_dir(dir: &Path, sddl: &str) -> Result<Created> {
    let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();
    let s = wide(OsStr::new(sddl));
    // SAFETY: NUL-terminated SDDL; on success `sd` is a LocalAlloc'd descriptor freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            s.as_ptr(),
            1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        bail!(
            "bad security descriptor {sddl}: {}",
            std::io::Error::last_os_error()
        );
    }
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let p = wide(dir.as_os_str());
    // SAFETY: NUL-terminated path, valid attributes for the duration of the call.
    let ok = unsafe { CreateDirectoryW(p.as_ptr(), &attrs) } != 0;
    let err = std::io::Error::last_os_error();
    unsafe { LocalFree(sd) };
    if ok {
        return Ok(Created::New);
    }
    match err.raw_os_error().map(|c| c as u32) {
        Some(ERROR_ALREADY_EXISTS) => Ok(Created::Existed),
        Some(ERROR_INVALID_OWNER) => Ok(Created::NotElevated),
        _ => Err(err).with_context(|| format!("creating {}", dir.display())),
    }
}

/// The owner and DACL of `path`, as SDDL.
fn sddl_of(path: &Path) -> Result<String> {
    let p = wide(path.as_os_str());
    let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    // SAFETY: NUL-terminated path; we only ask for the descriptor, which is LocalAlloc'd and freed below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            info,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        bail!(
            "reading the permissions of {}: {}",
            path.display(),
            std::io::Error::from_raw_os_error(rc as i32)
        );
    }
    let mut out: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `sd` is valid; `out` is LocalAlloc'd and freed below.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            1,
            info,
            &mut out,
            std::ptr::null_mut(),
        )
    };
    unsafe { LocalFree(sd) };
    if ok == 0 || out.is_null() {
        bail!("describing the permissions of {}", path.display());
    }
    let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
    unsafe { LocalFree(out as _) };
    Ok(s)
}

/// Whether an owner-and-DACL SDDL string is one flyw8t would have made: owned by Administrators or SYSTEM; every
/// allow entry for SYSTEM or Administrators, or (only when `readable`) read-and-run for Users; deny entries are fine.
/// With `top`, the DACL must not inherit from the folder above.
pub fn check_sddl(sddl: &str, readable: bool, top: bool) -> std::result::Result<(), String> {
    let rest = sddl.strip_prefix("O:").ok_or("no owner")?;
    let (owner, dacl) = rest.split_once("D:").ok_or("no DACL")?;
    if owner != "BA" && owner != "SY" {
        return Err(format!("owned by {owner}, not Administrators or SYSTEM"));
    }
    let (flags, aces) = dacl.split_at(dacl.find('(').unwrap_or(dacl.len()));
    if top && !flags.contains('P') {
        return Err("inherits permissions from the folder above".into());
    }
    if aces.is_empty() {
        return Err("has no permissions at all".into());
    }
    for ace in aces
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split(")(")
    {
        let f: Vec<&str> = ace.split(';').collect();
        if f.len() != 6 {
            return Err(format!("unexpected entry ({ace})"));
        }
        let (kind, rights, sid) = (f[0], f[2], f[5]);
        let ok = match (kind, sid) {
            ("D", _) => true,
            ("A", "SY" | "BA") => true,
            ("A", "BU") => readable && USERS_READ.contains(&rights),
            _ => false,
        };
        if !ok {
            return Err(format!("grants {rights} to {sid} ({ace})"));
        }
    }
    Ok(())
}

/// Refuse `root` unless it, and everything in it, is as flyw8t makes it: no junctions, symbolic links or other
/// reparse points, no file with a second name (hard link), and every owner and permission passing [`check_sddl`].
pub fn check_tree(root: &Path, readable: bool) -> Result<()> {
    fn walk(path: &Path, readable: bool, top: bool) -> Result<()> {
        let meta = std::fs::symlink_metadata(path)
            .with_context(|| format!("reading {}", path.display()))?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("{} is a junction or link", path.display());
        }
        check_sddl(&sddl_of(path)?, readable, top)
            .map_err(|why| anyhow::anyhow!("{} {why}", path.display()))?;
        if meta.is_dir() {
            for entry in std::fs::read_dir(path)? {
                walk(&entry?.path(), readable, false)?;
            }
        } else {
            let f =
                std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: an open file handle and a zeroed out-struct.
            if unsafe { GetFileInformationByHandle(f.as_raw_handle() as _, &mut info) } == 0 {
                bail!(
                    "reading {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                );
            }
            if info.nNumberOfLinks != 1 {
                bail!("{} has another name (a hard link)", path.display());
            }
        }
        Ok(())
    }
    walk(root, readable, true)
}

/// Make sure `dir` exists as flyw8t makes it: create it locked, or check what is there. `Ok(false)` when this
/// process is not elevated and so could not create it with Administrators as owner.
pub fn ensure_dir(dir: &Path, sddl: &str) -> Result<bool> {
    let readable = sddl == READABLE;
    match create_dir(dir, sddl)? {
        // Check what Windows actually made: a volume without persistent ACLs (FAT, exFAT) accepts the call and
        // ignores the descriptor.
        Created::New => {
            check_tree(dir, readable).with_context(|| {
                format!(
                    "{} could not be locked (is it on a volume without NTFS permissions?)",
                    dir.display()
                )
            })?;
            Ok(true)
        }
        Created::NotElevated => Ok(false),
        Created::Existed => {
            check_tree(dir, readable).with_context(|| {
                format!(
                    "{} was not made by flyw8t, or has been changed since. Check what is in it, delete it, and enroll again",
                    dir.display()
                )
            })?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_flyw8t_makes_passes() {
        assert_eq!(check_sddl(PRIVATE, false, true), Ok(()));
        assert_eq!(check_sddl(READABLE, true, true), Ok(()));
        assert_eq!(
            check_sddl("O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)", false, false),
            Ok(())
        );
        assert_eq!(
            check_sddl("O:SYD:P(D;OICI;FA;;;WD)(A;OICI;FA;;;SY)", false, true),
            Ok(())
        );
    }

    #[test]
    fn anything_else_is_refused() {
        let bad = [
            (
                "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;SY)",
                false,
                true,
                "owned",
            ),
            (
                "O:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                false,
                true,
                "inherits",
            ),
            (
                "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)",
                false,
                true,
                "BU",
            ),
            ("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BU)", true, true, "BU"),
            (
                "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FR;;;S-1-5-21-1-2-3-1001)",
                false,
                true,
                "S-1-5-21",
            ),
            ("O:BAD:P(A;OICIIO;GA;;;CO)", false, true, "CO"),
            ("O:BAD:P", false, true, "no permissions"),
        ];
        for (sddl, readable, top, why) in bad {
            let e = check_sddl(sddl, readable, top).expect_err(sddl);
            assert!(e.contains(why), "{sddl}: {e}");
        }
    }

    #[test]
    fn known_folders_come_from_windows() {
        assert!(program_files().unwrap().is_absolute());
        assert!(program_data().unwrap().is_absolute());
    }

    #[test]
    fn an_existing_folder_is_checked_not_trusted() {
        // A temp folder has the user's own permissions: not elevated, it cannot be created locked, and if it exists
        // it fails the check.
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("state");
        let created = create_dir(&sub, PRIVATE).unwrap();
        if created == Created::NotElevated {
            std::fs::create_dir(&sub).unwrap();
            assert!(check_tree(&sub, false).is_err());
        }
    }
}
