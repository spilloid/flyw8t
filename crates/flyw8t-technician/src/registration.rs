//! Explicit per-user registration for the browser handoff. Commit the command and
//! its ownership record together so a failed update leaves the old handler usable.
use std::ptr::{null, null_mut};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::{CommitTransaction, CreateTransaction},
    System::Registry::*,
    UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST},
};

const SCHEME: &str = r"Software\Classes\flyw8t";
const COMMAND: &str = r"shell\open\command";
const OWNER: &str = "Flyw8tTechnicianCommand";
const USER_ASSOCIATION: &str =
    r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\flyw8t";
const FOREIGN_CHOICE: &str = "Windows has a different or unreadable default for flyw8t links. Review the link type in Settings > Apps > Default apps.";
const MODIFIED_HANDLER: &str =
    "Another program modified the flyw8t link registration. The existing settings were preserved.";

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn checked(code: u32) -> Result<(), String> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "Windows could not change the browser link setting. {}",
            std::io::Error::from_raw_os_error(code as i32)
        ))
    }
}

struct Transaction(HANDLE);
impl Drop for Transaction {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

impl Key {
    fn open(parent: HKEY, path: &str, transaction: &Transaction) -> Result<Option<Self>, String> {
        let mut key = null_mut();
        let status = unsafe {
            RegOpenKeyTransactedW(
                parent,
                wide(path).as_ptr(),
                0,
                KEY_READ,
                &mut key,
                transaction.0,
                null(),
            )
        };
        if matches!(status, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
            return Ok(None);
        }
        checked(status)?;
        Ok(Some(Self(key)))
    }

    fn counts(&self) -> Result<(u32, u32), String> {
        let (mut subkeys, mut values) = (0, 0);
        unsafe {
            checked(RegQueryInfoKeyW(
                self.0,
                null_mut(),
                null_mut(),
                null(),
                &mut subkeys,
                null_mut(),
                null_mut(),
                &mut values,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            ))?;
        }
        Ok((subkeys, values))
    }

    fn create(parent: HKEY, path: &str, transaction: &Transaction) -> Result<(Self, bool), String> {
        let mut key = null_mut();
        let mut disposition = 0;
        unsafe {
            checked(RegCreateKeyTransactedW(
                parent,
                wide(path).as_ptr(),
                0,
                null(),
                0,
                KEY_READ | KEY_WRITE,
                null(),
                &mut key,
                &mut disposition,
                transaction.0,
                null(),
            ))?;
        }
        Ok((Self(key), disposition == REG_CREATED_NEW_KEY))
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u16>>, String> {
        let mut data = vec![0u16; 32_800];
        let mut bytes = (data.len() * 2) as u32;
        let status = unsafe {
            RegGetValueW(
                self.0,
                null(),
                wide(name).as_ptr(),
                RRF_RT_REG_SZ | RRF_NOEXPAND,
                null_mut(),
                data.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        checked(status)?;
        data.truncate(bytes as usize / 2);
        Ok(Some(data))
    }

    fn write(&self, name: &str, value: &[u16]) -> Result<(), String> {
        unsafe {
            checked(RegSetValueExW(
                self.0,
                wide(name).as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                std::mem::size_of_val(value) as u32,
            ))
        }
    }
}

fn check_owner(
    record: Option<&[u16]>,
    active: Option<&[u16]>,
    requested: &[u16],
    enable: bool,
) -> Result<(), String> {
    if record.is_none() || record != active {
        return Err("Another registration handles flyw8t links for this Windows user.".into());
    }
    if !enable && active != Some(requested) {
        return Err(
            "Another copy of Flyw8t Technician owns these links. Open that copy to remove them."
                .into(),
        );
    }
    Ok(())
}

fn check_progid(progid: Option<&[u16]>) -> Result<(), String> {
    let ours = progid
        .and_then(|s| s.strip_suffix(&[0]))
        .and_then(|s| String::from_utf16(s).ok())
        .is_some_and(|s| s.eq_ignore_ascii_case("flyw8t"));
    if ours {
        Ok(())
    } else {
        Err(FOREIGN_CHOICE.into())
    }
}

// Preferences are owned by Windows. Read both formats without creating,
// changing or deleting any preference, including during unregister.
fn check_user_choice(transaction: &Transaction) -> Result<(), String> {
    if let Some(legacy) = Key::open(
        HKEY_CURRENT_USER,
        &format!(r"{USER_ASSOCIATION}\UserChoice"),
        transaction,
    )? {
        check_progid(legacy.read("ProgId")?.as_deref())?;
    }
    if let Some(latest) = Key::open(
        HKEY_CURRENT_USER,
        &format!(r"{USER_ASSOCIATION}\UserChoiceLatest"),
        transaction,
    )? {
        let id = Key::open(latest.0, "ProgId", transaction)?.ok_or(FOREIGN_CHOICE)?;
        check_progid(id.read("ProgId")?.as_deref())?;
    }
    Ok(())
}

fn check_layout(counts: [(u32, u32); 4]) -> Result<(), String> {
    // Only the root has our three named/default values. The command leaf
    // has its default value. An extra verb, DelegateExecute or other value
    // belongs to someone else and would be lost if we deleted these keys.
    if counts == [(1, 3), (1, 0), (1, 0), (0, 1)] {
        Ok(())
    } else {
        Err(MODIFIED_HANDLER.into())
    }
}

pub fn configure(enable: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = exe
        .to_str()
        .ok_or("Move the app to a local folder with a Unicode path.")?;
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    if path.as_bytes().get(1..3) != Some(b":\\") || path.contains(['%', '"']) {
        return Err("Move the app to a local drive in a folder without a percent sign, then enable browser links.".into());
    }
    let command = wide(&format!(r#""{path}" --open-uri "%1""#));
    unsafe {
        let handle = CreateTransaction(null_mut(), null_mut(), 0, 0, 0, 0, null());
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let transaction = Transaction(handle);
        let (root, fresh) = Key::create(HKEY_CURRENT_USER, SCHEME, &transaction)?;
        if fresh && !enable {
            return Ok(());
        }
        check_user_choice(&transaction)?;
        if fresh {
            let mut machine = null_mut();
            let status = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(SCHEME).as_ptr(),
                0,
                KEY_READ,
                &mut machine,
            );
            if status == ERROR_SUCCESS {
                drop(Key(machine));
                return Err("A system-wide app already handles flyw8t links. Contact your Windows administrator.".into());
            }
            if status != ERROR_FILE_NOT_FOUND {
                checked(status)?;
            }
        }
        let (open, _) = Key::create(root.0, COMMAND, &transaction)?;
        if !fresh {
            check_owner(
                root.read(OWNER)?.as_deref(),
                open.read("")?.as_deref(),
                &command,
                enable,
            )?;
            let shell = Key::open(root.0, "shell", &transaction)?.ok_or(MODIFIED_HANDLER)?;
            let verb = Key::open(shell.0, "open", &transaction)?.ok_or(MODIFIED_HANDLER)?;
            check_layout([
                root.counts()?,
                shell.counts()?,
                verb.counts()?,
                open.counts()?,
            ])?;
            if root.read("")?.as_deref() != Some(&wide("URL:Flyw8t Technician"))
                || root.read("URL Protocol")?.as_deref() != Some(&wide(""))
            {
                return Err(MODIFIED_HANDLER.into());
            }
        }
        if enable {
            root.write("", &wide("URL:Flyw8t Technician"))?;
            root.write("URL Protocol", &wide(""))?;
            root.write(OWNER, &command)?;
            open.write("", &command)?;
        }
        drop(open);
        drop(root);
        if !enable {
            for sub in [r"\shell\open\command", r"\shell\open", r"\shell", ""] {
                checked(RegDeleteKeyTransactedW(
                    HKEY_CURRENT_USER,
                    wide(&format!("{SCHEME}{sub}")).as_ptr(),
                    0,
                    0,
                    transaction.0,
                    null(),
                ))?;
            }
        }
        if CommitTransaction(transaction.0) == 0 {
            return Err(format!(
                "Windows could not save the browser link setting. {}",
                std::io::Error::last_os_error()
            ));
        }
        SHChangeNotify(SHCNE_ASSOCCHANGED as i32, SHCNF_IDLIST, null(), null());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_flyw8t_progid_matches_an_existing_windows_choice() {
        assert!(check_progid(Some(&wide("FlyW8T"))).is_ok());
        for other in ["", "Other.Handler", "flyw8t\0Other", "flyw8t-other"] {
            assert!(check_progid(Some(&wide(other))).is_err());
        }
        assert!(check_progid(None).is_err());
        assert!(check_progid(Some(&[0xd800, 0])).is_err());
    }

    #[test]
    fn changed_verbs_delegates_and_unowned_values_block_registration_changes() {
        let layout = [(1, 3), (1, 0), (1, 0), (0, 1)];
        assert!(check_layout(layout).is_ok());
        // An additional subkey or value, anywhere along the known tree,
        // includes a foreign default verb, command delegate or DDE subkey.
        for index in 0..layout.len() {
            let mut subkey = layout;
            subkey[index].0 += 1;
            assert!(check_layout(subkey).is_err());
            let mut value = layout;
            value[index].1 += 1;
            assert!(check_layout(value).is_err());
        }
    }

    #[test]
    fn registration_honors_existing_handlers_and_only_removes_the_current_copy() {
        let old = wide("previous command");
        let new = wide("requested command");
        for enable in [true, false] {
            assert!(check_owner(None, None, &new, enable).is_err());
            assert!(check_owner(None, Some(&old), &new, enable).is_err());
            assert!(check_owner(Some(&old), Some(&new), &new, enable).is_err());
            assert!(check_owner(Some(&new), Some(&new), &new, enable).is_ok());
        }
        assert!(check_owner(Some(&old), Some(&old), &new, true).is_ok());
        assert!(check_owner(Some(&old), Some(&old), &new, false).is_err());
    }
}
