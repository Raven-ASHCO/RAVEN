//! Owner-only Windows DACLs for Raven's private files and directories: the
//! Windows half of the 0700 / 0600 modes in [`crate::paths`].
//!
//! A private directory gets a protected DACL (nothing inherited from its
//! parent) holding one Allow ACE: full access for the current user, inherited
//! by every new file and subdirectory (`D:P(A;OICI;FA;;;<user SID>)`). A
//! private file gets the same ACE without the inheritance flags
//! (`D:P(A;;FA;;;<user SID>)`). SYSTEM and the Administrators group get no ACE;
//! an administrator can still take ownership, as root can still read a 0600
//! file. Every change is read back and checked, and any failure is an error,
//! so callers fail closed like the Unix chmod paths (a drive without ACLs,
//! such as FAT32 / exFAT, cannot hold a Raven profile).

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, GetSecurityInfo, SetNamedSecurityInfoW, SetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACL,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const EVERYONE_SID: &str = "S-1-1-0";
const ANONYMOUS_SID: &str = "S-1-5-7";

/// What the DACL is for: a directory (its ACE is inherited by new children)
/// or a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Dir,
    File,
}

impl Kind {
    fn ace_flags(self) -> u8 {
        match self {
            Kind::Dir => (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
            Kind::File => 0,
        }
    }

    fn sddl(self, sid: &str) -> String {
        match self {
            Kind::Dir => format!("D:P(A;OICI;FA;;;{sid})"),
            Kind::File => format!("D:P(A;;FA;;;{sid})"),
        }
    }
}

/// One ACE as read back (SIDs as strings; `sid` is empty for ACE types whose
/// layout is not the plain allow / deny one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AceView {
    pub ace_type: u8,
    pub flags: u8,
    pub mask: u32,
    pub sid: String,
}

/// A DACL as read back. `present == false` covers both "no DACL" and a NULL
/// DACL (everyone gets full access).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaclView {
    pub present: bool,
    pub protected: bool,
    pub aces: Vec<AceView>,
}

impl DaclView {
    /// Exactly the owner-only DACL of `kind` for `sid`.
    pub(crate) fn is_owner_only(&self, kind: Kind, sid: &str) -> bool {
        self.present
            && self.protected
            && self.aces.len() == 1
            && self.aces[0]
                == AceView {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: kind.ace_flags(),
                    mask: FILE_ALL_ACCESS,
                    sid: sid.to_string(),
                }
    }
}

/// The current user's SID (`S-1-5-21-…`), read once per process.
pub(crate) fn user_sid() -> Result<&'static str, String> {
    static SID: OnceLock<String> = OnceLock::new();
    if let Some(sid) = SID.get() {
        return Ok(sid);
    }
    let sid = crate::ipc::win_pipe::current_user_sid()?;
    if sid.is_empty() || sid == EVERYONE_SID || sid == ANONYMOUS_SID {
        return Err(format!(
            "refusing to build an owner-only ACL for SID {sid:?} (not a user)"
        ));
    }
    Ok(SID.get_or_init(|| sid))
}

/// A security descriptor allocated by Windows (LocalAlloc), freed on drop.
struct LocalSd(PSECURITY_DESCRIPTOR);

impl Drop for LocalSd {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Windows call that documents
            // LocalFree as its release, and is freed exactly once.
            unsafe {
                LocalFree(self.0 as _);
            }
        }
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn os_error(code: u32) -> std::io::Error {
    std::io::Error::from_raw_os_error(code as i32)
}

/// The owner-only descriptor of `kind` and the DACL inside it (valid while
/// the descriptor lives).
fn owner_only_sd(kind: Kind) -> Result<(LocalSd, *const ACL), String> {
    let sddl: Vec<u16> = kind
        .sddl(user_sid()?)
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `sddl` is NUL-terminated and outlives the call; `sd` receives a
    // LocalAlloc'd descriptor that `LocalSd` frees; the size out-param is
    // optional.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    };
    if ok == 0 || sd.is_null() {
        return Err(format!(
            "cannot build the owner-only ACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let sd = LocalSd(sd);
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: `sd.0` is a valid descriptor; the out-params are plain locals.
    let ok = unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) };
    if ok == 0 || present == 0 || dacl.is_null() {
        return Err("the owner-only ACL has no DACL".into());
    }
    Ok((sd, dacl))
}

/// SAFETY: `sid` must point to a valid SID.
unsafe fn sid_string(sid: PSID) -> Result<String, String> {
    let mut text: windows_sys::core::PWSTR = null_mut();
    if ConvertSidToStringSidW(sid, &mut text) == 0 || text.is_null() {
        return Err(format!(
            "ConvertSidToStringSidW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut len = 0usize;
    while *text.add(len) != 0 {
        len += 1;
    }
    let out = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
    LocalFree(text as _);
    Ok(out)
}

/// SAFETY: `sd` must be a valid security descriptor read with
/// `DACL_SECURITY_INFORMATION`.
unsafe fn view(sd: PSECURITY_DESCRIPTOR) -> Result<DaclView, String> {
    let mut control = 0u16;
    let mut revision = 0u32;
    if GetSecurityDescriptorControl(sd, &mut control, &mut revision) == 0 {
        return Err(format!(
            "GetSecurityDescriptorControl failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = null_mut();
    if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
        return Err(format!(
            "GetSecurityDescriptorDacl failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let protected = control & SE_DACL_PROTECTED != 0;
    if present == 0 || dacl.is_null() {
        return Ok(DaclView {
            present: false,
            protected,
            aces: Vec::new(),
        });
    }
    let count = (*dacl).AceCount;
    let mut aces = Vec::with_capacity(count as usize);
    for i in 0..count {
        let mut ace: *mut c_void = null_mut();
        if GetAce(dacl, i as u32, &mut ace) == 0 || ace.is_null() {
            return Err(format!(
                "GetAce({i}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let allowed = ace as *const ACCESS_ALLOWED_ACE;
        let header = (*allowed).Header;
        // Allow and deny ACEs share this layout (header, mask, SID); other
        // types (object, callback) differ and only their header is read.
        let (mask, sid) = if header.AceType == ACCESS_ALLOWED_ACE_TYPE
            || header.AceType == ACCESS_DENIED_ACE_TYPE
        {
            let sid_ptr = std::ptr::addr_of!((*allowed).SidStart) as PSID;
            ((*allowed).Mask, sid_string(sid_ptr)?)
        } else {
            (0, String::new())
        };
        aces.push(AceView {
            ace_type: header.AceType,
            flags: header.AceFlags,
            mask,
            sid,
        });
    }
    Ok(DaclView {
        present: true,
        protected,
        aces,
    })
}

/// The DACL of `path` as it is on disk.
pub(crate) fn read_dacl(path: &Path) -> Result<DaclView, String> {
    let name = wide(path);
    let mut dacl: *mut ACL = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `name` is NUL-terminated; `sd` receives a LocalAlloc'd
    // descriptor that `LocalSd` frees; `dacl` points into it.
    let err = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        )
    };
    if err != ERROR_SUCCESS || sd.is_null() {
        return Err(format!(
            "cannot read the ACL of {}: {}",
            path.display(),
            os_error(err)
        ));
    }
    let sd = LocalSd(sd);
    // SAFETY: a descriptor just read with DACL_SECURITY_INFORMATION.
    unsafe { view(sd.0) }
}

fn handle_dacl(handle: HANDLE, path: &Path) -> Result<DaclView, String> {
    let mut dacl: *mut ACL = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `handle` is an open file handle with READ_CONTROL; `sd` is freed
    // by `LocalSd`.
    let err = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        )
    };
    if err != ERROR_SUCCESS || sd.is_null() {
        return Err(format!(
            "cannot read the ACL of {}: {}",
            path.display(),
            os_error(err)
        ));
    }
    let sd = LocalSd(sd);
    // SAFETY: a descriptor just read with DACL_SECURITY_INFORMATION.
    unsafe { view(sd.0) }
}

fn restrict_error(path: &Path, why: impl std::fmt::Display) -> String {
    format!(
        "cannot restrict {} to owner-only: {why} (a drive without ACLs, such as FAT32 or \
         exFAT, cannot hold a Raven profile)",
        path.display()
    )
}

/// Give `path` the owner-only DACL of `kind`, unless it already has exactly
/// that one (a directory change also walks every child that inherits, so it
/// is done once, not on every call). Read back and checked.
pub(crate) fn restrict_path(path: &Path, kind: Kind) -> Result<(), String> {
    let sid = user_sid()?;
    if read_dacl(path)?.is_owner_only(kind, sid) {
        return Ok(());
    }
    let (_sd, dacl) = owner_only_sd(kind)?;
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated; `dacl` lives inside `_sd` for the call.
    let err = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if err != ERROR_SUCCESS {
        return Err(restrict_error(path, os_error(err)));
    }
    if !read_dacl(path)?.is_owner_only(kind, sid) {
        return Err(restrict_error(path, "the ACL read back is not owner-only"));
    }
    Ok(())
}

/// Give the open `file` (opened with WRITE_DAC and READ_CONTROL, see
/// [`OWNER_ONLY_CREATE_ACCESS`]) the owner-only file DACL before anything is
/// written to it. Read back and checked.
pub(crate) fn restrict_open_file(file: &std::fs::File, path: &Path) -> Result<(), String> {
    let sid = user_sid()?;
    let handle = file.as_raw_handle() as HANDLE;
    let (_sd, dacl) = owner_only_sd(Kind::File)?;
    // SAFETY: `handle` is open for the duration (borrowed from `file`) with
    // WRITE_DAC; `dacl` lives inside `_sd` for the call.
    let err = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if err != ERROR_SUCCESS {
        return Err(restrict_error(path, os_error(err)));
    }
    if !handle_dacl(handle, path)?.is_owner_only(Kind::File, sid) {
        return Err(restrict_error(path, "the ACL read back is not owner-only"));
    }
    Ok(())
}

/// Access for a private file being created: write plus the right to set and
/// read back its DACL on the same handle.
pub(crate) const OWNER_ONLY_CREATE_ACCESS: u32 = windows_sys::Win32::Foundation::GENERIC_WRITE
    | windows_sys::Win32::Storage::FileSystem::WRITE_DAC
    | windows_sys::Win32::Storage::FileSystem::READ_CONTROL;

/// Create `path` exclusively (it must not exist), unshared (no other process
/// can open it for reading or writing until it is closed), with the
/// owner-only file DACL set before the caller writes anything.
pub(crate) fn create_new_owner_only(path: &Path) -> Result<std::fs::File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .access_mode(OWNER_ONLY_CREATE_ACCESS)
        .share_mode(0)
        .open(path)
        .map_err(|e| e.to_string())?;
    if let Err(e) = restrict_open_file(&file, path) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_owner_only(path: &Path, kind: Kind) {
        let sid = user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        let dacl = read_dacl(path).unwrap();
        assert!(
            dacl.present && dacl.protected,
            "{}: {dacl:?}",
            path.display()
        );
        assert_eq!(dacl.aces.len(), 1, "{}: {dacl:?}", path.display());
        let ace = &dacl.aces[0];
        assert_eq!(ace.ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(ace.sid, sid);
        assert_eq!(ace.mask, FILE_ALL_ACCESS);
        assert_eq!(ace.flags, kind.ace_flags());
        assert!(dacl.is_owner_only(kind, sid));
    }

    #[test]
    fn private_files_and_dirs_get_an_owner_only_protected_dacl() {
        let root = tempfile::tempdir().unwrap();
        // Before: an ordinary temp dir inherits its parent's ACEs.
        let before = read_dacl(root.path()).unwrap();
        assert!(
            !before.is_owner_only(Kind::Dir, user_sid().unwrap()),
            "{before:?}"
        );

        let dir = root.path().join("profile").join("nested");
        crate::paths::ensure_private_dir(&dir).unwrap();
        assert_owner_only(&dir, Kind::Dir);
        assert_owner_only(&root.path().join("profile"), Kind::Dir);
        // A second call finds it correct and changes nothing.
        crate::paths::ensure_private_dir(&dir).unwrap();
        assert_owner_only(&dir, Kind::Dir);

        let created = dir.join("identity.seed");
        crate::paths::create_new_private(&created, b"secret").unwrap();
        assert_owner_only(&created, Kind::File);
        assert_eq!(std::fs::read(&created).unwrap(), b"secret");
        assert!(crate::paths::create_new_private(&created, b"other").is_err());

        // Into a parent that is NOT private (an existing, ordinary dir): the
        // file itself is still owner-only, and the parent is left alone.
        let shared = root.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let replaced = shared.join("contacts.json");
        crate::paths::atomic_write_private(&replaced, b"one").unwrap();
        crate::paths::atomic_write_private(&replaced, b"two").unwrap();
        assert_owner_only(&replaced, Kind::File);
        assert_eq!(std::fs::read(&replaced).unwrap(), b"two");
        assert!(!read_dacl(&shared)
            .unwrap()
            .is_owner_only(Kind::Dir, user_sid().unwrap()));
        // Missing parents of a private file are created owner-only.
        let deep = shared.join("new").join("relay_key.ed25519");
        crate::paths::create_new_private(&deep, b"k").unwrap();
        assert_owner_only(&shared.join("new"), Kind::Dir);
        assert_owner_only(&deep, Kind::File);

        // An existing dir with inherited ACEs is tightened in place.
        let loose = root.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::write(loose.join("old.json"), b"{}").unwrap();
        crate::paths::ensure_private_dir(&loose).unwrap();
        assert_owner_only(&loose, Kind::Dir);
        // Its existing child now inherits only the owner ACE.
        let child = read_dacl(&loose.join("old.json")).unwrap();
        assert!(
            child.aces.iter().all(|a| a.sid == user_sid().unwrap()),
            "{child:?}"
        );
    }
}
