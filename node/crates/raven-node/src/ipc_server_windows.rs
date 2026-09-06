//! Windows named-pipe IPC transport.
//!
//! Binds the canonical `WINDOWS_NAMED_PIPE` endpoint with a current-user-only
//! DACL. Fail closed: if DACL setup fails, do not bind (NULL DACL is world-writable).
//! Framing and request handling are shared with the Unix UDS server
//! (including `SealUnderSession`; unsigned callers never reach handle_req).

use std::path::PathBuf;
use std::sync::Arc;

use raven_core::ipc::{default_pipe_name, WINDOWS_NAMED_PIPE};
use tokio::net::windows::named_pipe::NamedPipeServer;

use super::{open_forward_queue, serve_one};

/// Well-known Everyone / World SID. Must never appear on the pipe DACL.
const EVERYONE_SID: &str = "S-1-1-0";
/// Anonymous Logon — also forbidden on the pipe DACL.
const ANONYMOUS_SID: &str = "S-1-5-7";

/// Current-user-only security descriptor for `CreateNamedPipeW`.
pub(crate) struct UserOnlyPipeSecurity {
    sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
}

impl Drop for UserOnlyPipeSecurity {
    fn drop(&mut self) {
        if !self.sd.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.sd as _);
            }
            self.sd = std::ptr::null_mut();
        }
    }
}

impl UserOnlyPipeSecurity {
    /// Build a protected DACL that grants Generic All to the current user only.
    /// Any failure (token, SID, SDDL, NULL DACL, World ACE) is an error — fail closed.
    pub(crate) fn new() -> Result<Self, String> {
        unsafe { build_current_user_only_sd() }
    }

    fn attributes(&self) -> windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: self.sd,
            bInheritHandle: 0,
        }
    }

    /// Allowed ACE SIDs (string form) for tests / fail-closed verification.
    pub(crate) fn allowed_sids(&self) -> Result<Vec<String>, String> {
        unsafe { collect_allowed_sids(self.sd) }
    }
}

unsafe fn build_current_user_only_sd() -> Result<UserOnlyPipeSecurity, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
        return Err(format!(
            "OpenProcessToken failed (GLE={}); fail closed — not binding pipe",
            last_error()
        ));
    }
    let mut needed = 0u32;
    GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    if needed == 0 {
        CloseHandle(token);
        return Err("GetTokenInformation size failed; fail closed — not binding pipe".into());
    }
    let mut buf = vec![0u8; needed as usize];
    if GetTokenInformation(
        token,
        TokenUser,
        buf.as_mut_ptr() as *mut _,
        needed,
        &mut needed,
    ) == 0
    {
        CloseHandle(token);
        return Err(format!(
            "GetTokenInformation failed (GLE={}); fail closed — not binding pipe",
            last_error()
        ));
    }
    CloseHandle(token);

    let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
    let sid = token_user.User.Sid;
    if sid.is_null() {
        return Err("TOKEN_USER SID is null; fail closed — not binding pipe".into());
    }

    let mut sid_str: windows_sys::core::PWSTR = std::ptr::null_mut();
    if ConvertSidToStringSidW(sid, &mut sid_str) == 0 || sid_str.is_null() {
        return Err(format!(
            "ConvertSidToStringSidW failed (GLE={}); fail closed — not binding pipe",
            last_error()
        ));
    }
    let sid_os = pwstr_to_string(sid_str);
    LocalFree(sid_str as _);
    if sid_os.is_empty() || sid_os == EVERYONE_SID || sid_os == ANONYMOUS_SID {
        return Err(format!(
            "refusing non-user SID {sid_os:?}; fail closed — not binding pipe"
        ));
    }

    // D:P = protected DACL (no inherited ACEs). Single Allow Generic-All for this user.
    let sddl = format!("D:P(A;;GA;;;{sid_os})");
    let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut sd_size = 0u32;
    if ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl_wide.as_ptr(),
        SDDL_REVISION_1,
        &mut sd,
        &mut sd_size,
    ) == 0
        || sd.is_null()
    {
        return Err(format!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed (GLE={}); fail closed — not binding pipe",
            last_error()
        ));
    }

    let mut dacl_present: i32 = 0;
    let mut dacl_defaulted: i32 = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    if GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted) == 0 {
        LocalFree(sd as _);
        return Err("GetSecurityDescriptorDacl failed; fail closed — not binding pipe".into());
    }
    // NULL DACL = world-writable. Absent DACL is equally unusable as an auth gate.
    if dacl_present == 0 || dacl.is_null() {
        LocalFree(sd as _);
        return Err("DACL missing or NULL (world-writable); fail closed — not binding pipe".into());
    }

    let owned = UserOnlyPipeSecurity { sd };
    let sids = owned
        .allowed_sids()
        .map_err(|e| format!("{e}; fail closed — not binding pipe"))?;
    if sids.len() != 1 || sids[0] != sid_os {
        return Err(format!(
            "DACL SIDs {sids:?} are not current-user-only ({sid_os}); fail closed — not binding pipe"
        ));
    }
    if sids.iter().any(|s| s == EVERYONE_SID || s == ANONYMOUS_SID) {
        return Err(
            "DACL contains World/Everyone or Anonymous; fail closed — not binding pipe".into(),
        );
    }
    Ok(owned)
}

unsafe fn collect_allowed_sids(
    sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> Result<Vec<String>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        GetAce, GetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACL, PSID,
    };

    const ACCESS_ALLOWED: u8 = 0;
    const ACCESS_DENIED: u8 = 1;

    let mut dacl_present: i32 = 0;
    let mut dacl_defaulted: i32 = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    if GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted) == 0 {
        return Err("GetSecurityDescriptorDacl failed".into());
    }
    if dacl_present == 0 || dacl.is_null() {
        return Err("DACL missing or NULL".into());
    }
    let ace_count = (*dacl).AceCount;
    let mut out = Vec::with_capacity(ace_count as usize);
    for i in 0..ace_count {
        let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        if GetAce(dacl, u32::from(i), &mut ace_ptr) == 0 || ace_ptr.is_null() {
            return Err(format!("GetAce({i}) failed"));
        }
        let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
        if ace.Header.AceType == ACCESS_DENIED {
            return Err("unexpected ACCESS_DENIED ACE on pipe DACL".into());
        }
        if ace.Header.AceType != ACCESS_ALLOWED {
            return Err(format!("unexpected ACE type {}", ace.Header.AceType));
        }
        let sid = std::ptr::addr_of!(ace.SidStart) as PSID;
        let mut sid_str: windows_sys::core::PWSTR = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut sid_str) == 0 || sid_str.is_null() {
            return Err("ConvertSidToStringSidW(ACE) failed".into());
        }
        let s = pwstr_to_string(sid_str);
        LocalFree(sid_str as _);
        if s == EVERYONE_SID || s == ANONYMOUS_SID {
            return Err(format!("DACL ACE SID {s} is World/Everyone or Anonymous"));
        }
        out.push(s);
    }
    Ok(out)
}

unsafe fn pwstr_to_string(p: windows_sys::core::PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

fn last_error() -> u32 {
    unsafe { windows_sys::Win32::Foundation::GetLastError() }
}

fn create_pipe_instance(
    sec: &UserOnlyPipeSecurity,
    first: bool,
) -> Result<NamedPipeServer, String> {
    use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    let name: Vec<u16> = WINDOWS_NAMED_PIPE
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let sa = sec.attributes();
    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            raven_core::MAX_IPC_FRAME as u32,
            raven_core::MAX_IPC_FRAME as u32,
            0,
            &sa,
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(format!(
            "CreateNamedPipeW {} failed (GLE={}); fail closed",
            WINDOWS_NAMED_PIPE,
            unsafe { GetLastError() }
        ));
    }
    unsafe { NamedPipeServer::from_raw_handle(handle) }
        .map_err(|e| format!("NamedPipeServer wrap failed after bind ({e}); fail closed"))
}

/// Build the current-user DACL, `CreateNamedPipeW`, wrap `NamedPipeServer`,
/// then drop the security descriptor before returning.
///
/// `UserOnlyPipeSecurity` holds a `PSECURITY_DESCRIPTOR` (`*mut c_void`),
/// which is `!Send`. It must not be live across any `.await` — otherwise
/// `run_named_pipe_server` is `!Send` and `tokio::spawn` fails to compile.
fn bind_pipe_instance(first: bool) -> Result<NamedPipeServer, String> {
    // Fail closed *before* CreateNamedPipeW — never bind a world-readable pipe.
    let sec = UserOnlyPipeSecurity::new()?;
    let server = create_pipe_instance(&sec, first)?;
    drop(sec);
    Ok(server)
}

pub(crate) async fn run_named_pipe_server(
    data_dir: PathBuf,
    forward_path: Option<PathBuf>,
) -> Result<(), String> {
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    eprintln!("raven-node ipc: listening {}", default_pipe_name());

    let forward = open_forward_queue(forward_path);
    let data_dir = Arc::new(data_dir);
    let mut first = true;

    loop {
        let mut server = bind_pipe_instance(first)?;
        first = false;
        server
            .connect()
            .await
            .map_err(|e| format!("named pipe connect: {e}"))?;
        let dd = data_dir.clone();
        let fq = forward.clone();
        tokio::spawn(async move {
            serve_one(server, dd, fq).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_is_canonical() {
        assert_eq!(WINDOWS_NAMED_PIPE, r"\\.\pipe\raven-node");
        assert_eq!(default_pipe_name(), r"\\.\pipe\raven-node");
        assert_eq!(default_pipe_name(), WINDOWS_NAMED_PIPE);
    }

    #[test]
    fn dacl_is_current_user_only_no_world() {
        let sec = UserOnlyPipeSecurity::new().expect("current-user DACL");
        let sids = sec.allowed_sids().expect("walk DACL");
        assert_eq!(sids.len(), 1, "DACL must be exactly current-user: {sids:?}");
        assert_ne!(sids[0], EVERYONE_SID);
        assert_ne!(sids[0], ANONYMOUS_SID);
        assert!(
            sids[0].starts_with("S-1-"),
            "expected SID string, got {}",
            sids[0]
        );
    }

    #[tokio::test]
    async fn bind_canonical_pipe_with_user_dacl() {
        // bind_pipe_instance drops the SD before return — same Send boundary as
        // the accept loop (security descriptor must not live across .await).
        let pipe = bind_pipe_instance(true)
            .expect("CreateNamedPipeW \\\\.\\pipe\\raven-node with user DACL");
        drop(pipe);
    }

    #[test]
    fn named_pipe_server_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        assert_send(run_named_pipe_server(PathBuf::from("."), None));
    }
}
