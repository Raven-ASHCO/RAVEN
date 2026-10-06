//! Fail-closed SQLCipher profile env guard (Task 0A.2).
//!
//! Shared by `libsqlite3-sys-raven` build.rs and the standalone
//! `raven-sqlcipher-profile-guard` binary so negatives can assert the
//! diagnostic without racing `openssl-sys` (which also reads `CFLAGS`).

use std::env;
use std::ffi::{OsStr, OsString};

/// Reject host env that can retarget the frozen SQLCipher 4.17.0 codec profile.
/// Panics with a stable diagnostic substring: `forbidden SQLCipher profile override`
/// or `LIBSQLITE3_FLAGS is forbidden`.
pub fn reject_sqlcipher_profile_overrides() {
    if env::var_os("LIBSQLITE3_FLAGS").is_some() {
        panic!(
            "LIBSQLITE3_FLAGS is forbidden for Raven SQLCipher 4.17.0 lab builds (fail-closed profile)"
        );
    }

    reject_openssl_provider_overrides();
    reject_system_library_redirect();

    // `vars_os`, not `vars`: the latter panics on any non-Unicode variable in
    // the process environment, before a single profile check has run.
    if let Err(message) = check_profile_overrides(env::vars_os()) {
        panic!("{message}");
    }
}

/// Reject env that can swap the frozen openssl-src provider for system OpenSSL.
///
/// Stable diagnostic substring: `forbidden OpenSSL provider override`.
pub fn reject_openssl_provider_overrides() {
    if let Err(message) = check_openssl_overrides(env::vars_os()) {
        panic!("{message}");
    }
}

/// Reject env that redirects the `libsqlite3-sys` build to a system library.
///
/// `LIBSQLITE3_SYS_USE_PKG_CONFIG` makes the build script link whatever
/// SQLite/SQLCipher `pkg-config` finds, before any bundled-SQLCipher logic
/// (pin check, profile guard, release hold) runs. A `bundled-sqlcipher*`
/// graph must never take that route.
///
/// Stable diagnostic substring: `forbidden SQLCipher profile override`.
pub fn reject_system_library_redirect() {
    let value = env::var_os("LIBSQLITE3_SYS_USE_PKG_CONFIG");
    let value = value.as_deref().map(OsStr::to_string_lossy);
    if let Err(message) = check_system_library_redirect(value.as_deref()) {
        panic!("{message}");
    }
}

/// Require `openssl-sys` to have actually vendored via openssl-src.
/// Call only from `bundled-sqlcipher-vendored-openssl` builds after deps ran.
pub fn require_dep_openssl_vendored() {
    match env::var("DEP_OPENSSL_VENDORED") {
        Ok(v) if v == "1" => {}
        other => panic!(
            "forbidden OpenSSL provider override: DEP_OPENSSL_VENDORED must be 1 for Raven SQLCipher lab (got {other:?}); system/dynamic OpenSSL is forbidden"
        ),
    }
}

/// Emit `cargo:rerun-if-env-changed` lines for profile-sensitive variables.
pub fn emit_cargo_rerun_if_env_changed() {
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CXX");
    println!("cargo:rerun-if-env-changed=HOST_CC");
    println!("cargo:rerun-if-env-changed=HOST_CXX");
    println!("cargo:rerun-if-env-changed=CPPFLAGS");
    println!("cargo:rerun-if-env-changed=CFLAGS");
    println!("cargo:rerun-if-env-changed=CXXFLAGS");
    println!("cargo:rerun-if-env-changed=LIBSQLITE3_FLAGS");
    println!("cargo:rerun-if-env-changed=LIBSQLITE3_SYS_USE_PKG_CONFIG");
    println!("cargo:rerun-if-env-changed=OPENSSL_NO_VENDOR");
    println!("cargo:rerun-if-env-changed=OPENSSL_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_LIB_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_INCLUDE_DIR");
}

/// Compiler-flag substrings that must not appear in any CFLAGS-like value
/// (compared upper-cased).
const FORBIDDEN_SUBSTRINGS: [&str; 9] = [
    "PBKDF2",
    "SQLITE_TEMP_STORE",
    "SQLITE_HAS_CODEC",
    "SQLITE_EXTRA_INIT",
    "SQLITE_EXTRA_SHUTDOWN",
    "SQLCIPHER_CRYPTO",
    "SQLITE_THREADSAFE",
    "FAST_PBKDF2",
    // build.rs compiles extension loading out of the SQLCipher profile.
    "LOAD_EXTENSION",
];

fn check_profile_overrides<I>(vars: I) -> Result<(), String>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    for (key, val) in vars {
        // Lossy conversion keeps every ASCII byte, so the checks below still
        // see `-D`, `PBKDF2` and friends in an otherwise non-Unicode value.
        check_env_pair(&key.to_string_lossy(), &val.to_string_lossy())?;
    }
    Ok(())
}

fn check_openssl_overrides<I>(vars: I) -> Result<(), String>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    for (key, _val) in vars {
        let key = key.to_string_lossy();
        let key_up = key.to_ascii_uppercase();
        if key_up == "OPENSSL_NO_VENDOR" || key_up.ends_with("_OPENSSL_NO_VENDOR") {
            return Err(format!(
                "forbidden OpenSSL provider override in {key}: OPENSSL_NO_VENDOR is forbidden for Raven SQLCipher lab (require vendored openssl-src)"
            ));
        }
        if key_up == "OPENSSL_DIR"
            || key_up == "OPENSSL_LIB_DIR"
            || key_up == "OPENSSL_INCLUDE_DIR"
            || key_up.ends_with("_OPENSSL_DIR")
            || key_up.ends_with("_OPENSSL_LIB_DIR")
            || key_up.ends_with("_OPENSSL_INCLUDE_DIR")
        {
            return Err(format!(
                "forbidden OpenSSL provider override in {key}: external OPENSSL_* path overrides are forbidden for Raven SQLCipher lab"
            ));
        }
    }
    Ok(())
}

/// Same "set and not `0`" rule the build script applies to the variable.
fn check_system_library_redirect(use_pkg_config: Option<&str>) -> Result<(), String> {
    match use_pkg_config {
        Some(value) if value != "0" => Err(
            "forbidden SQLCipher profile override in LIBSQLITE3_SYS_USE_PKG_CONFIG: a bundled SQLCipher build must not be redirected to a system SQLite/SQLCipher (no pins, no profile guard, no release hold)"
                .to_owned(),
        ),
        _ => Ok(()),
    }
}

/// True when `value[index..]` begins a command-line flag: at the start of the
/// value, or right after whitespace, a quote (a shell-escaped flag list), `,`
/// (`-Wp,-D...`) or `=`. A `-D`, `-U` or `@` inside a path or word such as
/// `/opt/My-Dev/bin/cc` or `openssl@3` is not a flag.
fn flag_starts_at(value: &str, index: usize) -> bool {
    match value[..index].chars().next_back() {
        None => true,
        Some(prev) => prev.is_whitespace() || matches!(prev, '"' | '\'' | ',' | '='),
    }
}

fn contains_flag(value: &str, flag: &str) -> bool {
    value
        .match_indices(flag)
        .any(|(index, _)| flag_starts_at(value, index))
}

/// Check one environment variable. Variables other than the CFLAGS-like and
/// compiler-command ones are not the guard's business.
fn check_env_pair(key: &str, val: &str) -> Result<(), String> {
    let key_up = key.to_ascii_uppercase();
    let is_cflag_like = key_up == "CFLAGS"
        || key_up == "CXXFLAGS"
        || key_up == "CPPFLAGS"
        || key_up.ends_with("_CFLAGS")
        || key_up.ends_with("_CXXFLAGS")
        || key_up.ends_with("_CPPFLAGS")
        || key_up.starts_with("CFLAGS_")
        || key_up.starts_with("CXXFLAGS_")
        || key_up.starts_with("CPPFLAGS_");
    let is_compiler_cmd = key_up == "CC"
        || key_up == "CXX"
        || key_up == "HOST_CC"
        || key_up == "HOST_CXX"
        || key_up.ends_with("_CC")
        || key_up.ends_with("_CXX")
        || key_up.starts_with("CC_")
        || key_up.starts_with("CXX_");

    if !is_cflag_like && !is_compiler_cmd {
        return Ok(());
    }

    // Response files and forced includes can smuggle arbitrary -D macros.
    if contains_flag(val, "@") || contains_flag(val, "-include") {
        return Err(format!(
            "forbidden SQLCipher profile override in {key}: response-file (@) or -include not allowed"
        ));
    }

    if is_compiler_cmd {
        // CC/CXX must be a bare compiler path. Injected argv (e.g.
        // CC='clang -DPBKDF2_ITER=1') is a profile bypass.
        for part in val.split_whitespace().skip(1) {
            let part = part.trim_start_matches(['"', '\'']);
            if part.starts_with('-') || part.starts_with('@') {
                return Err(format!(
                    "forbidden SQLCipher profile override in {key}: compiler command must not include arguments (got {val:?})"
                ));
            }
        }
        if contains_flag(val, "-D") || contains_flag(val, "-U") {
            return Err(format!(
                "forbidden SQLCipher profile override in {key}: embedded compiler flags not allowed (got {val:?})"
            ));
        }
    }

    let val_up = val.to_ascii_uppercase();
    for needle in FORBIDDEN_SUBSTRINGS {
        if val_up.contains(needle) {
            return Err(format!(
                "forbidden SQLCipher profile override in {key}: contains {needle} (value rejected)"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(value: &[u8]) -> OsString {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(value.to_vec())
        }
        #[cfg(not(unix))]
        {
            OsString::from(String::from_utf8_lossy(value).into_owned())
        }
    }

    #[test]
    fn at_sign_inside_a_path_is_not_a_response_file() {
        for (key, val) in [
            ("CPPFLAGS", "-I/opt/homebrew/opt/openssl@3/include"),
            (
                "CFLAGS",
                "-O2 -I/Users/name@host/include -L/opt/openssl@3/lib",
            ),
            ("CC", "/opt/homebrew/opt/gcc@13/bin/gcc"),
            ("CXX", "/Users/name@host/bin/c++"),
        ] {
            assert_eq!(check_env_pair(key, val), Ok(()), "{key}={val}");
        }
    }

    #[test]
    fn dash_d_or_u_inside_a_compiler_path_is_not_a_flag() {
        for (key, val) in [
            ("CC", "/opt/My-Dev/bin/cc"),
            ("CXX", "/opt/x-Universal/bin/c++"),
            ("HOST_CC", "/opt/my-dev-tools/-Dir/cc"),
            ("CC", "ccache /opt/My-Dev/bin/clang"),
        ] {
            assert_eq!(check_env_pair(key, val), Ok(()), "{key}={val}");
        }
    }

    #[test]
    fn response_files_and_forced_includes_are_rejected() {
        for (key, val) in [
            ("CFLAGS", "@/tmp/resp"),
            ("CFLAGS", "-O2 @/tmp/resp"),
            ("CPPFLAGS", "\"@/tmp/resp\""),
            ("CFLAGS", "'@/tmp/resp'"),
            ("CFLAGS", "-Wl,@/tmp/resp"),
            ("CC", "clang @/tmp/resp"),
            ("CFLAGS", "-include /tmp/override.h"),
            ("CFLAGS", "\"-include\" /tmp/override.h"),
            ("CFLAGS", "-O2 -include/tmp/override.h"),
        ] {
            let err = check_env_pair(key, val).expect_err(val);
            assert!(
                err.contains("forbidden SQLCipher profile override"),
                "{key}={val}: {err}"
            );
        }
    }

    #[test]
    fn injected_compiler_arguments_are_rejected_even_when_quoted() {
        for val in [
            "clang -DPBKDF2_ITER=1",
            "clang -DSQLITE_MAX_X=1",
            "clang \"-DSQLITE_MAX_X=1\"",
            "clang '-USQLITE_HAS_CODEC'",
            "clang -Wp,-DFOO=1",
            "-DFOO=1",
            "-UFOO",
            "clang -include x.h",
        ] {
            let err = check_env_pair("CC", val).expect_err(val);
            assert!(
                err.contains("forbidden SQLCipher profile override"),
                "CC={val}: {err}"
            );
        }
    }

    #[test]
    fn profile_macros_in_cflags_are_rejected() {
        for val in [
            "-DPBKDF2_ITER=1",
            "-dpbkdf2_iter=1",
            "-DSQLITE_TEMP_STORE=3",
            "-DSQLCIPHER_CRYPTO_CC",
            "-DSQLITE_ENABLE_LOAD_EXTENSION=1",
        ] {
            let err = check_env_pair("CFLAGS", val).expect_err(val);
            assert!(err.contains("contains "), "CFLAGS={val}: {err}");
        }
        assert!(check_env_pair("CFLAGS_x86_64_apple_darwin", "-DPBKDF2_ITER=1").is_err());
    }

    #[test]
    fn unrelated_variables_are_ignored() {
        for (key, val) in [
            ("PATH", "/opt/homebrew/opt/openssl@3/bin:/usr/bin"),
            ("HOME", "@weird"),
            ("RUSTFLAGS", "-C link-arg=-DPBKDF2"),
        ] {
            assert_eq!(check_env_pair(key, val), Ok(()), "{key}={val}");
        }
    }

    #[test]
    fn non_unicode_environment_does_not_panic_or_hide_a_violation() {
        let clean = vec![
            (os(b"BAD\xff"), os(b"value")),
            (os(b"LATIN1"), os(b"caf\xe9")),
            (os(b"CFLAGS"), os(b"-O2 -I/opt/caf\xe9/include")),
        ];
        assert_eq!(check_profile_overrides(clean.clone()), Ok(()));
        assert_eq!(check_openssl_overrides(clean), Ok(()));

        // Invalid bytes elsewhere in the value must not hide the macro.
        let dirty = vec![(os(b"CFLAGS"), os(b"-I/opt/caf\xe9 -DPBKDF2_ITER=1"))];
        assert!(check_profile_overrides(dirty).is_err());
        let dirty_key = vec![(os(b"BAD\xff_OPENSSL_DIR"), os(b"/x"))];
        assert!(check_openssl_overrides(dirty_key).is_err());
    }

    #[test]
    fn openssl_provider_overrides_are_rejected() {
        for key in [
            "OPENSSL_NO_VENDOR",
            "X86_64_APPLE_DARWIN_OPENSSL_NO_VENDOR",
            "OPENSSL_DIR",
            "OPENSSL_LIB_DIR",
            "OPENSSL_INCLUDE_DIR",
            "AARCH64_APPLE_DARWIN_OPENSSL_DIR",
        ] {
            let err = check_openssl_overrides(vec![(os(key.as_bytes()), os(b"1"))]).expect_err(key);
            assert!(err.contains("forbidden OpenSSL provider override"), "{err}");
        }
        assert_eq!(
            check_openssl_overrides(vec![(os(b"OPENSSL_SRC_PERL"), os(b"/usr/bin/perl"))]),
            Ok(())
        );
    }

    #[test]
    fn pkg_config_redirect_is_rejected_unless_zero_or_unset() {
        assert_eq!(check_system_library_redirect(None), Ok(()));
        assert_eq!(check_system_library_redirect(Some("0")), Ok(()));
        for value in ["1", "true", ""] {
            let err = check_system_library_redirect(Some(value)).expect_err(value);
            assert!(
                err.contains("forbidden SQLCipher profile override"),
                "{err}"
            );
        }
    }
}
