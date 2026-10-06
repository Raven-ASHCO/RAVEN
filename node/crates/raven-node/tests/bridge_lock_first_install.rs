//! `raven-node bridge` also runs on a profile that has no identity yet, so
//! whatever it leaves behind (its per-data-dir lock included) must not trip
//! raven-core's first-install proof and wedge the first `init` / `service`.
//!
//! `init` needs an identity, so it runs in a *child* process with the
//! documented lab backend (debug builds only); no test touches the OS
//! keystore. The bridge ends on its own (`--timeout-secs`), so there is
//! nothing to poll for.

use std::process::{Command, Output, Stdio};

const NODE: &str = env!("CARGO_BIN_EXE_raven-node");

/// Needs the documented lab backend (debug builds only), which the Linux CI job
/// exports for the whole run (`RAVEN_IDENTITY_BACKEND=locked-file`). Elsewhere
/// the test is skipped rather than risk a keystore prompt: run it locally with
/// `RAVEN_IDENTITY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file
/// RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1 cargo test -p raven-node --test bridge_lock_first_install`.
fn lab_identity_available() -> bool {
    let requested = std::env::var("RAVEN_IDENTITY_BACKEND").is_ok_and(|v| v == "locked-file");
    if !(cfg!(debug_assertions) && requested) {
        eprintln!("skipped: needs a debug build and RAVEN_IDENTITY_BACKEND=locked-file");
        return false;
    }
    true
}

fn node() -> Command {
    let mut c = Command::new(NODE);
    c.env("RAVEN_IDENTITY_BACKEND", "locked-file")
        .env("RAVEN_CHAT_HISTORY_BACKEND", "locked-file")
        .env("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null());
    c
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Regression: the bridge lock was `.bridge.lock` on Unix, which the
/// first-install allow-list does not know, so after one `bridge` run on a fresh
/// profile `init` failed with "profile contains state but has no identity
/// continuity record" until the file was removed by hand.
#[test]
fn bridge_on_a_fresh_profile_does_not_block_the_first_identity() {
    if !lab_identity_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("fresh");

    let out = node()
        .args(["bridge", "--data-dir"])
        .arg(&data)
        .args(["--timeout-secs", "1"])
        .output()
        .expect("run bridge");
    assert!(out.status.success(), "bridge failed: {}", text(&out));
    let lock_left_behind = std::fs::read_dir(&data)
        .expect("bridge created the data dir")
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_string_lossy().starts_with(".bridge.lock"));
    assert!(lock_left_behind, "the bridge did not take its lock");

    let out = node()
        .args(["init", "--data-dir"])
        .arg(&data)
        .output()
        .expect("run init");
    assert!(
        out.status.success(),
        "init after a bridge run failed: {}",
        text(&out)
    );
}
