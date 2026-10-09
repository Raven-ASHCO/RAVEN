# shellcheck shell=bash
# Shared IPC-surface containment guard for the O6 checks
# (scripts/o6_m1_same_rvn1_bind_check.sh, scripts/o6_try_phase_gap_check.sh).
#
# The guard must fail when `pub enum IpcRequest` grows a plaintext-seal or a
# Whoami op. It used to be written `grep -Eq 'enum IpcRequest' -A 50 FILE |
# grep ...`: `-q` suppresses all output, so the second grep always read empty
# input and the `if` could never fire. Here the enum body is extracted first
# (awk) and matched through a here-string, and a missing enum is an error
# rather than a silent pass (a rename would otherwise disable the guard).
#
# Bash 3.2 compatible. Sourced; sets no shell options.

# o6_ipc_request_body FILE — print the `pub enum IpcRequest { ... }` text.
o6_ipc_request_body() {
  awk '/^pub enum IpcRequest/ { on = 1 } on { print } on && /^}/ { exit }' "$1"
}

# o6_ipc_guard FILE — status: 0 clean, 2 enum not found, 3 plaintext-seal op,
# 4 Whoami op. `SealUnderSession` (ADR 0004 D4 / M2, reviewed) is not in the
# deny-list: only the names of the REFUSED ops are.
o6_ipc_guard() {
  local body
  body="$(o6_ipc_request_body "$1")"
  if [[ -z "$body" ]]; then
    return 2
  fi
  if grep -Eqi 'SealPlaintext|SealPayload|EnqueuePlain' <<<"$body"; then
    return 3
  fi
  if grep -Eq 'Whoami' <<<"$body"; then
    return 4
  fi
  return 0
}

# o6_ipc_guard_selftest — exits 97 unless the guard is clean on a good enum and
# fires (with the right status) on injected forbidden ops and on a missing enum.
o6_ipc_guard_selftest() {
  local d rc f
  d="$(mktemp -d "${TMPDIR:-/tmp}/o6-ipc-guard-selftest.XXXXXX")"
  printf '%s\n' \
    '#[derive(Debug)]' \
    'pub enum IpcRequest {' \
    '    Ping { v: u16 },' \
    '    SealUnderSession { v: u16, peer_hint: String, app_payload_b64: String },' \
    '}' >"$d/ok.rs"
  awk '{ print } /^pub enum IpcRequest/ { print "    SealPlaintext { v: u16 }," }' "$d/ok.rs" >"$d/plain.rs"
  awk '{ print } /^pub enum IpcRequest/ { print "    Whoami { v: u16 }," }' "$d/ok.rs" >"$d/whoami.rs"
  printf 'pub enum Renamed {\n    Ping,\n}\n' >"$d/missing.rs"
  for f in ok:0 plain:3 whoami:4 missing:2; do
    rc=0
    o6_ipc_guard "$d/${f%%:*}.rs" || rc=$?
    if [[ "$rc" != "${f##*:}" ]]; then
      echo "O6 IPC GUARD SELF-TEST FAILED: ${f%%:*} gave status $rc, expected ${f##*:}" >&2
      rm -rf "$d"
      exit 97
    fi
  done
  rm -rf "$d"
  echo "o6 ipc guard self-test OK"
}
