#!/usr/bin/env bash
# Self-test for scripts/lib/harness_util.sh (portable timeout, bounded readiness
# polls, bound-address parsing). Runs in a second or two; needs no build.
#
# Usage: bash scripts/harness_util_selftest.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/lib/harness_util.sh
source "$REPO/scripts/lib/harness_util.sh"

D="$(mktemp -d "${TMPDIR:-/tmp}/harness-util-selftest.XXXXXX")"
trap 'rm -rf "$D"' EXIT

check() {
  echo "FAIL: $*" >&2
  exit 1
}

# raven_timeout: kills a long command with status 124, passes statuses and stdin through.
rc=0
raven_timeout 1 sleep 30 || rc=$?
[[ "$rc" -eq 124 ]] || check "raven_timeout: expected 124 on timeout, got $rc"
rc=0
raven_timeout 10 bash -c 'exit 7' || rc=$?
[[ "$rc" -eq 7 ]] || check "raven_timeout: expected the command's status 7, got $rc"
raven_timeout 10 true || check "raven_timeout: a successful command must return 0"
out="$(printf 'piped\n' | raven_timeout 10 cat)"
[[ "$out" == "piped" ]] || check "raven_timeout: stdin must pass through (got '$out')"

# raven_wait_file: an EMPTY file is not ready; a non-empty one is.
: >"$D/empty"
sleep 30 &
holder=$!
rc=0
raven_wait_file "$D/empty" "$holder" 1 2>/dev/null || rc=$?
[[ "$rc" -eq 1 ]] || check "raven_wait_file: empty file must not count as ready (rc=$rc)"
echo "127.0.0.1:1" >"$D/ready"
raven_wait_file "$D/ready" "$holder" 1 || check "raven_wait_file: non-empty file must be ready"

# ...and it fails fast, dumping the log, when the daemon is already dead.
sleep 0.1 &
dead=$!
wait "$dead" || true
echo "daemon-log-line" >"$D/log"
rc=0
raven_wait_file "$D/never" "$dead" 30 "$D/log" 2>"$D/err" || rc=$?
[[ "$rc" -eq 1 ]] || check "raven_wait_file: dead daemon must fail fast (rc=$rc)"
grep -q 'daemon-log-line' "$D/err" || check "raven_wait_file: must print the log when giving up"

# raven_wait_log / raven_listen_addr.
printf 'noise\nraven-node lan_direct: listen 127.0.0.1:4242\n' >"$D/node.log"
raven_wait_log "$D/node.log" 'lan_direct: listen' "$holder" 1 || check "raven_wait_log: pattern present"
[[ "$(raven_listen_addr "$D/node.log" lan_direct)" == "127.0.0.1:4242" ]] \
  || check "raven_listen_addr: wrong address"
[[ -z "$(raven_listen_addr "$D/node.log" internet_direct)" ]] \
  || check "raven_listen_addr: must print nothing for an absent kind"
rc=0
raven_wait_log "$D/node.log" 'never-appears' "$dead" 30 2>/dev/null || rc=$?
[[ "$rc" -eq 1 ]] || check "raven_wait_log: dead daemon must fail fast (rc=$rc)"

# raven_ipc_up / raven_wait_ipc probe the daemon through `ash ipc-ping` (its real
# endpoint), never through a socket file at <data-dir>/raven-node.sock: a long data
# dir is served on the /tmp/raven-<uid>/ fallback, which that test cannot see.
# A fake `ash` answers ipc-ping only while the marker file exists.
cat >"$D/fake-ash" <<'FAKE'
#!/usr/bin/env bash
# usage: fake-ash --data-dir DIR ipc-ping
[[ "$1" == "--data-dir" && "$3" == "ipc-ping" && -e "$2/.ipc-up" ]]
FAKE
chmod +x "$D/fake-ash"
mkdir -p "$D/prof"
rc=0
raven_ipc_up "$D/fake-ash" "$D/prof" || rc=$?
[[ "$rc" -ne 0 ]] || check "raven_ipc_up: a daemon that does not answer must not count as up"
# A socket file under the data dir is NOT readiness (and its absence is not
# "down"): only the ping decides.
: >"$D/prof/raven-node.sock"
rc=0
raven_ipc_up "$D/fake-ash" "$D/prof" || rc=$?
[[ "$rc" -ne 0 ]] || check "raven_ipc_up: a stray raven-node.sock file must not count as up"
rm -f "$D/prof/raven-node.sock"
: >"$D/prof/.ipc-up"
raven_ipc_up "$D/fake-ash" "$D/prof" || check "raven_ipc_up: an answering daemon is up (no socket file needed)"
rm -f "$D/prof/.ipc-up"
# raven_wait_ipc: succeeds once the daemon answers, fails fast when it is dead,
# and gives up (dumping the log) when nothing ever answers.
( sleep 0.4; : >"$D/prof/.ipc-up" ) &
raven_wait_ipc "$D/fake-ash" "$D/prof" "$holder" 10 || check "raven_wait_ipc: must see the daemon come up"
rm -f "$D/prof/.ipc-up"
rc=0
raven_wait_ipc "$D/fake-ash" "$D/prof" "$dead" 30 "$D/log" 2>"$D/err" || rc=$?
[[ "$rc" -eq 1 ]] || check "raven_wait_ipc: dead daemon must fail fast (rc=$rc)"
grep -q 'daemon-log-line' "$D/err" || check "raven_wait_ipc: must print the log when giving up"
rc=0
raven_wait_ipc "$D/fake-ash" "$D/prof" "$holder" 1 "$D/log" 2>"$D/err" || rc=$?
[[ "$rc" -eq 1 ]] || check "raven_wait_ipc: must time out when nothing answers (rc=$rc)"
grep -q 'no IPC answer' "$D/err" || check "raven_wait_ipc: must say it timed out"

# raven_build_bins: always builds (no-op when fresh) unless prebuilt binaries are
# supplied through RAVEN_BIN_DIR. `cargo` is shadowed by a recorder.
cargo() {
  printf '%s|%s\n' "$PWD" "$*" >>"$D/cargo.calls"
}
mkdir -p "$D/crate"
( RAVEN_BIN_DIR="$D/prebuilt" raven_build_bins "$D/crate" raven-node )
[[ ! -e "$D/cargo.calls" ]] || check "raven_build_bins: RAVEN_BIN_DIR must skip the build"
( unset RAVEN_BIN_DIR; raven_build_bins "$D/crate" raven-node raven-swarm )
[[ "$(wc -l <"$D/cargo.calls" | tr -d ' ')" == "1" ]] || check "raven_build_bins: expected exactly one cargo call"
grep -q '/crate|build -p raven-node -p raven-swarm -q$' "$D/cargo.calls" \
  || check "raven_build_bins: wrong cargo invocation: $(cat "$D/cargo.calls")"
unset -f cargo

# Installer helpers (macOS launchd, Linux systemd-user, ash_first_run.sh): profile
# resolution order, systemd word quoting, plist escaping. The functions are
# extracted from the scripts themselves, so this cannot drift from what they run.
fn_of() { sed -n "/^$2() {/,/^}/p" "$1"; }
for script in node/scripts/install/macos_launchd.sh node/scripts/install/linux_systemd_user.sh scripts/ash_first_run.sh; do
  fn_of "$REPO/$script" resolve_data_dir >"$D/resolve.sh"
  [[ -s "$D/resolve.sh" ]] || check "$script: resolve_data_dir not found"
  home="$D/home-$(basename "$script")"
  mkdir -p "$home/.raven-ash"
  resolved() { env "$@" bash -c "source '$D/resolve.sh'; resolve_data_dir"; }
  # Same order as raven-core `resolve_raven_data_dir`.
  [[ "$(resolved -u RAVEN_DATA_DIR -u ASH_DATA_DIR HOME="$home")" == "$home/.raven-ash" ]] \
    || check "$script: a lone legacy ~/.raven-ash must be kept (not orphaned by a new ~/.raven)"
  mkdir -p "$home/.raven"
  [[ "$(resolved -u RAVEN_DATA_DIR -u ASH_DATA_DIR HOME="$home")" == "$home/.raven" ]] \
    || check "$script: ~/.raven wins once it exists"
  [[ "$(resolved -u RAVEN_DATA_DIR ASH_DATA_DIR=/x/ash HOME="$home")" == "/x/ash" ]] \
    || check "$script: ASH_DATA_DIR"
  [[ "$(resolved RAVEN_DATA_DIR=/x/raven ASH_DATA_DIR=/x/ash HOME="$home")" == "/x/raven" ]] \
    || check "$script: RAVEN_DATA_DIR wins over ASH_DATA_DIR"
  [[ "$(resolved -u ASH_DATA_DIR RAVEN_DATA_DIR= HOME="$home")" == "$home/.raven" ]] \
    || check "$script: an empty RAVEN_DATA_DIR is ignored"
done
fn_of "$REPO/node/scripts/install/linux_systemd_user.sh" sd_quote >"$D/sd.sh"
cat >"$D/sd_case.sh" <<'EOS'
source "$1"
sd_quote 'a"b\c%d$e f'
EOS
[[ "$(bash "$D/sd_case.sh" "$D/sd.sh")" == '"a\"b\\c%%d$$e f"' ]] \
  || check "sd_quote: spaces, quotes, backslashes, % and \$ must be escaped for a systemd ExecStart word"
fn_of "$REPO/node/scripts/install/macos_launchd.sh" xml_escape >"$D/xml.sh"
cat >"$D/xml_case.sh" <<'EOS'
source "$1"
xml_escape 'a & <b> "c"'
EOS
[[ "$(bash "$D/xml_case.sh" "$D/xml.sh")" == 'a &amp; &lt;b&gt; "c"' ]] \
  || check "xml_escape: & < > must be escaped inside the launchd plist"

kill "$holder" 2>/dev/null || true
wait "$holder" 2>/dev/null || true
echo "harness_util self-test OK"
