# shellcheck shell=bash
# Shared helpers for the smoke / proof harnesses (scripts/ and node/scripts/).
# Source it (`source "$ROOT/../scripts/lib/harness_util.sh"`); it only defines
# functions and sets no shell options.
#
# Written for macOS /bin/bash 3.2 as well as Linux bash 5: no associative
# arrays, no `wait -n`, no ${var,,}. macOS has no `timeout` binary.
#
# Every wait below is a bounded poll on an observable condition (file, log
# line, process liveness) — never a fixed sleep standing in for readiness — and
# dumps the log it was waiting on when it gives up, so a failure explains
# itself (cleanup traps usually delete the logs afterwards).
#
# Call these as plain statements: under `set -e` a `return 1` is what stops the
# harness. Inside `if f; then` errexit is suppressed for the whole function body.

# raven_timeout SECS CMD [ARG...]
# Runs CMD and kills its whole process group after SECS (whole seconds).
# Exit status: CMD's, or 124 on timeout (GNU timeout convention). stdin/stdout/
# stderr pass straight through, so it works in pipelines and with redirects.
# Prefers GNU/BusyBox `timeout`, then Homebrew `gtimeout`, then python3 (POSIX
# only). Each candidate is probed first: on Windows (Git Bash) `timeout` is the
# unrelated DOS sleep command and would reject `timeout N cmd`, so there CMD runs
# without a bound (the CI job timeout is the backstop). With nothing usable on a
# POSIX host it also runs CMD unbounded and says so on stderr.
raven_timeout() {
  local secs="$1"
  shift
  if timeout 5 true >/dev/null 2>&1; then
    timeout "$secs" "$@" || return $?
    return 0
  fi
  if gtimeout 5 true >/dev/null 2>&1; then
    gtimeout "$secs" "$@" || return $?
    return 0
  fi
  case "$(uname -s 2>/dev/null)" in
    MINGW* | MSYS* | CYGWIN*)
      "$@" || return $?
      return 0
      ;;
    *)
      if command -v python3 >/dev/null 2>&1; then
        python3 -c '
import os, signal, subprocess, sys
secs = float(sys.argv[1].rstrip("s"))
p = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    rc = p.wait(timeout=secs)
except subprocess.TimeoutExpired:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(p.pid, sig)
        except ProcessLookupError:
            break
        try:
            p.wait(timeout=5)
            break
        except subprocess.TimeoutExpired:
            pass
    sys.exit(124)
sys.exit(128 - rc if rc < 0 else rc)
' "$secs" "$@" || return $?
        return 0
      fi
      ;;
  esac
  echo "raven_timeout: no usable timeout/gtimeout/python3; running without a time bound" >&2
  "$@" || return $?
  return 0
}

# raven_wait_file FILE PID SECS [LOG]
# Waits until FILE exists and is NON-EMPTY (daemons write --write-addr files
# with create+truncate then write, so existence alone can observe an empty
# file). Fails fast when PID dies and after SECS seconds; prints LOG then.
raven_wait_file() {
  local file="$1" pid="$2" secs="$3" log="${4:-}" i
  for ((i = 0; i < secs * 10; i++)); do
    if [[ -s "$file" ]]; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "raven_wait_file: process $pid exited before writing $file" >&2
      if [[ -n "$log" ]]; then cat "$log" >&2 || true; fi
      return 1
    fi
    sleep 0.1
  done
  echo "raven_wait_file: $file not written within ${secs}s" >&2
  if [[ -n "$log" ]]; then cat "$log" >&2 || true; fi
  return 1
}

# raven_wait_log LOG ERE PID SECS
# Waits until LOG contains a line matching the extended regex ERE. Fails fast
# when PID dies and after SECS seconds; prints LOG then.
raven_wait_log() {
  local log="$1" pat="$2" pid="$3" secs="$4" i
  for ((i = 0; i < secs * 10; i++)); do
    if grep -Eq -- "$pat" "$log" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "raven_wait_log: process $pid exited before '$pat' appeared in $log" >&2
      cat "$log" >&2 || true
      return 1
    fi
    sleep 0.1
  done
  echo "raven_wait_log: '$pat' not seen in $log within ${secs}s" >&2
  cat "$log" >&2 || true
  return 1
}

# raven_listen_addr LOG KIND
# Prints the address from the first "raven-node KIND: listen <addr>" line of
# LOG (KIND = lan_direct | internet_direct), i.e. the port the OS actually
# bound for a `--lan-listen 127.0.0.1:0` / `--internet-listen 127.0.0.1:0`.
# Prints nothing when the line is absent.
raven_listen_addr() {
  awk -v k="$2: listen" 'index($0, k) { print $NF; exit }' "$1"
}

# raven_ipc_up ASH DATA_DIR
# True when the daemon for DATA_DIR answers a Ping on its REAL IPC endpoint
# (`ash ipc-ping`). Use this, never `[[ -S "$dir/raven-node.sock" ]]`: a long data
# dir (deep checkout, sandbox TMPDIR) is served on the /tmp/raven-<uid>/ fallback
# socket, which that test can never see, so a healthy daemon looks dead.
raven_ipc_up() {
  "$1" --data-dir "$2" ipc-ping >/dev/null 2>&1
}

# raven_wait_ipc ASH DATA_DIR PID SECS [LOG]
# Waits until raven_ipc_up. Fails fast when PID dies and after SECS seconds;
# prints LOG then.
raven_wait_ipc() {
  local ash="$1" dir="$2" pid="$3" secs="$4" log="${5:-}" i
  for ((i = 0; i < secs * 10; i++)); do
    if raven_ipc_up "$ash" "$dir"; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "raven_wait_ipc: process $pid exited before answering IPC for $dir" >&2
      if [[ -n "$log" ]]; then cat "$log" >&2 || true; fi
      return 1
    fi
    sleep 0.1
  done
  echo "raven_wait_ipc: no IPC answer for $dir within ${secs}s" >&2
  if [[ -n "$log" ]]; then cat "$log" >&2 || true; fi
  return 1
}

# raven_build_bins CRATE_ROOT PACKAGE [PACKAGE...]
# Builds the debug packages a harness is about to run, unless the caller supplied
# prebuilt binaries (RAVEN_BIN_DIR is set, e.g. a private copy). It ALWAYS runs
# `cargo build` otherwise: that is a no-op when the tree is fresh, and the only way
# a code change reaches the test. `[[ -x "$BIN" ]] || cargo build` reused whatever
# binary was lying in target/debug, however stale, and one built with another
# feature set by an earlier harness.
raven_build_bins() {
  local root="$1" args=() p
  shift
  if [[ -n "${RAVEN_BIN_DIR:-}" || "$#" -eq 0 ]]; then
    return 0
  fi
  for p in "$@"; do
    args+=(-p "$p")
  done
  # (bash 3.2 + `set -u` rejects "${args[@]}" on an empty array: guarded above.)
  (cd "$root" && cargo build "${args[@]}" -q)
}
