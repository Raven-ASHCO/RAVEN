#!/usr/bin/env bash
# Linux RELEASE-build keystore smoke (docs/design/2026-10-linux-keystore.md).
# Two profiles, two `raven-node service` daemons on 127.0.0.1, contacts, one
# `raven send` each way, inbox check — with NO lab backend: the debug-only
# locked-file override must be absent (and is proven refused by Release).
#
#   bash node/scripts/linux_release_keystore_two_node.sh                  # passphrase vault
#   bash node/scripts/linux_release_keystore_two_node.sh --secret-service # inside an unlocked
#                                                                         # Secret Service session
# Vault mode hides any session bus, so profile A proves the automatic
# fallback and profile B the explicit RAVEN_KEYSTORE_BACKEND=vault override.
# Passphrases live in 0600 files under the temp work dir (never env/argv).
# Expects `cargo build --locked --release -p raven-node -p ash` to have run.
set -euo pipefail
set +m

MODE="vault"
if [[ "${1:-}" == "--secret-service" ]]; then
  MODE="secret-service"
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "FAIL: this smoke exercises the Linux release keystore (got $(uname -s))" >&2
  exit 1
fi
for lab in RAVEN_IDENTITY_BACKEND RAVEN_SESSION_BACKEND RAVEN_PREKEY_BACKEND \
  RAVEN_CHAT_HISTORY_BACKEND RAVEN_KEYSTORE_PASSPHRASE RAVEN_KEYSTORE_PASSPHRASE_FILE \
  RAVEN_KEYSTORE_BACKEND; do
  unset "$lab"
done
if [[ "$MODE" == "vault" ]]; then
  unset DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../../scripts/lib/harness_util.sh
source "$ROOT/../scripts/lib/harness_util.sh"
RAVEN="$ROOT/target/release/raven"
NODE="$ROOT/target/release/raven-node"
for bin in "$RAVEN" "$NODE"; do
  [[ -x "$bin" ]] || { echo "missing release binary $bin (cargo build --locked --release -p raven-node -p ash)" >&2; exit 1; }
done
WORKDIR="$(mktemp -d /tmp/raven-release-keystore-XXXXXX)"
chmod 700 "$WORKDIR"
A="$WORKDIR/a"
B="$WORKDIR/b"
A_PID=""
B_PID=""
X_PID=""

cleanup() {
  local pid
  for pid in "$A_PID" "$B_PID" "$X_PID"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  sleep 0.2
  for pid in "$A_PID" "$B_PID" "$X_PID"; do
    [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [[ "${RAVEN_KEEP_RELEASE_SMOKE:-}" == "1" ]]; then
    echo "keeping $WORKDIR" >&2
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  for f in "$WORKDIR"/*.log "$WORKDIR"/*.out "$WORKDIR"/*.err; do
    [[ -f "$f" ]] && { echo "--- $f" >&2; tail -n 60 "$f" >&2; }
  done
  exit 1
}

expect_failure() {
  local needle="$1" log="$2"
  shift 2
  if "$@" >"$log" 2>&1 </dev/null; then
    fail "expected failure but succeeded: $*"
  fi
  grep -Fq -- "$needle" "$log" || fail "missing diagnostic '$needle' from: $*"
}

# Per-profile wrappers: the passphrase reaches the binaries only as a file path.
make_wrapper() {
  local name="$1" bin="$2" pass="$3" extra="$4"
  {
    echo '#!/usr/bin/env bash'
    [[ -n "$pass" ]] && printf 'export RAVEN_KEYSTORE_PASSPHRASE_FILE=%q\n' "$pass"
    [[ -n "$extra" ]] && printf 'export %s\n' "$extra"
    printf 'exec %q "$@"\n' "$bin"
  } >"$WORKDIR/$name"
  chmod 700 "$WORKDIR/$name"
}

A_PASS=""
B_PASS=""
B_EXTRA=""
if [[ "$MODE" == "vault" ]]; then
  A_PASS="$WORKDIR/a.passphrase"
  B_PASS="$WORKDIR/b.passphrase"
  ( umask 077
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$A_PASS"; echo >>"$A_PASS"
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$B_PASS"; echo >>"$B_PASS" )
  B_EXTRA="RAVEN_KEYSTORE_BACKEND=vault"
fi
make_wrapper raven-a "$RAVEN" "$A_PASS" ""
make_wrapper raven-b "$RAVEN" "$B_PASS" "$B_EXTRA"
make_wrapper node-a "$NODE" "$A_PASS" ""
make_wrapper node-b "$NODE" "$B_PASS" "$B_EXTRA"
RA="$WORKDIR/raven-a"
RB="$WORKDIR/raven-b"

echo "=== Release refuses the debug locked-file lab backend ==="
mkdir -p "$WORKDIR/lab"
expect_failure "forbidden in Release builds" "$WORKDIR/lab.err" \
  env RAVEN_IDENTITY_BACKEND=locked-file "$RAVEN" --data-dir "$WORKDIR/lab" init

if [[ "$MODE" == "vault" ]]; then
  echo "=== vault: no passphrase source on a non-TTY is refused ==="
  mkdir -p "$WORKDIR/nopass"
  expect_failure "RAVEN_KEYSTORE_PASSPHRASE_FILE" "$WORKDIR/nopass.err" \
    "$RAVEN" --data-dir "$WORKDIR/nopass" init
  expect_failure "is refused" "$WORKDIR/envpass.err" \
    env RAVEN_KEYSTORE_PASSPHRASE=not-allowed "$RAVEN" --data-dir "$WORKDIR/nopass" init
  ( umask 022; echo "a world readable passphrase" >"$WORKDIR/loose.passphrase" )
  expect_failure "chmod 600" "$WORKDIR/loose.err" \
    env RAVEN_KEYSTORE_PASSPHRASE_FILE="$WORKDIR/loose.passphrase" \
    "$RAVEN" --data-dir "$WORKDIR/nopass" init
  [[ ! -e "$WORKDIR/nopass/keystore.vault" ]] || fail "refused init still created a vault"
fi

echo "=== init + prekey publish ($MODE) ==="
mkdir -p "$A" "$B"
"$RA" --data-dir "$A" init </dev/null | tee "$WORKDIR/a.init.out"
"$RB" --data-dir "$B" init </dev/null | tee "$WORKDIR/b.init.out"
A_ADDR=$(grep '^address=' "$WORKDIR/a.init.out" | cut -d= -f2)
B_ADDR=$(grep '^address=' "$WORKDIR/b.init.out" | cut -d= -f2)
A_PUB=$(grep '^pub_hex=' "$WORKDIR/a.init.out" | cut -d= -f2)
B_PUB=$(grep '^pub_hex=' "$WORKDIR/b.init.out" | cut -d= -f2)
[[ -n "$A_ADDR" && -n "$B_ADDR" && -n "$A_PUB" && -n "$B_PUB" ]] || fail "init printed no address/pub_hex"
"$RA" --data-dir "$A" prekey publish </dev/null
"$RB" --data-dir "$B" prekey publish </dev/null

echo "=== recorded keystore + file modes ==="
for dir in "$A" "$B"; do
  if [[ "$MODE" == "vault" ]]; then
    [[ "$(cat "$dir/keystore.backend")" == "passphrase-vault" ]] || fail "$dir keystore.backend is not passphrase-vault"
    [[ "$(cat "$dir/identity.backend")" == "passphrase-vault" ]] || fail "$dir identity.backend is not passphrase-vault"
    [[ "$(stat -c '%a' "$dir/keystore.vault")" == "600" ]] || fail "$dir/keystore.vault is not 0600"
    [[ "$(head -c 8 "$dir/keystore.vault")" == "RVNVLT01" ]] || fail "$dir/keystore.vault has no vault magic"
  else
    [[ "$(cat "$dir/keystore.backend")" == "secret-service" ]] || fail "$dir keystore.backend is not secret-service"
    [[ "$(cat "$dir/identity.backend")" == "linux-secret-service" ]] || fail "$dir identity.backend is not linux-secret-service"
    [[ ! -e "$dir/keystore.vault" ]] || fail "$dir has a vault although Secret Service was reachable"
  fi
  [[ ! -e "$dir/identity.seed" ]] || fail "$dir has a plaintext identity.seed"
  [[ "$(stat -c '%a' "$dir")" == "700" ]] || fail "$dir is not 0700"
done

if [[ "$MODE" == "vault" ]]; then
  echo "=== a wrong passphrase file keeps the daemon down ==="
  ( umask 077; echo "definitely the wrong passphrase" >"$WORKDIR/wrong.passphrase" )
  expect_failure "passphrase is wrong" "$WORKDIR/wrongpass.err" \
    env RAVEN_KEYSTORE_PASSPHRASE_FILE="$WORKDIR/wrong.passphrase" \
    "$NODE" service --data-dir "$A" --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 --timeout-secs 5
  expect_failure "never moves keys" "$WORKDIR/conflict.err" \
    env RAVEN_KEYSTORE_PASSPHRASE_FILE="$A_PASS" RAVEN_KEYSTORE_BACKEND=secret-service \
    "$RAVEN" --data-dir "$A" whoami
fi

echo "=== start two release raven-node services ==="
"$WORKDIR/node-a" service --data-dir "$A" --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
  >"$WORKDIR/a.node.log" 2>&1 &
A_PID=$!
"$WORKDIR/node-b" service --data-dir "$B" --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
  >"$WORKDIR/b.node.log" 2>&1 &
B_PID=$!
for _ in $(seq 1 300); do
  if raven_ipc_up "$RA" "$A" && raven_ipc_up "$RB" "$B" \
    && grep -q "lan_direct: listen" "$WORKDIR/a.node.log" \
    && grep -q "lan_direct: listen" "$WORKDIR/b.node.log"; then
    break
  fi
  if grep -Eqi 'lan_direct failed|service identity preflight failed' \
    "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" 2>/dev/null; then
    fail "daemon preflight failed"
  fi
  kill -0 "$A_PID" 2>/dev/null && kill -0 "$B_PID" 2>/dev/null || fail "a daemon exited"
  sleep 0.1
done
raven_ipc_up "$RA" "$A" && raven_ipc_up "$RB" "$B" || fail "daemons did not answer IPC"
A_DIAL="$(raven_listen_addr "$WORKDIR/a.node.log" lan_direct)"
B_DIAL="$(raven_listen_addr "$WORKDIR/b.node.log" lan_direct)"
[[ -n "$A_DIAL" && -n "$B_DIAL" ]] || fail "no lan_direct listen address in the logs"
echo "A_LAN=$A_DIAL B_LAN=$B_DIAL"

echo "=== contacts ==="
"$RA" --data-dir "$A" contact add --address "$B_ADDR" --pub-hex "$B_PUB" \
  --petname "Bob" --tag bob --lan-dial "$B_DIAL" </dev/null
"$RB" --data-dir "$B" contact add --address "$A_ADDR" --pub-hex "$A_PUB" \
  --petname "Alice" --tag alice --lan-dial "$A_DIAL" </dev/null

send_and_check() {
  local from_bin="$1" from_dir="$2" contact="$3" to_bin="$4" to_dir="$5" body="$6" tag="$7"
  set +e
  printf '%s\n' "$body" | raven_timeout 120 "$from_bin" --data-dir "$from_dir" send --contact "$contact" \
    >"$WORKDIR/$tag.send.out" 2>"$WORKDIR/$tag.send.err"
  local rc=$?
  set -e
  [[ "$rc" -eq 0 ]] || fail "$tag send failed rc=$rc"
  grep -qi 'status.*delivered' "$WORKDIR/$tag.send.out" || fail "$tag sender did not report delivered"
  "$to_bin" --data-dir "$to_dir" inbox </dev/null >"$WORKDIR/$tag.inbox.out" 2>&1 \
    || fail "$tag inbox failed"
  grep -Fq "$body" "$WORKDIR/$tag.inbox.out" || fail "$tag inbox is missing the message"
}

echo "=== raven send A -> B ==="
send_and_check "$RA" "$A" @bob "$RB" "$B" "hello from a over the $MODE" ab
echo "=== raven send B -> A ==="
send_and_check "$RB" "$B" @alice "$RA" "$A" "hello from b over the $MODE" ba

if [[ "$MODE" == "vault" ]]; then
  echo "=== secrets stayed in the vault ==="
  for dir in "$A" "$B"; do
    [[ ! -d "$dir/indexed-session-secrets" ]] || fail "$dir wrote lab session-secret files"
    [[ ! -e "$dir/prekey_lifecycle.protected" ]] || fail "$dir wrote the lab prekey file"
  done
fi

echo "LINUX_RELEASE_KEYSTORE_SMOKE_OK mode=$MODE"
