#!/usr/bin/env bash
# Install user-scoped raven-node launchd agent (macOS). Does NOT touch /bin/ash.
#
# LAN exposure is opt-in and identical on every OS installer: the service binds
# 127.0.0.1:7420 unless RAVEN_LAN_LISTEN is set, e.g.
#   RAVEN_LAN_LISTEN=192.168.1.20:7420 bash node/scripts/install/macos_launchd.sh
#
# Internet direct exposure is opt-in the same way (no listener by default):
#   RAVEN_INTERNET_LISTEN=0.0.0.0:7422 bash node/scripts/install/macos_launchd.sh
# (a bare IP gets port 7422). Without it, `raven node internet on --listen
# 0.0.0.0:7422` turns it on later (applied when the agent restarts).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN_DIR="${RAVEN_BIN_DIR:-$HOME/.local/bin}"
# Same profile resolution as `raven`/`ash` and raven-core (RAVEN_DATA_DIR, then
# ASH_DATA_DIR, then a legacy ~/.raven-ash while ~/.raven does not exist, else
# ~/.raven). Resolved BEFORE anything is created: `mkdir ~/.raven` below would
# otherwise orphan an existing legacy identity (contacts pinned its key) and flip
# plain `ash` onto a brand-new, empty profile.
resolve_data_dir() {
  if [[ -n "${RAVEN_DATA_DIR:-}" ]]; then
    printf '%s' "$RAVEN_DATA_DIR"
  elif [[ -n "${ASH_DATA_DIR:-}" ]]; then
    printf '%s' "$ASH_DATA_DIR"
  elif [[ -d "$HOME/.raven-ash" && ! -e "$HOME/.raven" ]]; then
    printf '%s' "$HOME/.raven-ash"
  else
    printf '%s' "$HOME/.raven"
  fi
}
DATA_DIR="$(resolve_data_dir)"
LAN_LISTEN="${RAVEN_LAN_LISTEN:-127.0.0.1:7420}"
INTERNET_LISTEN="${RAVEN_INTERNET_LISTEN:-}"
# IP[:port] / [IPv6][:port] characters only; raven-node validates the rest.
if [[ -n "$INTERNET_LISTEN" && ! "$INTERNET_LISTEN" =~ ^[][0-9A-Za-z.:]+$ ]]; then
  echo "RAVEN_INTERNET_LISTEN must look like 0.0.0.0:7422 or [::]:7422" >&2
  exit 1
fi
LABEL="com.raven.raven-node"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"

mkdir -p "$BIN_DIR" "$HOME/Library/LaunchAgents"
# Identity, sessions and chat history live here: owner-only.
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"
# launchd starts the agent with cwd=/: register absolute paths only. A relative
# RAVEN_DATA_DIR / RAVEN_BIN_DIR would make the agent serve (or exec from) a
# different directory than the one `raven init` just created.
BIN_DIR="$(CDPATH='' cd -- "$BIN_DIR" && pwd)"
DATA_DIR="$(CDPATH='' cd -- "$DATA_DIR" && pwd)"
# Paths are written into XML: escape the three characters that are special there.
xml_escape() {
  local s=$1
  # Quoted patterns and replacements: bash >= 5.2 (patsub_replacement, on by
  # default) reads an unquoted `&` in the replacement as "the matched text",
  # which turned `<` into `<lt;`. Quoted, `&` is literal in every bash.
  s=${s//'&'/'&amp;'}
  s=${s//'<'/'&lt;'}
  s=${s//'>'/'&gt;'}
  printf '%s' "$s"
}
# Internet direct listener: only when asked for (no flag otherwise, so a later
# `raven node internet on` in node_policy.json decides).
internet_listen_plist_args() {
  [[ -n "$INTERNET_LISTEN" ]] || return 0
  printf '    <string>--internet-listen</string>\n    <string>%s</string>\n' "$(xml_escape "$INTERNET_LISTEN")"
}
# --locked: build exactly the audited Cargo.lock.
cargo build --locked -p raven-node -p ash --release --manifest-path "$ROOT/Cargo.toml"
install -m 755 "$ROOT/target/release/raven-node" "$BIN_DIR/raven-node"
install -m 755 "$ROOT/target/release/ash" "$BIN_DIR/raven"
# Optional ash launcher only if safe (not overwriting /bin/ash)
if [[ ! -e /bin/ash ]] || [[ "$(readlink -f "$BIN_DIR/ash" 2>/dev/null || true)" == "$BIN_DIR/raven" ]]; then
  ln -sfn "$BIN_DIR/raven" "$BIN_DIR/ash"
  echo "linked $BIN_DIR/ash -> raven (user-local only)"
else
  echo "NOTE: system /bin/ash exists — use '$BIN_DIR/raven' (never overwrite /bin/ash)"
fi

cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(xml_escape "${BIN_DIR}")/raven-node</string>
    <string>service</string>
    <string>--data-dir</string>
    <string>$(xml_escape "${DATA_DIR}")</string>
    <string>--lan-listen</string>
    <string>$(xml_escape "${LAN_LISTEN}")</string>
    <string>--ble-listen</string>
    <string>127.0.0.1:7421</string>
$(internet_listen_plist_args)
    <string>--timeout-secs</string>
    <string>0</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$(xml_escape "${DATA_DIR}")/raven-node.log</string>
  <key>StandardErrorPath</key><string>$(xml_escape "${DATA_DIR}")/raven-node.err</string>
</dict>
</plist>
EOF

# Identity + prekey must exist before LAN preflight will keep the service up.
"${BIN_DIR}/raven" --data-dir "${DATA_DIR}" init

launchctl bootout "gui/$(id -u)/${LABEL}" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "installed launchd agent ${LABEL}"
echo "data-dir=${DATA_DIR}"
# Where the daemon really listens: a long data dir is served at
# /tmp/raven-<uid>/raven-<hash>.sock, not at <data-dir>/raven-node.sock. Ask the
# installed binary (`doctor` prints `ipc_endpoint=`) instead of guessing.
IPC_EP="$("${BIN_DIR}/raven" --data-dir "${DATA_DIR}" doctor 2>/dev/null \
  | sed -n 's/^[[:space:]]*ipc_endpoint=//p' | head -n1 || true)"
echo "IPC sock: ${IPC_EP:-<unknown: run '${BIN_DIR}/raven --data-dir ${DATA_DIR} doctor' and look for ipc_endpoint=>} (service = lan_direct + ipc)"
echo "LAN listen: ${LAN_LISTEN}"
case "$LAN_LISTEN" in
  127.*|localhost:*|\[::1\]:*)
    echo "LAN peers cannot reach this node (loopback only). To accept LAN peers, re-run with"
    echo "  RAVEN_LAN_LISTEN=<this-Mac-LAN-IP>:7420 and allow raven-node in the macOS firewall." ;;
  *)
    echo "Exposed on ${LAN_LISTEN}: allow inbound TCP 7420 on the LAN only (System Settings → Network → Firewall)." ;;
esac
if [[ -n "$INTERNET_LISTEN" ]]; then
  echo "Internet listen: ${INTERNET_LISTEN} (only your contacts get an answer; anyone can see that the port is open)"
  echo "  If the macOS firewall is on, allow raven-node yourself:"
  echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ${BIN_DIR}/raven-node"
  echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ${BIN_DIR}/raven-node"
  echo "  (an unsigned rebuild may need this again) and forward the TCP port on your router if you are behind NAT."
  echo "  A build with Internet direct off (INTERNET_DIRECT_PRODUCTION_ENABLED=false) keeps the port closed and logs INTERNET_DIRECT_HOLD; check: raven status (internet row)."
else
  echo "Internet listen: off (opt-in: re-run with RAVEN_INTERNET_LISTEN=0.0.0.0:7422, or 'raven node internet on' and restart the agent)"
fi
echo "PATH tip: export PATH=\"${BIN_DIR}:\$PATH\""
