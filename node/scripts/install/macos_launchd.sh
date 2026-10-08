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
#
# libp2p (relay + hole punching, TCP and UDP 7423) is opt-in the same way:
#   RAVEN_P2P_LISTEN=7423 bash node/scripts/install/macos_launchd.sh
# (a port = every interface, IPv4 + IPv6; IP:PORT = that address only; off =
# off even if `raven node p2p on` saved it). RAVEN_P2P_RELAYS=<multiaddr>[,<multiaddr>]
# (at most 2, each ending in /p2p/<relay PeerId>) keeps a reservation on those
# relays; RAVEN_P2P_RELAY=1 also relays for the PeerIds in relay_allow.json;
# RAVEN_UPNP=1|0 saves the router port-mapping choice (`raven node upnp on|off`).
# With RAVEN_UPNP unset, an interactive install that turns p2p listen on asks
# once (Enter = no); a non-interactive one never asks and leaves it unset (off).
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
# libp2p settings: empty = no flag (node_policy.json decides, as today).
P2P_LISTEN="${RAVEN_P2P_LISTEN:-}"
P2P_RELAYS="${RAVEN_P2P_RELAYS:-}"
P2P_RELAY="${RAVEN_P2P_RELAY:-}"
UPNP="${RAVEN_UPNP:-}"
# PORT / IP:PORT / [IPv6]:PORT / on / off characters only; raven-node validates the rest.
if [[ -n "$P2P_LISTEN" && ! "$P2P_LISTEN" =~ ^[][0-9A-Za-z.:]+$ ]]; then
  echo "RAVEN_P2P_LISTEN must look like 7423, 0.0.0.0:7423, [::]:7423 or off" >&2
  exit 1
fi
# Comma separated relay multiaddrs (spaces around commas are ignored). Written
# for macOS /bin/bash 3.2 too: an empty array is never expanded under set -u.
P2P_RELAY_LIST=()
P2P_RELAYS_REST="${P2P_RELAYS},"
while [[ -n "$P2P_RELAYS" && -n "$P2P_RELAYS_REST" ]]; do
  P2P_RELAY_ENTRY="${P2P_RELAYS_REST%%,*}"
  P2P_RELAYS_REST="${P2P_RELAYS_REST#*,}"
  P2P_RELAY_ENTRY="${P2P_RELAY_ENTRY#"${P2P_RELAY_ENTRY%%[![:space:]]*}"}"
  P2P_RELAY_ENTRY="${P2P_RELAY_ENTRY%"${P2P_RELAY_ENTRY##*[![:space:]]}"}"
  [[ -n "$P2P_RELAY_ENTRY" ]] || continue
  if [[ ! "$P2P_RELAY_ENTRY" =~ ^/[0-9A-Za-z./:_-]+$ || "$P2P_RELAY_ENTRY" != */p2p/?* ]]; then
    echo "RAVEN_P2P_RELAYS entries must look like /ip4/203.0.113.7/tcp/7423/p2p/<relay PeerId>" >&2
    exit 1
  fi
  P2P_RELAY_LIST+=("$P2P_RELAY_ENTRY")
done
if [[ ${#P2P_RELAY_LIST[@]} -gt 2 ]]; then
  echo "RAVEN_P2P_RELAYS takes at most 2 relays" >&2
  exit 1
fi
case "$P2P_RELAY" in
  ""|0|1) ;;
  *) echo "RAVEN_P2P_RELAY must be 1 (serve as a relay for relay_allow.json) or 0" >&2; exit 1 ;;
esac
case "$UPNP" in
  ""|0|1) ;;
  *) echo "RAVEN_UPNP must be 1 (map the p2p port on the router) or 0" >&2; exit 1 ;;
esac
# True when this install turns the libp2p listener on (set and not "off").
p2p_listen_requested() {
  [[ -n "$P2P_LISTEN" ]] || return 1
  case "$P2P_LISTEN" in
    [Oo][Ff][Ff]) return 1 ;;
  esac
  return 0
}
# The libp2p port of RAVEN_P2P_LISTEN: "[v6]:port", "v4:port", a bare port or
# "on" (the default port); empty for "relay" (no listening port) and off.
P2P_PORT=""
if p2p_listen_requested; then
  case "$P2P_LISTEN" in
    [Rr][Ee][Ll][Aa][Yy]) P2P_PORT="" ;;
    \[*\]:*) P2P_PORT="${P2P_LISTEN##*:}" ;;
    *:*:*) P2P_PORT=7423 ;;
    *:*) P2P_PORT="${P2P_LISTEN##*:}" ;;
    *[!0-9]*) P2P_PORT=7423 ;;
    *) P2P_PORT="$P2P_LISTEN" ;;
  esac
fi
# UPnP / NAT-PMP (owner decision Q8, "ask once at setup"): RAVEN_UPNP decides.
# Unset: an interactive install (stdin is a terminal) that opens a p2p port
# asks the same one-time question as `raven node p2p on`, unless node_policy.json
# already holds an answer ("upnp": true|false). Enter or EOF = no. Asked before
# the build so nobody waits for cargo to answer it; saved after install below.
UPNP_MODE=""
case "$UPNP" in
  1) UPNP_MODE=on ;;
  0) UPNP_MODE=off ;;
  *)
    if [[ -n "$P2P_PORT" && -t 0 ]] \
      && ! grep -Eq '"upnp"[[:space:]]*:[[:space:]]*(true|false)' "$DATA_DIR/node_policy.json" 2>/dev/null; then
      printf '%s ' "Open TCP/UDP ${P2P_PORT} on your router automatically (UPnP/NAT-PMP) so friends can reach this node and it can relay for them? [y/N]" >&2
      UPNP_ANSWER=""
      read -r UPNP_ANSWER || UPNP_ANSWER=""
      case "$UPNP_ANSWER" in
        [Yy]|[Yy][Ee][Ss]) UPNP_MODE=on ;;
        *) UPNP_MODE=off ;;
      esac
    fi
    ;;
esac
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
# libp2p flags: only the ones asked for. Printed into the same line of the plist
# as the Internet flags, so with nothing set the plist stays as before.
p2p_plist_args() {
  local r
  if [[ -n "$P2P_LISTEN" ]]; then
    printf '    <string>--p2p-listen</string>\n    <string>%s</string>\n' "$(xml_escape "$P2P_LISTEN")"
  fi
  if [[ ${#P2P_RELAY_LIST[@]} -gt 0 ]]; then
    for r in "${P2P_RELAY_LIST[@]}"; do
      printf '    <string>--p2p-relay</string>\n    <string>%s</string>\n' "$(xml_escape "$r")"
    done
  fi
  if [[ "$P2P_RELAY" == "1" ]]; then
    printf '    <string>--relay</string>\n'
  fi
  return 0
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
$(internet_listen_plist_args; p2p_plist_args)
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
# The same p2p settings go into node_policy.json too, so `raven whoami --card`
# and `raven status` agree with the agent even while it is not running (its
# flags above still decide while it runs). stdin is /dev/null: never asks.
if [[ -n "$P2P_LISTEN" ]]; then
  if p2p_listen_requested; then
    P2P_SAVE_ARGS=(node p2p on --listen "$P2P_LISTEN")
    if [[ ${#P2P_RELAY_LIST[@]} -gt 0 ]]; then
      for r in "${P2P_RELAY_LIST[@]}"; do
        P2P_SAVE_ARGS+=(--relay "$r")
      done
    fi
  else
    P2P_SAVE_ARGS=(node p2p off)
  fi
  if ! "${BIN_DIR}/raven" --data-dir "${DATA_DIR}" "${P2P_SAVE_ARGS[@]}" </dev/null >/dev/null; then
    echo "WARN: could not save the p2p settings in node_policy.json (the agent still uses its flags); run '${BIN_DIR}/raven --data-dir ${DATA_DIR} ${P2P_SAVE_ARGS[*]}'"
  fi
fi
# Saved in node_policy.json before the agent (re)starts below, which applies it.
UPNP_SAVED=""
if [[ -n "$UPNP_MODE" ]]; then
  if "${BIN_DIR}/raven" --data-dir "${DATA_DIR}" node upnp "$UPNP_MODE"; then
    UPNP_SAVED="$UPNP_MODE"
  else
    echo "WARN: could not save the UPnP choice; run '${BIN_DIR}/raven --data-dir ${DATA_DIR} node upnp ${UPNP_MODE}' and restart the agent"
  fi
fi

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
if p2p_listen_requested && [[ -z "$P2P_PORT" ]]; then
  echo "p2p listen: relay (no listening port: contacts reach this node only through its relays, RAVEN_P2P_RELAYS)"
elif p2p_listen_requested; then
  echo "p2p listen: ${P2P_LISTEN} (libp2p TCP+UDP ${P2P_PORT}; only your contacts get a Raven link; anyone can see that the port is open)"
  echo "  The macOS Application Firewall is off by default. If it is on, allow raven-node yourself:"
  echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ${BIN_DIR}/raven-node"
  echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ${BIN_DIR}/raven-node"
  echo "  (an unsigned rebuild may need this again) and forward TCP+UDP ${P2P_PORT} on your router if you are behind NAT (or RAVEN_UPNP=1);"
  echo "  without that a relay (RAVEN_P2P_RELAYS) still lets contacts reach you."
  echo "  A build with p2p off (P2P_PRODUCTION_ENABLED=false) never listens and logs P2P_HOLD; check: raven status (p2p row)."
elif [[ -n "$P2P_LISTEN" ]]; then
  echo "p2p listen: off (RAVEN_P2P_LISTEN=${P2P_LISTEN} overrides 'raven node p2p on')"
else
  echo "p2p listen: off (opt-in: re-run with RAVEN_P2P_LISTEN=7423, or 'raven node p2p on' and restart the agent)"
fi
if [[ ${#P2P_RELAY_LIST[@]} -gt 0 ]]; then
  echo "p2p relays: ${P2P_RELAY_LIST[*]} (a reservation is kept on each; a relay sees both PeerIds and IPs of every circuit, never your messages)"
fi
if [[ "$P2P_RELAY" == "1" ]]; then
  echo "relay: on for the PeerIds in ${DATA_DIR}/relay_allow.json (add a friend with 'raven relay allow @friend')"
  echo "  Its relay PeerId is your own libp2p PeerId (the one in your card): friends who use it can link it to your card."
fi
if { [[ ${#P2P_RELAY_LIST[@]} -gt 0 ]] || [[ "$P2P_RELAY" == "1" ]]; } && ! p2p_listen_requested; then
  echo "NOTE: relays and RAVEN_P2P_RELAY=1 take effect only while p2p listen is on (RAVEN_P2P_LISTEN=7423 or 'raven node p2p on')."
fi
case "$UPNP_SAVED" in
  on) echo "UPnP: on (raven-node asks the router to map TCP/UDP ${P2P_PORT:-of the p2p port, when one is open}; it logs only the mapped port and success or failure)" ;;
  off) echo "UPnP: off ('raven node upnp on' changes it; applied when the agent restarts)" ;;
esac
echo "PATH tip: export PATH=\"${BIN_DIR}:\$PATH\""
