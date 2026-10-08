#!/usr/bin/env bash
# Install user-scoped raven-node systemd unit (Linux). Never touches /bin/ash.
#
# LAN exposure is opt-in and identical on every OS installer: the service binds
# 127.0.0.1:7420 unless RAVEN_LAN_LISTEN is set, e.g.
#   RAVEN_LAN_LISTEN=192.168.1.20:7420 bash node/scripts/install/linux_systemd_user.sh
#
# Internet direct exposure is opt-in the same way (no listener by default):
#   RAVEN_INTERNET_LISTEN=0.0.0.0:7422 bash node/scripts/install/linux_systemd_user.sh
# (a bare IP gets port 7422). Without it, `raven node internet on --listen
# 0.0.0.0:7422` turns it on later (applied when the service restarts). Opening
# the port in a firewall stays your decision; the installer only prints the rule.
#
# Lifetime: a `systemd --user` manager is torn down when the user's last
# session ends, so on a headless / SSH-managed host (Raspberry Pi bridge node)
# the daemon would stop at logout and not start at boot. Lingering fixes that
# but is a host-wide setting, so it is opt-in:
#   RAVEN_ENABLE_LINGER=1 bash node/scripts/install/linux_systemd_user.sh
# (or run `loginctl enable-linger "$USER"` yourself; it may need admin rights).
#
# Keystore (docs/design/2026-10-linux-keystore.md): with an unlocked desktop
# keyring (Secret Service) the keys go there. Otherwise RAVEN keeps them in a
# passphrase vault, and the background service needs the passphrase from a
# file only you can read (mode 0600/0400). Pass its path at install time:
#   RAVEN_KEYSTORE_PASSPHRASE_FILE=$HOME/.config/raven/keystore-passphrase \
#     bash node/scripts/install/linux_systemd_user.sh
# The unit then gets Environment=RAVEN_KEYSTORE_PASSPHRASE_FILE=<path> (the
# path only, never the passphrase). RAVEN_SYSTEMD_LOAD_CREDENTIAL=1 uses
# LoadCredential=raven-keystore-passphrase:<path> instead (needs a systemd
# whose user manager supports credentials).
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
PASSPHRASE_FILE="${RAVEN_KEYSTORE_PASSPHRASE_FILE:-}"
if [[ -n "${RAVEN_KEYSTORE_PASSPHRASE:-}" ]]; then
  echo "RAVEN_KEYSTORE_PASSPHRASE is refused: put the passphrase in a 0600 file and set RAVEN_KEYSTORE_PASSPHRASE_FILE" >&2
  exit 1
fi
if [[ -n "$PASSPHRASE_FILE" ]]; then
  case "$PASSPHRASE_FILE" in
    /*) ;;
    *) echo "RAVEN_KEYSTORE_PASSPHRASE_FILE must be an absolute path" >&2; exit 1 ;;
  esac
  if [[ "$PASSPHRASE_FILE" == *[\$%\"\\]* || "$PASSPHRASE_FILE" == *$'\n'* ]]; then
    echo "RAVEN_KEYSTORE_PASSPHRASE_FILE must not contain \$ % \" \\ or newlines" >&2
    exit 1
  fi
  if [[ ! -f "$PASSPHRASE_FILE" || -L "$PASSPHRASE_FILE" ]]; then
    echo "RAVEN_KEYSTORE_PASSPHRASE_FILE=$PASSPHRASE_FILE is not a regular file" >&2
    exit 1
  fi
  case "$(stat -c '%a' "$PASSPHRASE_FILE")" in
    600|400) ;;
    *) echo "RAVEN_KEYSTORE_PASSPHRASE_FILE must be mode 0600 or 0400 (chmod 600 $PASSPHRASE_FILE)" >&2; exit 1 ;;
  esac
fi
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/raven-node.service"

mkdir -p "$BIN_DIR" "$UNIT_DIR"
# Identity, sessions and chat history live here: owner-only.
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"
# `systemd --user` starts the unit from the user's home: register absolute paths
# only. A relative RAVEN_DATA_DIR / RAVEN_BIN_DIR would make the daemon serve (or
# exec from) a different directory than the one `raven init` just created.
BIN_DIR="$(CDPATH='' cd -- "$BIN_DIR" && pwd)"
DATA_DIR="$(CDPATH='' cd -- "$DATA_DIR" && pwd)"
# systemd.service(5): a word may be double-quoted (so spaces survive), and `%`
# and `$` are special inside it (specifiers / variable expansion).
sd_quote() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//%/%%}
  s=${s//\$/\$\$}
  printf '"%s"' "$s"
}
# Internet direct listener: only when asked for (empty = no flag, so a later
# `raven node internet on` in node_policy.json decides).
internet_listen_args() {
  [[ -n "$INTERNET_LISTEN" ]] || return 0
  printf ' --internet-listen %s' "$(sd_quote "$INTERNET_LISTEN")"
}
# Passphrase vault: hand the service the passphrase *file* (never its contents).
keystore_unit_lines() {
  [[ -n "$PASSPHRASE_FILE" ]] || return 0
  if [[ "${RAVEN_SYSTEMD_LOAD_CREDENTIAL:-0}" == "1" ]]; then
    printf 'LoadCredential=raven-keystore-passphrase:%s\n' "$PASSPHRASE_FILE"
  else
    printf 'Environment=%s\n' "$(sd_quote "RAVEN_KEYSTORE_PASSPHRASE_FILE=${PASSPHRASE_FILE}")"
  fi
}
# --locked: build exactly the audited Cargo.lock.
cargo build --locked -p raven-node -p ash --release --manifest-path "$ROOT/Cargo.toml"
install -m 755 "$ROOT/target/release/raven-node" "$BIN_DIR/raven-node"
install -m 755 "$ROOT/target/release/ash" "$BIN_DIR/raven"
# `ash` is also the BusyBox / Alpine shell, and ~/.local/bin usually precedes
# /bin in PATH: only add the alias when no other `ash` exists.
EXISTING_ASH="$(PATH="${PATH//$BIN_DIR:/}" command -v ash 2>/dev/null || true)"
if [[ -z "$EXISTING_ASH" && ! -e /bin/ash && ! -e /usr/bin/ash ]] \
  || [[ "$(readlink -f "$BIN_DIR/ash" 2>/dev/null || true)" == "$(readlink -f "$BIN_DIR/raven")" ]]; then
  ln -sfn "$BIN_DIR/raven" "$BIN_DIR/ash"
  echo "linked $BIN_DIR/ash -> raven (user-local only)"
else
  echo "NOTE: a system 'ash' shell exists (${EXISTING_ASH:-/bin/ash}) — not shadowing it; use '$BIN_DIR/raven'"
fi

cat >"$UNIT" <<EOF
[Unit]
Description=RAVEN raven-node service (bridge + IPC)
After=network.target

[Service]
Type=simple
ExecStart=$(sd_quote "${BIN_DIR}/raven-node") service --data-dir $(sd_quote "${DATA_DIR}") --lan-listen $(sd_quote "${LAN_LISTEN}") --ble-listen 127.0.0.1:7421$(internet_listen_args) --timeout-secs 0
Restart=on-failure
RestartSec=3
# Sandboxing that works in a --user manager without a mount namespace (the
# Protect*/ReadWritePaths/PrivateTmp family needs unprivileged user namespaces
# and fails the unit with status=226/NAMESPACE where those are disabled, so it
# is deliberately not set). AF_NETLINK stays allowed: interface enumeration
# (getifaddrs) uses it.
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
$(keystore_unit_lines)

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
# Identity + prekey must exist before LAN preflight will keep the service up.
# On a host without a desktop keyring this creates the passphrase vault: from
# RAVEN_KEYSTORE_PASSPHRASE_FILE when set, else by asking twice on this terminal.
"${BIN_DIR}/raven" --data-dir "${DATA_DIR}" init
if [[ "$(cat "${DATA_DIR}/keystore.backend" 2>/dev/null || true)" == "passphrase-vault" && -z "$PASSPHRASE_FILE" ]]; then
  echo "NOTE: this profile's keys are in a passphrase vault, but the service was given no passphrase file."
  echo "  The service will fail to start until you re-run this installer with"
  echo "  RAVEN_KEYSTORE_PASSPHRASE_FILE=<file holding the passphrase, chmod 600> (see docs/INSTALL_Linux.md)."
fi
# `enable --now` is a no-op for an already-active unit, which would keep the
# previous binary running after an upgrade; `restart` also starts an inactive unit.
systemctl --user enable raven-node.service
systemctl --user restart raven-node.service
echo "enabled + (re)started systemd --user raven-node.service"
LINGER_USER="${USER:-$(id -un)}"
if [[ "${RAVEN_ENABLE_LINGER:-0}" == "1" ]]; then
  loginctl enable-linger "$LINGER_USER" \
    || echo "WARN: could not enable lingering; run 'loginctl enable-linger $LINGER_USER' (may need admin)"
fi
if [[ "$(loginctl show-user "$LINGER_USER" -p Linger 2>/dev/null || true)" == "Linger=no" ]]; then
  echo "NOTE: lingering is off: this user service stops when your last session ends and does not start at boot."
  echo "  Headless host? Run 'loginctl enable-linger $LINGER_USER' (or re-run with RAVEN_ENABLE_LINGER=1)."
fi
# Where the daemon really listens: a long data dir is served at
# /tmp/raven-<uid>/raven-<hash>.sock, not at <data-dir>/raven-node.sock. Ask the
# installed binary (`doctor` prints `ipc_endpoint=`) instead of guessing.
IPC_EP="$("${BIN_DIR}/raven" --data-dir "${DATA_DIR}" doctor 2>/dev/null \
  | sed -n 's/^[[:space:]]*ipc_endpoint=//p' | head -n1 || true)"
echo "IPC sock: ${IPC_EP:-<unknown: run '${BIN_DIR}/raven --data-dir ${DATA_DIR} doctor' and look for ipc_endpoint=>}"
echo "LAN listen: ${LAN_LISTEN}"
case "$LAN_LISTEN" in
  127.*|localhost:*|\[::1\]:*)
    echo "LAN peers cannot reach this node (loopback only). To accept LAN peers, re-run with"
    echo "  RAVEN_LAN_LISTEN=<this-host-LAN-IP>:7420 and allow inbound TCP 7420 (e.g. ufw allow 7420/tcp)." ;;
  *)
    echo "Exposed on ${LAN_LISTEN}: allow inbound TCP only from your LAN (e.g. ufw allow from 192.168.0.0/16 to any port 7420 proto tcp)." ;;
esac
if [[ -n "$INTERNET_LISTEN" ]]; then
  # "[v6]:port" or "v4:port"; a bare IP (IPv6 included) means the default port.
  case "$INTERNET_LISTEN" in
    \[*\]:*) INTERNET_PORT="${INTERNET_LISTEN##*:}" ;;
    *:*:*) INTERNET_PORT=7422 ;;
    *:*) INTERNET_PORT="${INTERNET_LISTEN##*:}" ;;
    *) INTERNET_PORT=7422 ;;
  esac
  echo "Internet listen: ${INTERNET_LISTEN} (only your contacts get an answer; anyone can see that the port is open)"
  echo "  Allow it yourself if you want it reachable: ufw allow ${INTERNET_PORT}/tcp (or firewalld / nftables / your cloud security group),"
  echo "  and forward TCP ${INTERNET_PORT} on your router if this host is behind NAT."
  echo "  A build with Internet direct off (INTERNET_DIRECT_PRODUCTION_ENABLED=false) keeps the port closed and logs INTERNET_DIRECT_HOLD; check: raven status (internet row)."
else
  echo "Internet listen: off (opt-in: re-run with RAVEN_INTERNET_LISTEN=0.0.0.0:7422, or 'raven node internet on' and restart the unit)"
fi
echo "export PATH=\"${BIN_DIR}:\$PATH\""
