#!/usr/bin/env bash
# O6 M1 same-RVN1 public pin bind — NON-RELEASE / HOLD still active.
#
# Imports ash public whoami into a temp RDAP home pin file matching ADR 0004 D3.
# Never writes device_ed25519.seed / identity.seed. Never copies private keys.
#
# Usage:
#   scripts/o6_m1_same_rvn1_bind.sh --rdap-home DIR --whoami-json FILE
#   scripts/o6_m1_same_rvn1_bind.sh --rdap-home DIR --address A --pub-hex H --fingerprint F
#
# Exit 0 = pin written (same RVN1).
# Exit 1 = refuse (missing fields / mismatch / parallel seed / secret tokens).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="NON-RELEASE"
RDAP_HOME=""
WHOAMI_JSON=""
ADDRESS=""
PUB_HEX=""
FINGERPRINT=""

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \?//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rdap-home) RDAP_HOME="${2:-}"; shift 2 ;;
    --whoami-json) WHOAMI_JSON="${2:-}"; shift 2 ;;
    --address) ADDRESS="${2:-}"; shift 2 ;;
    --pub-hex) PUB_HEX="${2:-}"; shift 2 ;;
    --fingerprint) FINGERPRINT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 1 ;;
  esac
done

refuse() {
  echo "O6_M1_BIND=RED"
  echo "LABEL=$LABEL"
  echo "HOLD=ACTIVE"
  echo "CLAIM=none (not confidential; not atsam_rvn1 send)"
  echo "reason=$*"
  exit 1
}

[[ -n "$RDAP_HOME" ]] || refuse "rdap-home required"
if [[ -n "$WHOAMI_JSON" ]]; then
  [[ -f "$WHOAMI_JSON" ]] || refuse "whoami-json missing: $WHOAMI_JSON"
  if python3 - "$WHOAMI_JSON" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(obj, dict):
    sys.exit(2)
forbidden = {"seed", "private_key", "plaintext", "recovery"}
keys = {str(k).lower() for k in obj}
if keys & forbidden:
    sys.exit(3)
sys.exit(0)
PY
  then
    :
  else
    code=$?
    if [[ "$code" -eq 3 ]]; then
      refuse "whoami JSON contains forbidden key (seed/private_key/plaintext/recovery)"
    fi
    refuse "whoami JSON is not a public card object"
  fi
  ADDRESS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["address"])' "$WHOAMI_JSON")"
  PUB_HEX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pub_hex"])' "$WHOAMI_JSON")"
  FINGERPRINT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' "$WHOAMI_JSON")"
fi

[[ -n "$ADDRESS" && -n "$PUB_HEX" && -n "$FINGERPRINT" ]] || refuse "address, pub_hex, fingerprint required"

# Public values may coincidentally contain those letter sequences; refuse keys only.

# Derive address + fingerprint from pub_hex (Identity V1 / same pin plane).
derived="$(
  PYTHONPATH="$ROOT/protocol/reference${PYTHONPATH:+:$PYTHONPATH}" python3 - "$PUB_HEX" "$ADDRESS" "$FINGERPRINT" <<'PY'
import sys
from raven_protocol.address import encode
from raven_protocol.fingerprint import device_fingerprint_v1

pub_hex, address, fingerprint = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    pub = bytes.fromhex(pub_hex)
except ValueError:
    print("bad_pub_hex", file=sys.stderr)
    sys.exit(2)
if len(pub) != 32:
    print("pub_hex_len", file=sys.stderr)
    sys.exit(2)
derived = encode(pub)
fp = device_fingerprint_v1(pub)
print(derived)
print(fp)
if derived != address:
    sys.exit(3)
if fp != fingerprint:
    sys.exit(4)
PY
)" || {
  code=$?
  case "$code" in
    3) refuse "address/pub mismatch (would invent a second RVN1)" ;;
    4) refuse "fingerprint mismatch (not ash-style pin of this RVN1)" ;;
    *) refuse "pub_hex is not a 32-byte identity public key" ;;
  esac
}

derived_addr="$(printf '%s\n' "$derived" | sed -n '1p')"
derived_fp="$(printf '%s\n' "$derived" | sed -n '2p')"
[[ "$derived_addr" == "$ADDRESS" ]] || refuse "derived address != whoami"
[[ "$derived_fp" == "$FINGERPRINT" ]] || refuse "derived fingerprint != whoami"

keys="$RDAP_HOME/.team/keys"
mkdir -p "$keys"
chmod 0700 "$keys" 2>/dev/null || true

if [[ -e "$keys/device_ed25519.seed" ]]; then
  refuse "parallel RDAP seed present (device_ed25519.seed); D3 forbids a second keypair"
fi
if [[ -e "$keys/identity.seed" ]]; then
  refuse "parallel identity.seed in RDAP keys dir; refuse seed copy"
fi

pin="$keys/o6_m1_same_rvn1.pin"
card="$keys/o6_m1_same_rvn1.json"
if [[ -f "$pin" ]]; then
  existing="$(grep -E '^address=' "$pin" | head -n1 | cut -d= -f2-)"
  if [[ -n "$existing" && "$existing" != "$ADDRESS" ]]; then
    refuse "existing pin address $existing != $ADDRESS (second pin namespace)"
  fi
fi

umask 022
cat >"$pin" <<EOF
# ADR 0004 D3 same-RVN1 public pin (NON-RELEASE)
# Public pin only — not a keypair and not private-key material.
# principal=user_identity  pin ≢ device_ed_pub (G5)
address=$ADDRESS
pub_hex=$PUB_HEX
fingerprint=$FINGERPRINT
source=raven-node-whoami
principal=user_identity
label=$LABEL
hold=ACTIVE
claim=none
EOF
chmod 0644 "$pin"

python3 - "$card" "$ADDRESS" "$PUB_HEX" "$FINGERPRINT" <<'PY'
import json, sys
path, address, pub_hex, fingerprint = sys.argv[1:5]
obj = {
    "schema": "o6_m1_same_rvn1_pin_v1",
    "address": address,
    "pub_hex": pub_hex,
    "fingerprint": fingerprint,
    "source": "raven-node-whoami",
    "principal": "user_identity",
    "g5_pin_ne_device_ed_pub": True,
    "label": "NON-RELEASE",
    "hold": "ACTIVE",
    "claim": "none",
}
open(path, "w", encoding="utf-8").write(json.dumps(obj, indent=2) + "\n")
PY
chmod 0644 "$card"

echo "pin=$pin"
echo "card=$card"
echo "address=$ADDRESS"
echo "bind=same_rvn1"
echo "LABEL=$LABEL"
echo "HOLD=ACTIVE"
echo "CLAIM=none (not confidential; not atsam_rvn1 send)"
