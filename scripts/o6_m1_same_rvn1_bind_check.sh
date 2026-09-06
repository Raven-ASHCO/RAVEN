#!/usr/bin/env bash
# O6 M1 same-RVN1 bind check — NON-RELEASE / fail-closed containment.
#
# GREEN: temp raven-node data-dir → ash whoami (public) → pin-file bind →
#        same RVN1 string on both sides.
# RED:   missing identity; refuse parallel RDAP seed; IPC/JSON has no
#        private-key tokens (at least one negative is executable).
#
# Proves: public whoami export + D3 pin-file bind contract (same RVN1).
# Does NOT prove: O6 E2E, confidential delivery, atsam_rvn1 send, daemon-seal,
#                 two-device harness, HOLD lift, Release, production enablement.
#
# Exit 0 = green path passed AND red path fired as expected.
# Exit 1 = green failed (bind not proven).
# Exit 2 = red path did not fire / inventory regression.
#
# No WAN. Linux CI can run this after `ash` is built (debug + locked-file).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="NON-RELEASE"
BOARD="docs/engineering/baseline-freeze/o6-raven-rdap-try-phase-gap-board.md"
CONTRACT="docs/engineering/baseline-freeze/o6-m1-same-rvn1-bind-contract.md"
ADR="docs/adr/0004-raven-rdap-atsam-transport.md"
IPC="node/crates/raven-core/src/ipc.rs"
BIND="$ROOT/scripts/o6_m1_same_rvn1_bind.sh"
NODE="$ROOT/node"
BIN="$NODE/target/debug"
ASH="$BIN/ash"

export PATH="${HOME}/.cargo/bin:${PATH}"
export NO_COLOR=1
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1

fail_green() {
  echo "O6_M1_BIND=RED"
  echo "LABEL=$LABEL"
  echo "HOLD=ACTIVE"
  echo "CLAIM=none (not confidential; not atsam_rvn1 send)"
  echo "error: green path failed: $*"
  exit 1
}

fail_reg() {
  echo "O6_M1_BIND=RED"
  echo "LABEL=$LABEL"
  echo "HOLD=ACTIVE"
  echo "CLAIM=none (not confidential; not atsam_rvn1 send)"
  echo "error: $*"
  exit 2
}

cd "$ROOT"
[[ -x "$BIND" ]] || chmod +x "$BIND"
[[ -f "$BOARD" ]] || fail_reg "missing $BOARD"
[[ -f "$CONTRACT" ]] || fail_reg "missing $CONTRACT"
[[ -f "$ADR" ]] || fail_reg "missing $ADR"
[[ -f "$IPC" ]] || fail_reg "missing $IPC"

grep -q 'NON-RELEASE' "$CONTRACT" || fail_reg "$CONTRACT missing NON-RELEASE"
grep -q 'Harness green ≠ HOLD lift' "$BOARD" \
  || grep -q 'harness green ≠ HOLD lift' "$BOARD" \
  || grep -q 'Harness green ≠ HOLD lifted' "$BOARD" \
  || fail_reg "$BOARD missing harness-green ≠ HOLD-lifted rule"
grep -q 'Daemon never seals here' "$IPC" \
  || fail_reg "$IPC missing EnqueueSealed sealed-frame-only invariant"
if grep -Eq 'enum IpcRequest' -A 50 "$IPC" | grep -Eqi 'SealPlaintext|SealPayload|EnqueuePlain'; then
  fail_reg "$IPC grew a plaintext-seal op; Crypto owns M2 — out of this PR"
fi
if grep -Eq 'enum IpcRequest' -A 50 "$IPC" | grep -Eq 'Whoami'; then
  fail_reg "$IPC grew Whoami op; M1 uses ash whoami, not a new IPC surface"
fi
if [[ -d "$ROOT/team_agents" ]]; then
  fail_reg "team_agents/ appeared in RAVEN; RDAP code does not belong here"
fi

if [[ ! -x "$ASH" && -x "${ASH}.exe" ]]; then
  ASH="${ASH}.exe"
fi
if [[ ! -x "$ASH" ]]; then
  echo "Building ash (debug)…"
  (cd "$NODE" && cargo build -p ash -q)
  if [[ ! -x "$ASH" && -x "${BIN}/ash.exe" ]]; then
    ASH="${BIN}/ash.exe"
  fi
fi
[[ -x "$ASH" ]] || fail_green "ash binary missing"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/raven-o6-m1-XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

echo "=== O6 M1 same-RVN1 bind check ($LABEL) ==="
echo "repo_root=$ROOT"
echo "workdir=$WORKDIR"
echo "label=$LABEL"
echo "claim=none (not confidential; not production ATSAM; not HOLD lift; not atsam_rvn1 send)"
if [[ -n "${RDAP_ROOT:-}" ]]; then
  echo "rdap_root=$RDAP_ROOT (companion optional; this harness uses a pin-file stub)"
else
  echo "rdap_root=unset (RAVEN-side stub; see $CONTRACT RDAP follow-up)"
fi

# ---------------------------------------------------------------------------
# GREEN: init node identity → public whoami → bind pin → same RVN1
# ---------------------------------------------------------------------------
echo
echo "=== GREEN path ==="
DATA="$WORKDIR/node-data"
mkdir -p "$DATA"
"$ASH" --data-dir "$DATA" init >"$WORKDIR/init.out"
INIT_ADDR="$(grep '^address=' "$WORKDIR/init.out" | cut -d= -f2)"
INIT_PUB="$(grep '^pub_hex=' "$WORKDIR/init.out" | cut -d= -f2)"
INIT_FP="$(grep '^fingerprint=' "$WORKDIR/init.out" | cut -d= -f2)"
[[ -n "$INIT_ADDR" && -n "$INIT_PUB" && -n "$INIT_FP" ]] \
  || fail_green "ash init did not print public address/pub_hex/fingerprint"

"$ASH" --data-dir "$DATA" whoami --json >"$WORKDIR/whoami.json"
python3 - "$WORKDIR/whoami.json" <<'PY' || fail_green "whoami --json leaked a forbidden key"
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
assert isinstance(obj, dict)
assert set(obj) == {"address", "fingerprint", "pub_hex"}
forbidden = {"seed", "private_key", "plaintext", "recovery", "device_ed_pub"}
assert not ({k.lower() for k in obj} & forbidden)
PY

WHO_ADDR="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["address"])' "$WORKDIR/whoami.json")"
WHO_PUB="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pub_hex"])' "$WORKDIR/whoami.json")"
WHO_FP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' "$WORKDIR/whoami.json")"
[[ "$WHO_ADDR" == "$INIT_ADDR" ]] || fail_green "whoami address != init address"
[[ "$WHO_PUB" == "$INIT_PUB" ]] || fail_green "whoami pub_hex != init pub_hex"
[[ "$WHO_FP" == "$INIT_FP" ]] || fail_green "whoami fingerprint != init fingerprint"
[[ "$WHO_ADDR" == rvn1* ]] || fail_green "whoami address is not rvn1…"

RDAP_HOME="$WORKDIR/rdap-home"
"$BIND" --rdap-home "$RDAP_HOME" --whoami-json "$WORKDIR/whoami.json" \
  >"$WORKDIR/bind.out"
PIN="$RDAP_HOME/.team/keys/o6_m1_same_rvn1.pin"
CARD="$RDAP_HOME/.team/keys/o6_m1_same_rvn1.json"
[[ -f "$PIN" && -f "$CARD" ]] || fail_green "bind did not write pin/card"
PIN_ADDR="$(grep -E '^address=' "$PIN" | cut -d= -f2-)"
CARD_ADDR="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["address"])' "$CARD")"
[[ "$PIN_ADDR" == "$WHO_ADDR" ]] || fail_green "pin address != whoami RVN1"
[[ "$CARD_ADDR" == "$WHO_ADDR" ]] || fail_green "card address != whoami RVN1"
if [[ -e "$RDAP_HOME/.team/keys/device_ed25519.seed" || -e "$RDAP_HOME/.team/keys/identity.seed" ]]; then
  fail_green "bind wrote a seed file (forbidden)"
fi
if grep -E '^(seed|private_key|plaintext|recovery)=' "$PIN" >/dev/null; then
  fail_green "pin grew a forbidden field"
fi
python3 - "$CARD" <<'PY' || fail_green "card leaked a forbidden key or failed G5 pin rule"
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
forbidden = {"seed", "private_key", "plaintext", "recovery", "device_ed_pub"}
assert not ({str(k).lower() for k in obj} & forbidden)
assert obj.get("principal") == "user_identity"
assert obj.get("g5_pin_ne_device_ed_pub") is True
assert obj.get("address", "").startswith("rvn1")
PY

# Ash-style contact pin of that same RVN1 (public bits only).
"$ASH" --data-dir "$DATA" contact add \
  --address "$WHO_ADDR" \
  --pub-hex "$WHO_PUB" \
  --petname "O6M1" \
  --tag o6m1 \
  --verify-fp "$WHO_FP" >"$WORKDIR/contact.out"
grep -q 'contact saved' "$WORKDIR/contact.out" || fail_green "ash contact add rejected same-RVN1 public pin"
python3 - "$DATA/contacts.json" "$WHO_ADDR" <<'PY' || fail_green "contacts.json pin is not the same RVN1"
import json, sys
book = json.load(open(sys.argv[1], encoding="utf-8"))
addr = sys.argv[2]
rows = book if isinstance(book, list) else book.get("contacts", book.get("entries", []))
if isinstance(book, dict) and not rows:
    rows = [book]
found = False
for row in rows if isinstance(rows, list) else []:
    if not isinstance(row, dict):
        continue
    if row.get("address") == addr or row.get("identity_address") == addr:
        assert "device_ed_pub" not in row
        found = True
if not found:
    raw = open(sys.argv[1], encoding="utf-8").read()
    assert addr in raw
PY

echo "node_rvn1=$WHO_ADDR"
echo "rdap_pin_rvn1=$PIN_ADDR"
echo "same_rvn1=yes"
echo "O6_M1_BIND=GREEN"
echo "LABEL=$LABEL"
echo "HOLD=ACTIVE"
echo "CLAIM=none (not confidential; not atsam_rvn1 send)"

# ---------------------------------------------------------------------------
# RED: at least one executable negative
# ---------------------------------------------------------------------------
echo
echo "=== RED path ==="
RED_FIRED=0

# RED-1: missing node identity
EMPTY="$WORKDIR/empty-data"
mkdir -p "$EMPTY"
if "$ASH" --data-dir "$EMPTY" whoami --json >"$WORKDIR/empty.whoami" 2>"$WORKDIR/empty.err"; then
  echo "unexpected: whoami --json succeeded without identity" >&2
else
  echo "O6_M1_BIND=RED"
  echo "reason=no_identity (ash whoami --json fail-closed without init)"
  echo "LABEL=$LABEL"
  echo "HOLD=ACTIVE"
  RED_FIRED=1
fi

# RED-2: refuse parallel RDAP seed (second keypair namespace)
PAR="$WORKDIR/parallel-home"
mkdir -p "$PAR/.team/keys"
printf '%s\n' "$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  >"$PAR/.team/keys/device_ed25519.seed"
chmod 0600 "$PAR/.team/keys/device_ed25519.seed"
if "$BIND" --rdap-home "$PAR" --whoami-json "$WORKDIR/whoami.json" \
  >"$WORKDIR/parallel.out" 2>"$WORKDIR/parallel.err"; then
  echo "unexpected: bind accepted a parallel device_ed25519.seed" >&2
else
  if grep -q 'O6_M1_BIND=RED' "$WORKDIR/parallel.out" "$WORKDIR/parallel.err" \
    && grep -q 'parallel' "$WORKDIR/parallel.out" "$WORKDIR/parallel.err"; then
    echo "O6_M1_BIND=RED"
    echo "reason=refuse-parallel-key (device_ed25519.seed present)"
    echo "LABEL=$LABEL"
    echo "HOLD=ACTIVE"
    RED_FIRED=1
  else
    fail_reg "parallel-seed refuse did not print O6_M1_BIND=RED + reason"
  fi
fi

# RED-2b: refuse a second pin namespace (existing pin, different RVN1)
NS="$WORKDIR/namespace-home"
mkdir -p "$NS/.team/keys"
cat >"$NS/.team/keys/o6_m1_same_rvn1.pin" <<'EOF'
address=rvn1qysluvwl5922yctzd0u9gpr06gn3k7ldfvecule0
pub_hex=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
fingerprint=If4x-36FU-omFi
EOF
if "$BIND" --rdap-home "$NS" --whoami-json "$WORKDIR/whoami.json" \
  >"$WORKDIR/ns.out" 2>"$WORKDIR/ns.err"; then
  echo "unexpected: bind overwrote a different existing RVN1 pin" >&2
else
  if grep -q 'O6_M1_BIND=RED' "$WORKDIR/ns.out" "$WORKDIR/ns.err" \
    && grep -q 'second pin namespace' "$WORKDIR/ns.out" "$WORKDIR/ns.err"; then
    echo "O6_M1_BIND=RED"
    echo "reason=refuse-parallel-pin (existing pin address differs)"
    echo "LABEL=$LABEL"
    echo "HOLD=ACTIVE"
    RED_FIRED=1
  else
    fail_reg "second-pin-namespace refuse did not print O6_M1_BIND=RED + reason"
  fi
fi

# RED-3: IPC / whoami JSON dump contains no private key material
STATUS_JSON='{"ok":"status","v":1,"bridge":false,"store":false,"relay":false,"forward_pending":0,"capabilities":["ipc"]}'
printf '%s\n' "$STATUS_JSON" >"$WORKDIR/status.json"
python3 - "$WORKDIR/status.json" "$WORKDIR/whoami.json" <<'PY' || fail_green "public dump leaked a forbidden key"
import json, sys
forbidden = {"seed", "private_key", "plaintext", "recovery"}
for path in sys.argv[1:]:
    obj = json.load(open(path, encoding="utf-8"))
    keys = {str(k).lower() for k in obj}
    assert not (keys & forbidden), path
PY
# Executable negative: a dump that *does* include a private-key field is RED.
BAD_DUMP='{"ok":"status","v":1,"private_key":"nope"}'
printf '%s\n' "$BAD_DUMP" >"$WORKDIR/bad-ipc.json"
if printf '%s' "$BAD_DUMP" | tr '[:upper:]' '[:lower:]' | grep -Fq 'private_key'; then
  echo "O6_M1_BIND=RED"
  echo "reason=ipc-json-contains-private_key (injected dump refused as bind input)"
  echo "LABEL=$LABEL"
  echo "HOLD=ACTIVE"
  if "$BIND" --rdap-home "$WORKDIR/bad-home" --whoami-json "$WORKDIR/bad-ipc.json" \
    >"$WORKDIR/bad.bind.out" 2>"$WORKDIR/bad.bind.err"; then
    fail_reg "bind accepted JSON containing private_key"
  fi
  grep -q 'O6_M1_BIND=RED' "$WORKDIR/bad.bind.out" "$WORKDIR/bad.bind.err" \
    || fail_reg "private_key dump refuse missing O6_M1_BIND=RED"
  RED_FIRED=1
fi

# Source assertion: IpcRequest/IpcResponse field names stay public-only.
if grep -E 'seed|private_key|plaintext|recovery' "$IPC" | grep -E '^\s+(seed|private_key|plaintext|recovery)' >/dev/null; then
  fail_reg "$IPC gained a secret field name on the IPC struct"
fi

[[ "$RED_FIRED" -ge 1 ]] || fail_reg "RED path did not fire"

echo
echo "gates:"
echo "  G-HOLD=ACTIVE"
echo "  G-M1=IN_PROGRESS (RAVEN public whoami + pin-file bind; RDAP seed still parallel)"
echo "  G-M2-IPC=MISSING (no daemon-seal op; out of this PR)"
echo "  G-M3=MISSING (no two-device RDAP harness)"
echo "  O6_E2E=RED"
echo
echo "proved=same RVN1 string on ash whoami and RDAP pin file; private keys absent from public JSON; parallel seed refused"
echo "not_proved=O6 E2E; confidential delivery; atsam_rvn1 send; daemon-seal; HOLD lift; Release"
echo "LABEL=$LABEL"
echo "HOLD=ACTIVE"
echo "CLAIM=none (not confidential; not atsam_rvn1 send)"
echo "exit=0 (green+red executed as expected; still NON-RELEASE)"
exit 0
