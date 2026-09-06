#!/usr/bin/env bash
# O6 try-phase gap check — NON-RELEASE / fail-closed containment.
#
# Purpose: executable RED evidence that the Raven↔RDAP two-device encrypted
# E2E harness (ADR 0004 M3 / O6 KPI harness half) is NOT green.
#
# This script MUST NOT be described as confidential Raven messaging,
# production ATSAM, or a HOLD lift. Harness green ≠ HOLD lifted.
# Python ATSAM seal is forbidden; this script does not send, dial, or seal.
#
# Exit 0 is reserved for a future HOLD-aware M3 harness (O6 E2E Proven) and
# is refused today. M2 SealUnderSession landed ≠ Exit 0.
# Exit 1 = expected RED: inventory/containment checks passed, but the O6
#          two-device harness is NOT green (HOLD intact; M2 IPC ≠ O6 E2E).
# Exit 2 = inventory/invariant regression (board, HOLD, EnqueueSealed
#          sealed-frame-only, or SealUnderSession citations missing).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="NON-RELEASE"
BOARD="docs/engineering/baseline-freeze/o6-raven-rdap-try-phase-gap-board.md"
ADR="docs/adr/0004-raven-rdap-atsam-transport.md"
TM="docs/THREAT_MODEL.md"
ERRATA="protocol/SECURITY_ERRATA_RVN1_2026-08-13.md"
IPC="node/crates/raven-core/src/ipc.rs"

red() { printf '%s\n' "$@"; }
fail_reg() { red "O6_TRY_PHASE=REGRESSION" "O6_HARNESS=NOT_GREEN" "HOLD=ACTIVE" "LABEL=$LABEL"; red "error: $*"; exit 2; }

cd "$ROOT"

echo "=== O6 try-phase gap check ($LABEL) ==="
echo "repo_root=$ROOT"
echo "label=$LABEL"
echo "claim=none (not confidential; not production ATSAM; not HOLD lift)"

[[ -f "$BOARD" ]] || fail_reg "missing $BOARD"
[[ -f "$ADR" ]] || fail_reg "missing $ADR"
[[ -f "$TM" ]] || fail_reg "missing $TM"
[[ -f "$ERRATA" ]] || fail_reg "missing $ERRATA"
[[ -f "$IPC" ]] || fail_reg "missing $IPC"

grep -q 'Release status | \*\*HOLD\*\*' "$TM" \
  || fail_reg "$TM missing Release status HOLD row"
grep -qi 'not approved for production' "$ERRATA" \
  || fail_reg "$ERRATA missing production-hold language"
# EnqueueSealed stays sealed-frame-only. Tip wording is "Daemon never seals
# here." Accept the pre-M2 citation too so this check does not false-fail.
if grep -q 'Daemon never seals here' "$IPC" \
  || grep -q 'Daemon never seals from plaintext here' "$IPC"; then
  :
else
  fail_reg "$IPC missing EnqueueSealed sealed-frame-only invariant"
fi
grep -q 'EnqueueSealed' "$IPC" && grep -q 'LanDial' "$IPC" \
  || fail_reg "$IPC missing EnqueueSealed / LanDial"
# M2 Crypto-owned daemon seal landed. Required; not a regression; not O6 green.
grep -q 'SealUnderSession' "$IPC" && grep -q 'SealUnderSessionResult' "$IPC" \
  || fail_reg "$IPC missing SealUnderSession / SealUnderSessionResult (M2 landed)"
if grep -Eqi 'SealPlaintext|SealPayload|EnqueuePlain' "$IPC"; then
  fail_reg "$IPC grew a plaintext-named seal op; Crypto-owned name is SealUnderSession"
fi
echo "m2_ipc=SealUnderSession landed (NON-RELEASE)"
echo "honesty=M2 IPC ≠ O6 E2E Proven; HOLD intact"
if grep -qi 'python MUST NOT construct' "$ADR"; then
  :
elif grep -q 'Python / RDAP MUST NOT' "$ADR"; then
  :
else
  fail_reg "$ADR missing Python-MUST-NOT-seal invariant"
fi
grep -q 'non-release' "$BOARD" || fail_reg "$BOARD missing non-release label"
grep -q 'Harness green ≠ HOLD lifted' "$BOARD" \
  || grep -q 'harness green ≠ hold lifted' "$BOARD" \
  || fail_reg "$BOARD missing harness-green ≠ HOLD-lifted rule"
grep -q 'SealUnderSession' "$BOARD" \
  || fail_reg "$BOARD missing SealUnderSession (G-M2-IPC honesty)"
grep -q 'Daemon never seals here' "$BOARD" \
  || fail_reg "$BOARD missing current EnqueueSealed sealed-frame-only citation"
if grep -q '3207e8ea' "$BOARD" || grep -q 'raven_ipc' "$BOARD"; then
  :
else
  fail_reg "$BOARD missing RDAP companion client citation (G-M2-PY)"
fi

# This repo must not grow a Python ATSAM / RDAP IPC client by accident.
if [[ -d "$ROOT/team_agents" ]]; then
  fail_reg "team_agents/ appeared in RAVEN; RDAP code does not belong here"
fi
py_hits="$(find "$ROOT" \( -name '*.py' -o -name '*.pyi' \) \
    ! -path '*/.git/*' \
    ! -path '*/protocol/reference/*' \
    -print0 2>/dev/null \
  | xargs -0 -r grep -l -E 'EnqueueSealed|LanDial' 2>/dev/null || true)"
if [[ -n "$py_hits" ]]; then
  fail_reg "Python EnqueueSealed/LanDial caller appeared; M2 must be daemon-seal, not a client seal"
fi

if [[ -n "${RDAP_ROOT:-}" ]]; then
  echo "rdap_root=$RDAP_ROOT"
  if [[ -f "$RDAP_ROOT/README.md" ]]; then
    if grep -q 'Important integration gap' "$RDAP_ROOT/README.md"; then
      echo "rdap_readme_gap=present (honest)"
    else
      echo "rdap_readme_gap=missing — do not assume M3 closed; confirm ADR 0004 pointer + HOLD"
    fi
  fi
  rdap_hits="$(find "$RDAP_ROOT" -name '*.py' ! -path '*/.git/*' -print0 2>/dev/null \
    | xargs -0 -r grep -l -E 'EnqueueSealed|SealUnderSession' 2>/dev/null || true)"
  if [[ -n "$rdap_hits" ]]; then
    echo "rdap_seal_client=present — M2 companion landed; still not O6 E2E Proven / HOLD intact"
  else
    echo "rdap_seal_client=absent"
  fi
else
  echo "rdap_root=unset (RAVEN-only check; companion gap cited from live README in the board)"
fi

echo
echo "gates:"
echo "  G-HOLD=ACTIVE"
echo "  G-TERM=NOT_PROVEN (named-pipe code landed #43; Proven still needs executed green/red)"
echo "  G-M1=IN_PROGRESS (RAVEN public whoami + pin-file bind; RDAP seed still parallel; NON-RELEASE)"
echo "  G-M2-IPC=LANDED (SealUnderSession; NON-RELEASE; M2 IPC ≠ O6 E2E Proven)"
echo "  G-M2-PY=LANDED_COMPANION (RDAP 3207e8ea raven_ipc; not in this repo; not O6 E2E Proven)"
echo "  G-M3=MISSING (no two-device RDAP harness / execute evidence)"
echo "  G-CI=MISSING (no Raven↔RDAP interop job)"
echo
echo "next_authorized_code_pr=M3 two-device execute evidence (HOLD-labeled); M2 IPC + RDAP companion already on main"
echo "forbidden=python ATSAM seal; Noise-only confidentiality claim; HOLD lift via this script; O6 Proven claim"
echo
red "O6_TRY_PHASE=RED"
red "O6_HARNESS=NOT_GREEN"
red "O6_INVENTORY=PRESENT"
red "M2_IPC=LANDED"
red "M2_IPC_NE_O6_E2E=1"
red "HOLD=ACTIVE"
red "LABEL=$LABEL"
echo "exit=1 (inventory/containment passed; O6 try-phase not green)"
exit 1
