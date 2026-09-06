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
# Exit 0 is reserved for a future HOLD-aware M3 harness and is refused today.
# Exit 1 = expected RED (gates still closed).
# Exit 2 = inventory/invariant regression (board or HOLD citations missing).
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
grep -q 'Daemon never seals from plaintext here' "$IPC" \
  || fail_reg "$IPC missing sealed-frame-only invariant"
grep -q 'EnqueueSealed' "$IPC" && grep -q 'LanDial' "$IPC" \
  || fail_reg "$IPC missing EnqueueSealed / LanDial"
if grep -Eq 'enum IpcRequest' -A 40 "$IPC" | grep -Eqi 'SealPlaintext|SealPayload|EnqueuePlain'; then
  fail_reg "$IPC grew a plaintext-seal op; do not treat as O6 green — Crypto must own M2"
fi
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
    | xargs -0 -r grep -l 'EnqueueSealed' 2>/dev/null || true)"
  if [[ -n "$rdap_hits" ]]; then
    echo "rdap_enqueue_sealed=present — still not O6 green without M1/M2/HOLD labeling"
  else
    echo "rdap_enqueue_sealed=absent"
  fi
else
  echo "rdap_root=unset (RAVEN-only check; companion gap cited from live README in the board)"
fi

echo
echo "gates:"
echo "  G-HOLD=ACTIVE"
echo "  G-TERM=NOT_PROVEN (named-pipe code landed #43; Proven still needs executed green/red)"
echo "  G-M1=MISSING (same-RVN1 bridge)"
echo "  G-M2-IPC=MISSING (no daemon-seal op)"
echo "  G-M2-PY=MISSING (no RDAP IPC client in this repo)"
echo "  G-M3=MISSING (no two-device RDAP harness)"
echo "  G-CI=MISSING (no Raven↔RDAP interop job)"
echo
echo "next_authorized_code_pr=M1 identity bridge only, after terminal board green (or CEO override)"
echo "forbidden=python ATSAM seal; Noise-only confidentiality claim; HOLD lift via this script"
echo
red "O6_TRY_PHASE=RED"
red "O6_HARNESS=NOT_GREEN"
red "O6_INVENTORY=PRESENT"
red "HOLD=ACTIVE"
red "LABEL=$LABEL"
echo "exit=1 (expected while gated)"
exit 1
