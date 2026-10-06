#!/usr/bin/env bash
# Secret / credential history scan for Raven serverless checklist (§5 / §57).
# Flags findings for HUMAN rotation — does not invent or perform rotations.
#
# Usage:
#   ./scripts/secret_history_scan.sh           # write docs/SECRET_HISTORY_SCAN_REPORT.md
#   ./scripts/secret_history_scan.sh --ci      # exit 1 on hard-fail tree/history classes
#   ./scripts/secret_history_scan.sh --self-test   # scanner regression test only (writes nothing)
#
# Scope: working tree + every blob reachable from every Git ref. Never prints
# full secret values — only path:line, pattern class, and a shortened blob ID.
#
# Raven-specific classes (hard-fail): raw identity seeds / node state files by
# name (identity.seed, *.seed, *.sqlite*, *.db, prekey_store.json, *.p12/*.pfx),
# exactly-32-byte binary blobs (a raw Ed25519 seed), and 64-hex seed /
# private-key assignments (public RFC 8032 test keys are allowlisted by hash).
# This script never rotates credentials and never rewrites git history —
# owner decisions are recorded in docs/SECRET_SCAN_TRIAGE.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CI_MODE=0
if [[ "${1:-}" == "--ci" ]]; then
  CI_MODE=1
fi

REPORT_DIR="$ROOT/docs"
REPORT="$REPORT_DIR/SECRET_HISTORY_SCAN_REPORT.md"
mkdir -p "$REPORT_DIR"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

HITS="$TMP/hits.txt"
HISTORY_BLOB_FILE="$TMP/history-blob"
HISTORY_OBJECTS="$TMP/history-objects.txt"
HISTORY_MATCHES="$TMP/history-matches.txt"
: >"$HITS"

# SHA-256 of 64-hex values that are PUBLIC test keys, not secrets:
# RFC 8032 section 7.1 TEST 1, TEST 2 and TEST 3 secret keys (the canonical
# alice / bob / carol fixtures used by protocol/reference and the vectors).
PUBLIC_TEST_KEY_SHA256=(
  099da475a54aacbacabde231639eed7b00b0a9359cddd2598004bd8b8ad23237
  80cd0406a778128b9b92931b4e89f5370c1b63657d3caf6ba051d19d60eea156
  dfdcf400fd38f3bc807fd3ea4113c2fb8265ed76a07327e84bb36cbeadfe6b21
)

# `name = "<64 hex>"`, `seed_hex: '<64 hex>'`, `PRIV = bytes.fromhex("<64 hex>")`…
RAVEN_KEY_HEX_ERE='(seed|priv(ate)?(_?key)?|secret(_?key)?)(_hex)?["'"'"']?[[:space:]]*[:=][[:space:]]*(b?["'"'"']|bytes\.fromhex\([[:space:]]*["'"'"']|hex::decode\([[:space:]]*["'"'"'])?[0-9a-f]{64}([^0-9a-f]|$)'

sha256_hex() {
  if command -v shasum >/dev/null 2>&1; then
    printf '%s' "$1" | shasum -a 256 | cut -c1-64
  else
    printf '%s' "$1" | sha256sum | cut -c1-64
  fi
}

is_public_test_key() {
  local digest known
  digest="$(sha256_hex "$1")"
  for known in "${PUBLIC_TEST_KEY_SHA256[@]}"; do
    [[ "$digest" == "$known" ]] && return 0
  done
  return 1
}

# Raven secret-bearing file names: identity seed, session / chat / prekey
# databases, private prekey store, PKCS#12 bundles. Matched on the basename of
# tracked files, present untracked/ignored files and every historical path.
is_raven_secret_filename() {
  local base="${1##*/}"
  case "$base" in
    identity.seed|*.seed|prekey_store.json) return 0 ;;
    *.sqlite|*.sqlite3|*.sqlite-wal|*.sqlite-shm|*.db) return 0 ;;
    *.p12|*.pfx) return 0 ;;
  esac
  return 1
}

# True when FILE is exactly 32 bytes and not plain text — the shape of a raw
# Ed25519 identity seed (`grep -I` alone is not enough: random bytes often
# contain no NUL and pass as "text" in the C locale).
is_raw_32_byte_blob() {
  local f="$1" size nonprint
  size=$(wc -c <"$f" 2>/dev/null | tr -d ' ')
  [[ "$size" == 32 ]] || return 1
  nonprint=$(LC_ALL=C tr -d '[:print:][:space:]' <"$f" | wc -c | tr -d ' ')
  [[ "$nonprint" -gt 0 ]]
}

# Emit RAVEN_KEY_MATERIAL_HEX hits for FILE (display name DISPLAY) — values are
# only hashed in memory, never written anywhere.
# The allow-list is applied BEFORE any cap: a file repeating the public RFC 8032
# test seeds 20+ times used to exhaust a raw `head -20` and hide a real seed
# further down. Only the number of EMITTED hits is bounded (20 per file). Each
# distinct value is hashed once (bash 3.2: a string, not an associative array); the
# loop runs in a pipeline subshell, which is fine because its state is local.
scan_raven_key_hex() {
  local f="$1" display="$2" match line value emitted=0 seen=" "
  LC_ALL=C grep -noiE "$RAVEN_KEY_HEX_ERE" "$f" 2>/dev/null \
    | while IFS= read -r match; do
      line="${match%%:*}"
      value="$(printf '%s' "${match#*:}" | LC_ALL=C grep -oiE '[0-9a-f]{64}' | tail -1 \
        | tr 'A-F' 'a-f')"
      [[ -n "$value" ]] || continue
      case "$seen" in *" $value "*) continue ;; esac
      seen="$seen$value "
      is_public_test_key "$value" && continue
      echo "RAVEN_KEY_MATERIAL_HEX|$display|$line|human_rotate_if_real" >>"$HITS"
      emitted=$((emitted + 1))
      [[ "$emitted" -lt 20 ]] || break
    done || true
}

# `--self-test`: regression for the cap-before-allow-list miss above. 25 allow-listed
# seed lines followed by one non-allow-listed seed must yield EXACTLY one row, on the
# last line; an all-allow-listed file must yield none.
secret_scan_selftest() {
  local f="$TMP/selftest.rs" i rows last
  : >"$f"
  for i in $(seq 1 25); do
    echo 'let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";' >>"$f"
  done
  : >"$HITS"
  scan_raven_key_hex "$f" "selftest-allowlisted"
  if [[ -s "$HITS" ]]; then
    echo "SECRET SCAN SELF-TEST FAILED: allow-listed RFC 8032 seed was reported" >&2
    exit 97
  fi
  # Built at run time: a literal 64-hex seed here would itself be flagged by this scanner
  # (in the working tree and, once committed, in history).
  printf 'let seed = "%s";\n' "$(printf '%064d' 0 | tr 0 1)" >>"$f"
  scan_raven_key_hex "$f" "selftest-real"
  rows="$(wc -l <"$HITS" | tr -d ' ')"
  last="$(cut -d'|' -f3 <"$HITS")"
  if [[ "$rows" != 1 || "$last" != 26 ]]; then
    echo "SECRET SCAN SELF-TEST FAILED: expected 1 hit on line 26, got $rows (lines: $last)" >&2
    exit 97
  fi
  echo "secret scan self-test OK"
}

# High-confidence patterns (private key material / cloud tokens). Avoid matching
# public test vectors (ed25519 pub hex, shared-vectors) by requiring keywords.
scan_file() {
  local f="$1"
  case "$f" in
    */target/*|*/.git/*|*/node_modules/*|*/Pods/*|*/build/*|*/DerivedData/*) return 0 ;;
    */fuzz/corpus/*|*/fuzz/artifacts/*) return 0 ;;
  esac
  [[ -f "$f" ]] || return 0
  # Name / shape classes run before the extension and binary guards: an identity
  # seed or a node database is binary by design (and may be called *.bin).
  if is_raven_secret_filename "$f"; then
    echo "RAVEN_SECRET_FILE|$f|0|human_rotate_if_real" >>"$HITS"
  fi
  if is_raw_32_byte_blob "$f"; then
    echo "RAW_32_BYTE_BLOB|$f|0|human_rotate_if_real" >>"$HITS"
  fi
  # Skip binaries / lock noise / vectors that are intentionally hex.
  case "$f" in
    *.png|*.jpg|*.jpeg|*.gif|*.webp|*.ico|*.pdf|*.wasm|*.bin) return 0 ;;
    */shared-vectors/*|shared-vectors/*) return 0 ;;
  esac
  [[ -s "$f" ]] || return 0
  local size
  size=$(wc -c <"$f" 2>/dev/null || echo 0)
  [[ "$size" =~ ^[0-9]+$ ]] || return 0
  (( size <= 2097152 )) || return 0
  LC_ALL=C grep -Iq . "$f" || return 0

  # Pattern classes — report class only.
  if grep -nE 'BEGIN (RSA |OPENSSH |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY' "$f" >/dev/null 2>&1; then
    grep -nE 'BEGIN (RSA |OPENSSH |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY' "$f" 2>/dev/null \
      | head -5 | while IFS= read -r line; do
      echo "PRIVATE_KEY_PEM|$f|${line%%:*}|human_rotate_if_real" >>"$HITS"
    done
  fi
  if LC_ALL=C grep -nE '(^|[^A-Za-z0-9_])re_[A-Za-z0-9]{6,}_[A-Za-z0-9]{16,}' "$f" >/dev/null 2>&1; then
    LC_ALL=C grep -nE '(^|[^A-Za-z0-9_])re_[A-Za-z0-9]{6,}_[A-Za-z0-9]{16,}' "$f" 2>/dev/null \
      | head -3 | while IFS= read -r line; do
      echo "RESEND_API_KEY|$f|${line%%:*}|human_rotate_if_real" >>"$HITS"
    done
  fi
  if LC_ALL=C grep -nE 'sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}' "$f" >/dev/null 2>&1; then
    LC_ALL=C grep -nE 'sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}' "$f" 2>/dev/null \
      | head -3 | while IFS= read -r line; do
      echo "CLOUD_API_KEY|$f|${line%%:*}|human_rotate_if_real" >>"$HITS"
    done
  fi
  scan_raven_key_hex "$f" "$f"
  if grep -nEi 'AKIA[0-9A-Z]{16}' "$f" >/dev/null 2>&1; then
    grep -nEi 'AKIA[0-9A-Z]{16}' "$f" 2>/dev/null | head -3 | while IFS= read -r line; do
      echo "AWS_ACCESS_KEY_ID|$f|${line%%:*}|human_rotate_if_real" >>"$HITS"
    done
  fi
  if grep -nEi 'ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}' "$f" >/dev/null 2>&1; then
    grep -nEi 'ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}' "$f" 2>/dev/null \
      | head -3 | while IFS= read -r line; do
      echo "GITHUB_TOKEN|$f|${line%%:*}|human_rotate_if_real" >>"$HITS"
    done
  fi
  if grep -nEi 'xox[baprs]-[A-Za-z0-9-]{10,}' "$f" >/dev/null 2>&1; then
    grep -nEi 'xox[baprs]-[A-Za-z0-9-]{10,}' "$f" 2>/dev/null | head -3 | while IFS= read -r line; do
      echo "SLACK_TOKEN|$f|${line%%:*}|human_rotate_if_real" >>"$HITS"
    done
  fi
  # .env style assignments that look like live secrets (not placeholders).
  if grep -nEi '^[A-Z0-9_]*(SECRET|PASSWORD|PRIVATE_KEY|API_KEY)[A-Z0-9_]*=.+' "$f" >/dev/null 2>&1; then
    grep -nEi '^[A-Z0-9_]*(SECRET|PASSWORD|PRIVATE_KEY|API_KEY)[A-Z0-9_]*=.+' "$f" 2>/dev/null \
      | grep -viE 'CHANGE_ME|TODO|placeholder|example|your_|<.*>|\*\*\*|xxx' \
      | head -5 | while IFS= read -r line; do
      echo "ENV_SECRET_ASSIGNMENT|$f|${line%%:*}|human_review" >>"$HITS"
    done
  fi
}

# Scan one historical Git blob without checking it out and without ever
# printing the matching line. `display_path` is metadata from
# `git rev-list --objects --all`; the shortened object ID makes a finding
# reviewable even when the path was later renamed or deleted.
scan_history_blob() {
  local oid="$1"
  local display_path="$2"
  local size="$3"
  local short_oid="${oid:0:12}"
  local finding_path="history:${display_path}@${short_oid}"

  case "$display_path" in
    */target/*|*/node_modules/*|*/Pods/*|*/build/*|*/DerivedData/*) return 0 ;;
  esac

  # Name / shape Raven classes: checked before any extension, size or binary
  # guard, because a committed seed or node database is binary.
  if is_raven_secret_filename "$display_path"; then
    echo "RAVEN_SECRET_FILE|$finding_path|0|human_rotate_if_real" >>"$HITS"
  fi
  if [[ "$size" == 32 ]]; then
    git cat-file blob "$oid" >"$HISTORY_BLOB_FILE" 2>/dev/null || return 0
    if is_raw_32_byte_blob "$HISTORY_BLOB_FILE"; then
      echo "RAW_32_BYTE_BLOB|$finding_path|0|human_rotate_if_real" >>"$HITS"
    fi
  fi

  case "$display_path" in
    *.png|*.jpg|*.jpeg|*.gif|*.webp|*.ico|*.pdf|*.wasm|*.bin) return 0 ;;
    shared-vectors/*|*/shared-vectors/*) return 0 ;;
  esac

  # Ignore large/binary blobs before regex work. The size guard is a resource
  # bound, not a security exemption: source/config credentials should be far
  # below it, while archived media and generated databases should not consume
  # unbounded scanner memory/CPU.
  [[ "$size" =~ ^[0-9]+$ ]] || return 0
  (( size > 0 && size <= 2097152 )) || return 0
  git cat-file blob "$oid" >"$HISTORY_BLOB_FILE" 2>/dev/null || return 0
  LC_ALL=C grep -Iq . "$HISTORY_BLOB_FILE" || return 0
  if LC_ALL=C grep -qE '(^|[^A-Za-z0-9_])re_[A-Za-z0-9]{6,}_[A-Za-z0-9]{16,}' "$HISTORY_BLOB_FILE"; then
    echo "RESEND_API_KEY|$finding_path|0|human_rotate_if_real" >>"$HITS"
  fi
  if LC_ALL=C grep -qE 'sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}' "$HISTORY_BLOB_FILE"; then
    echo "CLOUD_API_KEY|$finding_path|0|human_rotate_if_real" >>"$HITS"
  fi
  scan_raven_key_hex "$HISTORY_BLOB_FILE" "$finding_path"

  # One parser pass per blob. It emits only class + line number + action;
  # matching source text never leaves the temporary file.
  awk '
    {
      upper = toupper($0)
      lower = tolower($0)
      if (!pem && upper ~ /BEGIN (RSA |OPENSSH |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY/) {
        print "PRIVATE_KEY_PEM|" NR "|human_rotate_if_real"; pem = 1
      }
      if (!aws && upper ~ /AKIA[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z]/) {
        print "AWS_ACCESS_KEY_ID|" NR "|human_rotate_if_real"; aws = 1
      }
      if (!github && (lower ~ /ghp_[a-z0-9]{20,}/ || lower ~ /github_pat_[a-z0-9_]{20,}/)) {
        print "GITHUB_TOKEN|" NR "|human_rotate_if_real"; github = 1
      }
      if (!slack && lower ~ /xox[baprs]-[a-z0-9-]{10,}/) {
        print "SLACK_TOKEN|" NR "|human_rotate_if_real"; slack = 1
      }
      if (!envsecret && upper ~ /^[A-Z0-9_]*(SECRET|PASSWORD|PRIVATE_KEY|API_KEY)[A-Z0-9_]*=.+/ &&
          lower !~ /(change_me|todo|placeholder|example|your_|<.*>|\*\*\*|xxx)/) {
        print "ENV_SECRET_ASSIGNMENT|" NR "|human_review"; envsecret = 1
      }
    }
  ' "$HISTORY_BLOB_FILE" >"$HISTORY_MATCHES"

  while IFS='|' read -r cls line action; do
    [[ -n "${cls:-}" ]] || continue
    echo "$cls|$finding_path|${line:-0}|$action" >>"$HITS"
  done <"$HISTORY_MATCHES"
}

if [[ "${1:-}" == "--self-test" ]]; then
  secret_scan_selftest
  exit 0
fi

echo "Scanning working tree (tracked + common secret filenames)..."
# Tracked files (bounded)
git ls-files -z | while IFS= read -r -d '' f; do
  scan_file "$f"
done

# Include present untracked and ignored working files too. This catches a
# credential in a correctly-gitignored local deploy helper without exposing
# its value or pretending it was committed. Generated/build trees are skipped
# by `scan_file`; CI checkouts normally have no such local files.
git ls-files --others --exclude-standard -z | while IFS= read -r -d '' f; do
  scan_file "$f"
done
git ls-files --others --ignored --exclude-standard -z | while IFS= read -r -d '' f; do
  scan_file "$f"
done

echo "Scanning every reachable Git-history blob (values remain redacted)..."
HISTORY_BLOBS_SCANNED=0
git rev-list --objects --all \
  | git cat-file --batch-check='%(objectname) %(objecttype) %(objectsize) %(rest)' \
  >"$HISTORY_OBJECTS"
while IFS=' ' read -r oid object_type object_size path; do
  [[ -n "${path:-}" ]] || continue
  [[ "$object_type" == "blob" ]] || continue
  HISTORY_BLOBS_SCANNED=$((HISTORY_BLOBS_SCANNED + 1))
  scan_history_blob "$oid" "$path" "$object_size"
done <"$HISTORY_OBJECTS"

# Untracked but present secret-ish names (also assign the hard-fail filename
# class so an accidental `.env` never gets downgraded to pattern-only review).
for f in .env .env.local .env.production credentials.json service-account.json identity.seed; do
  if [[ -f "$f" ]]; then
    echo "UNTRACKED_SECRET_FILE|$f|0|human_ensure_gitignored" >>"$HITS"
    scan_file "$f"
  fi
done

# Recent commit message scan (subjects only — no blob dump of full history)
git log -n 200 --pretty=%s 2>/dev/null | grep -nEi 'password|api[_-]?key|secret|private[_-]?key|AKIA' \
  | head -20 | while IFS= read -r line; do
  echo "COMMIT_SUBJECT_KEYWORD|git-log|${line%%:*}|human_review_history" >>"$HITS"
done || true

HIT_COUNT=$(wc -l <"$HITS" | tr -d ' ')
# CI fails only on high-confidence live-secret classes (not .env.example docs).
CI_FAIL=0
if [[ -s "$HITS" ]]; then
  while IFS='|' read -r cls path _line _action; do
    case "$cls" in
      PRIVATE_KEY_PEM|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|SLACK_TOKEN|UNTRACKED_SECRET_FILE)
        CI_FAIL=1
        ;;
      RESEND_API_KEY|CLOUD_API_KEY|RAVEN_SECRET_FILE|RAW_32_BYTE_BLOB|RAVEN_KEY_MATERIAL_HEX)
        CI_FAIL=1
        ;;
      ENV_SECRET_ASSIGNMENT)
        # Current tree: a non-placeholder secret-looking assignment fails CI.
        # History: human_review only (it cannot be fixed without a rewrite;
        # triage lives in docs/SECRET_SCAN_TRIAGE.md).
        case "$path" in
          history:*) ;;
          *) CI_FAIL=1 ;;
        esac
        ;;
      *)
        ;;
    esac
  done <"$HITS"
fi
DATE_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BRANCH="$(git branch --show-current 2>/dev/null || echo unknown)"
HEAD="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

{
  echo "# Secret History Scan Report"
  echo
  echo "- Generated: \`$DATE_UTC\`"
  echo "- Branch: \`$BRANCH\`"
  echo "- HEAD: \`$HEAD\`"
  echo "- Script: \`scripts/secret_history_scan.sh\`"
  echo "- Hit rows: **$HIT_COUNT** (pattern class only — values redacted)"
  echo "- Historical blobs examined: **$HISTORY_BLOBS_SCANNED** (all reachable refs)"
  echo "- CI hard-fail classes present: **$CI_FAIL** (1=yes)"
  echo
  echo "## Policy"
  echo
  echo "- Findings are flagged for **HUMAN** rotation / history rewrite decisions."
  echo "- Historical findings use \`history:path@blob-id\`; no matching value is emitted."
  echo "- This script does **not** rotate credentials or rewrite git history."
  echo "- Public test vectors / shared-vectors hex are excluded from path scope."
  echo "- Hard-fail classes (tree **and** history): PEM private keys, AWS/GitHub/Slack/Resend/Stripe/Google tokens, untracked secret files, Raven secret files by name (\`identity.seed\`, \`*.seed\`, \`*.sqlite*\`, \`*.db\`, \`prekey_store.json\`, \`*.p12\`/\`*.pfx\`), 32-byte binary blobs (raw seed shape) and 64-hex seed / private-key assignments (RFC 8032 public test keys allowlisted by hash)."
  echo "- Environment-style secret assignments fail CI in the current tree; in history they are human-review rows."
  echo "- Owner triage decisions (rotation, false positives) are recorded by hand in [\`docs/SECRET_SCAN_TRIAGE.md\`](SECRET_SCAN_TRIAGE.md). Rotation must be done by the credential owner at the provider; this repository's tooling never rewrites history."
  echo
  echo "## Findings"
  echo
  if [[ "$HIT_COUNT" -eq 0 ]]; then
    echo "_No high-confidence pattern hits in scoped scan._"
  else
    echo "| Class | Path | Line | Action |"
    echo "|-------|------|------|--------|"
    while IFS='|' read -r cls path line action; do
      echo "| \`$cls\` | \`$path\` | $line | $action |"
    done <"$HITS"
  fi
  echo
  echo "## Human follow-ups (BLOCKED_HUMAN if real secrets)"
  echo
  echo "1. Review each row and record the verdict in [\`docs/SECRET_SCAN_TRIAGE.md\`](SECRET_SCAN_TRIAGE.md) — rows marked OPEN there need the credential owner."
  echo "2. If a credential was ever real: the **owner must rotate / revoke it at the provider**. Removing it from git (or rewriting history) does not un-leak it; this tooling never rewrites history."
  echo "3. Do not commit \`.env\` files, \`identity.seed\`, node databases or other key material; keep them gitignored."
  echo
  echo "## CI"
  echo
  echo "\`--ci\` exits non-zero on any hard-fail class above, and on environment-style secret assignments in the current tree. Historical environment-style rows stay non-blocking human-review findings (see the triage file)."
} >"$REPORT"

# Also refresh the short pointer file used by older checklist notes.
{
  echo "report_md=docs/SECRET_HISTORY_SCAN_REPORT.md"
  echo "hits=$HIT_COUNT"
  echo "ci_fail=$CI_FAIL"
  echo "head=$HEAD"
  echo "generated=$DATE_UTC"
  echo "scan_done"
} >"$REPORT_DIR/SECRET_SCAN_REPORT_2026-08-12.txt"

echo "Wrote $REPORT ($HIT_COUNT hits, ci_fail=$CI_FAIL)"

if [[ "$CI_MODE" -eq 1 ]]; then
  if [[ "$CI_FAIL" -eq 1 ]]; then
    echo "CI: failing closed on hard-fail secret-scan hit(s). See $REPORT"
    exit 1
  fi
  echo "CI: no hard-fail secret classes (human-review findings may remain)"
fi
