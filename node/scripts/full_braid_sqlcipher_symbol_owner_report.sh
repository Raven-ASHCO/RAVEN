#!/usr/bin/env bash
# Task 0A.2 / 0A.5 — final-image SQLite/SQLCipher symbol-owner + link report.
#
# Usage:
#   ./node/scripts/full_braid_sqlcipher_symbol_owner_report.sh default|lab
#
# Unix: nm + otool (Darwin) or ldd (Linux). Missing tools fail closed.
# Windows MSVC: llvm-nm or dumpbin for symbols; dumpbin /imports or
# llvm-readobj --coff-imports for DLL rejection. Missing tools fail closed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODE="${1:-}"

die() { echo "FAIL: $*" >&2; exit 1; }

command -v cargo >/dev/null || die "cargo not found on PATH"
command -v python3 >/dev/null || die "python3 required to parse cargo JSON"

[[ "$MODE" == "default" || "$MODE" == "lab" ]] || die "usage: $0 default|lab"

UNAME="$(uname -s 2>/dev/null || echo unknown)"
IS_WINDOWS=0
case "$UNAME" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT) IS_WINDOWS=1 ;;
esac
if [[ "${OS:-}" == "Windows_NT" ]]; then
  IS_WINDOWS=1
fi

resolve_symbol_tool() {
  if [[ "$IS_WINDOWS" -eq 1 ]]; then
    # Prefer dumpbin on MSVC: llvm-nm --defined-only often misses C symbols
    # statically linked from rusqlite's bundled sqlite (count=0 false fail).
    if command -v dumpbin >/dev/null 2>&1; then
      echo "dumpbin"
      return 0
    fi
    if command -v llvm-nm >/dev/null 2>&1; then
      echo "llvm-nm"
      return 0
    fi
    die "Windows MSVC symbol probe requires llvm-nm or dumpbin on PATH"
  fi
  command -v nm >/dev/null 2>&1 || die "nm required on Unix"
  echo "nm"
}

resolve_import_tool() {
  if [[ "$IS_WINDOWS" -eq 1 ]]; then
    if command -v dumpbin >/dev/null 2>&1; then
      echo "dumpbin"
      return 0
    fi
    if command -v llvm-readobj >/dev/null 2>&1; then
      echo "llvm-readobj"
      return 0
    fi
    die "Windows MSVC import probe requires dumpbin or llvm-readobj on PATH"
  fi
  if [[ "$UNAME" == "Darwin" ]]; then
    command -v otool >/dev/null 2>&1 || die "otool required on Darwin for dynamic-link proof"
    echo "otool"
    return 0
  fi
  command -v ldd >/dev/null 2>&1 || die "ldd required on Linux for dynamic-link proof"
  echo "ldd"
}

SYMBOL_TOOL="$(resolve_symbol_tool)"
IMPORT_TOOL="$(resolve_import_tool)"
echo "symbol_tool=$SYMBOL_TOOL import_tool=$IMPORT_TOOL" >&2

cd "$ROOT/node"
BUILD_JSON="$(mktemp "${TMPDIR:-/tmp}/raven-0a2-cargo-json-XXXXXX")"
SYM_OUT="$(mktemp "${TMPDIR:-/tmp}/raven-0a2-sym-XXXXXX")"
IMP_OUT="$(mktemp "${TMPDIR:-/tmp}/raven-0a2-imp-XXXXXX")"
cleanup() { rm -f "$BUILD_JSON" "$SYM_OUT" "$IMP_OUT"; }
trap cleanup EXIT

if [[ "$MODE" == "lab" ]]; then
  export RAVEN_EXPECT_SQLCIPHER_4_17_0=1
  EXPECT_KEY=1
  echo "=== build test binary (lab) ===" >&2
  cargo test -p raven-core --features full-braid-durable-lab \
    --test full_braid_sqlcipher_profile --no-run --message-format=json \
    >"$BUILD_JSON" 2> >(tee "${TMPDIR:-/tmp}/raven-0a2-sym-lab-stderr.txt" >&2)
else
  unset RAVEN_EXPECT_SQLCIPHER_4_17_0 || true
  EXPECT_KEY=0
  echo "=== build test binary (default) ===" >&2
  cargo test -p raven-core --lib --no-run --message-format=json \
    >"$BUILD_JSON" 2> >(tee "${TMPDIR:-/tmp}/raven-0a2-sym-def-stderr.txt" >&2)
fi

BIN="$(
  python3 - "$MODE" "$BUILD_JSON" <<'PY'
import json, sys
mode, path = sys.argv[1], sys.argv[2]
want = "full_braid_sqlcipher_profile" if mode == "lab" else "raven_core"
chosen = None
with open(path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        target = msg.get("target") or {}
        name = target.get("name") or ""
        exes = msg.get("executable")
        if not exes:
            continue
        if isinstance(exes, list):
            if not exes:
                continue
            exe = exes[0]
        else:
            exe = exes
        if mode == "lab" and name == "full_braid_sqlcipher_profile":
            chosen = exe
            break
        if mode == "default" and name == "raven_core" and "test" in (target.get("kind") or []):
            chosen = exe
if not chosen:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if want not in line or "compiler-artifact" not in line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            exes = msg.get("executable")
            if isinstance(exes, list) and exes:
                chosen = exes[0]
            elif isinstance(exes, str):
                chosen = exes
print(chosen or "")
PY
)"

[[ -n "${BIN}" ]] || die "could not resolve compiler-artifact.executable (got empty)"
if [[ ! -f "$BIN" ]]; then
  die "compiler-artifact executable missing: $BIN"
fi
echo "binary=$BIN" >&2

dump_symbols() {
  case "$SYMBOL_TOOL" in
    nm)
      nm -gU "$BIN" >"$SYM_OUT" 2>/dev/null || nm -g "$BIN" >"$SYM_OUT" 2>/dev/null \
        || die "nm failed on $BIN"
      ;;
    llvm-nm)
      llvm-nm --defined-only "$BIN" >"$SYM_OUT" 2>/dev/null \
        || llvm-nm "$BIN" >"$SYM_OUT" 2>/dev/null \
        || die "llvm-nm failed on $BIN"
      ;;
    dumpbin)
      dumpbin //SYMBOLS "$BIN" >"$SYM_OUT" 2>/dev/null \
        || dumpbin /SYMBOLS "$BIN" >"$SYM_OUT" 2>/dev/null \
        || die "dumpbin /SYMBOLS failed on $BIN"
      ;;
    *)
      die "unsupported symbol tool $SYMBOL_TOOL"
      ;;
  esac
}

count_sym() {
  local sym="$1"
  local n=0
  set +e
  case "$SYMBOL_TOOL" in
    nm|llvm-nm)
      n="$(python3 - "$sym" "$SYM_OUT" <<'PY'
import re, sys
sym, path = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8", errors="replace").read()
# BSD/llvm default: "00001234 T sqlite3_open_v2"
#if posix/sysv: "sqlite3_open_v2 T 00001234" or "name | addr | T"
patterns = [
    rf"(?:^|\s)[TtAaDd]\s+_?{re.escape(sym)}(?:@[0-9]+)?\s*$",
    rf"^_?{re.escape(sym)}(?:@[0-9]+)?\s+\|.*\|\s+[TtAaDd]\b",
    rf"^_?{re.escape(sym)}(?:@[0-9]+)?\s+[TtAaDd]\s+",
]
n = 0
for pat in patterns:
    n = len(re.findall(pat, text, flags=re.M))
    if n:
        break
if n == 0:
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        last = parts[-1].split("@")[0].lstrip("_")
        kind = parts[-2] if len(parts) >= 2 else ""
        if last == sym and kind not in {"U", "u"}:
            n += 1
print(n)
PY
)"
      ;;
    dumpbin)
      # MSVC dumpbin lists External | sqlite3_open_v2
      n="$(grep -E "External[[:space:]]+\|[[:space:]]+_?${sym}([[:space:]]|$)" "$SYM_OUT" | wc -l | tr -d ' ')"
      if [[ "$n" == "0" ]]; then
        n="$(grep -E "[[:space:]]_?${sym}([[:space:]]|$)" "$SYM_OUT" | grep -ci 'External' | tr -d ' ' || true)"
      fi
      ;;
  esac
  set -e
  [[ -n "$n" ]] || n=0
  echo "$n"
}

dump_symbols

echo "=== symbol owners ===" >&2
for sym in sqlite3_open_v2 sqlite3_libversion sqlite3_key; do
  n="$(count_sym "$sym")"
  echo "$sym count=$n" >&2
  if [[ "$n" == "0" && "$sym" != "sqlite3_key" ]]; then
    echo "--- symbol lines containing $sym ---" >&2
    grep -F "$sym" "$SYM_OUT" | head -n 40 >&2 || true
    echo "--- symbol table head ---" >&2
    head -n 25 "$SYM_OUT" >&2 || true
  fi
  if [[ "$sym" == "sqlite3_key" ]]; then
    if [[ "$EXPECT_KEY" == "1" ]]; then
      [[ "$n" == "1" ]] || die "$sym expected exactly 1 owner in lab image, got $n"
    else
      [[ "$n" == "0" ]] || die "$sym must be absent in default image, got $n"
    fi
  else
    [[ "$n" == "1" ]] || die "$sym expected exactly 1 owner, got $n"
  fi
done

if [[ "$EXPECT_KEY" == "1" ]]; then
  n_rekey="$(count_sym sqlite3_rekey)"
  n_rekey_v2="$(count_sym sqlite3_rekey_v2)"
  echo "sqlite3_rekey count=$n_rekey sqlite3_rekey_v2 count=$n_rekey_v2" >&2
  total=$((n_rekey + n_rekey_v2))
  [[ "$total" -ge 1 ]] || die "expected at least one rekey symbol in lab image"
fi

dump_imports() {
  case "$IMPORT_TOOL" in
    otool)
      otool -L "$BIN" >"$IMP_OUT"
      ;;
    ldd)
      ldd "$BIN" >"$IMP_OUT"
      ;;
    dumpbin)
      dumpbin //IMPORTS "$BIN" >"$IMP_OUT" 2>/dev/null \
        || dumpbin /IMPORTS "$BIN" >"$IMP_OUT" 2>/dev/null \
        || die "dumpbin /IMPORTS failed on $BIN"
      ;;
    llvm-readobj)
      llvm-readobj --coff-imports "$BIN" >"$IMP_OUT" 2>/dev/null \
        || die "llvm-readobj --coff-imports failed on $BIN"
      ;;
    *)
      die "unsupported import tool $IMPORT_TOOL"
      ;;
  esac
}

forbid_import_pattern() {
  local label="$1"
  local pattern="$2"
  if grep -Ei -- "$pattern" "$IMP_OUT" >/dev/null; then
    die "forbidden dynamic dependency matched /$pattern/ ($label)"
  fi
}

echo "=== dynamic / import linkage ===" >&2
dump_imports
forbid_import_pattern "libsqlite3" 'libsqlite3\.(dylib|so)|[/\\]sqlite3\.dll|[[:space:]]sqlite3\.dll'
if [[ "$MODE" == "lab" ]]; then
  forbid_import_pattern "libssl" 'libssl\.(dylib|so)|[/\\]libssl[^[:space:]]*\.dll|[[:space:]]libssl[^[:space:]]*\.dll'
  forbid_import_pattern "libcrypto" 'libcrypto\.(dylib|so)|[/\\]libcrypto[^[:space:]]*\.dll|[[:space:]]libcrypto[^[:space:]]*\.dll'
  echo "PASS: no dynamic sqlite3/ssl/crypto imports ($IMPORT_TOOL)" >&2
else
  echo "PASS: no dynamic libsqlite3 ($IMPORT_TOOL)" >&2
fi

echo "PASS: symbol-owner report (${MODE})" >&2
