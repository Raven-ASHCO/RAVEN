#!/usr/bin/env bash
# Task 0A.2 / 0A.5 — final-image SQLite/SQLCipher symbol-owner + link report.
#
# Usage:
#   ./node/scripts/full_braid_sqlcipher_symbol_owner_report.sh default|lab
#
# Unix: nm + otool (Darwin) or ldd (Linux). Missing tools fail closed.
# Windows MSVC: PE symbol tables are often empty (C symbols live in the PDB).
# Probe dumpbin (via vswhere if not on PATH), llvm-nm, then llvm-pdbutil on
# the sibling PDB. Missing tools / empty tables fail closed. Not a Release
# claim that llvm-nm --defined-only on the EXE is sufficient.
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

bash_path() {
  local p="${1%$'\r'}"
  [[ -n "$p" ]] || return 1
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -u "$p"
  else
    printf '%s\n' "$p"
  fi
}

first_existing() {
  local cand converted
  for cand in "$@"; do
    [[ -z "$cand" ]] && continue
    cand="${cand%$'\r'}"
    if [[ -f "$cand" ]]; then
      printf '%s\n' "$cand"
      return 0
    fi
    converted="$(bash_path "$cand" 2>/dev/null || true)"
    if [[ -n "$converted" && -f "$converted" ]]; then
      printf '%s\n' "$converted"
      return 0
    fi
  done
  return 1
}

locate_vswhere() {
  local c
  c="$(command -v vswhere 2>/dev/null || true)"
  first_existing "$c" \
    "/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe" \
    "/c/Program Files/Microsoft Visual Studio/Installer/vswhere.exe" \
    "/d/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
}

locate_dumpbin() {
  local c vswhere found
  c="$(command -v dumpbin 2>/dev/null || true)"
  if [[ -n "$c" ]]; then
    printf '%s\n' "$c"
    return 0
  fi
  vswhere="$(locate_vswhere || true)"
  if [[ -n "$vswhere" ]]; then
    found="$("$vswhere" -latest -products '*' -find '**/Hostx64/x64/dumpbin.exe' 2>/dev/null | tr -d '\r' | head -n 1 || true)"
    if [[ -z "$found" ]]; then
      found="$("$vswhere" -latest -products '*' -find '**/HostX64/x64/dumpbin.exe' 2>/dev/null | tr -d '\r' | head -n 1 || true)"
    fi
    if [[ -z "$found" ]]; then
      found="$("$vswhere" -latest -products '*' -find '**/dumpbin.exe' 2>/dev/null | tr -d '\r' | head -n 1 || true)"
    fi
    if first_existing "$found" >/dev/null; then
      first_existing "$found"
      return 0
    fi
  fi
  local g
  for g in \
    "/c/Program Files/Microsoft Visual Studio/"*/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe \
    "/c/Program Files/Microsoft Visual Studio/"*/VC/Tools/MSVC/*/bin/HostX64/x64/dumpbin.exe \
    "/d/Program Files/Microsoft Visual Studio/"*/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe
  do
    if [[ -f "$g" ]]; then
      printf '%s\n' "$g"
      return 0
    fi
  done
  return 1
}

locate_pdbutil() {
  local c nm_dir
  c="$(command -v llvm-pdbutil 2>/dev/null || true)"
  if [[ -n "$c" ]]; then
    printf '%s\n' "$c"
    return 0
  fi
  if command -v llvm-nm >/dev/null 2>&1; then
    nm_dir="$(dirname "$(command -v llvm-nm)")"
    if first_existing "$nm_dir/llvm-pdbutil" "$nm_dir/llvm-pdbutil.exe" >/dev/null; then
      first_existing "$nm_dir/llvm-pdbutil" "$nm_dir/llvm-pdbutil.exe"
      return 0
    fi
  fi
  first_existing \
    "/c/Program Files/LLVM/bin/llvm-pdbutil.exe" \
    "/c/Program Files/LLVM/bin/llvm-pdbutil"
}

DUMPBIN_BIN=""
PDBUTIL_BIN=""

prefer_windows_openssl_perl() {
  # Git Bash shadows Strawberry with /usr/bin/perl. openssl-src needs modules
  # from Strawberry. Does not set OPENSSL_DIR / OPENSSL_NO_VENDOR.
  local cand win
  for cand in \
    "/c/Strawberry/perl/bin/perl.exe" \
    "/c/Strawberry/perl/bin/perl" \
    "/d/Strawberry/perl/bin/perl.exe"
  do
    if [[ -x "$cand" ]]; then
      export PATH="$(dirname "$cand"):${PATH}"
      if command -v cygpath >/dev/null 2>&1; then
        win="$(cygpath -w "$cand")"
      else
        win="$cand"
      fi
      export PERL="$win"
      export OPENSSL_SRC_PERL="$win"
      echo "windows-openssl-perl=$cand" >&2
      return 0
    fi
  done
  if perl -e "use Locale::Maketext::Simple;" >/dev/null 2>&1; then
    echo "windows-openssl-perl=$(command -v perl)" >&2
    return 0
  fi
  echo "WARN: perl cannot load Locale::Maketext::Simple (lab openssl-src will fail)" >&2
}

resolve_symbol_tool() {
  if [[ "$IS_WINDOWS" -eq 1 ]]; then
    if [[ -n "$DUMPBIN_BIN" ]]; then
      echo "dumpbin"
      return 0
    fi
    if command -v llvm-nm >/dev/null 2>&1; then
      echo "llvm-nm"
      return 0
    fi
    if [[ -n "$PDBUTIL_BIN" ]]; then
      echo "llvm-pdbutil"
      return 0
    fi
    die "Windows MSVC symbol probe requires dumpbin, llvm-nm, or llvm-pdbutil"
  fi
  command -v nm >/dev/null 2>&1 || die "nm required on Unix"
  echo "nm"
}

resolve_import_tool() {
  if [[ "$IS_WINDOWS" -eq 1 ]]; then
    if [[ -n "$DUMPBIN_BIN" ]]; then
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

if [[ "$IS_WINDOWS" -eq 1 ]]; then
  prefer_windows_openssl_perl
  # Locate outside $(...) — assignments inside command substitution are lost.
  DUMPBIN_BIN="$(locate_dumpbin || true)"
  PDBUTIL_BIN="$(locate_pdbutil || true)"
  # nmake/cl/lib live next to dumpbin; do not import full VS 2026 vcvars
  # (that breaks rustc host build scripts on GHA windows-latest).
  if [[ -n "$DUMPBIN_BIN" ]]; then
    export PATH="$(dirname "$DUMPBIN_BIN"):${PATH}"
  fi
fi
SYMBOL_TOOL="$(resolve_symbol_tool)"
IMPORT_TOOL="$(resolve_import_tool)"
echo "symbol_tool=$SYMBOL_TOOL import_tool=$IMPORT_TOOL dumpbin=${DUMPBIN_BIN:-none} pdbutil=${PDBUTIL_BIN:-none}" >&2

cd "$ROOT/node"
BUILD_JSON="$(mktemp "${TMPDIR:-/tmp}/raven-0a2-cargo-json-XXXXXX")"
SYM_OUT="$(mktemp "${TMPDIR:-/tmp}/raven-0a2-sym-XXXXXX")"
IMP_OUT="$(mktemp "${TMPDIR:-/tmp}/raven-0a2-imp-XXXXXX")"
cleanup() { rm -f "$BUILD_JSON" "$SYM_OUT" "$IMP_OUT"; }
trap cleanup EXIT

dump_cargo_json_errors() {
  python3 - "$BUILD_JSON" <<'PY' >&2 || true
import json, sys
path = sys.argv[1]
print("--- cargo compiler-message errors ---")
try:
    fh = open(path, encoding="utf-8", errors="replace")
except OSError as exc:
    print(exc)
    raise SystemExit(0)
for line in fh:
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue
    if msg.get("reason") != "compiler-message":
        continue
    rendered = (msg.get("message") or {}).get("rendered") or ""
    if rendered:
        print(rendered.rstrip())
PY
}

if [[ "$MODE" == "lab" ]]; then
  export RAVEN_EXPECT_SQLCIPHER_4_17_0=1
  EXPECT_KEY=1
  echo "=== build test binary (lab) ===" >&2
  set +e
  cargo test -p raven-core --features full-braid-durable-lab \
    --test full_braid_sqlcipher_profile --no-run --message-format=json \
    >"$BUILD_JSON" 2> >(tee "${TMPDIR:-/tmp}/raven-0a2-sym-lab-stderr.txt" >&2)
  cargo_rc=$?
  set -e
else
  unset RAVEN_EXPECT_SQLCIPHER_4_17_0 || true
  EXPECT_KEY=0
  echo "=== build test binary (default) ===" >&2
  set +e
  cargo test -p raven-core --lib --no-run --message-format=json \
    >"$BUILD_JSON" 2> >(tee "${TMPDIR:-/tmp}/raven-0a2-sym-def-stderr.txt" >&2)
  cargo_rc=$?
  set -e
fi
if [[ "$cargo_rc" -ne 0 ]]; then
  dump_cargo_json_errors
  die "cargo test --no-run failed rc=$cargo_rc"
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

count_sym() {
  local sym="$1"
  local n
  n="$(python3 - "$sym" "$SYM_OUT" <<'PY'
import re, sys
sym, path = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8", errors="replace").read()
patterns = [
    # BSD/llvm: "00001234 T sqlite3_open_v2"
    rf"(?:^|\s)[TtAaDd]\s+_?{re.escape(sym)}(?:@[0-9]+)?\s*$",
    # posix/sysv: "sqlite3_open_v2 T 00001234" or "name | addr | T"
    rf"^_?{re.escape(sym)}(?:@[0-9]+)?\s+\|.*\|\s+[TtAaDd]\b",
    rf"^_?{re.escape(sym)}(?:@[0-9]+)?\s+[TtAaDd]\s+",
    # dumpbin: External | sqlite3_open_v2
    rf"External\s+\|\s+_?{re.escape(sym)}(?:\s|$)",
    # llvm-pdbutil dump -publics
    rf"name\s*=\s*`_?{re.escape(sym)}`",
    rf"\|\s+_?{re.escape(sym)}\s*$",
    # llvm-pdbutil pretty -publics ("  sqlite3_open_v2 [32-bit function]")
    rf"^\s+_?{re.escape(sym)}(?:\s|$)",
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
        last = parts[-1].split("@")[0].lstrip("_").strip("`")
        kind = parts[-2] if len(parts) >= 2 else ""
        if last == sym and kind not in {"U", "u"}:
            n += 1
print(n)
PY
)"
  [[ -n "$n" ]] || n=0
  echo "$n"
}

# Run one symbol dumper. Empty success (MSVC PE has no COFF table) is not a hit.
windows_try_source() {
  local label="$1"
  shift
  set +e
  "$@" >"$SYM_OUT" 2>/dev/null
  local rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "symbol source $label failed rc=$rc" >&2
    : >"$SYM_OUT"
    return 1
  fi
  if [[ ! -s "$SYM_OUT" ]]; then
    echo "symbol source $label empty" >&2
    return 1
  fi
  local n
  n="$(count_sym sqlite3_open_v2)"
  echo "symbol source $label sqlite3_open_v2 count=$n lines=$(wc -l <"$SYM_OUT" | tr -d ' ')" >&2
  [[ "$n" != "0" ]]
}

resolve_pdb() {
  local bin="$1"
  local cand extracted sib
  for cand in "${bin%.exe}.pdb" "${bin%.EXE}.pdb"; do
    if [[ -f "$cand" ]]; then
      printf '%s\n' "$cand"
      return 0
    fi
  done
  if command -v llvm-readobj >/dev/null 2>&1; then
    extracted="$(
      llvm-readobj --coff-debug-directory "$bin" 2>/dev/null | python3 - <<'PY'
import re, sys
text = sys.stdin.read()
for pat in (
    r"PdbFileName:\s+(\S+)",
    r"Filename:\s+(\S+\.pdb)",
    r"PDBFileName:\s+(\S+)",
):
    match = re.search(pat, text, flags=re.I)
    if match:
        print(match.group(1).strip().strip('"'))
        break
PY
    )"
    extracted="${extracted%$'\r'}"
    if [[ -n "$extracted" ]]; then
      if [[ -f "$extracted" ]]; then
        printf '%s\n' "$extracted"
        return 0
      fi
      sib="$(dirname "$bin")/$(basename "$extracted")"
      if [[ -f "$sib" ]]; then
        printf '%s\n' "$sib"
        return 0
      fi
      converted="$(bash_path "$extracted" 2>/dev/null || true)"
      if [[ -n "$converted" && -f "$converted" ]]; then
        printf '%s\n' "$converted"
        return 0
      fi
    fi
  fi
  return 1
}

newest_native_sqlite_lib() {
  local deps dir cand
  deps="$(dirname "$BIN")"
  dir="$(dirname "$deps")"
  local found=""
  set +e
  found="$(ls -1t \
    "$deps"/sqlite3.lib \
    "$deps"/sqlcipher.lib \
    "$deps"/libsqlite3.a \
    "$dir"/build/libsqlite3-sys-*/out/sqlite3.lib \
    "$dir"/build/libsqlite3-sys-*/out/sqlcipher.lib \
    "$dir"/build/libsqlite3-sys-*/out/libsqlite3.a \
    2>/dev/null | head -n 1)"
  set -e
  found="${found%$'\r'}"
  [[ -n "$found" && -f "$found" ]] || return 1
  printf '%s\n' "$found"
}

dump_symbols() {
  if [[ "$IS_WINDOWS" -eq 0 ]]; then
    case "$SYMBOL_TOOL" in
      nm)
        nm -gU "$BIN" >"$SYM_OUT" 2>/dev/null || nm -g "$BIN" >"$SYM_OUT" 2>/dev/null \
          || die "nm failed on $BIN"
        ;;
      *)
        die "unsupported Unix symbol tool $SYMBOL_TOOL"
        ;;
    esac
    return 0
  fi

  # MSVC: llvm-nm --defined-only on the EXE often exits 0 with an empty table
  # because bundled sqlite C symbols live in the PDB, not the PE.
  if [[ -n "$DUMPBIN_BIN" ]]; then
    windows_try_source "dumpbin-exe" "$DUMPBIN_BIN" //SYMBOLS "$BIN" \
      || windows_try_source "dumpbin-exe" "$DUMPBIN_BIN" /SYMBOLS "$BIN" \
      || true
    if [[ "$(count_sym sqlite3_open_v2)" != "0" ]]; then
      SYMBOL_TOOL="dumpbin"
      echo "symbol_source=dumpbin exe" >&2
      return 0
    fi
  fi

  if command -v llvm-nm >/dev/null 2>&1; then
    # Empty --defined-only is success; do not treat it as the only dump.
    windows_try_source "llvm-nm-defined" llvm-nm --defined-only "$BIN" || true
    if [[ "$(count_sym sqlite3_open_v2)" != "0" ]]; then
      SYMBOL_TOOL="llvm-nm"
      echo "symbol_source=llvm-nm --defined-only exe" >&2
      return 0
    fi
    windows_try_source "llvm-nm" llvm-nm "$BIN" || true
    if [[ "$(count_sym sqlite3_open_v2)" != "0" ]]; then
      SYMBOL_TOOL="llvm-nm"
      echo "symbol_source=llvm-nm exe" >&2
      return 0
    fi
  fi

  local pdb=""
  pdb="$(resolve_pdb "$BIN" || true)"
  if [[ -n "$pdb" ]]; then
    echo "pdb=$pdb" >&2
    if [[ -n "$PDBUTIL_BIN" ]]; then
      windows_try_source "pdbutil-pretty" "$PDBUTIL_BIN" pretty -publics "$pdb" || true
      if [[ "$(count_sym sqlite3_open_v2)" != "0" ]]; then
        SYMBOL_TOOL="llvm-pdbutil"
        echo "symbol_source=llvm-pdbutil pretty -publics" >&2
        return 0
      fi
      windows_try_source "pdbutil-dump" "$PDBUTIL_BIN" dump -publics "$pdb" || true
      if [[ "$(count_sym sqlite3_open_v2)" != "0" ]]; then
        SYMBOL_TOOL="llvm-pdbutil"
        echo "symbol_source=llvm-pdbutil dump -publics" >&2
        return 0
      fi
    fi
    if command -v llvm-nm >/dev/null 2>&1; then
      windows_try_source "llvm-nm-pdb" llvm-nm "$pdb" || true
      if [[ "$(count_sym sqlite3_open_v2)" != "0" ]]; then
        SYMBOL_TOOL="llvm-nm"
        echo "symbol_source=llvm-nm pdb" >&2
        return 0
      fi
    fi
  else
    echo "pdb=missing (sibling of $BIN)" >&2
  fi

  # Last resort: newest libsqlite3-sys archive next to this artifact. Import
  # rejection still proves the final image did not take sqlite3.dll.
  local native=""
  native="$(newest_native_sqlite_lib || true)"
  if [[ -n "$native" ]]; then
    echo "native_lib=$native" >&2
    if command -v llvm-nm >/dev/null 2>&1; then
      windows_try_source "native-lib-nm-defined" llvm-nm --defined-only "$native" \
        || windows_try_source "native-lib-nm" llvm-nm "$native" \
        || true
      if [[ "$(count_sym sqlite3_open_v2)" != "0" ]]; then
        SYMBOL_TOOL="llvm-nm"
        echo "symbol_source=llvm-nm native lib" >&2
        return 0
      fi
    fi
    if [[ -n "$DUMPBIN_BIN" ]]; then
      windows_try_source "native-lib-dumpbin" "$DUMPBIN_BIN" //SYMBOLS "$native" \
        || windows_try_source "native-lib-dumpbin" "$DUMPBIN_BIN" /SYMBOLS "$native" \
        || true
      if [[ "$(count_sym sqlite3_open_v2)" != "0" ]]; then
        SYMBOL_TOOL="dumpbin"
        echo "symbol_source=dumpbin native lib" >&2
        return 0
      fi
    fi
  fi

  echo "--- last symbol dump head ---" >&2
  head -n 25 "$SYM_OUT" >&2 || true
  die "Windows MSVC symbol table empty for $BIN (tried dumpbin/llvm-nm/PDB/native lib; C symbols are not in the PE)"
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
      "${DUMPBIN_BIN:-dumpbin}" //IMPORTS "$BIN" >"$IMP_OUT" 2>/dev/null \
        || "${DUMPBIN_BIN:-dumpbin}" /IMPORTS "$BIN" >"$IMP_OUT" 2>/dev/null \
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
