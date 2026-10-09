#!/usr/bin/env bash
# Keychain guard check. Every macOS Keychain call (security_framework::*,
# get/set/add/delete/find_*_password, ItemSearchOptions, SecItem*, SecKeychain*)
# must sit inside a raven_core::macos_keychain::guarded(...) call: a blocked
# access dialog then prints a hint instead of hanging a terminal in silence. A
# new raw call anywhere else fails here, and so does a raw call that sits beside
# the guard inside an allow-listed function, or a function that lost its guard.
#
# This is a textual scan, not a Rust parser. // comments and the inside of
# string and char literals are skipped; /* */ comments, macros, aliases and a
# closure built outside guarded(...) are not understood, so keep every call
# inline in the closure of its wrapper's guarded(...). `use` lines may import
# the API anywhere inside an allow-listed function; only calls need the guard.
#
#   scripts/keychain_guard_check.sh              scan node/crates/**/*.rs
#   scripts/keychain_guard_check.sh --self-test  prove the scanner on a scratch tree
#
# Exit: 0 clean, 1 violation, 2 tree not found, 97 self-test failure.
# Bash 3.2 compatible (macOS /bin/bash): no arrays, mapfile or ${x,,}; awk and
# find are used with POSIX features only.
set -euo pipefail

# file:function pairs that may call the Keychain, each wrapping every call in
# `guarded(`. A `*` function allows the whole file (the guard module itself).
# The names `get` / `put` / `delete` are the trait methods of the macOS
# session and prekey backends.
ALLOWED='node/crates/raven-core/src/macos_keychain.rs:*
node/crates/raven-core/src/identity_store.rs:keychain_get
node/crates/raven-core/src/identity_store.rs:keychain_set
node/crates/raven-core/src/identity_store.rs:keychain_delete
node/crates/raven-core/src/chat_history.rs:platform_get_key
node/crates/raven-core/src/chat_history.rs:platform_add_key
node/crates/raven-core/src/indexed_session_store.rs:get
node/crates/raven-core/src/indexed_session_store.rs:put
node/crates/raven-core/src/indexed_session_store.rs:delete
node/crates/raven-core/src/prekey_lifecycle.rs:get
node/crates/raven-core/src/prekey_lifecycle.rs:put'

# Reads the allow-list file (first argument), then Rust files. Tracks the
# enclosing `fn`, skips comments, strings and char literals, and follows the
# parentheses of every guarded( call so each API use is known to be inside one
# (gdepth > 0) or not. Prints one line per problem. The $0 and $ anchors below
# are awk's, not shell expansions. No apostrophes in this program: it sits in a
# single-quoted shell string.
# shellcheck disable=SC2016
AWK_PROGRAM='
BEGIN {
  bad = 0
  sq = sprintf("%c", 39); dq = sprintf("%c", 34); bs = sprintf("%c", 92)
  # Whole identifiers that are Keychain calls (the crate path is handled in walk).
  api = "^((get|set|add|delete|find)_(generic|internet)_password|SecItem[A-Z][A-Za-z]*|SecKeychain[A-Za-z]*|ItemSearchOptions)$"
  # A line that can matter: only these (or one inside a guarded call, a string
  # or a use statement) are looked at token by token. Keep it in step with api.
  hot = "guarded|security_framework|ItemSearchOptions|SecItem|SecKeychain|_(generic|internet)_password"
  decl = "^[[:space:]]*(pub([(][a-z_ ]+[)])?[[:space:]]+)?((async|const|unsafe)[[:space:]]+)*(extern[[:space:]]+\"[A-Za-z]+\"[[:space:]]+)?fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*"
  usestmt = "^[[:space:]]*(pub([(][a-z_ ]+[)])?[[:space:]]+)?use[[:space:]]"
}
# The line without its // comment and with every string or char literal
# replaced by one space. A string can span lines: in_str carries over.
function blank(s,   out, n, i, c, j) {
  out = ""
  n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (in_str) {
      if (c == bs) i++
      else if (c == dq) in_str = 0
    } else if (c == "/" && substr(s, i + 1, 1) == "/") {
      break
    } else if (c == dq) {
      in_str = 1
      out = out " "
    } else if (c == sq && substr(s, i + 1, 1) == bs && (j = index(substr(s, i + 3), sq)) > 0) {
      out = out " "
      i = i + 2 + j
    } else if (c == sq && substr(s, i + 2, 1) == sq) {
      out = out " "
      i = i + 2
    } else {
      out = out c
    }
  }
  return out
}
# Walk the identifiers and parentheses of one blanked line. gdepth counts the
# parentheses open since the guarded( call we are inside (0 = outside any).
# usage is true for a use statement: it may name the API without calling it.
function walk(s, lineno, usage,   tok) {
  while (match(s, /[A-Za-z_][A-Za-z0-9_]*|[()]/)) {
    tok = substr(s, RSTART, RLENGTH)
    s = substr(s, RSTART + RLENGTH)
    if (tok == "(") {
      if (gdepth > 0) gdepth++
    } else if (tok == ")") {
      if (gdepth > 0) gdepth--
    } else if (tok == "guarded" && match(s, /^[[:space:]]*[(]/)) {
      s = substr(s, RLENGTH + 1)
      guarded_in[fid] = 1
      gdepth++
    } else if (tok ~ api || (tok == "security_framework" && substr(s, 1, 2) == "::")) {
      if (!(fid in first)) {
        first[fid] = lineno
        file_of[fid] = FILENAME
        fn_of[fid] = fname
      }
      if (!usage && gdepth == 0 && !(fid in raw)) raw[fid] = lineno
    }
  }
}
FILENAME == ARGV[1] { if ($0 != "") allow[$0] = 1; next }
FNR == 1 {
  fname = "<module>"; fid = FILENAME ":" fname ":0"
  gdepth = 0; in_str = 0; in_use = 0
}
{
  line = $0
  sub(/\/\/.*/, "", line)
  if (match(line, decl)) {
    n = split(substr(line, RSTART, RLENGTH), parts, /[[:space:]]+/)
    fname = parts[n]
    fid = FILENAME ":" fname ":" FNR
    gdepth = 0; in_str = 0; in_use = 0
  }
  starts_use = (!in_use && line ~ usestmt)
  usage = (in_use || starts_use)
  if (starts_use && line !~ /;/) in_use = 1
  if (gdepth > 0 || in_str || usage || $0 ~ hot) walk(blank($0), FNR, usage)
  if (in_use && line ~ /;/) in_use = 0
  if ($0 ~ /^}/) {
    fname = "<module>"; fid = FILENAME ":" fname ":" FNR
    gdepth = 0; in_str = 0; in_use = 0
  }
}
END {
  for (id in first) {
    f = file_of[id]; name = fn_of[id]; key = f ":" name
    if ((f ":*") in allow) continue
    if (!(key in allow)) {
      printf "%s:%d: Keychain API used in %s(), which is not allow-listed\n", f, first[id], name
      bad = 1
      continue
    }
    used[key] = 1
    if (id in raw) {
      printf "%s:%d: %s() calls the Keychain outside macos_keychain::guarded\n", f, raw[id], name
      bad = 1
    } else if (!(id in guarded_in)) {
      printf "%s:%d: %s() calls the Keychain outside macos_keychain::guarded\n", f, first[id], name
      bad = 1
    }
  }
  for (key in allow) {
    if (key ~ /:[*]$/) continue
    if (!(key in used)) {
      printf "%s: stale allow-list entry (no Keychain call left in that function)\n", key
      bad = 1
    }
  }
  exit bad
}'

# scan_tree ROOT ALLOWED — scan ROOT/node/crates. Problems go to stdout.
# Status: 0 clean, 1 problems, 2 no Rust sources found (a moved tree must not
# pass by scanning nothing).
scan_tree() {
  local root="$1" allowed="$2" tmp count rc=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/keychain-guard.XXXXXX")"
  printf '%s\n' "$allowed" >"$tmp/allow"
  count="$(cd "$root" && find node/crates -name target -prune -o -type f -name '*.rs' -print 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$count" == "0" ]]; then
    rm -rf "$tmp"
    return 2
  fi
  (cd "$root" && LC_ALL=C find node/crates -name target -prune -o -type f -name '*.rs' \
    -exec awk "$AWK_PROGRAM" "$tmp/allow" {} +) >"$tmp/out" || rc=$?
  LC_ALL=C sort "$tmp/out"
  rm -rf "$tmp"
  [[ "$rc" == "0" ]] || return 1
  return 0
}

selftest_fail() {
  echo "KEYCHAIN GUARD SELF-TEST FAILED: $*" >&2
  exit 97
}

# selftest_expect NAME ROOT ALLOWED WANT_STATUS [WANT_TEXT]
selftest_expect() {
  local name="$1" root="$2" allowed="$3" want="$4" text="${5:-}" out rc=0
  out="$(scan_tree "$root" "$allowed")" || rc=$?
  if [[ "$rc" != "$want" ]]; then
    selftest_fail "$name: status $rc, expected $want; output: $out"
  fi
  if [[ -n "$text" ]] && ! grep -qF -- "$text" <<<"$out"; then
    selftest_fail "$name: output lacks '$text': $out"
  fi
}

selftest() {
  local root
  SELFTEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/keychain-guard-selftest.XXXXXX")"
  trap 'rm -rf "${SELFTEST_DIR:-}"' EXIT
  root="$SELFTEST_DIR/tree"
  mkdir -p "$root/node/crates/demo/src"
  # An empty tree is an error, not a pass.
  selftest_expect "empty tree" "$root" "" 2

  local src="$root/node/crates/demo/src" pre="node/crates/demo/src"
  # Allow-listed function, raw call inside guarded(: clean.
  cat >"$src/ok.rs" <<'EOF'
fn read_item(account: &str) -> u8 {
    use security_framework::passwords::get_generic_password;
    guarded(KeychainWhat::IdentitySeed, || get_generic_password("s", account))
}
EOF
  selftest_expect "guarded allow-listed call" "$root" "$pre/ok.rs:read_item" 0

  # Comments, a status constant and look-alike names are not Keychain calls.
  cat >"$src/quiet.rs" <<'EOF'
/// Reads with get_generic_password and SecItemCopyMatching.
// set_generic_password is only named here, security_framework::passwords too.
use security_framework_sys::base::errSecItemNotFound;
fn helpers() -> bool {
    let reset_generic_password_policy = 1;
    let my_get_generic_password_cache = 2;
    reset_generic_password_policy + my_get_generic_password_cache > 0 && errSecItemNotFound != 0
}
EOF
  selftest_expect "comments and look-alikes" "$root" "$pre/ok.rs:read_item" 0

  # A raw call in any other function fails and names file, line and function.
  cat >"$src/newsite.rs" <<'EOF'
fn sneaky(account: &str) {
    let _ = security_framework::passwords::set_generic_password("svc", account, b"x");
}
EOF
  selftest_expect "new call site" "$root" "$pre/ok.rs:read_item" 1 \
    "$pre/newsite.rs:2: Keychain API used in sneaky(), which is not allow-listed"
  rm "$src/newsite.rs"

  # Raw FFI names are caught too.
  cat >"$src/ffi.rs" <<'EOF'
fn raw() {
    unsafe { SecItemCopyMatching(query, &mut out) };
}
EOF
  selftest_expect "raw SecItem call" "$root" "$pre/ok.rs:read_item" 1 \
    "$pre/ffi.rs:2: Keychain API used in raw()"
  rm "$src/ffi.rs"

  # An allow-listed function that lost its guard fails.
  cat >"$src/unguarded.rs" <<'EOF'
fn read_item(account: &str) -> u8 {
    use security_framework::passwords::get_generic_password;
    get_generic_password("s", account)
}
EOF
  selftest_expect "allow-listed but unguarded" "$root" "$pre/unguarded.rs:read_item" 1 \
    "$pre/unguarded.rs:3: read_item() calls the Keychain outside macos_keychain::guarded"
  rm "$src/unguarded.rs"

  # An allow-listed function that only imports the API has no guarded call.
  cat >"$src/importonly.rs" <<'EOF'
fn read_item() {
    use security_framework::passwords::get_generic_password;
}
EOF
  selftest_expect "allow-listed, import only" "$root" "$pre/ok.rs:read_item
$pre/importonly.rs:read_item" 1 \
    "$pre/importonly.rs:2: read_item() calls the Keychain outside macos_keychain::guarded"
  rm "$src/importonly.rs"

  # A raw call BESIDE the guard fails too: before it, after it, on its line, or
  # in a closure that is built outside guarded(...) and only passed in.
  cat >"$src/before.rs" <<'EOF'
fn read_item(account: &str) -> u8 {
    let _leak = get_generic_password("s", account);
    guarded(KeychainWhat::IdentitySeed, || get_generic_password("s", account))
}
EOF
  selftest_expect "raw call before the guard" "$root" "$pre/ok.rs:read_item
$pre/before.rs:read_item" 1 \
    "$pre/before.rs:2: read_item() calls the Keychain outside macos_keychain::guarded"
  rm "$src/before.rs"
  cat >"$src/after.rs" <<'EOF'
fn read_item(account: &str) -> u8 {
    let v = guarded(KeychainWhat::IdentitySeed, || get_generic_password("s", account));
    let _leak = get_generic_password("s", account);
    v
}
EOF
  selftest_expect "raw call after the guard" "$root" "$pre/ok.rs:read_item
$pre/after.rs:read_item" 1 \
    "$pre/after.rs:3: read_item() calls the Keychain outside macos_keychain::guarded"
  rm "$src/after.rs"
  cat >"$src/sameline.rs" <<'EOF'
fn read_item(account: &str) -> u8 {
    let _x = get_generic_password("s", account); guarded(KeychainWhat::IdentitySeed, || get_generic_password("s", account))
}
EOF
  selftest_expect "raw call on the guard's line" "$root" "$pre/ok.rs:read_item
$pre/sameline.rs:read_item" 1 \
    "$pre/sameline.rs:2: read_item() calls the Keychain outside macos_keychain::guarded"
  rm "$src/sameline.rs"
  cat >"$src/prebuilt.rs" <<'EOF'
fn read_item() {
    let call = || get_generic_password("s", "a");
    guarded(KeychainWhat::IdentitySeed, call)
}
EOF
  selftest_expect "closure built outside the guard" "$root" "$pre/ok.rs:read_item
$pre/prebuilt.rs:read_item" 1 \
    "$pre/prebuilt.rs:2: read_item() calls the Keychain outside macos_keychain::guarded"
  rm "$src/prebuilt.rs"
  cat >"$src/search.rs" <<'EOF'
fn read_item() {
    use security_framework::item::ItemSearchOptions;
    let mut q = ItemSearchOptions::new();
    guarded(KeychainWhat::IdentitySeed, || get_generic_password("s", "a"))
}
EOF
  selftest_expect "raw item search beside the guard" "$root" "$pre/ok.rs:read_item
$pre/search.rs:read_item" 1 \
    "$pre/search.rs:3: read_item() calls the Keychain outside macos_keychain::guarded"
  rm "$src/search.rs"

  # What a real wrapper looks like: multi-line imports, nested calls, and
  # parentheses or quotes inside comments, strings and char literals must not
  # end the guarded extent early (all calls inside stay clean) ...
  cat >"$src/tricky.rs" <<'EOF'
fn read_item(account: &str) -> u8 {
    use security_framework::item::{
        ItemClass,
        ItemSearchOptions,
    };
    use security_framework::passwords::get_generic_password;
    match guarded(KeychainWhat::IdentitySeed, || {
        // a comment with a closing paren ) and a quote "
        let note: &'static str = "closing ) only";
        let paren = ')';
        let quote = '"';
        let escaped_quote = '\"';
        let escaped = "a \" ) b";
        let query = ItemSearchOptions::new();
        get_generic_password("s", account).map_err(|e| format!("{note}{paren}{quote}{escaped_quote}{escaped}{e}"))
    }) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
EOF
  selftest_expect "multi-line guard with tricky literals" "$root" "$pre/ok.rs:read_item
$pre/tricky.rs:read_item" 0
  rm "$src/tricky.rs"
  # ... and must not keep it open past its end (a call after it still fails).
  cat >"$src/trickyend.rs" <<'EOF'
fn read_item(account: &str) -> u8 {
    let v = guarded(KeychainWhat::IdentitySeed, || {
        // a comment with an opening paren ( and a quote "
        let note: &'static str = "opening ( only";
        let paren = '(';
        let quote = '"';
        let escaped_quote = '\"';
        let escaped = "a \" ( b";
        get_generic_password("s", account).map(|_| note.len() + escaped.len()).unwrap_or(paren as usize + quote as usize)
    });
    let q = '\"'; let _leak = get_generic_password("s", account);
    v as u8
}
EOF
  selftest_expect "tricky literals do not hold the guard open" "$root" "$pre/ok.rs:read_item
$pre/trickyend.rs:read_item" 1 \
    "$pre/trickyend.rs:11: read_item() calls the Keychain outside macos_keychain::guarded"
  rm "$src/trickyend.rs"
  cat >"$src/nested.rs" <<'EOF'
fn read_item() {
    guarded(KeychainWhat::IdentitySeed, || {
        guarded(KeychainWhat::ChatHistoryKey, || get_generic_password("s", "a"))
    });
}
EOF
  selftest_expect "nested guard" "$root" "$pre/ok.rs:read_item
$pre/nested.rs:read_item" 0
  rm "$src/nested.rs"
  # An API name inside a string is a message, not a call.
  cat >"$src/message.rs" <<'EOF'
fn describe() -> &'static str {
    "get_generic_password failed; SecItemCopyMatching said no (security_framework::x)"
}
EOF
  selftest_expect "API names in a string" "$root" "$pre/ok.rs:read_item" 0
  rm "$src/message.rs"
  # Any other use of the crate is a Keychain API too, even without a named call.
  cat >"$src/crateonly.rs" <<'EOF'
fn sneaky() {
    security_framework::item::add_item(options);
}
EOF
  selftest_expect "crate path alone" "$root" "$pre/ok.rs:read_item" 1 \
    "$pre/crateonly.rs:2: Keychain API used in sneaky(), which is not allow-listed"
  rm "$src/crateonly.rs"
  # `guarded` is a call only when a parenthesis follows.
  cat >"$src/plainname.rs" <<'EOF'
fn read_item() {
    let guarded = true;
    get_generic_password("s", "a");
}
EOF
  selftest_expect "guarded as a plain name" "$root" "$pre/ok.rs:read_item
$pre/plainname.rs:read_item" 1 \
    "$pre/plainname.rs:3: read_item() calls the Keychain outside macos_keychain::guarded"
  rm "$src/plainname.rs"
  # A guard that is never closed does not carry over into the next function.
  cat >"$src/unclosed.rs" <<'EOF'
impl Backend {
    fn first() {
        guarded(KeychainWhat::IdentitySeed, || get_generic_password("s", "a")
    }
    fn second() {
        get_generic_password("s", "a");
        guarded(KeychainWhat::IdentitySeed, || get_generic_password("s", "a"))
    }
}
EOF
  selftest_expect "unclosed guard stays in its function" "$root" "$pre/ok.rs:read_item
$pre/unclosed.rs:first
$pre/unclosed.rs:second" 1 \
    "$pre/unclosed.rs:6: second() calls the Keychain outside macos_keychain::guarded"
  rm "$src/unclosed.rs"

  # A module-level import after an allowed function is not that function's.
  cat >"$src/modlevel.rs" <<'EOF'
fn read_item() {
    guarded(KeychainWhat::PrekeyState, || ());
}
use security_framework::passwords::get_generic_password;
EOF
  selftest_expect "module-level import" "$root" "$pre/modlevel.rs:read_item" 1 \
    "Keychain API used in <module>()"
  rm "$src/modlevel.rs"

  # A * entry allows a whole file (the guard module), no guard required.
  cat >"$src/wild.rs" <<'EOF'
fn anything() {
    SecKeychainFindGenericPassword();
}
EOF
  selftest_expect "wildcard file" "$root" "$pre/ok.rs:read_item
$pre/wild.rs:*" 0
  rm "$src/wild.rs"

  # An allow-list entry nobody uses any more is a standing hole.
  selftest_expect "stale entry" "$root" "$pre/ok.rs:read_item
$pre/ok.rs:gone" 1 "$pre/ok.rs:gone: stale allow-list entry"

  # The same function name in another file is not covered.
  cat >"$src/other.rs" <<'EOF'
fn read_item() {
    guarded(KeychainWhat::SessionSecret, || get_generic_password("s", "a"));
}
EOF
  selftest_expect "same name, other file" "$root" "$pre/ok.rs:read_item" 1 \
    "$pre/other.rs:2: Keychain API used in read_item()"
  echo "keychain guard self-test OK"
}

main() {
  case "${1:-}" in
    --self-test)
      selftest
      return 0
      ;;
    "") ;;
    *)
      echo "usage: $0 [--self-test]" >&2
      return 2
      ;;
  esac
  local repo out rc=0 count
  repo="$(cd "$(dirname "$0")/.." && pwd)"
  out="$(scan_tree "$repo" "$ALLOWED")" || rc=$?
  case "$rc" in
    0)
      count="$(cd "$repo" && find node/crates -name target -prune -o -type f -name '*.rs' -print | wc -l | tr -d ' ')"
      echo "keychain guard OK: $count Rust files scanned, every Keychain call is inside macos_keychain::guarded(...)"
      ;;
    2)
      echo "keychain guard: no Rust sources under $repo/node/crates (moved tree?)" >&2
      return 2
      ;;
    *)
      printf '%s\n' "$out" >&2
      echo "KEYCHAIN_GUARD_VIOLATION: route Keychain access through raven_core::macos_keychain::guarded" >&2
      echo "  (add a new wrapper to ALLOWED in scripts/keychain_guard_check.sh only with every call inside its guarded(...))" >&2
      return 1
      ;;
  esac
}

main "$@"
