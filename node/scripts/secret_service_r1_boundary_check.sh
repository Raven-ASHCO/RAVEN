#!/usr/bin/env bash
# R1 Secret Service boundary (owner decision 2026-10-08,
# docs/design/2026-10-linux-keystore.md). Replaces the R0 stop-line that
# forbade any live use of the no-prompt fork. Raven may now use Secret Service,
# but only:
#   1. through the frozen Raven fork third_party/secret-service-2.0.2-raven-noprompt
#      (raven-core's GNU/Linux dependency), never the crates.io client;
#   2. with the fork's no-prompt APIs (create_item_no_prompt, delete_no_prompt,
#      with_secret_zeroizing) called only from the approved wrapper,
#      crates/raven-core/src/identity_store.rs;
#   3. identity creation (secret_service_set) only via create_item_no_prompt,
#      never the prompt-executing create_item;
#   4. never unlocking a collection or item (no prompt) and never a plain
#      (unencrypted) Secret Service session in product code.
# Static only: no D-Bus, no build. `--self-test` proves each rule fires.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APPROVED_WRAPPER="crates/raven-core/src/identity_store.rs"
FORK_DEP='secret-service = { path = "../../third_party/secret-service-2.0.2-raven-noprompt" }'

check_tree() {
  local node="$1" failures=0
  fail() { echo "R1_BOUNDARY_FAIL: $*" >&2; failures=$((failures + 1)); }

  grep -qxF "$FORK_DEP" "$node/crates/raven-core/Cargo.toml" \
    || fail "raven-core must depend on the frozen no-prompt fork ($FORK_DEP)"

  # The crates.io client must be absent from both product lockfiles.
  local lock
  for lock in "$node/Cargo.lock" "$node/fuzz/Cargo.lock"; do
    [[ -f "$lock" ]] || continue
    if awk '/^\[\[package\]\]/{name=""} /^name = "secret-service"$/{name=1} name && /^source = "registry/{found=1} END{exit !found}' "$lock"; then
      fail "${lock#"$node"/} resolves the crates.io secret-service client"
    fi
  done

  local callers
  callers="$(cd "$node" && grep -rlE 'create_item_no_prompt|delete_no_prompt|with_secret_zeroizing' crates --include='*.rs' | LC_ALL=C sort || true)"
  if [[ -n "$callers" && "$callers" != "$APPROVED_WRAPPER" ]]; then
    fail "no-prompt Secret Service APIs used outside $APPROVED_WRAPPER: $(echo "$callers" | tr '\n' ' ')"
  fi

  local body
  body="$(awk '/^fn secret_service_set\(/{inside=1} inside{print} inside && /^}/{exit}' "$node/$APPROVED_WRAPPER")"
  if [[ -z "$body" ]]; then
    fail "secret_service_set not found in $APPROVED_WRAPPER"
  else
    grep -q 'create_item_no_prompt(' <<<"$body" \
      || fail "identity creation must use create_item_no_prompt"
    if grep -qE '\.create_item\(' <<<"$body"; then
      fail "identity creation reaches the prompt-executing create_item"
    fi
  fi

  local unlockers
  unlockers="$(cd "$node" && grep -rnE '(collection|item|service|ss)\.unlock\(|lock_or_unlock|EncryptionType::Plain' crates/*/src --include='*.rs' || true)"
  if [[ -n "$unlockers" ]]; then
    fail "Secret Service unlock/plain-session use in product code: $unlockers"
  fi
  return "$failures"
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/node"
  cp -R "$ROOT/node/crates" "$tmp/node/crates"
  cp "$ROOT/node/Cargo.lock" "$tmp/node/Cargo.lock"
  check_tree "$tmp/node" >/dev/null 2>&1 || { echo "self-test: clean tree must pass" >&2; return 1; }

  expect_fail() {
    local what="$1"
    if check_tree "$tmp/node" >/dev/null 2>&1; then
      echo "self-test: rule did not fire: $what" >&2
      return 1
    fi
  }
  local core="$tmp/node/crates/raven-core"
  cp "$core/Cargo.toml" "$tmp/Cargo.toml.bak"
  sed -i.sed 's|^secret-service = { path = .*|secret-service = "2.0"|' "$core/Cargo.toml"
  expect_fail "crates.io client in raven-core/Cargo.toml"
  cp "$tmp/Cargo.toml.bak" "$core/Cargo.toml"

  echo 'fn rogue() { let _ = c.create_item_no_prompt("x", h, b"", "t"); }' >"$core/src/rogue_caller.rs"
  expect_fail "no-prompt API outside the approved wrapper"
  rm "$core/src/rogue_caller.rs"

  echo 'fn rogue() { let _ = collection.unlock(); }' >"$core/src/rogue_unlock.rs"
  expect_fail "collection unlock"
  rm "$core/src/rogue_unlock.rs"

  cp "$core/src/identity_store.rs" "$tmp/identity_store.rs.bak"
  sed -i.sed 's|\.create_item_no_prompt(|.create_item(|' "$core/src/identity_store.rs"
  expect_fail "identity creation through create_item"
  cp "$tmp/identity_store.rs.bak" "$core/src/identity_store.rs"

  printf '[[package]]\nname = "secret-service"\nversion = "2.0.2"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' \
    >>"$tmp/node/Cargo.lock"
  expect_fail "crates.io client in Cargo.lock"
  echo "R1_BOUNDARY_SELFTEST_OK"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi
check_tree "$ROOT/node"
echo "R1_SECRET_SERVICE_BOUNDARY_OK"
