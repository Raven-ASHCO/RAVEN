#!/usr/bin/env bash
# Non-interactive smoke for ash menus 1/3/5 + q (first-run + empty contacts),
# contact pick → send prompt, and the one-text invite merge path.
# Safe: ephemeral mktemp data dirs only. No secrets.
# Must use target/debug/ash: RAVEN_IDENTITY_BACKEND=locked-file is refused in Release.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../../scripts/lib/harness_util.sh
source "$ROOT/../scripts/lib/harness_util.sh"
BIN="${RAVEN_BIN_DIR:-$ROOT/target/debug}"   # optional prebuilt debug bin dir
ASH="$BIN/ash"
export PATH="${HOME}/.cargo/bin:${PATH}"
export NO_COLOR=1

if [[ ! -x "$ASH" && -x "${ASH}.exe" ]]; then
  ASH="${ASH}.exe"
fi
if [[ ! -x "$ASH" ]]; then
  echo "Building ash…"
  (cd "$ROOT" && cargo build -p ash -p raven-node -q)
  if [[ ! -x "$ASH" && -x "${BIN}/ash.exe" ]]; then
    ASH="${BIN}/ash.exe"
  fi
fi
[[ -x "$ASH" ]]

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/raven-ash-menu-XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

# Share identity across ash menu smoke without Keychain ACL issues.
# locked-file is debug-only. An explicit --data-dir is always used as given;
# RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1 only silences the throwaway-identity note.
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1

echo "=== ash menu smoke workdir=$WORKDIR ==="

# --- First-run: no identity → first-run prompt creates identity ---
DATA1="$WORKDIR/fresh"
mkdir -p "$DATA1"
# Drive: y (first-run wizard creates identity) → 3 status → 1 send(no contact→n) → 5 contacts → q
printf 'y\n3\n1\nn\n5\n\nq\n' | raven_timeout 120 "$ASH" --data-dir "$DATA1" >"$WORKDIR/fresh.log" 2>&1 || true
grep -q 'identity created\|● identity' "$WORKDIR/fresh.log"
grep -q 'serverless_rvn1' "$WORKDIR/fresh.log"
grep -q 'no contacts yet\|Add someone first\|Add a contact first' "$WORKDIR/fresh.log"
grep -q 'Contacts\|No contacts yet\|Contacts menu' "$WORKDIR/fresh.log"
grep -q 'fly safe' "$WORKDIR/fresh.log"
echo "fresh menus OK"

# --- With identity: whoami + contact add CLI + send empty-path teaches ---
DATA2="$WORKDIR/ready"
mkdir -p "$DATA2"
"$ASH" --data-dir "$DATA2" init >"$WORKDIR/init.out"
ADDR=$(grep '^address=' "$WORKDIR/init.out" | cut -d= -f2)
PUB=$(grep '^pub_hex=' "$WORKDIR/init.out" | cut -d= -f2)
FP=$(grep '^fingerprint=' "$WORKDIR/init.out" | cut -d= -f2)
[[ -n "$ADDR" && -n "$PUB" && -n "$FP" ]]
"$ASH" --data-dir "$DATA2" whoami | tee "$WORKDIR/whoami.out"
grep -q "$ADDR" "$WORKDIR/whoami.out"
grep -q "$PUB" "$WORKDIR/whoami.out"

# Self-contact (public bits only) with lan_dial for dial-reuse path
"$ASH" --data-dir "$DATA2" contact add \
  --address "$ADDR" \
  --pub-hex "$PUB" \
  --petname "Me" \
  --tag me \
  --lan-dial "127.0.0.1:17999" \
  --verify-fp "$FP" | tee "$WORKDIR/contact.out"
grep -q 'contact saved' "$WORKDIR/contact.out"
grep -q 'lan_dial' "$WORKDIR/contact.out"

"$ASH" --data-dir "$DATA2" contact list | tee "$WORKDIR/clist.out"
grep -q 'Me' "$WORKDIR/clist.out"
grep -q '127.0.0.1:17999' "$WORKDIR/clist.out"

book_digest() { cksum <"$DATA2/contacts.json"; }
BOOK_BEFORE="$(book_digest)"

# Interactive: 5 contacts (Enter = back) → 1 send → pick #1 → empty message → q.
# The empty message returns before any dial, so nothing is spawned (the menu
# send is the secure PairInit/indexed path, never raven-node unsafe-interim).
printf '5\n\n1\n1\n\nq\n' | raven_timeout 120 "$ASH" --data-dir "$DATA2" >"$WORKDIR/ready.log" 2>&1 || true
grep -q 'Send / Chat' "$WORKDIR/ready.log"
grep -q 'message for Me' "$WORKDIR/ready.log"     # picker resolved contact #1 via saved dial
grep -q 'empty message' "$WORKDIR/ready.log"
grep -q 'fly safe' "$WORKDIR/ready.log"
if grep -q 'unsafe-interim\|ATSAM_SESSION_REQUIRED\|could not start raven-node' "$WORKDIR/ready.log"; then
  echo "menu send must not take the unsafe-interim raven-node lane" >&2
  cat "$WORKDIR/ready.log" >&2
  exit 1
fi
[[ "$(book_digest)" == "$BOOK_BEFORE" ]]

# @tag pick resolves the same contact (never a silent first-match among dupes).
printf '1\n@me\n\nq\n' | raven_timeout 120 "$ASH" --data-dir "$DATA2" >"$WORKDIR/tagpick.log" 2>&1 || true
grep -q 'message for Me' "$WORKDIR/tagpick.log"
grep -q 'empty message' "$WORKDIR/tagpick.log"
echo "ready menus OK"

# One-text invite paste (menu 5 → a) must MERGE into the book: the pinned
# "Me" row and its saved lan_dial survive, Abort saves nothing.
DATA3="$WORKDIR/friend"
mkdir -p "$DATA3"
"$ASH" --data-dir "$DATA3" init >/dev/null
INVITE="$("$ASH" --data-dir "$DATA3" whoami | awk '/^invite/ {print $2}')"
[[ "$INVITE" == raven:rvn1* ]]
printf '5\na\n%s\nFriend\na\n\nq\n' "$INVITE" | raven_timeout 120 "$ASH" --data-dir "$DATA2" >"$WORKDIR/invite_abort.log" 2>&1 || true
grep -q 'nothing saved' "$WORKDIR/invite_abort.log"
[[ "$(book_digest)" == "$BOOK_BEFORE" ]]
printf '5\na\n%s\nFriend\nc\n\nq\n' "$INVITE" | raven_timeout 120 "$ASH" --data-dir "$DATA2" >"$WORKDIR/invite.log" 2>&1 || true
grep -q 'contact saved' "$WORKDIR/invite.log"
[[ "$(grep -c '"pub_hex"' "$DATA2/contacts.json")" == "2" ]]
grep -q '"petname": "Me"' "$DATA2/contacts.json"
grep -q '"petname": "Friend"' "$DATA2/contacts.json"
grep -q '127.0.0.1:17999' "$DATA2/contacts.json"
echo "invite merge OK"

# Manual add (menu 5 → a → bare rvn1…) answering the pub_hex prompt with the
# labelled whoami line `pub_hex   <hex>`: it must be taken as the pub_hex, not
# skipped as a leftover (that shifted every later answer by one prompt).
DATA4="$WORKDIR/third"
mkdir -p "$DATA4"
"$ASH" --data-dir "$DATA4" init >"$WORKDIR/init4.out"
ADDR4=$(grep '^address=' "$WORKDIR/init4.out" | cut -d= -f2)
PUB4=$(grep '^pub_hex=' "$WORKDIR/init4.out" | cut -d= -f2)
[[ -n "$ADDR4" && -n "$PUB4" ]]
printf '5\na\n%s\npub_hex       %s\nthird\nThird\n\nc\n\nq\n' "$ADDR4" "$PUB4" \
  | raven_timeout 120 "$ASH" --data-dir "$DATA2" >"$WORKDIR/labelled_pub.log" 2>&1 || true
grep -q 'contact saved' "$WORKDIR/labelled_pub.log"
if grep -q 'rejected' "$WORKDIR/labelled_pub.log"; then
  echo "labelled pub_hex answer must not be rejected" >&2
  cat "$WORKDIR/labelled_pub.log" >&2
  exit 1
fi
[[ "$(grep -c '"pub_hex"' "$DATA2/contacts.json")" == "3" ]]
grep -q '"petname": "Third"' "$DATA2/contacts.json"
grep -q "$PUB4" "$DATA2/contacts.json"
echo "labelled pub_hex answer OK"

# Banner / doctor non-interactive (avoid SIGPIPE panic from grep -q closing early)
"$ASH" --data-dir "$DATA2" banner >"$WORKDIR/banner.out"
grep -q "R A V E N" "$WORKDIR/banner.out"
"$ASH" --data-dir "$DATA2" doctor >"$WORKDIR/doctor.out" 2>&1 || true
grep -qE 'messaging_path|identity' "$WORKDIR/doctor.out"

echo "=== ASH MENU SMOKE PASSED ==="
