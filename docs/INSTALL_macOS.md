# Install Raven Serverless (macOS)

`node/scripts/install.sh` is **not** a production installer. It fails closed
and does not put binaries on `PATH`. Use the release-build steps below
(`scripts/install/macos_launchd.sh`). Do not `curl | bash` a convenience
script.

**Unsigned developer layout.** Notarization requires your Apple Developer ID — see [`SIGNING_NOTARIZATION_CHECKLIST.md`](SIGNING_NOTARIZATION_CHECKLIST.md).

## Option A — from source

```bash
cd node
cargo build -p raven-node -p ash --release
bash scripts/install/macos_launchd.sh
# ash/raven → ~/.local/bin ; raven-node launchd agent
export PATH="$HOME/.local/bin:$PATH"
ash init
ash doctor
```

Never overwrite `/bin/ash`. The installer links `~/.local/bin/ash` → `raven` only in the user prefix.

## Option B — unsigned release tarball

```bash
bash scripts/release/build_unsigned.sh
# → dist/raven-serverless-*-darwin-*.tar.gz
tar xzf dist/raven-serverless-*.tar.gz
cd raven-serverless-*/
./bin/ash --data-dir ./raven-data init
./bin/raven-node service --data-dir ./raven-data
```

Verify:

```bash
shasum -a 256 -c SHA256SUMS.txt
```

## Gatekeeper note

Unsigned binaries will be quarantined if downloaded from the Internet. Either:
- build from source locally, or
- complete Developer ID + notarization (checklist), or
- (dev only) remove quarantine: `xattr -dr com.apple.quarantine ./bin`

## Proof

```bash
bash scripts/final_serverless_proof.sh
```

## Identity seed

macOS stores the node seed in the **login Keychain** (service `app.raven.node.identity`). Legacy plaintext `identity.seed` files are migrated and removed on first load. See [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md).

## CI menu smoke is not an install proof

GitHub Actions `rust-linux`, `rust-macos`, and `rust-windows` run `node/scripts/ash_menu_smoke.sh` against **debug** `target/debug/ash` only. That is **menu/CLI smoke** (init → doctor → contacts → send). It does **not** prove:

- Keychain identity (Option A default above remains the login Keychain)
- launchd service install (`scripts/install/macos_launchd.sh`)
- Gatekeeper-clean or notarized install (still unsigned; notarization remains `BLOCKED_HUMAN`)

CI and lab scripts force `RAVEN_IDENTITY_BACKEND=locked-file` so ash and raven-node share an ephemeral `0600` seed file under `mktemp` `--data-dir` (avoids Keychain ACL hangs). `locked-file` is refused in Release. Operators must **not** set that override for a normal Keychain install.
