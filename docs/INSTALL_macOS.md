# Install Raven Serverless (macOS)

`node/scripts/install.sh` is **not** a production installer. It fails closed
and does not put binaries on `PATH`. Use the release-build steps below
(`scripts/install/macos_launchd.sh`). Do not `curl | bash` a convenience
script.

**Unsigned developer layout.** Notarization requires your Apple Developer ID — see [`SIGNING_NOTARIZATION_CHECKLIST.md`](SIGNING_NOTARIZATION_CHECKLIST.md).

**Toolchain:** install Rust with [rustup](https://rustup.rs) (current stable);
older or externally packaged compilers may be too old (rustc 1.83.0 fails at
dependency resolution because the locked graph needs edition 2024; its highest
declared `rust-version` is 1.88). CI is validated on rustc 1.98.0 only; the exact
minimum is not yet verified.

## Option A — from source

```bash
cd node
cargo build --locked -p raven-node -p ash --release
bash scripts/install/macos_launchd.sh
# ash/raven → ~/.local/bin ; raven-node launchd agent
export PATH="$HOME/.local/bin:$PATH"
ash init
ash doctor
```

Never overwrite `/bin/ash`. The installer links `~/.local/bin/ash` → `raven` only in the user prefix.
The data directory (`~/.raven`) is created mode `0700`. The installer picks the
same profile `raven` / `ash` use without `--data-dir` (`RAVEN_DATA_DIR`, then
`ASH_DATA_DIR`, then a legacy `~/.raven-ash` while `~/.raven` does not exist, else
`~/.raven`), and registers *absolute* paths in the launchd agent (launchd starts
it with the working directory `/`, so a relative `RAVEN_DATA_DIR` /
`RAVEN_BIN_DIR` is resolved by the installer first).

**IPC socket location.** The daemon listens on `<data-dir>/raven-node.sock`. When
that path would be too long for a Unix socket (about 100 bytes on macOS, e.g. a
deep checkout or sandbox temp dir) it serves `/tmp/raven-<uid>/raven-<hash>.sock`
instead (a private, owner-only directory). The choice depends on the resolved
data dir, never on how the path was spelled. Do not hard-code the socket path:
`raven doctor` (and the installer's last lines) print the real `ipc_endpoint=`.

**LAN exposure is opt-in with the installer scripts (same default on every
OS):** `scripts/install/macos_launchd.sh` starts the agent listening on
`127.0.0.1:7420`, so LAN peers cannot reach it. (A bare `raven-node service`
without `--lan-listen` binds `0.0.0.0:7420` — always pass an explicit address
when you start it by hand, as in Option B.) To accept LAN peers:

```bash
RAVEN_LAN_LISTEN=<this-Mac-LAN-IP>:7420 bash scripts/install/macos_launchd.sh
```

and allow `raven-node` in the macOS firewall for the local network only.

**Internet direct is opt-in too (off by default).** It lets contacts who have
your Internet address (`raven whoami --card --inet <public-ip-or-name>:7422`)
reach this computer over TCP port **7422** (7421 is mock BLE's, 7423 is
reserved for libp2p). Only your contacts get an answer: anyone else completes
the Noise handshake and is disconnected before this node names itself, but a
scanner still learns that something listens on that port. A build with
Internet direct off (`INTERNET_DIRECT_PRODUCTION_ENABLED = false`, the state
until its waiver is signed) keeps the port closed and logs `internet_direct
failed: INTERNET_DIRECT_HOLD ...`; the debug lab unlock is `RAVEN_LAB_TEST_A=1`.
`raven status` shows an `internet` row: `YES` only while the running service
really has the listener up.

```bash
# at install time
RAVEN_INTERNET_LISTEN=0.0.0.0:7422 bash scripts/install/macos_launchd.sh
# or later (saved in node_policy.json, applied when the agent restarts)
raven node internet on --listen 0.0.0.0:7422
launchctl kickstart -k "gui/$(id -u)/com.raven.raven-node"
raven node internet off          # closes it again at the next restart
```

Firewall: the macOS Application Firewall is off by default. When it is on it
prompts per code identity (an unsigned rebuild prompts again), and "Block all
incoming connections" drops the connections silently. Allow the agent yourself:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ~/.local/bin/raven-node
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ~/.local/bin/raven-node
```

Forward TCP 7422 on your router if the Mac is behind NAT. Contacts:
`raven contact add --card '<their card line>'`, `raven contact set-addr <name>
--internet HOST:PORT`, then `raven send --contact <name>` (LAN address first,
then Internet; `--carrier lan|internet` forces one). An address is only a hint:
every connection still has to prove the contact's pinned key. Internet delivery
is for verified contacts only. A contact whose fingerprint you have not
confirmed (`--verify-fp` when adding) is reached over the LAN carrier only, and
only when every address its LAN route resolves to is on your local network:
loopback, private (10/8, 172.16/12, 192.168/16), link-local (169.254/16,
fe80::/10) or unique-local IPv6 (fc00::/7); a public or CGNAT (100.64/10)
address is refused and nothing is dialled. Your Internet listener treats an
unverified contact like a stranger, and so does your LAN listener when it
connects from outside those ranges.

## Option B — unsigned release tarball

```bash
bash scripts/release/build_unsigned.sh
# → dist/raven-serverless-*-darwin-*.tar.gz
tar xzf dist/raven-serverless-*.tar.gz
cd raven-serverless-*/
./bin/ash --data-dir ./raven-data init
./bin/raven-node service --data-dir ./raven-data --lan-listen 127.0.0.1:7420
```

Without `--lan-listen` the service binds `0.0.0.0:7420` and accepts connections
from every host on the network.

Verify (**integrity only, not authenticity**):

```bash
shasum -a 256 -c SHA256SUMS.txt
```

`SHA256SUMS.txt` ships *inside* the tarball, so a tampered archive can carry a
matching file: this check only detects accidental corruption after extraction.
For authenticity, compare the separate `<archive>.tar.gz.sha256` written next to
the tarball against a hash you obtained out-of-band from the builder over a
trusted channel (or use a signature).

## Gatekeeper note

Unsigned binaries will be quarantined if downloaded from the Internet. Either:
- build from source locally, or
- complete Developer ID + notarization (checklist), or
- (dev only, archives you built yourself) remove quarantine: `xattr -dr com.apple.quarantine ./bin`. Do not strip quarantine from an archive you downloaded and have not verified out-of-band.

## Proof

```bash
bash scripts/final_serverless_proof.sh
```

## Identity seed

macOS stores the node seed in the **login Keychain** (service `app.raven.node.identity`). Legacy plaintext `identity.seed` files are migrated and removed on first load. See [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md). If a command seems frozen the first time you run it, read the next section.

## Keychain prompts

Raven keeps four kinds of secrets in the login Keychain. The service name is what the macOS dialog shows:

| Service | Holds | Raven's hint calls it |
| --- | --- | --- |
| `app.raven.node.identity` | the identity of one data dir | your Raven identity |
| `app.raven.node.chat-history.v1` | the key that encrypts local chat history | your chat history |
| `app.raven.node.atsam-indexed-session` | one item per conversation | a conversation key |
| `app.raven.node.prekey-lifecycle` | key-exchange state | key-exchange data |

**What happens and why.** A Keychain item trusts only the program that created it, identified by its code signature. The command line (`ash` / `raven`) and the background service (`raven-node`) are separate programs, so when a different one reads an item for the first time (or the same one after you rebuilt or upgraded it) macOS opens a dialog, something like "… wants to use your confidential information stored in "app.raven.node.…" in your keychain", and the program **waits for your answer**. There is no timeout and macOS prints nothing in the terminal, so `ash send`, `ash inbox` or a chat can look frozen. After 3 seconds Raven prints `raven: still waiting for macOS Keychain access (<what>) after 3s.` and the next step on stderr, then a short reminder every 30 seconds. The background service writes the same hint plus a `BLOCKED_ON_KEYCHAIN` line to its log: `raven-node-service.log` in the data dir (`~/.raven` by default) when `ash` started the service, `raven-node.err` there when the launchd agent from Option A runs it.

**A second command waits behind the first.** While the dialog for your identity is open, another `ash` or `raven` command has to wait for the one that is blocked (identity access is one at a time). After 3 seconds it prints `raven: waiting for another raven program that is using your identity (3s).` and carries on by itself once you have answered; it gives up after about a minute, so answer the dialog and run it again.

**What to click.** Find the dialog; it can sit behind other windows (try Mission Control), and if `SecurityAgent` is listed in Activity Monitor a dialog is waiting. Enter your macOS login password and choose **Always Allow**. *Allow* covers this one access only and you will be asked again; *Deny* makes the command fail with a Keychain error (the background service may ask again after it restarts). Ctrl-C stops a command you started in the terminal; the background service has no terminal and simply waits until you answer.

**Why the command line and the service each ask.** Each program is asked once per item. In an installed layout (Option A, or the Option B tarball) `ash` and `raven` are one file, one a link to the other, so there are two programs: `ash` / `raven` and `raven-node`. Straight from a build directory (`node/target/release`) `ash`, `raven` and `raven-node` are three separate executables, and each is asked. Conversations have one item each, so several conversations can mean several dialogs the first time the other program touches them.

**Rebuilt or upgraded binaries ask again.** An unsigned (ad-hoc signed) binary gets a new identity with every build, so macOS no longer recognises it as the program that was allowed. Binaries from `cargo build` and from `scripts/release/build_unsigned.sh` are unsigned in this sense.

**A stable identity for developer builds.** Sign the binaries with a certificate of your own and macOS keeps recognising them:

1. In Keychain Access choose Certificate Assistant, Create a Certificate…, name it (for example `Raven Dev`), set *Identity Type* to Self Signed Root and *Certificate Type* to Code Signing. It stays in your login Keychain on this Mac.
2. Sign the files that actually run, with the same certificate and identifier, then check that the requirement names the certificate and not a `cdhash`. Which files those are depends on how you installed:

   | Layout | Sign |
   | --- | --- |
   | Option A (installer) | `~/.local/bin/raven` and `~/.local/bin/raven-node` (`ash` there is a link to `raven`), then restart the agent |
   | Option B (tarball) | `bin/ash` and `bin/raven-node` (`bin/raven` is a link to `bin/ash`) |
   | Straight from a build | `node/target/release/ash`, `raven` and `raven-node` (`target/debug` for debug builds) |

   Option A with the installer's default location (use `RAVEN_BIN_DIR` if you set it); for the other layouts run the same `codesign` line on the files in the table:

   ```bash
   for bin in raven raven-node; do
     codesign -f -s "Raven Dev" -i app.raven.node "$HOME/.local/bin/$bin"
   done
   codesign -d -r- "$HOME/.local/bin/raven-node"   # designated => identifier "app.raven.node" and certificate leaf = H"…"
   launchctl kickstart -k "gui/$(id -u)/com.raven.raven-node"   # restart the agent so it runs the signed file
   ```

   (`codesign` asks to use the certificate's private key: choose **Allow**, not *Always Allow*. If `codesign` may use that key without asking, any program running as you can sign itself as Raven and then read Raven's Keychain items without a dialog; with *Allow* you confirm each signing run.) Signing sticks to the file, so repeat it whenever the files that run are replaced: the installer copies freshly built, unsigned files over the installed ones every time it runs, and a rebuild replaces the ones in `target`.
3. Run `ash` once, let the service start (or restart it as above) and answer the dialogs with **Always Allow**. Items that already exist keep trusting the old identity, so each one asks once more; after that, rebuilds you sign again should stop asking. If a dialog keeps coming back, the `codesign -d -r-` line above shows whether the file that runs really carries the certificate.

**SSH sessions have no dialog.** Over SSH macOS cannot show the window, so a command that needs an answer waits or fails. Run it once on the Mac itself (Terminal app or Screen Sharing), answer the dialog there, then use SSH.

**Never delete these items by hand to "fix" a prompt.** In particular do not run `security delete-generic-password -s app.raven.node.identity` without `-a <account>`: it removes whichever matching item macOS finds first, possibly the identity of another data dir. A deleted identity cannot be recovered; Raven refuses to start with "recorded Keychain identity is missing" rather than invent a new address.

## CI menu smoke is not an install proof

GitHub Actions `rust-linux`, `rust-macos`, and `rust-windows` run `node/scripts/ash_menu_smoke.sh` against **debug** `target/debug/ash` only. That is **menu/CLI smoke** (init → doctor → contacts → send). It does **not** prove:

- Keychain identity (Option A default above remains the login Keychain)
- launchd service install (`scripts/install/macos_launchd.sh`)
- Gatekeeper-clean or notarized install (still unsigned; notarization remains `BLOCKED_HUMAN`)

CI and lab scripts force `RAVEN_IDENTITY_BACKEND=locked-file` so ash and raven-node share an ephemeral `0600` seed file under `mktemp` `--data-dir` (avoids Keychain ACL hangs). `locked-file` is refused in Release. Operators must **not** set that override for a normal Keychain install.

The chat-history / outbound-stage key is a separate Keychain item (service `app.raven.node.chat-history.v1`, one per data dir). In **debug** builds `RAVEN_CHAT_HISTORY_BACKEND=locked-file` (or `RAVEN_IDENTITY_BACKEND=locked-file`) makes ash and raven-node derive a per-data-dir lab key instead and never touch the Keychain for it; Release builds ignore the variable. Without it, the first history read of each binary (service, `ash`) waits on a Keychain access prompt until someone answers it (see [Keychain prompts](#keychain-prompts)); no cross-process lock is held meanwhile, and the service logs `… is taking longer than 15s … answer its prompt` when its start-up is stuck there.
