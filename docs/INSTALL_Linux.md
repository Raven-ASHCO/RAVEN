# Install Raven Serverless (Linux)

`node/scripts/install.sh` is **not** a production installer. It fails closed
and does not put binaries on `PATH`. Use the release-build steps below
(`scripts/install/linux_systemd_user.sh`). Do not `curl | bash` a convenience
script.

> **Where your keys live.** With an unlocked desktop keyring (GNOME Keyring /
> KWallet, i.e. Secret Service) RAVEN stores its keys there. Without one (servers,
> SSH sessions, a Raspberry Pi bridge, musl builds) it keeps them in an encrypted
> file, `<data-dir>/keystore.vault`, protected by a **passphrase** you choose
> (Argon2id + XChaCha20-Poly1305). The choice is made once per profile and recorded
> in `<data-dir>/keystore.backend`; RAVEN never moves keys between the two on its
> own. Details: [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md) and
> [`design/2026-10-linux-keystore.md`](design/2026-10-linux-keystore.md).

### Passphrase vault in practice

- `raven init` / `ash init` on a terminal explains this and asks for the
  passphrase twice (nothing is echoed; at least 8 characters). Later runs ask once.
  There is no recovery without it.
- Non-interactive use (scripts, CI, the service) needs a passphrase **file**:

  ```bash
  mkdir -p ~/.config/raven && chmod 700 ~/.config/raven
  ( umask 077; printf '%s\n' 'your long passphrase' > ~/.config/raven/keystore-passphrase )
  export RAVEN_KEYSTORE_PASSPHRASE_FILE=~/.config/raven/keystore-passphrase
  ```

  The file must be a regular file owned by you with mode `0600` or `0400`. The
  passphrase itself is never accepted in an environment variable or on the command
  line (`RAVEN_KEYSTORE_PASSPHRASE` is refused). A file next to the data dir
  protects only against copies of the data dir *without* it: keep it out of
  backups that contain `keystore.vault`.
- `raven-node service` never prompts. Give it the file through the installer
  (below), or with systemd `LoadCredential=raven-keystore-passphrase:<file>`.
- Force the vault on a desktop with `RAVEN_KEYSTORE_BACKEND=vault` before the
  first `raven init` of a profile.

**Toolchain:** install Rust with [rustup](https://rustup.rs) (current stable);
distro-packaged compilers are usually too old (rustc 1.83.0 fails at dependency
resolution because the locked graph needs edition 2024; its highest declared
`rust-version` is 1.88). CI is validated on rustc 1.98.0 only; the exact minimum
is not yet verified.

## From source

```bash
cd node
cargo build --locked -p raven-node -p ash --release
bash scripts/install/linux_systemd_user.sh
export PATH="$HOME/.local/bin:$PATH"
raven init        # `ash` is only aliased when no system ash shell exists
raven doctor
```

Headless host (no desktop keyring): pass the passphrase file so the unit can
unlock the vault. The unit gets `Environment=RAVEN_KEYSTORE_PASSPHRASE_FILE=<path>`
(the path only); `RAVEN_SYSTEMD_LOAD_CREDENTIAL=1` uses `LoadCredential=` instead:

```bash
RAVEN_KEYSTORE_PASSPHRASE_FILE=$HOME/.config/raven/keystore-passphrase \
  bash scripts/install/linux_systemd_user.sh
```

User systemd unit runs `raven-node service` (bridge + IPC). Does not require root.
The data directory (`~/.raven`) is created mode `0700`. The installer picks the
same profile `raven` / `ash` use without `--data-dir` (`RAVEN_DATA_DIR`, then
`ASH_DATA_DIR`, then a legacy `~/.raven-ash` while `~/.raven` does not exist, else
`~/.raven`), and writes *absolute*, quoted paths into the unit (`systemd --user`
starts it from your home directory, so a relative `RAVEN_DATA_DIR` /
`RAVEN_BIN_DIR` is resolved by the installer first).

**IPC socket location.** The daemon listens on `<data-dir>/raven-node.sock`. When
that path would be too long for a Unix socket (about 107 bytes on Linux) it serves
`/tmp/raven-<uid>/raven-<hash>.sock` instead (a private, owner-only directory).
The choice depends on the resolved data dir, never on how the path was spelled.
Do not hard-code the socket path: `raven doctor` (and the installer's last lines)
print the real `ipc_endpoint=`.

**LAN exposure is opt-in with the installer scripts (same default on every
OS):** `scripts/install/linux_systemd_user.sh` starts the service listening on
`127.0.0.1:7420`, so LAN peers cannot reach it. (A bare `raven-node service`
without `--lan-listen` binds `0.0.0.0:7420` — always pass an explicit address
when you start it by hand.) To accept LAN peers, install with an explicit
address and open the port to your LAN only:

```bash
RAVEN_LAN_LISTEN=<this-host-LAN-IP>:7420 bash scripts/install/linux_systemd_user.sh
sudo ufw allow from 192.168.0.0/16 to any port 7420 proto tcp
```

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
RAVEN_INTERNET_LISTEN=0.0.0.0:7422 bash scripts/install/linux_systemd_user.sh
# or later (saved in node_policy.json, applied when the service restarts)
raven node internet on --listen 0.0.0.0:7422
systemctl --user restart raven-node
raven node internet off          # closes it again at the next restart
```

The service reads `--internet-listen`, then `RAVEN_INTERNET_LISTEN`, then
`node_policy.json`; a bare IP gets port 7422 and an empty value is off.
Firewall: Linux shows no prompt, ufw / firewalld / nftables and cloud security
groups decide. Open the port yourself, e.g. `sudo ufw allow 7422/tcp`
(`firewall-cmd --add-port=7422/tcp --permanent` on firewalld), and forward TCP
7422 on your router if the host is behind NAT. A VPS with a public IP or a home
with global IPv6 (`[::]:7422`) needs no forwarding.

Contacts: `raven contact add --card '<their card line>'` saves their routes,
`raven contact set-addr <name> --internet HOST:PORT` (or `--lan`, `--clear
internet`) edits them, and `raven send --contact <name>` tries their LAN
address first, then their Internet address (`--carrier lan|internet` forces
one). An address is only a hint: every connection still has to prove the
contact's pinned key.

## Unsigned tarball

```bash
bash scripts/release/build_unsigned.sh
tar xzf dist/raven-serverless-*-linux-*.tar.gz
cd raven-serverless-*/
./bin/ash --data-dir ./raven-data init
```

If you then start the daemon by hand, bind it explicitly, e.g.
`./bin/raven-node service --data-dir ./raven-data --lan-listen 127.0.0.1:7420`
(the bare default is `0.0.0.0:7420`).

**Checksums are integrity-only.** `SHA256SUMS.txt` ships *inside* the tarball, so
a tampered archive can carry a matching file; checking it only detects accidental
corruption after extraction. For authenticity, compare the separate
`<archive>.tar.gz.sha256` written next to the tarball against a hash you obtained
out-of-band from the builder over a trusted channel (or use a signature). Signing/
packages (deb/rpm) are operator-owned — not produced unsigned.

## Notes

- `ash` is also the BusyBox / Alpine shell. The installer only links `~/.local/bin/ash` → `raven` when no other `ash` is on the system; otherwise use `raven`.
- No central message server is configured; see `SERVERLESS_MODEL.md`.
- Identity seed storage: Secret Service when an unlocked keyring answers, else the passphrase vault (above). The mode `0600` `locked-file` seed is a debug/lab/CI-only override that Release builds refuse — see [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md).
