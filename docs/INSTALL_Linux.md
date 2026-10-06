# Install Raven Serverless (Linux)

`node/scripts/install.sh` is **not** a production installer. It fails closed
and does not put binaries on `PATH`. Use the release-build steps below
(`scripts/install/linux_systemd_user.sh`). Do not `curl | bash` a convenience
script.

> **Known limitation — Linux Release builds cannot create an identity yet.**
> Identity creation on GNU/Linux is disabled in Release builds until R1 (existing
> Secret Service identities still load), musl/other Unix targets have no protected
> identity backend, and the `locked-file` seed override is refused in Release.
> So with the `--release` steps below, `raven init` / `ash init` — and therefore
> the `raven-node service` unit, which creates an identity if none exists — fail
> closed with an R1 / "no protected identity backend" error on a fresh install.
> Do not work around this with a debug/lab build for real conversations. Details:
> [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md).

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
- Identity seed storage: Linux Release builds cannot create an identity yet (Secret Service creation is disabled before R1; existing identities load). The mode `0600` `locked-file` seed is a debug/lab/CI-only override that Release builds refuse — see [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md).
