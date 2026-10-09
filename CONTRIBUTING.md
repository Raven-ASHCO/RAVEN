# Contributing to RAVEN

Thank you for your interest in contributing to RAVEN! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and constructive in all communications
- Focus on the code, not the person
- Welcome newcomers and help them get started

## How to Contribute

### Reporting Bugs

1. Search existing issues to avoid duplicates
2. Include the commit, the crate / binary / script involved, and the build
   features used (for example `unsafe-demo-crypto` or a lab feature)
3. Include steps to reproduce, expected vs actual behavior
4. Include OS / device version if relevant

### Suggesting Features

1. Open an issue with the `[Feature Request]` prefix
2. Describe the use case and expected behavior
3. Explain why this would benefit RAVEN users

### Security Issues

**Do NOT open public issues for security vulnerabilities.**
See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

### Code Contributions

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Write/update tests if applicable
5. Ensure code follows existing style conventions
6. Submit a Pull Request with a clear description

## Development Setup

This repository contains the Rust serverless node workspace (`node/`), the
protocol specifications (`protocol/`), the Python reference implementation
(`protocol/reference/`) and the shared vectors (`shared-vectors/`). Mobile apps
and the legacy application server are **not** in this repository.

### Serverless node and terminal (Rust)

Use [rustup](https://rustup.rs) with a current stable toolchain; CI is pinned to
rustc 1.98.0 (`RUST_TOOLCHAIN` in `.github/workflows/`). Distro-packaged
compilers are usually too old: the locked dependency graph includes edition-2024
crates, its highest declared `rust-version` is 1.88, and rustc/cargo 1.83.0 fails
at dependency resolution (see
[`perf-baseline-2026-09-04.md`](docs/engineering/baseline-freeze/perf-baseline-2026-09-04.md)).
The workspace does not yet declare a `rust-version`, so the exact minimum is
unverified.

```bash
cd node
cargo test --locked -p raven-core -p raven-node -p ash -p raven-swarm
cargo test --locked -p raven-core --test network_sim_1000
cargo run -p ash -- --help
```

Platform installation notes live in [`docs/INSTALL_Linux.md`](docs/INSTALL_Linux.md),
[`docs/INSTALL_macOS.md`](docs/INSTALL_macOS.md), and
[`docs/INSTALL_Windows.md`](docs/INSTALL_Windows.md). `docs/` is the canonical
home for project documentation; files of the same name under `node/` are
pointers only.

### Protocol changes

Protocol changes must update the deterministic vectors under
`shared-vectors/rvn1/` (`python3 protocol/reference/generate_rvn1.py`) and pass
the Python reference tests (`cd protocol/reference && python3 -m pytest -q`)
and the Rust vector tests. Swift/Dart clients consume the same vectors from
their own trees, so a wire change must be versioned, never silently edited.
If you change a frozen protocol file, regenerate
[`docs/PROTOCOL_FREEZE_HASHES_V1.md`](docs/PROTOCOL_FREEZE_HASHES_V1.md) with
`bash scripts/freeze_protocol_hashes.sh` in the same pull request and explain
the change; CI runs `bash scripts/freeze_protocol_hashes.sh --check`.

### Harness scripts

Proof and smoke scripts must fail when an assertion fails. Under `set -e`,
bash ignores errexit inside the left side of `&&`/`||`, inside `if`/`while`
conditions and on `!`-negated commands, so write negative checks as
`if grep -q X f; then echo ...; exit 1; fi` and never call an asserting
function from a condition. `scripts/lib/proof_assert.sh` provides a step
runner and assertion helpers with a self-test
(`bash scripts/final_serverless_proof.sh --self-test`).

Security-sensitive experimental features must remain disabled by default until
their documented activation gate is complete.

### Legacy application server

The FastAPI application is not part of the serverless text-message path and is
not in this repository. Do not add a mandatory message, identity, lookup, or
routing dependency on it.

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 License.
Brand names and visual assets are governed separately by
[`TRADEMARK.md`](TRADEMARK.md) and [`ASSET_LICENSE.md`](ASSET_LICENSE.md).
