# Secret History Scan Report

- Generated: `2026-09-29T18:33:01Z`
- Branch: ``
- HEAD: `81a540d`
- Script: `scripts/secret_history_scan.sh`
- Hit rows: **3** (pattern class only — values redacted)
- Historical blobs examined: **3919** (all reachable refs)
- CI hard-fail classes present: **0** (1=yes)

## Policy

- Findings are flagged for **HUMAN** rotation / history rewrite decisions.
- Historical findings use `history:path@blob-id`; no matching value is emitted.
- This script does **not** rotate credentials or rewrite git history.
- Public test vectors / shared-vectors hex are excluded from path scope.
- Hard-fail classes (tree **and** history): PEM private keys, AWS/GitHub/Slack/Resend/Stripe/Google tokens, untracked secret files, Raven secret files by name (`identity.seed`, `*.seed`, `*.sqlite*`, `*.db`, `prekey_store.json`, `*.p12`/`*.pfx`), 32-byte binary blobs (raw seed shape) and 64-hex seed / private-key assignments (RFC 8032 public test keys allowlisted by hash).
- Environment-style secret assignments fail CI in the current tree; in history they are human-review rows.
- Owner triage decisions (rotation, false positives) are recorded by hand in [`docs/SECRET_SCAN_TRIAGE.md`](SECRET_SCAN_TRIAGE.md). Rotation must be done by the credential owner at the provider; this repository's tooling never rewrites history.

## Findings

| Class | Path | Line | Action |
|-------|------|------|--------|
| `ENV_SECRET_ASSIGNMENT` | `history:news_bot/README.md@6f99d558b254` | 84 | human_review |
| `ENV_SECRET_ASSIGNMENT` | `history:server/.env.example@4387e6e4ba72` | 36 | human_review |
| `ENV_SECRET_ASSIGNMENT` | `history:server/setup-resend.sh@bfc2b9f760c0` | 27 | human_review |

## Human follow-ups (BLOCKED_HUMAN if real secrets)

1. Review each row and record the verdict in [`docs/SECRET_SCAN_TRIAGE.md`](SECRET_SCAN_TRIAGE.md) — rows marked OPEN there need the credential owner.
2. If a credential was ever real: the **owner must rotate / revoke it at the provider**. Removing it from git (or rewriting history) does not un-leak it; this tooling never rewrites history.
3. Do not commit `.env` files, `identity.seed`, node databases or other key material; keep them gitignored.

## CI

`--ci` exits non-zero on any hard-fail class above, and on environment-style secret assignments in the current tree. Historical environment-style rows stay non-blocking human-review findings (see the triage file).
