# Secret scan — owner triage record

Hand-maintained. `scripts/secret_history_scan.sh` regenerates
[`SECRET_HISTORY_SCAN_REPORT.md`](SECRET_HISTORY_SCAN_REPORT.md) (pattern class,
path and line only — never values); this file records what a human decided
about each row. Neither file rotates anything, and **this repository's tooling
never rewrites git history**.

## ACTION REQUIRED — credential owner

| Row | Status | Required action |
|---|---|---|
| `history:server/setup-resend.sh@bfc2b9f760c0` line 27 (`ENV_SECRET_ASSIGNMENT`) | **OPEN — owner must confirm** | If a Resend API key was **ever** used with this script, or ever sat in this file or any other file of this repository's history (including branches, forks and clones), the Resend account owner must **revoke / rotate that key at Resend now**, independent of anything in this repository. |

What the automated triage found (2026-09-29, values never printed):

- Line 27 assigns a **14-character** value to a variable named `SECRET_NAME` — the
  shape of a secret *name* (for example a CI / provider secret identifier), not
  of an API key.
- No blob reachable from any ref in the scanned clone contains a Resend-format
  token (`re_<id>_<secret>`); the scanner now hard-fails on that format
  (`RESEND_API_KEY`) in the tree and in history.

That makes a leaked key in *this* history unlikely, but it cannot be proven from
the repository alone (a key may have been pasted and force-pushed away, or used
from a local copy). Only the key owner can close this row: record "rotated on
<date>" or "confirmed never a real key" here.

History rewriting is deliberately **not** done: it would not un-leak a key that
was ever public (forks, clones, caches), and rotation is the only effective
remedy.

## Reviewed — no action

| Row | Verdict |
|---|---|
| `history:news_bot/README.md@6f99d558b254` line 84 | Documentation example assignment (false positive). |
| `history:server/.env.example@4387e6e4ba72` line 36 | Placeholder template value (false positive). |

## Scanner coverage (see the script header for details)

Hard-fail in tree and history: PEM private keys, AWS / GitHub / Slack / Resend /
Stripe-live / Google API tokens, untracked `.env`-style files, Raven secret files
by name (`identity.seed`, `*.seed`, `*.sqlite*`, `*.db`, `prekey_store.json`,
`*.p12`, `*.pfx`), exactly-32-byte non-text blobs (raw Ed25519 seed shape), and
64-hex seed / private-key assignments. The public RFC 8032 §7.1 test keys used
by the vectors are allowlisted by SHA-256. Environment-style secret assignments
fail CI in the current tree and are human-review rows in history.
