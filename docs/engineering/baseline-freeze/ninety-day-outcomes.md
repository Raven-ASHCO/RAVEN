# Ninety-Day Outcomes (O1–O7)

Target window: ~90 days from Baseline Freeze (anchor date 2026-09-04).

| ID | Outcome | Success signal | Primary roles |
|----|---------|----------------|---------------|
| **O1** | **Org + Teams live** | Repos under Org; `@Raven-ASHCO/*` teams resolve; CODEOWNERS active | Eng Mgmt, #1, #20 |
| **O2** | **Protected main** | `main` protected on RAVEN and RDAP; required reviews + required CI checks; rulesets as needed | #20, #17, #19 |
| **O3** | **Ownership complete** | Architecture map, trust boundaries, component ownership published; every critical path has role #+team | #1, domain leads |
| **O4** | **R3 discipline** | Risk classes + approval matrix enforced; **zero** R3 self-merges | #17, #1, all authors |
| **O5** | **Protocol freeze baseline** | Current protocol versions documented; experimental-only features listed; version bumps go through matrix | #2, #3, #14 |
| **O6** | **Interop & gaps** | Raven↔RDAP gaps (security/interop) inventoried with owners; interop tests in CI | #4, #18, #14, #2 |
| **O7** | **Perf + roadmap** | Performance baseline recorded; 90-day roadmap agreed and tracked | #19 (SRE Perf), #1, Eng Mgmt |

## Dependencies

```
O1 (Org/Teams) ──► O2 (protection) ──► O4 (R3 discipline)
       │                                    ▲
       └────────► O3 (ownership) ───────────┘
O5 (protocol) + O6 (interop) can proceed in parallel once O3 draft exists.
O7 needs O3 + initial CI from O2.
```

**O6 honesty (2026-09-06):** inventory board [`o6-raven-rdap-try-phase-gap-board.md`](o6-raven-rdap-try-phase-gap-board.md). ADR 0004 two-device encrypted harness remains **RED / gated** (terminal + HOLD + M1–M3). Inventory ≠ harness green ≠ HOLD lift.

## Explicit non-outcome

Staffing every role #1–#20 with a named human is **not** required to claim O1–O7 if teams and boards cover the approval matrix; vacant roles must still have an acting owner recorded by Eng Management.
