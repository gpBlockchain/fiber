# Fiber Network Node — Security Audit Workspace

This directory contains the working artifacts of the FNN security audit, executed
according to the [security-audit SKILL](https://github.com/gpBlockchain/ckb-test-skills/blob/main/.claude/skills/security-audit/SKILL.md).

## Layout

| Path | Purpose |
|---|---|
| [`SECURITY_AUDIT_TODO.md`](./SECURITY_AUDIT_TODO.md) | Single Source of Truth for audit progress. Updated after every session. |
| [`findings/`](./findings/) | Per-item audit records (`AUDIT-{ID}.md`), one per TODO item that has been touched. |
| [`REPORT.md`](./REPORT.md) | Final report (produced once all P0/P1 items are complete; placeholder until then). |

## Workflow

1. **Phase 0** — Recon & framing: complete (see `SECURITY_AUDIT_TODO.md` §"Project Profile").
2. **Phase 1** — Iterative deep audits, 1–3 items per session. The TODO doc tracks state.
3. **Phase 2** — Doc updates after every session (status, findings, new attack-surface items).
4. **Phase 3** — Final report.

## Status (TODO v3, 2026-05-13)

| Bucket | Count |
|---|---|
| Total TODO items | 31 |
| ✅ Passed | 0 |
| ⚠️ Advisory / Improvement | 2 (AUDIT-CRYPTO-003, AUDIT-INPUT-001) |
| ❌ Suspected vulnerability | 1 (AUDIT-CRYPTO-001, requires dynamic validation) |
| ⚠️ Weak design | 3 (AUDIT-CRYPTO-002, AUDIT-LOGIC-001, AUDIT-LOGIC-003) |
| ℹ️ Informational | 1 (AUDIT-DEP-001 — no known CVE in surveyed deps) |
| ⏳ Pending | 24 |

## Next session (S4) — planned

- AUDIT-LOGIC-002 — TLC / PTLC lifecycle & timelocks
- AUDIT-LOGIC-006 — Watchtower reaction paths (preimage monitor, settle, HTLC-success/timeout)
