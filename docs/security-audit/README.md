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

## Status (TODO v9, 2026-05-13)

| Bucket | Count |
|---|---|
| Total TODO items | 32 |
| ✅ Passed | 0 |
| ⚠️ Advisory / Improvement | 2 (AUDIT-CRYPTO-003, AUDIT-INPUT-001) |
| ❌ Suspected vulnerability | 1 (AUDIT-CRYPTO-001, requires dynamic validation) |
| ⚠️ Weak design | 11 (AUDIT-CRYPTO-002, AUDIT-LOGIC-001..007, AUDIT-AUTH-001, AUDIT-AUTH-002, AUDIT-MEM-001) |
| ℹ️ Informational | 1 (AUDIT-DEP-001 — no known CVE in surveyed deps) |
| ⏳ Pending | 17 |

## Next session (S10) — planned

- AUDIT-MEM-002 — numeric overflow & boundary (fee calc, HTLC amount + capacity, channel state)
- AUDIT-LOGIC-008 — CCH cross-chain HTLC dependency & expiry
- AUDIT-INPUT-002 — Invoice parsing (bech32 / lightning-invoice)
- Pending PoC follow-ups (MEM-001-A, AUTH-001-A, AUTH-002-A, LOGIC-007-A highest priority)

## Findings index

| ID | Severity | Title | File |
|---|---|---|---|
| AUDIT-CRYPTO-001 | 🔴 Suspected H/Critical | MuSig2 nonce reuse (requires dynamic PoC) | [findings/AUDIT-CRYPTO-001.md](./findings/AUDIT-CRYPTO-001.md) |
| AUDIT-CRYPTO-002 | 🟡 Medium + 🟢 Low + ℹ️ Info | Sphinx onion peeling & replay protection | [findings/AUDIT-CRYPTO-002.md](./findings/AUDIT-CRYPTO-002.md) |
| AUDIT-CRYPTO-003 | 🟡 Medium × 2 + 🟢 Low × 3 | Wallet encryption (key derivation, AEAD) | [findings/AUDIT-CRYPTO-003.md](./findings/AUDIT-CRYPTO-003.md) |
| AUDIT-DEP-001 | ℹ️ Info | Dependency vulnerability scan | [findings/AUDIT-DEP-001.md](./findings/AUDIT-DEP-001.md) |
| AUDIT-INPUT-001 | 🟢 Low + 🟡 Improvement × 3 | P2P Molecule input fuzz coverage | [findings/AUDIT-INPUT-001.md](./findings/AUDIT-INPUT-001.md) |
| AUDIT-LOGIC-001 | 🟡 Medium × 1 + 🟢 Low × 4 + ℹ️ Info × 2 | Channel state-machine illegal transitions | [findings/AUDIT-LOGIC-001.md](./findings/AUDIT-LOGIC-001.md) |
| AUDIT-LOGIC-002 | 🟡 Medium × 1 + 🟢 Low × 2 + ℹ️ Info × 1 | TLC / PTLC lifecycle & timelocks | [findings/AUDIT-LOGIC-002.md](./findings/AUDIT-LOGIC-002.md) |
| AUDIT-LOGIC-003 | 🟡 Medium × 3 + 🟢 Low × 2 | Commitment number & revocation key | [findings/AUDIT-LOGIC-003.md](./findings/AUDIT-LOGIC-003.md) |
| AUDIT-LOGIC-004 | 🟡 Medium × 1 + 🟢 Low × 3 + ℹ️ Info × 2 | Multi-hop forward amount / fee consistency | [findings/AUDIT-LOGIC-004.md](./findings/AUDIT-LOGIC-004.md) |
| AUDIT-LOGIC-005 | 🟡 Medium × 1 + 🟢 Low × 3 + ℹ️ Info × 2 | MPP / Trampoline split consistency | [findings/AUDIT-LOGIC-005.md](./findings/AUDIT-LOGIC-005.md) |
| AUDIT-LOGIC-006 | 🟢 Low × 4 + ℹ️ Info × 2 | Watchtower reaction paths (remaining surface) | [findings/AUDIT-LOGIC-006.md](./findings/AUDIT-LOGIC-006.md) |
| AUDIT-LOGIC-007 | 🟠 High (协同) / 🟡 Medium × 3 + 🟢 Low × 3 + ℹ️ Info × 2 | Channel close (cooperative + force) & shutdown_script validation | [findings/AUDIT-LOGIC-007.md](./findings/AUDIT-LOGIC-007.md) |
| AUDIT-AUTH-001 | 🟠 High / 🟡 Medium × 2 + 🟢 Low × 5 + ℹ️ Pass × 2 | Biscuit RPC auth — incl. standalone-watchtower multi-tenant NodeId::local collision | [findings/AUDIT-AUTH-001.md](./findings/AUDIT-AUTH-001.md) |
| AUDIT-AUTH-002 | 🟡 Medium / 🟡 Medium × 2 + 🟢 Low × 4 + ℹ️ Pass × 4 | Peer identity binding (secio) & onion service — incl. inbound eviction Sybil DoS, onion privacy gap | [findings/AUDIT-AUTH-002.md](./findings/AUDIT-AUTH-002.md) |
| AUDIT-MEM-001 | 🟠 High / 🟠 High × 1 + 🟡 Medium × 2 + 🟢 Low × 3 + ℹ️ Pass × 2 | Resource exhaustion — gossip `messages_to_be_saved` accepts unverified messages with no per-peer cap → remote OOM (~50 MB/s) | [findings/AUDIT-MEM-001.md](./findings/AUDIT-MEM-001.md) |
