# AUDIT-SPEC-003 — Trampoline / CCH 规范对照

| 字段 | 值 |
|---|---|
| 维度 | DIM-SPEC |
| 严重度 | 🟡 Medium (Medium × 3 + Low × 3 + Info × 2 + Pass × 4) |
| 状态 | [!] 发现弱设计 |
| 关联代码 | `docs/specs/trampoline-routing.md`, `docs/specs/cross-chain-htlc.md`, `docs/specs/cch-expiry-dependency.md`, `crates/fiber-lib/src/fiber/payment.rs:46-50,233-236,365-385`, `types.rs:1860,1964,3773-3846`, `graph.rs:1294-1507`, `network.rs:2438-2550`, `channel.rs:1182-1195`, `crates/fiber-lib/src/cch/*` |

## 1. 背景

`docs/specs/trampoline-routing.md` 与 `docs/specs/cross-chain-htlc.md` 是 fiber 自身扩展（非 BOLT 直系）；AUDIT-SPEC-001/002 已覆盖 P2P 消息与 invoice 规范。本项专门审计两个增值功能的「规范 vs 实现」对照。

## 2. Trampoline 规范差异

### F1 🟡 Medium — 规范缺少 onion 内层 payload 字段表

- spec 仅说明 "inner trampoline onion encodes the remaining hops"，未列出 `TrampolineHopData` 实际字段：
  - 实现在 `types.rs:3773-3818`，包含 `amount_to_forward`, `expiry`, `next_hop_pubkey`, `build_max_fee_amount`, `next_trampoline`，但 spec 完全无字段表。
  - 三方互操作者无法实装 trampoline forwarder；payment probing 防御层（per-hop padding）也无规范背书。

### F2 🟡 Medium — `MAX_TRAMPOLINE_HOPS_LIMIT = 5` 仅源码 hard-code

- 实现 `crates/fiber-lib/src/fiber/payment.rs:49` 写死 5；spec 只说 "Max trampoline hops: MAX_TRAMPOLINE_HOPS_LIMIT (5)" 并链回源码。
- 与 BOLT-04 onion payload 最大 hop 数 (20) 的关系未文档化；攻击者构造 > 5 hops 时是发送方还是接收方拒绝、错误码是什么，全部未规范。

### F3 🟢 Low — Trampoline + MPP 组合行为未规范

- 实现 (`channel.rs:1182-1195` + `settle_tlc_set_command.rs`) 未禁止 trampoline invoice 与 MPP split 组合；但 AUDIT-LOGIC-005 已识别 MPP `total_amount` 接受任意倍超付。
- spec 未说明 trampoline forwarder 是否要把 MPP `payment_secret`/`total_amount` 透传给下一 hop；实现透传，三方实装者可能漏掉 → 跨节点 MPP 失败 / 银行家攻击窗口。

### F4 ℹ️ Info — Trampoline 失败错误码语义

- spec "Forwarding behavior" 节只提 "validates the forward payload"，未列举失败时构造的 `TlcErrPacket` 错误码 (`TemporaryNodeFailure` vs `InvalidOnionPayload` vs trampoline 专用错误码)；与 AUDIT-CRYPTO-002.F1（cross-channel replay）+ AUDIT-ERR-001.F1 (probing) 同链：每多一种错误码就多一个 probing oracle。

### F5 ✅ Pass — 路由约束已实现

- `tlc_expiry_limit` 检查、`build_max_fee_amount` 在 trampoline 节点严格等式（AUDIT-LOGIC-004.F4 Pass 已确认）、内外 onion 用 `payment_hash` tweak 绑定 (AUDIT-LOGIC-005.F2 Pass) — 协议核心机制正确。

## 3. CCH 规范差异

### F6 🟡 Medium — `cross-chain-htlc.md` vs 实现 expiry 假设不一致

- spec 仅描述抽象的 "atomic via shared preimage"，**完全未文档化 expiry 关系**。
- 实现实际依赖 `order_expiry_delta_seconds=36h` < `tlc_final_expiry_delta=60h` 这一不变式（AUDIT-LOGIC-008.F1 High：默认 24h 攻击窗口 → 资金直损）。
- `cch-expiry-dependency.md` 是后补的设计文档，但 `cross-chain-htlc.md` 仍是"用户级别概述"，没有 spec-as-contract 性质。三方运营自建 CCH hub 无规范化约束，配置失误 = 资金损失。

### F7 🟢 Low — Fee 政策无规范

- spec 在 "Example Between Bitcoin and CKB" 节只说 "Ingrid will keep F BTC as the fee" 不展开。
- 实现 `cch/config.rs` 含 `fee_rate_per_million_sats` + base fee + 最小阈值；user-facing 透明度差，节点运维不易告知用户。

### F8 🟢 Low — preimage 转发延迟 / cancel_invoice 路径

- AUDIT-LOGIC-008 已识别 CCH 模块完全无 `cancel_invoice` / `cancel_payment` 调用路径（grep 0 命中）。
- spec 未规范"中途取消"语义；BTC HTLC 与 CKB TLC 双向链路任一中断时的 hub 责任未规范。

### F9 ℹ️ Info — BTC 600s/block 固定假设

- AUDIT-LOGIC-008.F3 已 cross-ref；spec 应记载 block-time 假设并允许部署方下调安全系数。

### F10 ✅ Pass — preimage hash 算法约束

- spec "Another requirement is that the two networks must use the same hash algorithm for HTLCs." 与实现一致（CCH 默认 SHA256 双链）；`HashAlgorithm` enum 已支持选择 (CRYPTO-005 / SPEC-002 已 cross-ref)。

### F11 ✅ Pass — 静态 + 动态 half-budget check

- AUDIT-LOGIC-008.F5/F6 已 Pass：`actor.rs:557-664` + `send_outgoing_payment.rs:180-281` 严格遵循 LN HTLC 标准的"中转节点至少保留剩余 timelock 的一半"原则。

### F12 ✅ Pass — preimage SHA256 校验

- `state_machine.rs:49-54` 接受 outgoing preimage 前强制 hash 校验（防伪造）。

## 4. 整体评价

| 维度 | trampoline | CCH |
|---|---|---|
| 规范是否能让三方实装 | ❌（缺 payload 字段表 / 最大 hops 关系） | ❌（不提 expiry 关系 / cancel 语义） |
| 实现是否安全 | ⚠️（依赖 LOGIC-004/005 修复） | ⚠️（依赖 LOGIC-008 修复） |
| 协议核心 | ✓（onion tweak / fee 严格等式） | ✓（双重 half-budget / SHA256 校验） |

与 SPEC-001/SPEC-002 同质：**实现层守住协议核心，规范层欠债**。fiber 自身无直接资金风险（实现正确），但公共规范缺位给生态扩展和未来 PTLC / Trampoline v2 讨论制造障碍。

## 5. 修复建议

| 优先级 | 建议 |
|---|---|
| P1 | 跟随 AUDIT-LOGIC-008-FOLLOWUP-A/B 落地后，把 `cross-chain-htlc.md` 升级为含 expiry 关系/cancel 语义/fee 政策的 spec-as-contract |
| P2 | trampoline-routing.md 补 `TrampolineHopData` 字段表 + MAX_HOPS 错误码 + MPP 组合行为约束 |
| P2 | 把 `cch-expiry-dependency.md` 合并入 `cross-chain-htlc.md` 主文档；解决"用户向" vs "实装向"双层割裂 |
| P3 | SPEC-001/002/003 三处共同的 "spec 失同步" 问题用 CI script 防回退（grep 公共类型名一致性） |

## 6. 跟踪项

- AUDIT-SPEC-003-FOLLOWUP-A：起草 `trampoline-routing.md` v2 (含 payload 字段表 + 错误码 + MPP 组合)
- AUDIT-SPEC-003-FOLLOWUP-B：起草 `cross-chain-htlc.md` v2 (含 expiry 关系/cancel 语义)
- AUDIT-SPEC-003-FOLLOWUP-C：与 SPEC-001 F-G、SPEC-002 H 合并的 CI lint：spec-as-contract 类型一致性检查
