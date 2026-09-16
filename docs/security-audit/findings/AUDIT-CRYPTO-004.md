# AUDIT-CRYPTO-004 — 签名验证完整性 (gossip / commitment / shutdown / network)

**审计目标**: 检查 Fiber 节点对外部 (P2P / RPC / gossip / CCH) 信任边界上**所有**签名路径是否强制校验，包括 ECDSA、Schnorr、MuSig2 partial signature，以及曲线点/标量的有效性。

**Session**: S20  
**审计日期**: 2026-05-14  
**审计员**: Copilot (research subagent)  
**整体严重性**: 🟡 **Medium** — 1 高频路径设计缺陷 + 3 中等不一致

---

## 概览

| Severity | Count |
|---|---|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 4 (F1, F2, F3, F4) |
| 🔵 Low | 2 (F5, F6) |
| ✅ Pass | 5 (F7–F11) |

**关键发现**: Channel 状态机中 **MuSig2 partial signature 的预校验在三个不同消息路径上分别处理**：`CommitmentSigned` ✅ 正确预校验；`ClosingSigned`、`RevokeAndAck`、`AnnouncementSignatures` ❌ 都跳过了 `verify_partial`，直接进入 `aggregate_partial_signatures`。虽然最终的聚合 Schnorr 校验会拦截无效签名，导致**无资金损失**，但攻击 surface 仍可被恶意 peer 利用为 channel-stuck / 拒绝合作关闭的 DoS。

Gossip 路径整体设计良好（依赖排序、三签全验、on-chain 绑定都正确），但 UDT 通道 capacity 不做链上校验（TODO 占位），可被用于污染路由决策。

---

## F1 — 🟡 Medium · `ClosingSigned` partial signature 未预校验，缺状态守卫

**位置**: `crates/fiber-lib/src/fiber/channel.rs:792-803`, `:6591-6598`

`handle_closing_signed_peer_message` 收到对端 `partial_signature` 后**直接落库**，代码自评注释承认了双重缺陷：

```rust
// Note that we don't check the validity of the signature here.
// we will check the validity when we're about to build the shutdown tx.
// This may be or may not be a problem.
// We do this to simplify the handling of the message.
// We may change this in the future.
// We also didn't check the state here.
if let Some(shutdown_info) = state.remote_shutdown_info.as_mut() {
    shutdown_info.signature = Some(partial_signature);  // 未校验
}
state.maybe_transfer_to_shutdown().await?;
```

之后在 `maybe_transfer_to_shutdown` 中 `.unwrap()` 取出 → `aggregate_partial_signatures_to_consume_funding_cell`。musig2 0.2 的 `aggregate_partial_signatures` 只校验最终聚合 Schnorr，不对每个 partial 单独校验。

### 攻击场景

1. Alice 发起合作关闭，发送 `Shutdown`；
2. Mallory（远端）发回 `ClosingSigned { partial_signature: 64 字节随机 }`；
3. Alice 状态机进入"双方已交换关闭脚本+签名"分支，调用聚合 → 失败 → 整个合作关闭路径报错；
4. Alice 只能 force-close（unilateral），承担更长 timelock + 链上 fee 成本。

附加风险：注释承认"也没检查 state"，意味着任意 channel 状态下 Mallory 都能注入这个 partial sig（state guard 缺失见 AUDIT-LOGIC-001 互补）。

### 资金影响

无直接资金损失（聚合校验兜底），但：
- 合作关闭路径可被永久阻塞 → 强制 force-close
- 攻击者重复发送 → 反复触发状态机错误 → 日志噪声 / 资源消耗

### 修复

获取 `Musig2VerifyContext`（同 `verify_and_complete_tx` 的 `get_funding_verify_context()` 模式），在 line 799 之前 `verify_partial(partial_signature, &message)`，失败则断开 peer。状态守卫见 LOGIC-001。

---

## F2 — 🟡 Medium · `RevokeAndAck` revocation partial signature 未预校验

**位置**: `crates/fiber-lib/src/fiber/channel.rs:7301-7356`

```rust
let aggregated_signature =
    sign_ctx.sign_and_aggregate(message.as_slice(), revocation_partial_signature)?;
```

`sign_and_aggregate` → `aggregate_partial_signatures_for_msg` → 只验最终聚合。**与 `CommitmentSigned` 路径不一致**：后者在 `channel.rs:8339-8340` 正确调用 `get_funding_verify_context().verify(...)` 后再聚合。

### Revocation 上下文的特殊意义

`revocation_partial_signature` 用于构造 `RevocationData`，是 watchtower 惩罚作弊对端的关键凭证。若聚合失败：
- 当前 commitment 编号的 revocation data **永久无法构造**；
- 该 commitment 的 force-close 攻击窗口期内，本节点失去惩罚手段；
- watchtower 也无法接管该 commitment 的反作弊（已知问题：见 AUDIT-INPUT-005.F1，watchtower 自身已脆弱）。

### 攻击场景

恶意对端在每次 commitment 升级中发送 garbage `revocation_partial_signature` → 本节点状态机错误 → 通道进入降级状态。配合 INPUT-005.F1 watchtower panic 链路，可形成"先污染 revocation，再 cheat"的两阶段攻击。

### 修复

```rust
let common_ctx = self.get_revoke_common_context(...);
common_ctx.verify(revocation_partial_signature, message)?;
let aggregated_signature = sign_ctx.sign_and_aggregate(message.as_slice(), revocation_partial_signature)?;
```

---

## F3 — 🟡 Medium · `AnnouncementSignatures` 聚合前未校验远端 partial（含 stale TODO）

**位置**: `crates/fiber-lib/src/fiber/channel.rs:4720-4737`

```rust
if let Ok(signature) = aggregate_partial_signatures(&key_agg_ctx, &agg_nonce, partial_signatures, message)
{
    channel_announcement.ckb_signature = Some(signature);
    ...
} else {
    // TODO: we should ban remote peer if we fail to aggregate the signature
    // since the error is caused by the wrong nonce.
    warn!("Failed to aggregate channel announcement signature...");
    None
}
```

TODO 注释错误归因（"wrong nonce"），实际上恶意 partial sig 也会导致失败。被害方：
- 公开通道的 `ChannelAnnouncement` 永远不会被 gossip 出去 → 路由不可达；
- 对端不被断开，可重复攻击；
- 与 F1/F2 同一模式：相信对端的 musig2 partial 而不预验。

### 修复

聚合前 `verify_partial`；失败则 ban peer 并返回 `ProcessingChannelError::InvalidPeer`。同时把 TODO 注释改为正确归因（"any malformed partial sig"）。

---

## F4 — 🟡 Medium · UDT 通道 capacity 不做链上校验

**位置**: `crates/fiber-lib/src/fiber/gossip.rs:2499-2505`

```rust
match channel_announcement.udt_type_script {
    Some(_) => {
        // TODO: verify the capacity of the UDT
    }
    None => {
        if channel_announcement.capacity > capacity { return Err(...); }
    }
}
```

CKB 原生通道的 capacity 上限受 funding cell 的 CKB 容量约束，gossip 校验严格。但 UDT 通道完全跳过，攻击者可声明远超实际 UDT 余额的 capacity。

### 影响

- 路径搜索算法（`fiber/graph.rs::find_path`）将该通道视为大容量优先路径；
- 攻击者通过虚高 capacity 把 UDT 通道塞进多条路由 → 后续 payment attempt 失败 → 路由学习被污染（结合 AUDIT-GRAPH slander，扩大攻击面）；
- 中转节点统计被扭曲，影响 fee market 估计。

### 修复

`get_on_chain_channel_info` 已经能查到 funding cell；扩展返回 cell 的 `output_data`（UDT 余额前 16 字节，参考 AUDIT-INPUT-005.F4），与 `channel_announcement.capacity` 比对。

---

## F5 — 🔵 Low · 未签名 invoice 静默通过 `check_signature()`

**位置**: `crates/fiber-types/src/invoice.rs:601-604`, `crates/fiber-lib/src/cch/actor.rs:~628`

```rust
pub fn check_signature(&self) -> Result<(), InvoiceError> {
    if self.signature.is_none() {
        return Ok(());                  // 静默 pass
    }
    ...
}
```

CCH `from_str(pay_req)` 调用栈中没看到 `is_signed()` 守卫。攻击者构造未签名 invoice 指定**自己不知道 preimage** 的 `payment_hash`，受害方付款后资金会卡在 HTLC 直到超时（虽然最终会退回，但攻击者可批量发起，造成中转节点的 liquidity lockup）。

### 修复

CCH `ReceiveBTC` 路径强制 `if !fiber_invoice.is_signed() { return Err(InvalidInvoice("must be signed")) }`。RPC `parse_invoice` 可保留宽容（供用户调试），但 `send_payment` 同样应加 `is_signed` 强制。

---

## F6 — 🔵 Low · Gossip 消息签名缺少域分离

**位置**: `crates/fiber-types/src/protocol.rs:547-590`, `crates/fiber-lib/src/fiber/network.rs:607-613`

`message_to_sign()` 直接对 molecule 序列化做 `deterministically_hash`，未加入域分离 tag (例 `"fiber/channel-ann/v1"`)。BIP340 要求 Schnorr 强制 tagged hash；这里 ECDSA 部分缺失。

实际风险低（每条消息包含 `chain_hash` + 类型差异化字段使跨类型 collision 极难构造），但作为加固建议：在 `message_to_sign` 输入前缀加可读 tag，并在 ckb_signature 路径切换到 BIP340-style tagged hash。

---

## ✅ Pass: F7-F11

- **F7** `CommitmentSigned.verify_and_complete_tx` 正确调用 `get_funding_verify_context().verify(...)` 后再聚合 — 是 F1/F2/F3 应该对齐的范本 (`channel.rs:8339-8340`)
- **F8** `verify_channel_announcement` 三签全验 (node1 ECDSA / node2 ECDSA / ckb Schnorr) + 强制 `node1_id ≠ node2_id` + 链上 cell 绑定 `ckb_key` hash (`gossip.rs:2428-2530`)
- **F9** `Pubkey::from_slice` 由 secp256k1 0.30 拒绝 identity point / off-curve / 错误编码 (`primitives.rs:503-508`)
- **F10** `EcdsaSignature` / `SchnorrSignature` 编译期类型隔离，无互转 (`protocol.rs`)
- **F11** `BroadcastMessage::Ord` 强制 NodeAnn < ChannelAnn < ChannelUpdate，`prune_messages_to_be_saved` 排序后逐条验证，杜绝依赖顺序绕过 (`protocol.rs:1122-1134`)

---

## Cross-References

- **F1/F2/F3** ↔ AUDIT-LOGIC-003 (commitment flow)、AUDIT-LOGIC-007 (shutdown)、AUDIT-CRYPTO-001 (MuSig2 nonce)
- **F2** 配合 AUDIT-INPUT-005.F1 (watchtower panic) 可形成"污染 revocation + cheat"两阶段攻击链
- **F4** ↔ AUDIT-LOGIC-001.F4 (UDT 流动性)、AUDIT-INPUT-005.F4 (UDT cell data len)
- **F5** ↔ AUDIT-INPUT-002 (invoice parse DoS)、CCH 链路
- **F6** ↔ AUDIT-AUTH-002.F8 (chain identity)

---

## 后续 follow-ups

- **CR-A** (High): F1/F2/F3 三处统一引入 `verify_partial` 模式，提取 helper `verify_remote_partial_or_ban(...)`。
- **CR-B** (Medium): F4 实现 UDT capacity on-chain 校验（需要 `get_on_chain_channel_info` 返回 output_data）。
- **CR-C** (Medium): F5 在 CCH `ReceiveBTC` 入口强制 `is_signed()`。
- **CR-D** (Low): F6 加 domain-separation tag 到 gossip `message_to_sign`。
- **CR-E** (Info): 补充 fuzz target — peer 发送随机 partial_signature 后 channel 状态机 invariant 检查。
