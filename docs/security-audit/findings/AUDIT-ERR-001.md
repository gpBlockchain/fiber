# AUDIT-ERR-001 — 支付错误码与 payment probing

- **维度**: DIM-ERRINFO / DIM-PRIVACY
- **严重级别**: 🟡 **Medium**（Medium × 2 + Low × 3 + Info × 1 + Pass × 2）
- **审计 Session**: S13 (2026-05-14)
- **关联代码**:
  - `crates/fiber-types/src/payment.rs:793-852` (`TlcErrorCode` 枚举，BOLT-04 风格的 PERM/NODE/UPDATE/BADONION 位掩码)
  - `crates/fiber-types/src/payment.rs:161-285` (`TlcErr` / `TlcErrData`，结构化错误 + extra_data)
  - `crates/fiber-types/src/payment.rs:273-278` (`TlcErr::serialize` `.expect` ⚠️)
  - `crates/fiber-types/src/onion.rs:31-145` (`TlcErrPacket` sphinx 错误信封，27 轮 padding 防 timing oracle)
  - `crates/fiber-types/src/onion.rs:124` (`PublicKey::from_slice(&k.0).expect("valid pubkey")` ⚠️)
  - `crates/fiber-lib/src/fiber/channel.rs:830-906` (`get_tlc_error` 错误码映射 ⚠️ **probing oracle**)
  - `crates/fiber-lib/src/fiber/channel.rs:1148-1206` (`try_to_settle_down_tlc_with_invoice` → 显式发回 `InvoiceExpired`/`InvoiceCancelled` ⚠️)
  - `crates/fiber-lib/src/fiber/channel.rs:1333-1564` (`apply_add_tlc_operation_with_peeled_onion_packet` / `apply_final_hop_tlc_onion_packet`)
  - `crates/fiber-lib/src/fiber/payment.rs:603-614` (`PaymentSession → GetPaymentResult.failed_error` 透出错误文本)
  - `crates/fiber-lib/src/fiber/payment.rs:1076-1117` (`update_graph_with_tlc_fail` ⚠️ **slander attack**)
  - `crates/fiber-lib/src/fiber/payment.rs:1728-1758` (`handle_remove_tlc_event` → 解 sphinx → 直接信任 `extra_data`)
  - `crates/fiber-lib/src/fiber/history.rs:167-307` (`record_payment_fail` 按 `error_node_id` 在 route 中定位 — 这里有 ✓ slander 防护)
  - `crates/fiber-lib/src/fiber/graph.rs:1091-1122` (`mark_channel_failed` / `mark_node_failed` 本地图标记)

## 1. 审计目标

支付错误信息是 fiber 节点中**双向的隐私敏感面**：

1. **发送方→接收方**：错误码在洋葱回程的最终一跳上由接收节点（merchant）产出。如果不同的失败原因映射到不同错误码 → 攻击者用任意 payment_hash 发起 1-sat 探测 TLC，根据回复的错误码即可远程确认目标节点的 invoice 状态（存在/已取消/已过期/金额匹配）= **payment probing** 隐私泄露。
2. **中转节点→发送方**：error packet 由 sphinx onion 加密回程，发送方解密后通过 `error_node_id`/`channel_outpoint` 标记本地图。如果**未验证**返回的 `node_id`/`outpoint` 确实属于路由中的某个跳，恶意中转可以"诬陷"任意其他节点 = **graph slander** 攻击。
3. **本机查询**：`get_payment` RPC 返回 `failed_error: String` 给本机调用方（生成订单的应用）。该字段包含错误码字面量，与上面 (1) 是同一条信息流的本地端，加重 (1) 的影响。
4. **错误包构造/解构** panic 路径：`TlcErrPacket::decode` / `TlcErr::serialize` 是否有可远程触发的 panic？

本审计扫描：
- `TlcErrorCode` 枚举的语义颗粒度（BOLT-04 对比）；
- final-hop 错误码生成站点是否折叠为 `IncorrectOrUnknownPaymentDetails`（参 BOLT-04 §"failure messages"）；
- 中转 hop 错误的 `extra_data.node_id`/`channel_outpoint` 是否在本地图更新前校验属于 route；
- sphinx 错误包的 timing-side-channel 防护；
- 序列化/反序列化的 panic 可达性。

## 2. 系统性梳理

### 2.1 错误码集

`TlcErrorCode`（payment.rs:808-834）严格沿用 BOLT-04 的 `PERM`/`NODE`/`UPDATE`/`BADONION` 位掩码，包含 25 个变体：

| 类别 | 代码 | 行为说明 |
|---|---|---|
| Node | TemporaryNodeFailure / PermanentNodeFailure / RequiredNodeFeatureMissing | 节点级失败 |
| BadOnion | InvalidOnionVersion/Hmac/Key/Error/Payload | 洋葱包语义错误 |
| Channel | Temporary/Permanent ChannelFailure, RequiredChannelFeatureMissing, ChannelDisabled, UnknownNextPeer | 通道级失败 |
| Forwarding | AmountBelowMinimum / FeeInsufficient / IncorrectTlcExpiry / ExpiryTooSoon / ExpiryTooFar / IncorrectTlcDirection | 转发参数失败 |
| Final | **IncorrectOrUnknownPaymentDetails** (15) / **InvoiceExpired** (16) / **InvoiceCancelled** (17) / FinalIncorrectExpiryDelta (18) / FinalIncorrectTlcAmount (19) / HoldTlcTimeout (23) | **接收方失败 — 本审计核心关注** |

**与 BOLT-04 的差异**：BOLT-04 规范明确要求接收方对所有"payment 失败"原因（未知 payment_hash / 金额不符 / cltv 不符 / invoice 过期 / 已取消）一律返回 `incorrect_or_unknown_payment_details`（带可选 `htlc_msat`/`height`），其设计目的就是**防 payment probing**：

> The reason for this conflation [...] is to prevent an attacker from determining how an HTLC failed [...] which might reveal information about the recipient's invoices.

Fiber 引入了 BOLT-04 之外的两个独立终态码：`InvoiceExpired` (16) 与 `InvoiceCancelled` (17)，并在 `FinalIncorrectTlcAmount` 与 `FinalIncorrectExpiryDelta` 上分别区分（虽然这两个 BOLT-04 也用，但现代 LN 实现普遍把它们折叠到 `IncorrectOrUnknownPaymentDetails`）。

### 2.2 final-hop 错误码生成站点

`get_tlc_error` (channel.rs:830-906) 与 `try_to_settle_down_tlc_with_invoice` (channel.rs:1148-1206) 是产生 final-hop 错误码的两条路径：

```rust
// channel.rs:840-844 — get_tlc_error 路径
ProcessingChannelError::FinalInvoiceInvalid(status) => match status {
    CkbInvoiceStatus::Expired => TlcErrorCode::InvoiceExpired,
    CkbInvoiceStatus::Cancelled => TlcErrorCode::InvoiceCancelled,
    _ => TlcErrorCode::IncorrectOrUnknownPaymentDetails,
},
// :845-849
ProcessingChannelError::FinalIncorrectPreimage
| ProcessingChannelError::FinalIncorrectPaymentHash
| ProcessingChannelError::FinalIncorrectMPPInfo(_) => {
    TlcErrorCode::IncorrectOrUnknownPaymentDetails  // ✓ 已折叠
}
// :850-852
ProcessingChannelError::FinalIncorrectHTLCAmount => {
    TlcErrorCode::FinalIncorrectTlcAmount  // ✗ 未折叠
}
// :855-857
ProcessingChannelError::IncorrectFinalTlcExpiry => {
    TlcErrorCode::FinalIncorrectExpiryDelta  // ✗ 未折叠
}
```

```rust
// channel.rs:1156-1170 — try_to_settle_down_tlc_with_invoice 路径
CkbInvoiceStatus::Expired => {
    RemoveTlcReason::RemoveTlcFail(TlcErrPacket::new(
        TlcErr::new(TlcErrorCode::InvoiceExpired), &tlc.shared_secret,
    ))
}
CkbInvoiceStatus::Cancelled => {
    RemoveTlcReason::RemoveTlcFail(TlcErrPacket::new(
        TlcErr::new(TlcErrorCode::InvoiceCancelled), &tlc.shared_secret,
    ))
}
```

**结论**：从对端视角看，发送一份 payment_hash X 的 1-sat probing TLC 给疑似 merchant 节点，回程错误码分别区分如下场景：

| 接收方实际状态 | 返回错误码 | 攻击者推断 |
|---|---|---|
| invoice(X) 不存在 | `IncorrectOrUnknownPaymentDetails` | "未知 payment_hash 或细节错" — 不确定 |
| invoice(X) 已 Paid | `IncorrectOrUnknownPaymentDetails`（store.get_invoice 返回 None? 见下文） | 同上 |
| invoice(X) 已 **Expired** | **`InvoiceExpired`** | **invoice 存在 + 已过期** |
| invoice(X) 已 **Cancelled** | **`InvoiceCancelled`** | **invoice 存在 + 商家主动取消** |
| invoice(X) Open + amount 不符 | `FinalIncorrectTlcAmount` | **invoice 存在 + 金额错** |
| invoice(X) Open + expiry 不符 | `FinalIncorrectExpiryDelta` | **invoice 存在 + cltv 错** |
| invoice(X) Open + 一切正常 | （结算成功 — 但需要 preimage 才能拿钱，攻击者拿不到） | invoice 存在 |
| keysend 模式 + preimage 不匹配 | `IncorrectOrUnknownPaymentDetails` (channel.rs:847 FinalIncorrectPreimage) | 已折叠 ✓ |

### 2.3 中转 hop 错误的 slander 攻击面

sphinx onion error packet 由 erroring hop 用自己的 shared_secret 加密 payload，中转 hop 仅做 XOR 转发，**发送方解密后从 payload 中拿到 `TlcErr.extra_data`**。`extra_data` 是 erring hop 自己写入的，包含 `NodeFailed { node_id }` 或 `ChannelFailed { channel_outpoint, node_id, channel_update }`。

回到发送方处理：

```rust
// payment.rs:1668-1670  (handle_add_tlc_event 路径)
self.update_graph_with_tlc_fail(&self.network, &tlc_err).await;   // ← 先标记
let need_to_retry = self.network_graph.write().await.record_attempt_fail(  // ← 再校验
    &attempt, tlc_err.clone(), true,
);

// payment.rs:1735-1738  (handle_remove_tlc_event 路径) — 同样顺序
let tlc_error = reason.decode(&attempt.session_key, attempt.hops_public_keys())
    .unwrap_or_else(|| TlcErr::new(TlcErrorCode::InvalidOnionError));
let need_to_retry = self.network_graph.write().await.record_attempt_fail(...);
```

`update_graph_with_tlc_fail` (payment.rs:1099-1116) 对 `PermanentChannelFailure` / `ChannelDisabled` / `UnknownNextPeer` 直接调 `graph.mark_channel_failed(channel_outpoint)`，对 `PermanentNodeFailure` 调 `graph.mark_node_failed(node_id)`，**完全不校验 `channel_outpoint`/`node_id` 是否属于本次 attempt 的 route**：

```rust
TlcErrorCode::PermanentChannelFailure
| TlcErrorCode::ChannelDisabled
| TlcErrorCode::UnknownNextPeer => {
    let channel_outpoint = tlc_error_detail.error_channel_outpoint()
        .expect("expect channel outpoint");           // ← 攻击者控
    let mut graph = self.network_graph.write().await;
    graph.mark_channel_failed(&channel_outpoint);     // ← 标记任意通道
}
TlcErrorCode::PermanentNodeFailure => {
    let node_id = tlc_error_detail.error_node_id().expect("expect node id");  // ← 攻击者控
    let mut graph = self.network_graph.write().await;
    graph.mark_node_failed(node_id);                  // ← 标记任意节点
}
```

与之对比，`record_payment_fail` (history.rs:170-180) 在 history 路径上**有**校验：

```rust
let error_index = nodes.iter().position(|s| Some(s.pubkey) == tlc_err.error_node_id());
let Some(index) = error_index else {
    error!("Error index not found in the route: {:?}", tlc_err);
    return false;
};
```

历史记录拒绝了"不在 route 中的 error_node_id"，但 **graph 标记**已经先执行了 — 攻击效果保留在本地 graph 中，影响后续路径选择。

#### 攻击 PoC 简化版

1. 攻击者 A 在 fiber 网络中持有一对通道，能成为某发送方 V 的中转。
2. V 发起一次正常付款，A 作为中转 hop。
3. A 不转发，反而构造 `TlcErr { error_code: PermanentChannelFailure, extra_data: ChannelFailed { channel_outpoint: <V 的死对头 T 的某条主力通道>, node_id: <T>, channel_update: None } }`，用 sphinx 包封后回传 V。
4. V 解 sphinx → 拿到 `tlc_err` → 在 `update_graph_with_tlc_fail` 中无校验地把 T 的目标通道标记为 disabled。
5. V 在本地图中后续不会再选用 T 的该通道；T 失去一笔潜在转发收入。
6. 同样手法可对 `PermanentNodeFailure → mark_node_failed(any_node)` 把任意节点的所有通道禁用。

**影响范围**：
- 本地（仅 V 的视图），不会广播 — 不会污染整个网络；
- 持久至本地 graph 下一次 gossip 刷新（一般 `mark_channel_failed` 只改 `enabled = false` 字段，直到收到下一份 `ChannelUpdate` 才被覆盖）；
- 攻击成本：A 只需付出参与一次失败 attempt 的延迟（无资金损失，因为这是失败路径）；
- 攻击放大：A 在 1 次失败中可同时填入多个 `extra_data`（不行 — `extra_data` 是单个 enum，但 A 可在不同的失败 attempt 中针对不同目标）。

### 2.4 timing & info leak — 防护机制

`TlcErrPacket::decode` (onion.rs:108-145) 的 padding 设计：

```rust
const ERROR_DECODING_PASSES: usize = 27;
// ...
.map(|(error, hop_index)| {
    for _ in hop_index..ERROR_DECODING_PASSES {
        OnionErrorPacket::from_bytes(self.onion_packet.clone())
            .xor_cipher_stream(&NO_SHARED_SECRET);
    }
    error
})
```

注释明确说明："Always decrypting 27 times so the erroring node cannot learn its relative position in the route by performing a timing analysis if the sender were to retry the same route multiple times." → **✓ 防 timing side channel**。前提是 sphinx error packet 路径的 27 - hop_index 次 dummy XOR 实际不被优化掉（`xor_cipher_stream` 必须有副作用；这里 `from_bytes` 返回的临时对象立即丢弃，副作用是借用 `&NO_SHARED_SECRET` 做 XOR 但写入 own bytes 即丢弃 — **编译器可能消除整个 dummy 调用**！需在 release build 上跑 disassembly 验证；归为 F-Info follow-up）。

### 2.5 错误包构造/解构 panic 面

- `TlcErr::serialize` (payment.rs:273-278) — `.expect("TlcErr serialization should not fail for valid TlcErr")`：依赖 `TryFrom<TlcErr> for molecule_fiber::TlcErr` (payment.rs:353-366) 永远 Ok。回看实现：`tlc_err.extra_data.map(|data| data.try_into()).transpose()?` — `try_into` 是 `TryFrom<TlcErrData> for molecule_fiber::TlcErrData` (payment.rs:287-321)，每个分支直接 `.new_builder().*.build()` 并 `Ok(...)`，**当前不可触发**。但属"用 expect 表达不变式"反模式，与 INPUT-002.F4 同质。

- `TlcErrPacket::decode` (onion.rs:124) — `PublicKey::from_slice(&k.0).expect("valid pubkey")`：`hops_public_keys` 由 sender 自己在 `attempt.hops_public_keys()` 中提供，**非 attacker-controlled**。所有 `Pubkey` 类型在构造时已经过 secp256k1 校验。**不可远程触发**，仅在 internal corruption 时崩溃 — 可接受。

## 3. 发现

### 3.1 F1 (🟡 Medium) — Final-hop probing oracle：`InvoiceExpired` / `InvoiceCancelled` 显式回送泄露 invoice 状态

**位置**：`crates/fiber-lib/src/fiber/channel.rs:840-844` (`get_tlc_error`)、`:1156-1170` (`try_to_settle_down_tlc_with_invoice`)、`crates/fiber-types/src/payment.rs:824-825` (`TlcErrorCode::InvoiceExpired = PERM | 16` / `InvoiceCancelled = PERM | 17`)

#### 攻击场景

攻击者 E 想知道某商家 M 的 invoice(payment_hash=X) 是否被取消（这本身是商家的商业秘密 — 例如订单是否被退款）：

1. E 用 `send_payment({payment_hash: X, amount: 1, target_pubkey: M})` 发起一次最小金额探测；
2. M 的 final hop 路径执行 `apply_final_hop_tlc_onion_packet` 找到 invoice(X)，状态为 Cancelled → 走 channel.rs:1471 抛 `FinalInvoiceInvalid(Cancelled)`；
3. `get_tlc_error` 映射为 `TlcErrorCode::InvoiceCancelled` (17, PERM)；
4. sphinx error 包回程到 E；
5. E 解 sphinx → 拿到 `TlcErr.error_code = InvoiceCancelled` → 在 `GetPaymentResult.failed_error = "InvoiceCancelled"` (payment.rs:606) 中读到结论。

类似地：
- 区分 invoice 不存在 vs 存在但过期；
- 区分 invoice 存在但金额错 (`FinalIncorrectTlcAmount`) vs invoice 不存在 (`IncorrectOrUnknownPaymentDetails`)；
- 区分 invoice 存在但 cltv 错 (`FinalIncorrectExpiryDelta`)。

#### 严重性论证

- **远程零成本**：探测 TLC 失败后不扣资金（因为最终未到 commit/settle），仅消耗 fee 预算（也不扣 — 失败 TLC 不收 fee）。
- **零授权**：网络层任何人能 `send_payment` 到任意目标。
- **隐私维度**：泄露的是 **merchant 端订单生命周期** 信息（订单生成/取消/过期）— 商家不一定希望对外公开。聚合多份探测可绘制商家的下单密度时序。
- **BOLT-04 规范偏离**：LN 主网经过多版本演进刻意把这些状态全部折叠为 `incorrect_or_unknown_payment_details`，fiber 应当遵循。
- **可利用边界**：探测者需先知道 payment_hash。`payment_hash` 通常通过 invoice 字符串带外分发，但 (a) 公开发布的 invoice (打赏链接、订单页面)；(b) merchant 之前已支付的 payment_hash 都可被任何曾经的支付者/中转知晓。

**评级**：🟡 **Medium**（隐私类、非资金、规范明确反对、利用门槛低）。

#### 修复建议

把 channel.rs:840-844 的三个分支折叠：

```rust
ProcessingChannelError::FinalInvoiceInvalid(_) => TlcErrorCode::IncorrectOrUnknownPaymentDetails,
ProcessingChannelError::FinalIncorrectHTLCAmount => TlcErrorCode::IncorrectOrUnknownPaymentDetails,
ProcessingChannelError::IncorrectFinalTlcExpiry => TlcErrorCode::IncorrectOrUnknownPaymentDetails,
```

并把 `try_to_settle_down_tlc_with_invoice` 的两个 `InvoiceExpired`/`InvoiceCancelled` 改回 `IncorrectOrUnknownPaymentDetails`。

`InvoiceExpired`/`InvoiceCancelled` 仍可保留为枚举值用于**本机内部错误传递**（例如 RPC `cancel_invoice` 的返回值），但**不应**进入 sphinx error packet 回传给发送方。如要保留区分能力供本机 debug，可在 `last_error` 字符串上保留细分而**只把 wire-level 错误码折叠**（这需要 `TlcErr` 与 `last_error` 解耦）。

但更简单的做法是直接折叠枚举值，与 BOLT-04 对齐。

### 3.2 F2 (🟡 Medium) — 中转 hop graph slander via 未校验 `error_node_id` / `channel_outpoint`

**位置**：`crates/fiber-lib/src/fiber/payment.rs:1099-1116` (`update_graph_with_tlc_fail`)、`graph.rs:1091-1122` (`mark_channel_failed` / `mark_node_failed`)

#### 问题

`update_graph_with_tlc_fail` 接收解 sphinx 后的 `TlcErr`，对 PermanentChannelFailure / ChannelDisabled / UnknownNextPeer / PermanentNodeFailure 直接用 attacker-controlled `extra_data.channel_outpoint` / `extra_data.node_id` 标记本地图，**未校验**这些 ID 属于本次 attempt 的 route：

```rust
TlcErrorCode::PermanentChannelFailure
| TlcErrorCode::ChannelDisabled
| TlcErrorCode::UnknownNextPeer => {
    let channel_outpoint = tlc_error_detail.error_channel_outpoint().expect(...);
    graph.mark_channel_failed(&channel_outpoint);    // 标记任意通道为 disabled
}
TlcErrorCode::PermanentNodeFailure => {
    let node_id = tlc_error_detail.error_node_id().expect(...);
    graph.mark_node_failed(node_id);                 // 标记任意节点的所有通道为 disabled
}
```

`history.rs::record_payment_fail` 在历史评分路径上**有**校验（`error_index = nodes.iter().position(...)`，line 170-180），但 graph 标记已先发生，攻击效果已落地。

#### 攻击影响

- 本地图被污染至下一次 gossip ChannelUpdate 收到为止（`mark_*_failed` 仅改 `info.enabled = false`，下一份带 `enabled=true` 的更新会覆盖 — 但攻击者可重复攻击）；
- 受害节点 V 在本地视图中无法选用 slander 目标 T 作为中转，**直接收入损失**给 T；
- 由于不广播，影响仅限 V，但任何被攻击者中转的节点都会独立中招 — 影响累加；
- 单个攻击 = 1 次失败 attempt，成本 ≈ 0。

**评级**：🟡 **Medium**（隐私非资金，但属于 routing-level griefing，破坏 fiber 网络可用性）。

#### 修复建议

在 `update_graph_with_tlc_fail` 调用 `mark_*_failed` 前校验 `node_id` / `channel_outpoint` 在 `attempt.route` 中（参考 `history.rs:170-180` 的 `error_index` 逻辑）。如果 ID 不在 route 中：

- log warning（可能恶意中转）；
- 不更新本地图；
- 可考虑反向：对该 attempt 的实际中转 hop 计入"恶意中转"评分。

### 3.3 F3 (🟢 Low) — `update_graph_with_tlc_fail` 三个 `.expect(...)` 在攻击者构造非常规 TlcErr 时 panic

**位置**：`crates/fiber-lib/src/fiber/payment.rs:1103-1112`

```rust
TlcErrorCode::PermanentChannelFailure
| TlcErrorCode::ChannelDisabled
| TlcErrorCode::UnknownNextPeer => {
    let channel_outpoint = tlc_error_detail
        .error_channel_outpoint()
        .expect("expect channel outpoint");        // ← PANIC if extra_data 不是 ChannelFailed
    ...
}
TlcErrorCode::PermanentNodeFailure => {
    let node_id = tlc_error_detail.error_node_id().expect("expect node id");  // ← PANIC if extra_data 是 None
    ...
}
```

中转 hop 可发送 `TlcErr { error_code: PermanentChannelFailure, extra_data: None }`（或 `NodeFailed`/`TrampolineFailed` 而非 `ChannelFailed`）。`error_channel_outpoint()` (payment.rs:247-254) 只 match `ChannelFailed`，否则返回 `None` → `.expect` panic。

发送方 panic 影响范围：

- 触发位置在 PaymentActor 的异步路径 → 如果是 `tokio::spawn` 内的 panic，仅杀该 task；
- 但 `update_graph_with_tlc_fail` 通过 `.await` 在 PaymentActor 主消息处理流程中 → panic 传播到 ractor actor 处理函数 → ractor 默认 restart 或 stop actor；
- 取决于 ractor 在该 actor 上的 supervisor 策略，可能导致**单笔 payment 进入卡死/丢失最终状态**（attempt 的 inflight 状态未被更新，需手动 retry 或重启进程）。

**评级**：🟢 **Low**（单笔 payment DoS，攻击者付出 1 次失败转发的成本 / 发送方 panic 不会击垮整个 fiber 进程但破坏 payment actor）。

#### 修复

```rust
TlcErrorCode::PermanentChannelFailure
| TlcErrorCode::ChannelDisabled
| TlcErrorCode::UnknownNextPeer => {
    if let Some(channel_outpoint) = tlc_error_detail.error_channel_outpoint() {
        // 加 F2 修复中的 route-membership 校验
        let mut graph = self.network_graph.write().await;
        graph.mark_channel_failed(&channel_outpoint);
    }
}
TlcErrorCode::PermanentNodeFailure => {
    if let Some(node_id) = tlc_error_detail.error_node_id() {
        let mut graph = self.network_graph.write().await;
        graph.mark_node_failed(node_id);
    }
}
```

### 3.4 F4 (🟢 Low) — `GetPaymentResult.failed_error: Option<String>` 透出错误码字面量加重 F1

**位置**：`crates/fiber-lib/src/fiber/payment.rs:606` (`failed_error: session.last_error.clone()`)、`crates/fiber-lib/src/fiber/payment.rs:1751` (`set_attempt_fail_with_error(..., tlc_error.error_code.as_ref(), ...)`)

`last_error` 在失败时被设为 `error_code.as_ref()`（即 "InvoiceCancelled" / "FinalIncorrectTlcAmount" 等字面量字符串），并通过 RPC `get_payment` 返回给本地调用方。

虽然这是发送方**自己**的本地视图（不是新泄露面），但与 F1 互相加重：即使 F1 修复后 wire-level 错误码被折叠，本地仍可读到细分 — 而这同样不应作为 attacker 拿到的信息（因为 RPC 在某些部署下可能授权给第三方应用使用同一 biscuit token / `parse_invoice` 端点无授权 — 见 AUDIT-AUTH-001）。

**评级**：🟢 **Low**（取决于本地 RPC 授权边界；F1 修复后即不再是问题）。

#### 修复

随 F1 修复时同步：在 sphinx error packet 中携带的 `TlcErr` 折叠后，本地的 `last_error` 字符串自然也会变成 `"IncorrectOrUnknownPaymentDetails"`。无须额外处理。

### 3.5 F5 (🟢 Low) — `TlcErr::serialize` `.expect(...)` 反模式

**位置**：`crates/fiber-types/src/payment.rs:273-278`

```rust
pub fn serialize(&self) -> Vec<u8> {
    molecule_fiber::TlcErr::try_from(self.clone())
        .expect("TlcErr serialization should not fail for valid TlcErr")
        .as_slice().to_vec()
}
```

当前实现 `TryFrom<TlcErr> for molecule_fiber::TlcErr` (payment.rs:353-366) 实际不会失败（每个分支 `Ok(...)`），但 `.expect` 表达不变式的反模式与 INPUT-002.F4 同质。若未来扩展 `TlcErrData` 引入可失败转换，会变成第二个真实 panic 面。

**评级**：🟢 **Low**（防御性 — 当前不可触发）。

#### 修复

```rust
pub fn serialize(&self) -> Vec<u8> {
    // 当前所有 TlcErr 变体都可成功转换；序列化失败仅在内部 bug 时发生。
    // 改用 unreachable!() 显式表达不变式，便于未来扩展时静态发现。
    molecule_fiber::TlcErr::try_from(self.clone())
        .unwrap_or_else(|e| unreachable!("TlcErr → molecule conversion is infallible: {:?}", e))
        .as_slice().to_vec()
}
```

或更稳妥：把 `serialize` 改为返回 `Result<Vec<u8>>`，由调用方处理（但波及调用面较广）。

### 3.6 F6 (ℹ️ Info) — `ERROR_DECODING_PASSES = 27` 的 dummy XOR 在 release build 上是否被优化消除？

**位置**：`crates/fiber-types/src/onion.rs:138-143`

```rust
.map(|(error, hop_index)| {
    for _ in hop_index..ERROR_DECODING_PASSES {
        OnionErrorPacket::from_bytes(self.onion_packet.clone())
            .xor_cipher_stream(&NO_SHARED_SECRET);  // ← 返回值丢弃
    }
    error
})
```

`OnionErrorPacket::from_bytes(self.onion_packet.clone()).xor_cipher_stream(&NO_SHARED_SECRET)` 创建临时对象、对其字节做 XOR，然后丢弃。LLVM 可识别"没有副作用的纯计算"并消除整个循环 → 27 轮 dummy 退化为 0 轮 → **timing side channel 防护失效**。

`xor_cipher_stream` 内部可能调用 `chacha20` 或 `sha256` 之类的密码学例程，这些通常被 `#[inline(never)]` 或者通过 black_box 防优化 — 但 fiber-sphinx 2.3 上游是否如此需在 release build 上反汇编验证。

**评级**：ℹ️ **Info**（取决于 fiber-sphinx 上游实现 + 编译优化路径，需动态验证）。

#### 验证步骤

```bash
cargo build --release -p fiber-lib --no-default-features
objdump -d target/release/.../fiber_lib*.rlib | grep -A 30 'TlcErrPacket.*decode'
# 检查 dummy 循环是否仍存在
```

如已优化掉，需用 `std::hint::black_box(...)` 包裹 dummy XOR 返回值，或使用 `subtle::ConstantTimeEq`。

### 3.7 F7 (✅ Pass) — Sphinx error packet 加密 + HMAC 保护

`TlcErrPacket::new` → `OnionErrorPacket::create(shared_secret, payload)` 使用 LN 风格的 sphinx error encryption（HMAC + 流密码）。中转 hop 仅做 XOR (`backward()`) 转发，无法读出明文。发送方使用 `attempt.session_key` 和路由的 `hops_public_keys` 反向解 sphinx → 仅发送方可读 ✓。

### 3.8 F8 (✅ Pass) — `record_payment_fail` 历史评分路径上有 route-membership 校验

`history.rs:170-180` 在 history 评分前先用 `nodes.iter().position(|s| Some(s.pubkey) == tlc_err.error_node_id())` 校验 `error_node_id` 在 route 中，否则直接返回 — 这是正确的 slander 防护。**问题是同样的校验未在 graph 标记路径上做（见 F2）**。

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — Final-hop 错误码细分 (`InvoiceExpired`/`InvoiceCancelled`/`FinalIncorrectTlcAmount`/`FinalIncorrectExpiryDelta`) 导致 payment probing | 🟡 Medium | ❌ 未修复 |
| F2 — `update_graph_with_tlc_fail` 未校验 `node_id`/`channel_outpoint` 属于本次 route → 中转 hop graph slander | 🟡 Medium | ❌ 未修复 |
| F3 — `update_graph_with_tlc_fail` 三处 `.expect(...)` 在攻击者构造 `extra_data` 缺失时 panic → PaymentActor DoS | 🟢 Low | ❌ 未修复 |
| F4 — `GetPaymentResult.failed_error` 透出错误码字面量加重 F1 | 🟢 Low | ❌ 未修复（随 F1 自动消解） |
| F5 — `TlcErr::serialize` `.expect(...)` 反模式 | 🟢 Low | ❌ 未修复 |
| F6 — `ERROR_DECODING_PASSES=27` dummy XOR 在 release 上是否被优化消除 | ℹ️ Info | ⚠️ 待动态验证 |
| F7 — Sphinx error encryption 完备 | ✅ Pass | — |
| F8 — `record_payment_fail` 评分路径有 route-membership 校验 | ✅ Pass | — |
| 整体 | 🟡 **Medium** | ❌ |

### 总体评价

错误处理框架结构良好（BOLT-04 风格的位掩码语义、sphinx encryption、constant-time padding 设计、history slander 防护），但存在两个**规范/对称性**层面的差距：

1. **隐私维度** (F1)：fiber 引入了 BOLT-04 之外的 `InvoiceExpired`/`InvoiceCancelled` 终态码，并保留了 `FinalIncorrect{TlcAmount,ExpiryDelta}` 细分，构成 payment probing oracle。修复一致性：把 final-hop 所有失败原因折叠为 `IncorrectOrUnknownPaymentDetails`，与 LN 主网对齐。
2. **可用性维度** (F2/F3)：`update_graph_with_tlc_fail` 路径上信任 attacker-controlled `extra_data` 进行本地图标记 + 三处 panic 面。`history.rs::record_payment_fail` 已有正确的校验模板，**直接复用**到 graph 路径即可。

这些都不是直接资金损失类发现，但 F1 + F2 在长期使用中可构成 **fiber 网络可用性 + 商业隐私** 双重退化。修复成本极低（<50 行 Rust），是性价比很高的稳定性改进。

## 5. Follow-ups

- **AUDIT-ERR-001-FOLLOWUP-A (🟡 Medium, 必修)**: F1 — 把 `channel.rs:get_tlc_error` 中 `FinalInvoiceInvalid`/`FinalIncorrectHTLCAmount`/`IncorrectFinalTlcExpiry` 三个分支统一映射到 `TlcErrorCode::IncorrectOrUnknownPaymentDetails`；把 `try_to_settle_down_tlc_with_invoice` 中 `InvoiceExpired`/`InvoiceCancelled` 改为 `IncorrectOrUnknownPaymentDetails`。新增测试：发送方收到的 error_code 不区分 invoice 状态。
- **AUDIT-ERR-001-FOLLOWUP-B (🟡 Medium, 必修)**: F2/F3 — 在 `payment.rs::update_graph_with_tlc_fail` 中加 route-membership 校验（复用 `history.rs:170-180` 的 `error_index` 模板），同时把三处 `.expect(...)` 改为 `if let Some(...) = ...` 防御式匹配。
- **AUDIT-ERR-001-FOLLOWUP-C (🟢 Low)**: F5 — `TlcErr::serialize` 把 `.expect()` 改为 `unwrap_or_else(|_| unreachable!())` 或返回 `Result<Vec<u8>>`。
- **AUDIT-ERR-001-FOLLOWUP-D (ℹ️ Info, 测试/验证)**: F6 — 在 release build 上反汇编验证 `ERROR_DECODING_PASSES=27` dummy XOR 没被优化消除。如已消除，用 `std::hint::black_box(...)` 包裹返回值或换 `subtle::ConstantTimeEq` 风格。
- **AUDIT-ERR-001-FOLLOWUP-E (🟢 Low, 测试)**: 新增 `tests/fiber/payment.rs` 集成测试覆盖 slander 攻击 PoC：模拟中转 hop 返回 `PermanentChannelFailure { channel_outpoint: random }`，断言本地图未被错误标记。

**关联**：
- F1 与 AUDIT-LOGIC-008 (CCH 资金损失) 间接相关 — `InvoiceCancelled` 泄露能帮助攻击者识别 CCH 的内部状态；
- F2/F3 与 AUDIT-MEM-001 (gossip OOM) 形成镜像 — 都是"信任对端输入做本地图改动"，前者标 `enabled=false`、后者放入 `messages_to_be_saved`。
- F5 与 AUDIT-INPUT-002.F4 同质（`.expect` 表达不变式的反模式），可一并整改。
