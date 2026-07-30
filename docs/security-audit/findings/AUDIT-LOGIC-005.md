# AUDIT-LOGIC-005 — MPP / Trampoline 拆分一致性

- **维度**: DIM-LOGIC（业务逻辑 / 状态机）
- **严重级别**: 🟡 Medium（Medium × 1 + Low × 2 + Info × 2; 多项加固建议）
- **审计 Session**: S5 (2026-05-13)
- **关联代码**:
  - `crates/fiber-lib/src/fiber/settle_tlc_set_command.rs` (整文件 354 行)
  - `crates/fiber-lib/src/fiber/channel.rs:1148-1229` (`try_to_settle_down_tlc_with_invoice`)
  - `crates/fiber-lib/src/fiber/channel.rs:1425-1564` (`apply_final_hop_tlc_onion_packet` 含 MPP 校验)
  - `crates/fiber-lib/src/fiber/network.rs:3042-3157` (`forward_trampoline_packet`)
  - `crates/fiber-lib/src/fiber/types.rs:1700-1815` (`TrampolineHopPayload`)
  - `crates/fiber-lib/src/fiber/types.rs:2058-2080` (`peeled_packet_mpp_custom_records`)
  - `crates/fiber-lib/src/fiber/payment.rs:485-495` (`BasicMppPaymentData` 写入路径)
  - `crates/fiber-lib/src/utils/payment.rs` (`is_invoice_fulfilled`)
  - `crates/fiber-lib/src/fiber/tests/mpp.rs` (覆盖)

## 1. 审计目标

验证 MPP（多路径支付）和 Trampoline 路由的支付拆分与聚合一致性：

- MPP 各 shard 的 `total_amount` / `payment_secret` 必须一致才能 fulfill；
- 单 shard 无法假冒 MPP 完成支付（`total_amount > amount` 时必须等待其他 shard）；
- 攻击者无法通过混合 shard（如不同 invoice 的 shard 拼凑）触发非预期 fulfill；
- 过度支付 / 欠付的处理；
- Trampoline 转发的 fee 严格匹配 + 路径分离正确传递（`remaining_trampoline_onion`）；
- Hold invoice 的 hold_expire_at 计算正确，不会被恶意延迟。

## 2. 关键代码路径

### 2.1 MPP fulfill 决策

```
inbound AddTlc (final hop, has invoice, MPP records)
    ↓ apply_final_hop_tlc_onion_packet (channel.rs:1425)
    │   ├─ if total_amount < invoice.amount → FinalIncorrectMPPInfo
    │   ├─ if payment_secret mismatch (when invoice.payment_secret.is_some())
    │   │     → FinalIncorrectMPPInfo
    │   └─ tlc.payment_secret = Some(record.payment_secret)
    │       tlc.total_amount  = Some(record.total_amount)
    │
    ↓ try_to_settle_down_tlc_with_invoice (channel.rs:1148)
    │   ├─ if !is_mpp && !is_invoice_fulfilled(once(tlc)) → FinalIncorrectTlcAmount
    │   └─ else: pending_notify_settle_tlcs.push(...)
    │
    ↓ [NetworkActor periodic] SettleTlcSetCommand::run (settle_tlc_set_command.rs:110)
        ├─ verify():
        │   ├─ invoice status (Open/Received...)
        │   └─ verify_mpp_tlcs_have_consistent_total_amount() :
        │         len > 1 && all (w[0].total_amount == w[1].total_amount)
        ├─ leave_just_fulfilled_tlcs():
        │   ├─ MPP branch: leave_just_fulfilled_tlcs_for_mpp_invoice()
        │   │     ├─ total := first_tlc.total_amount_or_amount()
        │   │     ├─ if total < invoice.amount → reject_all(IncorrectOrUnknownPaymentDetails)
        │   │     ├─ greedy: accumulate until >= total, retain those
        │   │     └─ if accumulated < total → clear + return (wait for more)
        │   │     └─ else reject overpaid TLCs (HoldTlcTimeout)
        │   └─ non-MPP branch: pick single TLC with amount >= invoice.amount
        └─ try_settle_all(): fulfill with preimage from store
```

### 2.2 Trampoline 转发

```
final hop of OUTER onion = trampoline node
    ↓ apply_add_tlc_operation_with_peeled_onion_packet (channel.rs:1342-1380)
    │     is_trampoline := peeled.trampoline_onion().is_some()
    │     if is_last && is_trampoline:
    │         peel INNER trampoline onion via state.private_key
    │         last_hop_inner_onion := Some(peeled_trampoline.current)
    │     [if Final → continue settle as final]
    │     [if Forward → registered for outer-onion forwarding via network.rs:3042]
    ↓ network actor: forward_trampoline_packet (network.rs:3042)
        ├─ require state.features.supports_trampoline_routing
        ├─ peel inner trampoline onion (second peel, different from outer)
        ├─ Forward branch:
        │     ├─ incoming_amount > amount_to_forward      (FeeInsufficient)
        │     ├─ STRICT: available_fee == build_max_fee   (InvalidOnionPayload)
        │     ├─ build SendPaymentData with TrampolineContext { remaining_trampoline_onion }
        │     └─ start_payment_actor (start a fresh payment from this trampoline node)
        └─ Final branch → unreachable (handled in channel actor)
```

## 3. 不变式表

| ID | 不变式 | 实现位置 | 状态 |
|---|---|---|---|
| INV-1 | Final hop MPP: `total_amount >= invoice.amount` | `channel.rs:1488` | ✅ |
| INV-2 | Final hop MPP: `payment_secret == invoice.payment_secret`（当 invoice 有 secret） | `channel.rs:1498-1507` | ✅ |
| INV-3 | Final hop non-MPP/no-record + invoice: `is_invoice_fulfilled(once(tlc))` | `channel.rs:1522-1525` | ✅ |
| INV-4 | MPP+无 invoice: 拒绝 (`FinalIncorrectMPPInfo("invoice not found")`) | `channel.rs:1527-1532` | ✅ |
| INV-5 | SettleTlcSet: 所有 shard 的 `total_amount` 必须相等（len>1） | `settle_tlc_set_command.rs:250-265` | ✅ |
| INV-6 | SettleTlcSet: invoice.amount > total_amount 时拒绝 | `settle_tlc_set_command.rs:165-166` | ✅ |
| INV-7 | SettleTlcSet: 累加金额 < total 时 clear (wait for more shards)，不释放 preimage | `settle_tlc_set_command.rs:179-182` | ✅ |
| INV-8 | SettleTlcSet: invoice 状态不在 Open/Received 时拒绝 | `settle_tlc_set_command.rs:222-247` | ✅ |
| INV-9 | Trampoline forwarding: 严格 fee 等式（防上下游捞钱）| `network.rs:3092-3102` | ✅ |
| INV-10 | Trampoline forwarding: 需 `supports_trampoline_routing` feature | `network.rs:3050-3058` | ✅ |
| INV-11 | Trampoline forwarding: 内层 onion 用 `state.private_key` peel | `channel.rs:1366-1372`, `network.rs:3067-3071` | ✅ |
| INV-12 | Trampoline forwarding: `remaining_trampoline_onion` 仅来自 `peeled.next` | `network.rs:3104-3111` | ✅ |
| INV-13 | Trampoline forwarding: payment_hash 复用同一值（pin 内外 onion 关联） | `network.rs:3068, 3114` | ✅ |
| INV-14 | Hold TLC: `hold_expire_at` ≤ `tlc.expiry`（不允许 hold 超过 TLC 自身 expiry） | `channel.rs:1204-1213` | ✅ |

## 4. 发现

### 4.1 F1 (🟡 Medium) — `leave_just_fulfilled_tlcs_for_mpp_invoice` 接受超额 `total_amount` 与多倍支付

**位置**：`settle_tlc_set_command.rs:156-187`

```rust
fn leave_just_fulfilled_tlcs_for_mpp_invoice(&mut self, invoice: &CkbInvoice) -> Vec<TlcSettlement> {
    let total_amount = first_tlc.total_amount_or_amount();
    if total_amount < invoice.amount.unwrap_or_default() {
        return self.reject_all(IncorrectOrUnknownPaymentDetails);
    }
    let mut accumulated_amount = 0;
    let mut retain_len: usize = 0;
    for tlc in self.tlcs.iter() {
        if accumulated_amount < total_amount {
            accumulated_amount = accumulated_amount.saturating_add(tlc.amount);
            retain_len += 1;
        }
    }
    if accumulated_amount < total_amount {
        self.tlcs.clear();
        Vec::new()
    } else {
        let overpaid_tlcs = self.tlcs.split_off(retain_len);
        self.reject_tlcs(overpaid_tlcs, HoldTlcTimeout)   // ← 错误码语义
    }
}
```

**问题 A — 无 total_amount 上界，接受任意倍超付**：

`total_amount` 完全由 sender（通过 onion 内层 MPP 记录）控制。
- `total_amount >= invoice.amount` 是唯一上界检查（line 165）。
- Sender 可以 claim `total_amount = invoice.amount * 1000`，提供 `tlcs = 1000 个 invoice.amount` 的 shard；本节点会全数 fulfill，发起 1000 倍超付。
- 发起方拿回 invoice 价值的服务/商品，但本节点（接收方）确实收到了 1000x 的资金 ✓。但发起方可借此**消耗对方流动性**或**伪造充值记录**（应用层风险）。
- 反之，sender 也可 claim `total_amount = invoice.amount`，提供 `tlcs = 1 个 amount = invoice.amount * 1000` 的 shard：
  - 单 shard 走 `apply_final_hop_tlc_onion_packet:1460` "forward_amount != add_tlc.amount" 检查？这里 `forward_amount = peeled.amount` 是 sender 控制的，sender 可以填 `peeled.amount = add_tlc.amount = invoice.amount * 1000`，绕过。
  - 进 settle 路径：`total_amount = invoice.amount`，accumulated = invoice.amount * 1000 >= total ⇒ fulfill。完成 1000 倍超付。

**问题 B — overpaid TLC 错误码错位**：

`reject_tlcs(overpaid_tlcs, HoldTlcTimeout)` —— 把"我们收到了超过 total 的多余 shard"标记为 hold timeout。对发起方来说该 shard 失败，看起来是网络错误而非"接收方主动拒绝多余"。建议改为 `IncorrectOrUnknownPaymentDetails` 或新增专门错误码。

**严重级别**：🟡 Medium —— 资金安全无损（本节点是受益方），但：
- 对手可以借此进行**资金注水攻击**：把对方的真实流动性消耗（每个 shard 都占 max_tlc_number_in_flight slot），同时给受害者账本灌入大量"已收到但不期望"的资金，触发上层应用（充值、对账）异常。
- 错误码不准确影响 sender 的失败诊断。

**建议**：

```rust
- if total_amount < invoice.amount.unwrap_or_default() {
+ let invoice_amount = invoice.amount.unwrap_or_default();
+ if total_amount < invoice_amount {
      return self.reject_all(IncorrectOrUnknownPaymentDetails);
  }
+ // Prevent absurd overpayment that may cause accounting issues at the application layer.
+ if total_amount > invoice_amount.saturating_mul(2) {
+     return self.reject_all(IncorrectOrUnknownPaymentDetails);
+ }
```

阈值 `2x` 可配置（如 `accept_overpay_factor`）。或者更严：`total_amount == invoice.amount` 强制等式（与 LN BOLT-4 推荐一致）。

### 4.2 F2 (🟢 Low) — `verify_mpp_tlcs_have_consistent_total_amount` 在 `len == 1` 时不校验

**位置**：`settle_tlc_set_command.rs:250-265`

```rust
if invoice.allow_mpp()
    && self.tlcs.len() > 1
    && !self.tlcs.windows(2).all(|w| w[0].total_amount == w[1].total_amount)
{
    return Err(IncorrectOrUnknownPaymentDetails);
}
```

`len() > 1` 跳过单 TLC 情况。单 TLC 的 `total_amount` 字段未校验。结合 F1 的 `total_amount_or_amount()` 行为：
- 若单 TLC 且 `tlc.total_amount = Some(x)`，则 `total = x`，可能 `x > tlc.amount`：进 line 179 `accumulated < total` 分支，clear + wait。**正确行为**（等待更多 shard）。
- 若单 TLC 且 `tlc.total_amount = None`，则 `total = tlc.amount`，line 180 `accumulated == total` ⇒ settle。**正确**。

所以 `len == 1` 跳过校验不会导致错误 fulfill。**Pass**，但建议显式注释为何 len==1 安全跳过。

### 4.3 F3 (🟢 Low) — `apply_final_hop_tlc_onion_packet` 对 invoice + 无 MPP 记录的 MPP 行为未明确

**位置**：`channel.rs:1512-1525`

```rust
(Some(invoice), None) => {
    if invoice.allow_mpp() {
        // FIXME: whether we allow MPP without MPP records in onion packet?
        // currently we allow it pay with enough amount
        // TODO: add a unit test of using single path payment pay MPP invoice successfully
        warn!("invoice allows MPP but no MPP records in onion packet: {:?}", payment_hash);
    }
    if !is_invoice_fulfilled(invoice, std::iter::once(&*tlc)) {
        return Err(FinalIncorrectHTLCAmount);
    }
}
```

代码自带 FIXME / TODO。当前行为：MPP-enabled invoice + 单 TLC + 无 MPP 记录 ⇒ 走 single-path fulfill。`is_invoice_fulfilled` 要求 `tlc.amount >= invoice.amount`，没问题。

**风险**：未来如果应用依赖"MPP invoice 一定通过 MPP 路径"做策略（如 strict-MPP），此处会绕过。**当前安全**，但 FIXME 长期未解决是技术债。

**建议**：将 FIXME 解决：要么按 LN BOLT-4 严格要求 MPP invoice 必须带 MPP 记录（即使单 TLC），要么明确允许并加测试。

### 4.4 F4 (🟢 Low) — `verify_mpp_tlcs_have_consistent_total_amount` 不校验 `payment_secret` 一致性

**位置**：`settle_tlc_set_command.rs:250-265`

只校验 `total_amount`，未校验各 shard 的 `payment_secret`。

实际上，`apply_final_hop_tlc_onion_packet:1499-1507` 已对**每个 shard**单独校验 `record.payment_secret == invoice.payment_secret`（当 invoice 有 secret 时）。所以每个 shard 的 payment_secret 都已等于 invoice.payment_secret，传递一致性自动成立。**Pass**。

但若未来 invoice 的 `payment_secret` 可选（`is_some_and` 中 None 时跳过校验），多 shard 可能各自带不同的 record.payment_secret 通过个体校验后聚合，这会绕过 MPP-secret 防御。**建议**在 `verify_mpp_tlcs_have_consistent_total_amount` 中额外断言 `w[0].payment_secret == w[1].payment_secret`，为未来防御。

### 4.5 F5 (🟢 Low) — Hold invoice expire_at 计算的 saturating 边界

**位置**：`channel.rs:1204-1213`

```rust
Some(match invoice.expiry_time() {
    Some(invoice_expiry) => u64::try_from(
        invoice_expiry.as_millis()
            .saturating_add(invoice.data.timestamp)
            .min(tlc.expiry.into()),
    ).unwrap_or(u64::MAX),
    None => tlc.expiry,
})
```

- `invoice_expiry.as_millis()` 返回 `u128`；`invoice.data.timestamp` 是 `u64`；
- `.saturating_add` 在 u128 域，饱和到 `u128::MAX`；
- `.min(tlc.expiry.into())` 在 u128；
- `u64::try_from(...)` 在 u128 > u64::MAX 时返回 Err → `unwrap_or(u64::MAX)`。

**正确性**：`.min(tlc.expiry)` 上界保护，最终值不会超 `tlc.expiry` ≤ u64::MAX，所以 try_from 实际不会失败。但代码逻辑健壮。**Pass**。

**风险**：`tlc.expiry` 来自 inbound TLC，**peer 完全控制**（结合 LOGIC-002.F1 inbound 不校验 expiry）。peer 可设 `tlc.expiry = u64::MAX`，导致 `hold_expire_at = invoice_timestamp + invoice_expiry`（合理）。在 LOGIC-002.F1 修复前，本路径继承同样的"超长 expiry 锁定资源"问题。

### 4.6 F6 (ℹ️ Info / Pass) — Trampoline 内层 onion 复用外层 `payment_hash` 做 tweak

**位置**：`channel.rs:1367, network.rs:3068`

内层 `TrampolineOnionPacket.peel(state.private_key, Some(payment_hash.as_ref()), SECP256K1)` 使用与外层相同的 `payment_hash` 作为 HMAC tweak。这绑定了内外 onion，防止"用一份外层 onion 替换另一份内层 onion"的拼接攻击。**Pass**。

### 4.7 F7 (ℹ️ Info / Pass) — Trampoline 转发起新支付，复用 sender's `payment_hash`

**位置**：`network.rs:3113-3134`

`SendPaymentDataBuilder::new(next_node_id, amount_to_forward, payment_hash)` 用相同的 `payment_hash`，意味着本 trampoline 节点对下游发起的新支付与 sender 的原支付**共享同一个 preimage**。下游 fulfill 时返回的 preimage 同样可用来 fulfill 上游 inbound TLC。**Pass**（这是 trampoline 协议的核心机制）。

但要注意：trampoline 节点变成了"代付者"，**承担**整段下游路径的失败风险（自己付钱却拿不到 preimage 的话，无法 fulfill 上游）。`build_max_fee_amount` 是 sender 给的预算，超出预算即转发失败。这是经济风险但不是安全风险。

## 5. 结论

| 子项 | 严重级别 | 状态 |
|---|---|---|
| F1 — MPP 接受任意倍超付 + 错误码语义错位 | 🟡 Medium | ⚠️ 未修复 |
| F2 — `verify_mpp_consistent_total` 跳过 len==1 | 🟢 Low (verified safe) | — |
| F3 — MPP invoice + 单 TLC 无 MPP record（FIXME）| 🟢 Low (tech debt) | ⚠️ 未修复 |
| F4 — `verify_mpp_consistent` 未显式校验 `payment_secret` | 🟢 Low (defense-in-depth) | ⚠️ 未修复 |
| F5 — Hold expire_at 继承 LOGIC-002.F1 inbound expiry 问题 | 🟢 Low (依赖 LOGIC-002 修复) | ⚠️ 未修复 |
| F6 — Trampoline 内层 onion tweak | ℹ️ Info / Pass | — |
| F7 — Trampoline 共享 preimage 设计 | ℹ️ Info / Pass | — |
| 整体严重 | 🟡 Medium | — |

## 6. Follow-ups

- **AUDIT-LOGIC-005-FOLLOWUP-A**：MPP 超付 PoC — 构造 `total_amount = invoice.amount * 100` + 100 shards × invoice.amount，验证本节点 fulfill 全部并触发资金注水。
- **AUDIT-LOGIC-005-FOLLOWUP-B**：在 `leave_just_fulfilled_tlcs_for_mpp_invoice` 中加 `total_amount <= invoice.amount * accept_overpay_factor` 限额；同时把 overpaid 错误码改为 `IncorrectOrUnknownPaymentDetails`。
- **AUDIT-LOGIC-005-FOLLOWUP-C**：解决 `apply_final_hop_tlc_onion_packet:1513` 的 FIXME — 决定 MPP invoice 是否强制要求 MPP record，并加测试。
- **AUDIT-LOGIC-005-FOLLOWUP-D**：在 `verify_mpp_tlcs_have_consistent_total_amount` 中加 `payment_secret` 一致性断言。
- **AUDIT-LOGIC-005-FOLLOWUP-E**：审计 trampoline 节点选路 (`fiber/graph.rs:1451`)，验证 trampoline 的 `build_max_fee_amount` 是否被严格约束在 sender 的总预算内。
