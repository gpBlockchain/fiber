# AUDIT-LOGIC-004 — 多跳支付转发金额 / 费用一致性

- **维度**: DIM-LOGIC（业务逻辑 / 状态机）
- **严重级别**: 🟡 Medium（Low × 3 + Info × 1; 整体 Pass + 多项加固建议）
- **审计 Session**: S5 (2026-05-13)
- **关联代码**:
  - `crates/fiber-lib/src/fiber/channel.rs:1382-1421` (`apply_add_tlc_operation_with_peeled_onion_packet` — forwarding hop fee 计算)
  - `crates/fiber-lib/src/fiber/channel.rs:1882-1929` (`handle_add_tlc_command` — 出站 fee 校验)
  - `crates/fiber-lib/src/fiber/channel.rs:2185-2222` (`register_and_apply_forward_tlc`)
  - `crates/fiber-lib/src/fiber/channel.rs:6252-6284` (`check_tlc_forward_amount`)
  - `crates/fiber-lib/src/fiber/fee.rs:115-142` (`calculate_fee_with_base` / `calculate_tlc_forward_fee`)
  - `crates/fiber-lib/src/fiber/network.rs:3042-3157` (`forward_trampoline_packet`)
  - `crates/fiber-lib/src/utils/payment.rs:15-41` (`is_invoice_fulfilled`)
  - `crates/fiber-lib/src/fiber/channel.rs:1148-1277` (`try_to_settle_down_tlc*`)

## 1. 审计目标

验证多跳支付（非 trampoline）转发链路上的金额与费用一致性不变式：

- 入站 TLC `amount` 与 onion 内层 `peeled.amount` 关系是否被正确校验（不允许下游获得"凭空生成"的资金）；
- 转发 fee = `received - forward` 与 outgoing 通道广告的 `tlc_fee_proportional_millionths` 之间的关系；
- 费用计算（`amount × ppm / 1_000_000`）的溢出与舍入边界；
- 终点节点对 `add_tlc.amount` 与 onion 内层 `peeled.amount` 与 invoice.amount 之间的关系；
- 攻击者能否通过：
  - (a) 构造 onion `forward_amount > received_amount` 让下游被"白拿"；
  - (b) 构造 onion `forward_amount < received_amount - fee` 偷换费用；
  - (c) `forward_amount = 0` / `forward_amount` 极小，让中间节点白工作；
  - (d) `amount × ppm` 溢出 `u128`。

## 2. 数据流与不变式

### 2.1 转发 (forwarding hop) 完整流程

```
Peer → AddTlc { amount: received_amount, expiry, onion_packet, ... }
    ↓ handle_add_tlc_peer_message (channel.rs:1575)
    │  ※ INV-LOGIC-002.F1: 此处缺 check_tlc_expiry（已在 LOGIC-002 记录）
    ↓ apply_add_tlc_operation (channel.rs:1279)
    ↓ peel onion → peeled.amount, peeled.expiry
    ↓ apply_add_tlc_operation_with_peeled_onion_packet (channel.rs:1333)
        │
        ├─ [final hop]   → apply_final_hop_tlc_onion_packet
        │     ├─ require add_tlc.amount == peeled.amount               (line 1460)
        │     └─ if invoice + MPP: check total_amount + payment_secret
        │
        └─ [forwarding hop]
              ├─ INV-EXP: add_tlc.expiry >= peeled.expiry + tlc_expiry_delta  (line 1391)
              ├─ INV-AMT: received_amount >= forward_amount                  (line 1403-1406)
              ├─ forward_fee := received_amount.saturating_sub(forward_amount)  (line 1410)
              └─ register_and_apply_forward_tlc(forward_fee)                   (line 1414)
                    ↓ SendPaymentOnionPacket { previous_tlc: { forwarding_fee }
                    ↓ NetworkActor 路由到出站通道
                    ↓ handle_add_tlc_command (channel.rs:1882)
                        ├─ check_tlc_expiry(command.expiry)
                        ├─ check_tlc_forward_amount(forward_amount, Some(forwarding_fee))  (line 1892)
                        │     ├─ forward_amount >= local.tlc_minimum_value
                        │     ├─ expected_fee := calculate_tlc_forward_fee(forward_amount, local.fee_rate)
                        │     │       = ceil(forward_amount * fee_rate / 1_000_000)
                        │     └─ forwarding_fee >= expected_fee else TlcForwardFeeIsTooLow  (line 6271-6277)
                        └─ AddTlc to next peer
```

### 2.2 关键不变式

| ID | 不变式 | 实现位置 | 状态 |
|---|---|---|---|
| INV-1 | Forwarding hop: `add_tlc.amount >= peeled.amount`（防资金凭空生成） | `channel.rs:1403-1406` | ✅ |
| INV-2 | Forwarding hop: `forward_fee = received - forward`（saturating_sub 防 underflow，但被 INV-1 排除） | `channel.rs:1410` | ✅ |
| INV-3 | Forwarding hop: 出站 `forwarding_fee >= ceil(forward_amount × out_channel.fee_rate / 1e6)` | `channel.rs:6271`（出站 channel `check_tlc_forward_amount`） | ✅ |
| INV-4 | Forwarding hop: 出站 `forward_amount >= out_channel.tlc_minimum_value` | `channel.rs:6257-6260` | ✅ |
| INV-5 | Final hop: `add_tlc.amount == peeled.amount`（既不允许超付也不允许少付） | `channel.rs:1460-1462` | ✅ |
| INV-6 | Final hop（invoice）：`add_tlc.amount >= invoice.amount`（通过 `is_invoice_fulfilled`） | `channel.rs:1522-1525` | ✅ |
| INV-7 | Fee 计算：`amount × ppm` 用 `checked_mul`，溢出明确报错 | `fee.rs:120-127` | ✅ |
| INV-8 | Fee 计算：余数非零向上取整（防 sender 通过 1 wei 舍入差白嫖） | `fee.rs:128-134` | ✅ |
| INV-9 | Trampoline forwarding: `available_fee == build_max_fee_amount`（**严格等式**） | `network.rs:3092-3102` | ✅ |
| INV-10 | Trampoline forwarding: `incoming_amount > amount_to_forward` | `network.rs:3082-3091` | ✅ |
| INV-11 | `try_to_settle_down_tlc` 只在 `should_settle == true`（onion last hop）触发，防"看到熟悉 preimage 就 fulfill" | `channel.rs:1325-1328, 1422` | ✅ |
| INV-12 | `try_to_settle_down_tlc_without_invoice` 守卫 `is_waiting_forward_result_for_received_tlc`，防全局已知 preimage 抢付 | `channel.rs:1239-1241` | ✅ |

## 3. 发现

### 3.1 F1 (🟡 Medium) — `apply_add_tlc_operation_with_peeled_onion_packet` 缺 `forward_amount > 0` / 最小可表达单元检查

**位置**：`channel.rs:1390-1421`

转发 hop 流程：

```rust
} else {
    if add_tlc.expiry < peeled.expiry + state.local_tlc_info.tlc_expiry_delta && !is_trampoline {
        return Err(IncorrectTlcExpiry);
    }
    let received_amount = add_tlc.amount;
    if received_amount < forward_amount {
        return Err(InvalidParameter("received_amount is less than forward_amount"));
    }
    let forward_fee = received_amount.saturating_sub(forward_amount);
    self.register_and_apply_forward_tlc(state, add_tlc.payment_hash, add_tlc.tlc_id,
                                         peeled_onion_packet, forward_fee);
}
```

**问题 1**: `forward_amount == 0` 未被拒绝。

- onion 内层 `peeled.amount = 0`：本地认为合法（`received >= 0` 永真），fee = `received - 0 = received`，调用 `register_and_apply_forward_tlc`。
- 下游通道 `check_tlc_forward_amount(0, Some(received))`：
  - `forward_amount(=0) < tlc_minimum_value` 若 `tlc_minimum_value > 0` → 拒。
  - 但 **`tlc_minimum_value` 默认为 0**（`TlcInfo` 默认 / 通道开启时未必设置）。
  - `calculate_tlc_forward_fee(0, fee_rate) = 0`，`forwarding_fee = received >= 0` ⇒ 通过。
  - 下游 `AddTlc { amount: 0, ... }` 发出。

**后果**：攻击者作为发起方可让中间节点为 `amount=0` 的 TLC 占用 commitment slot（`max_tlc_number_in_flight` 默认 125），扣占资源直到 TLC 失败/过期。fee=full received_amount 进入本节点账户，但下游收到 `amount=0` 的 TLC 后回 RemoveTlcFail（FinalIncorrectHTLCAmount 之类），上游回滚，本节点退还 received_amount。**净效果**：本节点没赚到钱，但**占用了一次 TLC slot + 一轮 commitment_signed/revoke_and_ack 网络往返**。

**问题 2**: `received_amount < forward_amount` 用 strict less-than 但 fee 用 saturating_sub。当 `received_amount == forward_amount` 时 fee = 0。如果出站通道 `fee_rate > 0`，下游会拒（`TlcForwardFeeIsTooLow`），但前者已经发出。可优化为提前拒绝 `received_amount <= forward_amount * (1 + fee_rate / 1e6)` 以省一轮通信。

**严重级别**：🟡 Medium — 资源占用攻击。配合 `max_tlc_number_in_flight` = 125，攻击者可以稳定占满每个被路由通道的 TLC slot，导致**真实支付被压垮**（HTLC slot exhaustion）。LN 上有相似的"channel jamming"攻击讨论，Fiber 应至少加 minimum-amount 闸门。

**建议**：

```rust
} else {
    if add_tlc.expiry < peeled.expiry + state.local_tlc_info.tlc_expiry_delta && !is_trampoline {
        return Err(IncorrectTlcExpiry);
    }
    let received_amount = add_tlc.amount;
+   if forward_amount == 0 {
+       return Err(ProcessingChannelError::InvalidParameter(
+           "forward_amount must be greater than 0".to_string()));
+   }
    if received_amount < forward_amount {
        return Err(InvalidParameter("received_amount is less than forward_amount"));
    }
    ...
}
```

或更严：根据出站通道的 `tlc_minimum_value` 检查 forward_amount。

### 3.2 F2 (🟢 Low) — `check_tlc_forward_amount` fee 校验只看出站通道，无入站对称校验

**位置**：`channel.rs:6252-6284`, 调用点 `channel.rs:1892`

`check_tlc_forward_amount` 在**出站** `handle_add_tlc_command` 中调用，使用**出站通道**的 `tlc_fee_proportional_millionths`。这正确实现了"forwarding fee 由出站通道收取"的 LN 约定。

**潜在问题**：转发 fee 在**入站**节点（即本节点路由进入侧的对端）的视角，是由其支付的；该入站通道的 `tlc_fee_proportional_millionths` 可能与出站不同。当前实现：

1. 入站 `apply_add_tlc_operation_with_peeled_onion_packet` 计算 `forward_fee = received - forward`（line 1410），**不对照入站通道的 fee_rate**；
2. 出站 `check_tlc_forward_amount` 用**出站**通道的 fee_rate 验证 `forward_fee >= expected`。

这意味着：
- 如果出站通道刚刚提高了 fee_rate（peer 控制），原本"足够"的 forward_fee 变"不足"，TLC 被拒；
- 如果入站通道的 fee_rate 比 onion 构造时还高，本节点实际只收到 `received - forward = (sender 按入站旧 ppm 计算的)` 而出站方仍然能通过（fee 看似足够）。这是潜在的"差价被本节点白嫖"或"被白嫖"的边界情况。

**严重级别**：🟢 Low — 这是 LN 网络的固有竞态（fee 更新与 in-flight 路由不一致）；当前实现与 LN BOLT-7 节点行为一致。可在 changelog 中明确说明。

### 3.3 F3 (🟢 Low) — `calculate_fee_with_base` 在极端 ppm 时仍可能 overflow（边界场景）

**位置**：`fee.rs:115-135`

```rust
let fee = fee_proportational_millionths
    .checked_mul(amount)
    .ok_or_else(|| format!(...))?;
let base_fee = fee / base;
let remainder = fee % base;
if remainder > 0 { Ok(base_fee + 1) } else { Ok(base_fee) }
```

- `checked_mul` 在 `ppm × amount > u128::MAX` 时返回 `None`，返回 `Err` ✅。
- `base_fee + 1` 当 `base_fee == u128::MAX` 时溢出 panic（debug） / 回绕 (release)。但 `base_fee = fee / 1_000_000`；要让 `base_fee == u128::MAX` 需 `fee >= u128::MAX * 1_000_000`，已超过 `u128`，被 `checked_mul` 排除。**实际不可达**。

但 graph.rs:783 限制 `tlc_expiry_delta <= MAX_PAYMENT_TLC_EXPIRY_LIMIT`，**没有**对 `tlc_fee_proportional_millionths` 设上界。理论上 peer 可广告 `ppm = u128::MAX`，导致**对所有非零 amount 的 fee 计算都返回 Err**，等同于该通道"对所有金额都嫌 fee 太低"——下游永远拒，等同 DoS 该通道。

**严重级别**：🟢 Low — 自损式（peer 把自己的通道变成不可路由），无攻击收益；但建议对 ppm 设软上界（如 100_000 = 10%）。

**建议**：在 `graph.rs` 验证 channel_update 时加 `tlc_fee_proportional_millionths <= MAX_FEE_PPM`（如 `100_000`）。

### 3.4 F4 (ℹ️ Info / Pass) — Trampoline forwarding 强制 fee 等式是合理设计

**位置**：`network.rs:3092-3102`

```rust
let available_fee_amount = incoming_amount.saturating_sub(amount_to_forward);
if available_fee_amount != build_max_fee_amount {  // 严格等式
    return Err(InvalidOnionPayload);
}
```

不同于普通转发的 `forward_fee >= expected_fee`（允许超付），trampoline 强制 `available == build_max_fee_amount`。这防止：
- 上游 hop 偷偷"压扣" trampoline 节点应得的 fee（available < build_max ⇒ 拒）；
- 上游"贴付" trampoline 节点（available > build_max ⇒ 拒，避免 trampoline 节点被诱导接受未授权的额外资金 / 改变路由决策）。

**Pass**。是有意识的安全设计。

### 3.5 F5 (ℹ️ Info / Pass) — `is_invoice_fulfilled` 单 TLC 调用路径正确

**位置**：`utils/payment.rs:15-41`，3 处调用：`channel.rs:1181, 1522, 2664`

所有调用点均使用 `std::iter::once(&tlc)`，单 TLC 输入：
- `total_amount := first_tlc.total_amount.unwrap_or(first_tlc.amount)`；
- MPP 真正多 TLC 的聚合不走此函数，走 `SettleTlcSetCommand`（见 LOGIC-005）。

`total_tlc_amount += tlc.amount` 在迭代多 TLC 时**没有 checked_add**，但当前所有调用是 single-iter，不触发溢出路径。**Pass**，但建议改为 `checked_add` / `saturating_add` 做防御。

### 3.6 F6 (🟢 Low) — `try_to_settle_down_tlc_without_invoice` 全局 preimage 抢付的次要风险

**位置**：`channel.rs:1231-1256`

```rust
fn try_to_settle_down_tlc_without_invoice(...) {
    if state.is_waiting_forward_result_for_received_tlc(tlc.tlc_id) {
        return;
    }
    let Some(payment_preimage) = self.store.get_preimage(&tlc.payment_hash) else {
        return;
    };
    self.register_retryable_tlc_remove(...,
        RemoveTlcReason::RemoveTlcFulfill(RemoveTlcFulfill { payment_preimage }));
}
```

**触发链**：
- `apply_add_tlc_operation` 仅当 `peeled.is_last() == true`（onion 把本节点标为终点）才进入 `try_to_settle_down_tlc`；
- 进入后，若 invoice 不存在（无关 invoice 的 keysend / 测试 TLC），尝试拿 preimage fulfill。
- **若 `payment_hash` 与本节点曾收到过的某个 fulfilled-payment 的 preimage 碰撞（极小概率，2^160 安全）**，本节点会把这个 TLC 当作"自己的"fulfill，将 preimage 透露给上游，从而"白收" `add_tlc.amount`。

**实际可行性**：
- Hash 强抗碰撞 → 不可控；
- 但若攻击者**真的拿到了某个 preimage**（已经在某个旧支付里完成过、preimage 已发布 / 上链 / watchtower 看到），那么攻击者可针对该 preimage 的 `payment_hash` 构造 final-hop TLC，要求本节点 fulfill。
  - 本节点确实会 fulfill，因为 `store.get_preimage(payment_hash)` 命中。
  - 但攻击者必须**自己**作为路径中的最后一跳的**上游**给本节点送钱，最终是攻击者付钱给本节点。攻击者不获利。
  - 反向思考：攻击者实际是"凭空给本节点送钱"——这不是攻击，是 donation。

**真正风险**：测试场景中，多个测试用例可能共享 preimage，导致一个测试的 fulfill 影响另一个测试。
**严重级别**：🟢 Low — 测试 / 操作 hazard，非生产安全问题。

**建议**：注释中明确"preimage store should be partitioned by payment-hash uniqueness; reusing preimage across payments is unsupported"。

## 4. 结论

| 子项 | 严重级别 | 状态 |
|---|---|---|
| F1 — forwarding hop `forward_amount == 0` 未拒绝（HTLC slot jamming）| 🟡 Medium | ⚠️ 未修复 |
| F2 — fee 校验入/出不对称（LN 固有竞态）| 🟢 Low (informational) | — |
| F3 — `ppm` 缺上界，可自损式 DoS 通道 | 🟢 Low | ⚠️ 未修复 |
| F4 — Trampoline 严格 fee 等式 | ℹ️ Info / Pass | — |
| F5 — `is_invoice_fulfilled` 防御性 checked_add 建议 | ℹ️ Info / Pass | — |
| F6 — `try_to_settle_down_tlc_without_invoice` 测试场景 hazard | 🟢 Low | — |
| 整体严重 | 🟡 Medium | — |

## 5. Follow-ups

- **AUDIT-LOGIC-004-FOLLOWUP-A**：HTLC slot jamming PoC — 测试网构造 forward_amount=0 路由，验证中间节点 TLC slot 被占用 + 测算占用时长；评估是否需要"最小转发金额"全网软共识。
- **AUDIT-LOGIC-004-FOLLOWUP-B**：为 `tlc_fee_proportional_millionths` 设软上界（如 `100_000` = 10%），在 `graph.rs:783` 区域加守卫。
- **AUDIT-LOGIC-004-FOLLOWUP-C**：将 `is_invoice_fulfilled` 中 `+=` 改为 `checked_add`，并通过参数 `total_amount` 直接复用 SettleTlcSetCommand 已验证一致性的值。
