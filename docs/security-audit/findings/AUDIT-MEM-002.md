# AUDIT-MEM-002 — 数值溢出与边界 (Numeric Overflow & Boundaries)

- **维度**: DIM-MEM（数值算术）
- **严重级别**: 🟡 Medium（Low × 3 + Info × 2 + Pass × 4）
- **审计 Session**: S10 (2026-05-13)
- **关联代码**:
  - `crates/fiber-lib/src/fiber/fee.rs:115-135` (`calculate_fee_with_base`)
  - `fee.rs:188` (`commitment_fee * 2 > reserved_fee` 未检查)
  - `crates/fiber-lib/src/fiber/channel.rs:5518` (`get_liquid_capacity` 未检查 `+`)
  - `channel.rs:6420-6451` (`check_tlc_limits` `.fold(... sum + tlc.amount) + add_amount` 未检查)
  - `channel.rs:8266-8272` (`build_settlement_data` 链式 `+`/`-` 未检查)
  - `channel.rs:5320-5329` (`available_max_fee` `u128 as u64 +` 截断 + 未检查)
  - `channel.rs:5824-5849` (`apply_remove_tlc` checked_add/sub — 正确)
  - `channel.rs:4400-4418` (`get_funding_and_reserved_amount` 已正确边界检查)
  - `channel.rs:6410-6411` (`check_tlc_limits` add_amount==0 拒绝)
  - `payment.rs:196-201` (`amount + max_fee_amount` checked_add — 正确)
  - `graph.rs:1538-1545, 1984-1990` (path-find checked_add — 正确)
  - `settle_tlc_set_command.rs:174` (`accumulated_amount.saturating_add` — 正确)
  - `fiber/types.rs:2070` (molecule `checked_add` — 正确)
  - `network.rs:177-182, 246-253` (`funding_retry_delay` / `compute_peer_reconnect_delay` shift + saturating — 正确)

## 1. 审计目标

- 验证 fee / amount / capacity / expiry 等关键算术使用了 `checked_*` / `saturating_*` / `wrapping_*` 等显式语义；
- 验证 u128 ↔ u64 ↔ usize 强转处的截断行为；
- 验证攻击者控制输入字段（OpenChannel 的 funding_amount、AddTlc 的 amount、ChannelUpdate 的 fee 字段、CCH 跨链等）流向的算术安全；
- 验证溢出/下溢的失败模式（panic / 返回 Err / 静默 wrap）。

## 2. 系统性梳理

Rust 默认行为：
- **debug build**: 整数 overflow → panic；
- **release build**（生产）：默认 wrap-around，不 panic。

因此 release 中关键不变式必须显式使用 `checked_*` / `saturating_*` 才能可靠地拒绝异常输入。本审计针对所有"远程输入参与的算术"逐点检查。

### 2.1 攻击者可控的算术输入面

| 输入 | 来源 | 算术参与点 |
|---|---|---|
| `OpenChannel.funding_amount` (u128) | remote peer | `get_funding_and_reserved_amount`, `to_local_amount + to_remote_amount` |
| `AddTlc.amount` (u128) | remote peer | `check_tlc_limits.fold`, `apply_remove_tlc.checked_*` |
| `ChannelUpdate.{fee_rate, fee_proportational_millionths}` (u128) | gossip | `calculate_tlc_forward_fee` |
| `BroadcastMessage.timestamp` (u64) | gossip | 时间窗对比 |
| MPP `total_amount` (u128) | remote peer | `leave_just_fulfilled_tlcs_for_mpp_invoice.saturating_add` |
| Payment fee/expiry params (RPC) | user | `payment.rs` checked_add |
| Path-find hop amount/fee (u128) | NetworkGraph | `graph.rs` 大部分 saturating_，部分 checked_ |
| Onion HopData length (u64) | remote peer | `types.rs:2070` checked_add (✅ 已有测试) |

### 2.2 三类算术的实际分布（统计自源码 grep）

| 类型 | 使用次数 | 备注 |
|---|---|---|
| `checked_*` | 14 | 多数关键路径已正确使用 |
| `saturating_*` | 41 | 主要在 fee / amount path-find、时间戳 |
| 普通 `+`/`-`/`*` 涉及远程输入 | ~6 | 见下方 F1-F3 |

## 3. 发现

### 3.1 F1 (🟢 Low) — `check_tlc_limits` 累加溢出可绕过 `max_tlc_value_in_flight`

**位置**：`channel.rs:6425-6431` 与 `6444-6450`

```rust
let active_offered_amount = self
    .get_all_offer_tlcs()
    .fold(0_u128, |sum, tlc| sum + tlc.amount)       // ← unchecked u128 +
    + add_amount;                                     // ← unchecked u128 +
if active_offered_amount > self.local_constraints.max_tlc_value_in_flight {
    return Err(ProcessingChannelError::TlcValueInflightExceedLimit);
}
```

`max_tlc_value_in_flight` 默认 `u128::MAX`（见 MEM-001.F4 + `channel.rs:284`）。在该默认下 limit 永远不会触发，所以该 fold 的累加溢出无业务后果。但若用户**配置**了较低的 `max_tlc_value_in_flight`，攻击者通过累计 in-flight TLCs（值之和靠近 `u128::MAX`）可使下一次 `add_amount` 的 fold 结果 wrap 到一个很小的数 → 绕过 limit。

**触发难度**：
- u128::MAX ≈ 3.4e38，攻击者需要让 in-flight TLC 累计 ≈ 3.4e38 → 实际不可能（CKB 总量 ~3.36e10 shannon，UDT 也有限）；
- **但**：攻击者无需让真实 in-flight 累积到 u128::MAX——只需通过协议消息塞 `add_tlc.amount = u128::MAX - small_sum`，这本身被前置 `to_local_amount.saturating_sub` 检查 (line 6416) 拦截，因为 `add_amount > to_local_amount` 必然失败；
- **唯一可达**：用户配置 `max_tlc_value_in_flight = u128::MAX - 1` 时，攻击者控制 `add_amount = u128::MAX`（被 line 6416 拦截）or 累计已 ack 的 TLCs ≈ u128::MAX（不现实，资金问题）。
- 因此实际不可利用，但**这是一个潜在的"depth in defense"缺口**：fold 应当使用 `checked_add` 或 `saturating_add`。

**修复建议**：

```rust
let active_offered_amount = self
    .get_all_offer_tlcs()
    .try_fold(0_u128, |sum, tlc| sum.checked_add(tlc.amount))
    .and_then(|s| s.checked_add(add_amount))
    .ok_or(ProcessingChannelError::TlcValueInflightExceedLimit)?;
```

### 3.2 F2 (🟢 Low) — `build_settlement_data` 链式 `+`/`-` 在 release build 中可 wrap

**位置**：`channel.rs:8266-8272`

```rust
let mut to_local_value =
    self.to_local_amount + received_fulfilled - offered_pending - offered_fulfilled;
let mut to_remote_value =
    self.to_remote_amount + offered_fulfilled - received_pending - received_fulfilled;
if self.funding_udt_type_script.is_none() {
    to_local_value += self.local_reserved_ckb_amount as u128;
    to_remote_value += self.remote_reserved_ckb_amount as u128;
}
```

`build_settlement_data` 用于**生成 commitment_tx 的 outputs** —— 这是 force-close 时上链的实际金额。所有 4 个加减都是 unchecked u128 算术。

**不变式依赖**：
- `to_local_amount + received_fulfilled` 不能 overflow → 由 funding amount cap 保证（`get_funding_and_reserved_amount` line 4408 限制 < u64::MAX）；
- `offered_pending + offered_fulfilled <= to_local_amount + received_fulfilled` → 由 `add_tlc` 时的 capacity 检查保证；
- 但**这些是状态机不变式**，若状态机有 bug（参考 AUDIT-LOGIC-001 系列）则可能 underflow。

**Underflow 后果**（release）：
- `to_local_value` 静默 wrap 成 ≈ u128::MAX，远超 channel capacity；
- commitment_tx 构造仍会进行（不会立即拒绝异常大的 output）；
- 但实际上链时，CKB 节点会拒绝：cell capacity 必须 ≤ inputs，所以攻击者无法直接通过这条路径骗取资金。
- 然而 **u128 → u64 转换处**（`channel.rs:5324 self.to_local_amount as u64`）会从 wrapped 值截断 64 位 → 仍可能产生异常但合法的小数值。

**风险**：状态机 bug 协同 → 受害者本地构造异常 commitment_tx → 上链失败、或对端利用差异化拒绝。

**修复建议**：将链式表达式改为分步 `checked_*` 并在 underflow 时返回 `InternalError`（与 `apply_remove_tlc` 一致风格，见 `channel.rs:5825`）。

### 3.3 F3 (🟢 Low) — `fee.rs:188` `commitment_fee * 2` 未检查 + `available_max_fee` u128→u64 截断

#### F3a — `commitment_fee * 2`

```rust
// fee.rs:186-193
let commitment_fee = calculate_commitment_tx_fee(commitment_fee_rate, udt_type_script);
let reserved_fee = reserved_ckb_amount - occupied_capacity;
if commitment_fee * 2 > reserved_fee {
    ...
}
```

`commitment_fee: u64`，乘 2 未检查。在 `commitment_fee_rate = u64::MAX` 等极端值下：
- `calculate_commitment_tx_fee` 内部 `FeeRate::fee(tx_size)` 是 `(fee_rate * tx_size) / 1000` — `fee_rate as u128 * tx_size as u128` 不会溢出，但最终 `.as_u64()` 可能截断；
- 即便 `calculate_commitment_tx_fee` 返回 u64 满值，`* 2` 会 wrap。release build 中 wrap 到一个小数 → 通过 `> reserved_fee` 检查 → 接受异常 fee_rate。

但这是 OpenChannel/AcceptChannel 参数验证；接受异常参数后，下游 commitment_tx 构造时上链会失败（fee 超出 capacity）。所以不是 fund-loss，而是 DoS / channel-stuck 风险。

#### F3b — `to_local_amount as u64` 截断

```rust
// channel.rs:5323-5325
let available_max_fee = if self.funding_udt_type_script.is_none() {
    (self.to_local_amount as u64 + self.local_reserved_ckb_amount)
        .saturating_sub(occupied_capacity)
} else { ... };
```

`to_local_amount` 是 u128。Rust 中 `u128 as u64` **静默截断高 64 位**。对 native CKB channels，`get_funding_and_reserved_amount`（line 4408）已限制 `total_amount < u64::MAX`，所以 `to_local_amount` 在 OpenChannel 阶段 ≤ u64::MAX。但**状态机演进**中 `to_local_amount` 可能因状态 bug 超出 u64::MAX（参考 F2）→ 截断后产生错误的 `available_max_fee`。

**严重级别**：🟢 Low —— 都是状态机 bug 协同放大器，单独不可利用。

**修复建议**：
- F3a：`commitment_fee.checked_mul(2).ok_or(...)?`；
- F3b：`u128 → u64` 之前显式检查 `if to_local_amount > u64::MAX as u128 { return Err(InternalError(...)); }` 或使用 `u64::try_from(...)?`。

### 3.4 F4 (ℹ️ Info) — `apply_remove_tlc` 使用 checked_* 是正面典范

**位置**：`channel.rs:5824-5849`

```rust
to_local_amount = to_local_amount.checked_sub(current.amount).ok_or(
    ProcessingChannelError::InternalError(format!(
        "Cannot remove tlc {:?} with amount {} from local balance {}",
        tlc_id, current.amount, to_local_amount
    )),
)?;
```

注释明确说明意图：

```rust
// update balance according to the tlc,
// we already checked the amount is valid in handle_add_tlc_command and handle_add_tlc_peer_message
// here we double confirm everything is correct with `checked_*` methods
```

这是正确的 "deep defense" 写法 —— 即便上游有 bug，settlement 不会静默 wrap。**F1/F2/F3 应当沿用此风格**。

### 3.5 F5 (ℹ️ Info) — `get_funding_and_reserved_amount` 显式 cap < u64::MAX

**位置**：`channel.rs:4408-4413`

```rust
if total_amount >= u64::MAX as u128 {
    return Err(ProcessingChannelError::InvalidParameter(format!(
        "The funding amount ({}) should be less than {}",
        total_amount, u64::MAX
    )));
}
```

native CKB channel 的 funding 严格 < u64::MAX。这隐性保证了后续 `to_local_amount as u64` 转换安全（前提：状态机不破坏不变式）。

但 UDT channel 的 funding_amount 是 u128，**没有上限**，后续可能在 UDT-specific 路径产生 u128 计算 → UDT 实现需要谨慎（UDT 数值 cell data 是 u128，所以与 u128 同步合理）。

### 3.6 F6 (✅ Pass) — Payment / Graph / Onion 输入 checked_add 完整

- `payment.rs:196` `amount.checked_add(max_fee_amount)` ✅
- `graph.rs:1538, 1543, 1984` checked_add 处理 expiry_delta 与 amount + max_fee_amount ✅
- `types.rs:2070` `molecule::NUMBER_SIZE.checked_add(table_len)` 防御 HopData 解析 u64::MAX overflow，且已有单元测试 `test_unpack_hop_data_v0_u64_max_overflow` (`types.rs:420-427`) 与 `test_unpack_hop_data_v0_near_max_overflow` (`types.rs:472-480`) ✅

### 3.7 F7 (✅ Pass) — 时间戳 / 指数退避 saturating

- `network.rs:177-182 funding_retry_delay` shift cap 至 63，saturating_mul ✅
- `network.rs:246-253 compute_peer_reconnect_delay` shift cap 至 10，`checked_mul` + `unwrap_or(MAX)` + `.min(MAX)` ✅
- `gossip.rs:2144-2147` 时间戳 saturating_sub ✅
- `history.rs` 大量 saturating_sub 用于时间差 ✅

### 3.8 F8 (✅ Pass) — MPP 累加 saturating_add

`settle_tlc_set_command.rs:174`:

```rust
accumulated_amount = accumulated_amount.saturating_add(tlc.amount);
```

MPP 接收端正确防止累加溢出（避免协助 LOGIC-005 "100x 超付"问题的二阶段放大）。

### 3.9 F9 (✅ Pass) — `check_tlc_limits` add_amount==0 拒绝

`channel.rs:6410-6411`:

```rust
if add_amount == 0 {
    return Err(ProcessingChannelError::TlcAmountIsTooLow);
}
```

防止 zero-value TLC 灌入（与 LOGIC-004 `forward_amount=0` 配合：本地 add 拒绝 0，但远程转发场景 `forward_amount=0` 仍可路由，因为是 `received_amount - forward_amount = forward_fee`）。

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — `check_tlc_limits` fold 未 checked_add（理论性，max_tlc_value_in_flight 默认 u128::MAX 时无后果） | 🟢 Low | ⚠️ 未修复 |
| F2 — `build_settlement_data` 链式 unchecked +/-（依赖状态机不变式） | 🟢 Low | ⚠️ 未修复 |
| F3 — `commitment_fee * 2` 未 checked_mul；`u128 as u64` 截断 | 🟢 Low | ⚠️ 未修复 |
| F4 — `apply_remove_tlc` checked_* 是正面典范 | ℹ️ Info | — |
| F5 — funding_amount < u64::MAX 显式 cap | ℹ️ Info | — |
| F6 — payment/graph/onion 输入 checked_add 完整 | ✅ Pass | — |
| F7 — 时间戳与指数退避 saturating | ✅ Pass | — |
| F8 — MPP saturating_add | ✅ Pass | — |
| F9 — add_amount==0 拒绝 | ✅ Pass | — |
| 整体 | 🟡 Medium | — |

**总体评价**：与 AUDIT-MEM-001 形成鲜明对比 —— 本维度（数值算术）的整体设计**接近正确**：
- 关键 settlement 路径 (`apply_remove_tlc`) 使用 `checked_*` 二次防御；
- 跨账户输入（payment / graph / onion）已经 `checked_add`；
- 时间戳与退避算术普遍 `saturating_*`；
- HopData 解析甚至有针对 u64::MAX overflow 的专门单元测试。

剩余 Low 项均属 "depth in defense" — 实际触发需要前置状态机 bug。建议作为代码质量改进任务而非紧急修复。

最有价值的修复是 **F2**（`build_settlement_data`），因为：
1. 这是 force-close 路径，错误金额可能被对端利用差异化拒绝；
2. 改造成 `checked_*` 后即便上游有 bug，settlement 阶段会显式失败而非静默 wrap；
3. 改动局部、可读、低风险。

## 5. Follow-ups

- **AUDIT-MEM-002-FOLLOWUP-A (Low, 代码改进)**: F1 — `check_tlc_limits` fold 改 `try_fold` + `checked_add`，与 `apply_remove_tlc` 风格一致。
- **AUDIT-MEM-002-FOLLOWUP-B (Low)**: F2 — `build_settlement_data` 链式表达式拆分为分步 `checked_*` + 返回 `InternalError`（最有价值）。
- **AUDIT-MEM-002-FOLLOWUP-C (Low)**: F3 — `fee.rs:188` `commitment_fee.checked_mul(2)`；`channel.rs:5324` `u64::try_from(to_local_amount)`。
- **AUDIT-MEM-002-FOLLOWUP-D (维护)**: 建议在 `Cargo.toml` 工作区设置 `[profile.release] overflow-checks = true`（性能代价 ~5%，但消除所有静默 wrap 风险）—— 需要评估对 nextest/CI 时间影响。
- **关联**: F1/F2 与 MEM-001.F4 (`DEFAULT_MAX_TLC_VALUE_IN_FLIGHT = u128::MAX`) 解耦：即便修了 MEM-001.F4，F1 的 fold 也应改为 checked 防御。
