# AUDIT-LOGIC-002 — TLC / PTLC 生命周期与时间锁

- **维度**: DIM-LOGIC（业务逻辑 / 状态机）
- **严重级别**: 🔴 P0
- **审计 Session**: S4 (2026-05-13)
- **关联代码**:
  - `crates/fiber-lib/src/fiber/channel.rs:1279-1564` (`apply_add_tlc_operation` / `apply_add_tlc_operation_with_peeled_onion_packet` / `apply_final_hop_tlc_onion_packet`)
  - `crates/fiber-lib/src/fiber/channel.rs:1575-1591` (`handle_add_tlc_peer_message`)
  - `crates/fiber-lib/src/fiber/channel.rs:1882-1929` (`handle_add_tlc_command`)
  - `crates/fiber-lib/src/fiber/channel.rs:2697-2765` (`maintain_pending_tlcs`)
  - `crates/fiber-lib/src/fiber/channel.rs:6221-6250` (`check_tlc_expiry`)
  - `crates/fiber-lib/src/fiber/channel.rs:4453-4458` (`tlc_expiry_delay`)
  - `crates/fiber-lib/src/fiber/config.rs:38-58` (TLC expiry 常量)
  - `crates/fiber-lib/src/fiber/fee.rs:144-228` (`check_open_channel_parameters` — `commitment_delay_epoch` 校验)
  - `crates/fiber-lib/src/fiber/network.rs:5263-5283` (`on_open_channel_msg` 入站校验)

## 1. 审计目标

验证 TLC（Time-Locked Contract，Fiber 的 HTLC 等价物）生命周期与时间锁约束：

- 出站 / 入站 `AddTlc` 的 expiry（绝对时间戳，毫秒）下界与上界是否对称校验；
- 中间节点（forwarding hop）与终点节点（final hop）对 expiry 的差异化校验是否合理；
- 过期 TLC 的回收路径（`maintain_pending_tlcs`、`maintain_waiting_onchain_settlement_tlcs`）是否在期望时间内触发；
- `tlc_expiry_delay` 的 epoch → 毫秒换算是否有数值健壮性问题；
- 攻击者（peer）能否通过构造异常 expiry 锁定本方资金、强制强关、绕过 forward-fee/expiry 一致性。

## 2. 数据流与不变式

### 2.1 关键常量（`config.rs:38-58`）

```rust
pub const DEFAULT_TLC_EXPIRY_DELTA:        u64 = 4  * 60 * 60 * 1000;  // 4h
pub const DEFAULT_FINAL_TLC_EXPIRY_DELTA:  u64 = 24 * 60 * 60 * 1000;  // 24h
pub const MIN_TLC_EXPIRY_DELTA:            u64 = 2/3 epoch (≈ 2.67h prod, ≈ 1.3s dev)
pub const MAX_PAYMENT_TLC_EXPIRY_LIMIT:    u64 = 14 * 24 * 60 * 60 * 1000; // 14d
```

### 2.2 出站路径（本方主动发起 / 转发 TLC）

`handle_add_tlc_command` → `check_tlc_expiry(command.expiry)`：

```rust
// channel.rs:6221-6250
fn check_tlc_expiry(&self, expiry: u64) -> ProcessingChannelResult {
    let current_time = now_timestamp_as_millis_u64();
    if expiry <= current_time + MIN_TLC_EXPIRY_DELTA          { Err(TlcExpirySoon) }
    let expect_expiry = current_time + tlc_expiry_delay(&delay_epoch);
    if expiry < expect_expiry                                  { Err(TlcExpirySoon) }
    if expiry >= current_time + MAX_PAYMENT_TLC_EXPIRY_LIMIT   { Err(TlcExpiryTooFar) }
    Ok(())
}
```

✅ 全双向边界检查（下界 `MIN_TLC_EXPIRY_DELTA` + 2/3 epoch buffer，上界 `MAX_PAYMENT_TLC_EXPIRY_LIMIT`）。

### 2.3 入站路径（peer 发来的 `AddTlc`）

```rust
// channel.rs:1575-1591
fn handle_add_tlc_peer_message(&self, state, add_tlc: AddTlc) {
    state.check_for_tlc_update(TlcUpdateAction::AddTlcPeer { amount })?;   // 仅状态守卫
    let tlc_info = state.create_inbounding_tlc(add_tlc.clone())?;           // 仅复制字段
    state.check_insert_tlc(&tlc_info)?;                                     // 仅 tlc_id 序号检查
    state.tlc_state.add_received_tlc(tlc_info);
    state.increment_next_received_tlc_id();
    Ok(())
}
```

⚠️ **完全没有调用 `check_tlc_expiry(add_tlc.expiry)`**。绝对时间戳直接写入 state。

随后在 `apply_add_tlc_operation_with_peeled_onion_packet`（peel onion 后）才做相对一致性校验：

```rust
// channel.rs:1382-1396 (forwarding hop)
if (is_last && !is_trampoline) || last_hop_inner_onion.is_some() {
    self.apply_final_hop_tlc_onion_packet(...)?;          // 终点
} else {
    if add_tlc.expiry < peeled.expiry + tlc_expiry_delta { return Err(IncorrectTlcExpiry); }
    // ...
    self.register_and_apply_forward_tlc(...);
}

// channel.rs:1460-1478 (final hop)
if add_tlc.expiry < peeled_payment_expiry { return Err(IncorrectFinalTlcExpiry); }
if let Some(invoice) = invoice {
    if invoice.is_tlc_expire_too_soon(add_tlc.expiry) { return Err(IncorrectFinalTlcExpiry); }
}
```

二者均**只是相对/下界**比较：

| 路径 | 入站 expiry 下界 | 入站 expiry 上界 |
|---|---|---|
| Forwarding hop | `peeled.expiry + tlc_expiry_delta`（peer 控制） | **无** |
| Final hop（无 invoice） | `peeled_payment_expiry`（peer 控制） | **无** |
| Final hop（有 invoice） | `invoice.is_tlc_expire_too_soon`（≥ now + final_expiry_delta） | **无** |

### 2.4 过期回收

`maintain_pending_tlcs` 每 `CHECK_CHANNELS_INTERVAL`（dev 3s / prod 60s）跑一次：

```rust
// channel.rs:2702-2733
let expect_expiry = now + epoch_delay + CHECK_CHANNELS_INTERVAL;
for tlc in committed_received_tlcs.filter(|t| t.forwarding_tlc.is_none() && t.expiry < expect_expiry) {
    queue_channel_remove_tlc(... RemoveTlcFail(ExpiryTooSoon) ...);
}

// channel.rs:2735-2764
let expect_expiry = now + epoch_delay;
if state.tlc_state.get_expired_offered_tlcs(expect_expiry).next().is_some() {
    Shutdown(force: true);   // 触发链上 commitment publish → 等待 timeout claim
}
```

✅ 已过期 / 即将过期的 received TLC 主动 RemoveTlc；offered TLC 即将过期则强关进入链上 settle 流程。

### 2.5 `tlc_expiry_delay` epoch → 毫秒换算

```rust
// channel.rs:4452-4458
pub(crate) fn tlc_expiry_delay(delay_epoch: &EpochNumberWithFraction) -> u64 {
    ((delay_epoch.number() as f64
        + delay_epoch.index() as f64 / delay_epoch.length() as f64)
        * MILLI_SECONDS_PER_EPOCH as f64
        * 2.0 / 3.0) as u64
}
```

- 浮点除法 + `as u64` 饱和转换；
- `length() == 0` ⇒ NaN ⇒ `as u64` = 0；
- `number()` 接近 `f64::MAX / MILLI_SECONDS_PER_EPOCH` 时溢出 ⇒ 饱和到 `u64::MAX` 不是大问题，但 NaN/Inf 路径返回 0 等价于"无延迟"。

`commitment_delay_epoch`（决定 `delay_epoch`）的来源：
1. 本方创建（`OpenChannel`/`AcceptChannel` initiator）→ `check_open_channel_parameters`（fee.rs:144-228）；
2. peer 创建（入站 `OpenChannel`）→ `on_open_channel_msg`（network.rs:5271）调用同一 `check_open_channel_parameters`；

两处均强制 `epoch.is_well_formed()`（保证 `length > 0`），且范围 `[MIN_COMMITMENT_DELAY_EPOCHS, MAX_COMMITMENT_DELAY_EPOCHS]`。
所以 NaN/0 路径**在协议层是不可达**的。

## 3. 不变式表

| ID | 不变式 | 实现位置 | 状态 |
|---|---|---|---|
| INV-1 | 出站 TLC expiry ∈ [now+MIN_TLC_EXPIRY_DELTA, now+MAX_PAYMENT_TLC_EXPIRY_LIMIT) | `check_tlc_expiry` | ✅ |
| INV-2 | 出站 TLC expiry ≥ now + tlc_expiry_delay(commitment_delay_epoch) | `check_tlc_expiry` | ✅ |
| INV-3 | 入站 TLC expiry ≥ now + MIN_TLC_EXPIRY_DELTA | — | ⚠️ **未实施** |
| INV-4 | 入站 TLC expiry < now + MAX_PAYMENT_TLC_EXPIRY_LIMIT | — | ⚠️ **未实施** |
| INV-5 | Forwarding hop: add_tlc.expiry ≥ peeled.expiry + local.tlc_expiry_delta | `apply_add_tlc_operation_with_peeled_onion_packet:1391` | ✅ |
| INV-6 | Final hop: add_tlc.expiry ≥ peeled.expiry | `apply_final_hop_tlc_onion_packet:1463` | ✅ |
| INV-7 | Final hop (invoice): add_tlc.expiry ≥ now + invoice.min_final_cltv | `invoice.is_tlc_expire_too_soon:1475` | ✅ |
| INV-8 | 过期 received TLC 自动 RemoveTlc | `maintain_pending_tlcs:2705-2733` | ✅ |
| INV-9 | 即将过期 offered TLC 触发强关 | `maintain_pending_tlcs:2735-2764` | ✅ |
| INV-10 | `commitment_delay_epoch.is_well_formed() && length > 0` | `check_open_channel_parameters:196-202`, `network.rs:5271` | ✅ |
| INV-11 | forward_amount + fee ≤ received_amount | `apply_add_tlc_operation_with_peeled_onion_packet:1403-1410` | ✅ |

## 4. 发现

### 4.1 F1 (🟡 Medium) — 入站 `AddTlc` 缺绝对时间 / 上界 expiry 校验，可被用于长期锁定资金

**位置**：`channel.rs:1575-1591` (`handle_add_tlc_peer_message`)

**问题**：

入站 TLC 路径完全没有调用 `check_tlc_expiry`。`add_tlc.expiry` 直接写入 `TlcInfo`，等到 onion peel 完成后才做相对一致性校验（INV-5/INV-6/INV-7）。这些相对校验比较的是 `add_tlc.expiry` 与 `peeled.expiry`，而 **peer 同时控制这两个值**（peer 既构造 AddTlc，也构造 onion 内层）。

**受影响场景**：

1. **远未来 expiry（grief / 资金锁定）**：peer 构造 forwarding hop AddTlc，`expiry = now + 100 years`，相应 onion 内 `peeled.expiry = expiry - tlc_expiry_delta`。INV-5 通过。`register_and_apply_forward_tlc` 触发本方发起**出站**转发 → 该出站会被 `check_tlc_expiry` 拒绝 `TlcExpiryTooFar`，本方对下游回送 `RemoveTlcFail`。BUT：上游入站 TLC 已经 `add_received_tlc`，commit 后才会通过 RemoveTlc 异步清理。
   - 期间锁定本方 `to_remote_amount` 中等于 `add_tlc.amount` 的额度。
   - 配合 `max_tlc_number_in_flight`（默认 125），peer 可同时锁住 125 个 TLC 额度。
   - 清理在 `apply_remove_tlc` 后完成，本方可 RemoveTlcFail 但需要两轮 commitment_signed/revoke_and_ack 才能真正释放。
   - **影响**：短期（~秒到分钟级）的容量耗尽，但不会"永久"锁定。

2. **直接 final hop 远未来 expiry**：peer 作为最终接收方，构造 final-hop AddTlc with `expiry = u64::MAX`：
   - 无 invoice / keysend：只检查 `add_tlc.expiry >= peeled.expiry`（peer 自控），通过。
   - 有 invoice：`invoice.is_tlc_expire_too_soon` 只是下界检查。
   - TLC 进入 state、`apply_final_hop_tlc_onion_packet` 寻找 preimage：若 peer 是真实 invoice 持有者（不是恶意 peer 直连），可立即 fulfill；若 peer 不持有 preimage 也不 RemoveTlc，**该 TLC 永远不会被 `maintain_pending_tlcs` 标记为过期**（`tlc.expiry < expect_expiry` 永不为 true）。
   - 锁定 `add_tlc.amount` 直到 cooperative shutdown（双方同意，但 peer 不会同意）或 force-close（本方主动强关、上链 commitment、等待 timeout）。
   - **影响**：迫使本方对每个被恶意锁定的 TLC 强关通道、付出链上费用 + 等待解锁时间。

3. **过去 expiry（轻微 grief）**：peer 构造 `expiry = 0`。
   - 相对检查 `add_tlc.expiry >= peeled.expiry + delta`：若 peeled.expiry 也 = 0，可能通过；若不通过则立即 RemoveTlcFail。
   - 即便通过，下个 `maintain_pending_tlcs` tick（≤60s prod）即清理。
   - **影响**：分钟级短暂占用，不算严重。

**与出站路径的对称性差**：

| 校验 | 出站（`check_tlc_expiry`） | 入站（实际） |
|---|---|---|
| `expiry > now + MIN_TLC_EXPIRY_DELTA` | ✅ | ❌ |
| `expiry > now + commitment_delay_buffer` | ✅ | ❌ |
| `expiry < now + MAX_PAYMENT_TLC_EXPIRY_LIMIT` | ✅ | ❌ |

**严重级别**：🟡 Medium —— 资金不会永久丢失，但提供了：
- (a) 强关诱导：恶意 peer 可迫使本方强关通道、付链上费；
- (b) 容量耗尽：在 `max_tlc_number_in_flight` 上限内短期锁住额度；
- (c) 同步性削弱：对 watchtower 而言，超长 expiry 意味着该 TLC 在 commitment tx 上的 since/expiry 同样超长，链上 punishment 窗口配置可能与预期不符。

**建议**：
- 在 `handle_add_tlc_peer_message` 入口加 `state.check_tlc_expiry(add_tlc.expiry)`，与出站对称；
- 对 final-hop（peer 是终点）尤其要加 `MAX_PAYMENT_TLC_EXPIRY_LIMIT` 上界；
- 若担心打破协议兼容性（不同节点 MIN/MAX 配置不同），至少使用一个独立的更宽松的上界（如 `MAX_PAYMENT_TLC_EXPIRY_LIMIT * 2`）来防极端 `u64::MAX` 攻击。

### 4.2 F2 (🟢 Low) — `tlc_expiry_delay` 浮点除法缺数值健壮性（当前不可达）

**位置**：`channel.rs:4452-4458`

```rust
pub(crate) fn tlc_expiry_delay(delay_epoch: &EpochNumberWithFraction) -> u64 {
    ((delay_epoch.number() as f64
        + delay_epoch.index() as f64 / delay_epoch.length() as f64)  // ← length()==0 ⇒ NaN
        * MILLI_SECONDS_PER_EPOCH as f64
        * 2.0 / 3.0) as u64                                          // ← NaN as u64 = 0
}
```

`length() == 0` 时 NaN 经 `as u64` → 0，意味着"无 expiry buffer"，下游 `check_tlc_expiry` 的 INV-2 退化为只依赖 `MIN_TLC_EXPIRY_DELTA`。

**可达性分析**：

`delay_epoch` 来自 `EpochNumberWithFraction::from_full_value(self.commitment_delay_epoch)`。`commitment_delay_epoch` 的两条入口：
1. 本方设置：`check_open_channel_parameters` → `is_well_formed()` 强制 length>0；
2. 入站 OpenChannel：`on_open_channel_msg` → 同 `check_open_channel_parameters`。

故协议层**不可达**。**Pass**，但建议改用 checked 整数运算（`u128` 中间计算后 `min(u64::MAX)`），消除 f64 footgun。

### 4.3 F3 (ℹ️ Info) — 出站 / 入站 expiry 校验不对称

**问题**：出站命令路径（`handle_add_tlc_command:1891` → `check_tlc_expiry`）做完整三项检查；入站 peer 消息路径仅做相对 onion-expiry 检查。

虽然 onion 内层签名了 `peeled.expiry`，但攻击者既是 onion 构造者又是 AddTlc 发送者，所有"内层"值都是它说了算。相对检查只能保证"peer 给本方的两个值一致"，无法保证"绝对时间窗口合理"。

**建议**：将入站校验也走 `check_tlc_expiry`，或抽出一个共享的 `validate_absolute_expiry(expiry)` 函数。

### 4.4 F4 (🟢 Low) — Debug 模式下接受无 onion 的 TLC

**位置**：`channel.rs:1306-1318`

```rust
None => {
    debug_assert!(add_tlc.onion_packet.is_none());
    if cfg!(debug_assertions) {
        warn!("Processing TLC with no onion packet, only for testing or development environment");
        true        // ← should_settle = true: 当 final hop 处理
    } else {
        return Err(ProcessingChannelError::PeelingOnionPacketError(
            "TLC with no onion packet is not supported".to_string(),
        ).without_shared_secret());
    }
}
```

Release 编译禁止该路径。**Debug** 编译下，任何 peer 发来不带 onion 的 AddTlc 会被当作 final hop 处理（直接进入 `try_to_settle_down_tlc`），仅依赖 preimage 校验。

**影响**：仅限调试构建；生产部署不受影响。**Low**。

**建议**：注释强化或拆为单独 cfg(test) 路径，避免开发者在 `--features debug-prod` 等非常规组合下意外打开。

### 4.5 Pass — Forward fee 与 amount 一致性

`apply_add_tlc_operation_with_peeled_onion_packet:1403-1411`：

```rust
if received_amount < forward_amount {
    return Err(ProcessingChannelError::InvalidParameter(
        "received_amount is less than forward_amount".to_string()));
}
let forward_fee = received_amount.saturating_sub(forward_amount);
```

✅ 防 underflow，强制 `received_amount >= forward_amount`。下游 `check_tlc_forward_amount` 校验 `forward_fee >= expected_fee`。

### 4.6 Pass — `maintain_pending_tlcs` 正确清理过期 TLC

`channel.rs:2697-2764`：
- received 过期 ⇒ RemoveTlc(ExpiryTooSoon) 通知 peer；
- offered 过期 ⇒ 强制 `Shutdown(force: true)` 进入链上 settle，watchtower 接管 timeout 回收。

✅ 与 LN BOLT-2 推荐一致。

### 4.7 Pass — `commitment_delay_epoch` 严格校验

`fee.rs:144-228` `check_open_channel_parameters`：
- `is_well_formed()` 保证 `length() > 0`、`index() < length()`、`number()` 合法；
- 范围 `[MIN_COMMITMENT_DELAY_EPOCHS, MAX_COMMITMENT_DELAY_EPOCHS]`；
- 在 `on_open_channel_msg`（入站）和本方 `OpenChannel`/`AcceptChannel`（出站）三处均调用。

✅ 杜绝了 F2 的可达性。

## 5. 结论与级别

| 子项 | 严重级别 | 状态 |
|---|---|---|
| F1 — 入站 AddTlc 无 `check_tlc_expiry` | 🟡 Medium | ⚠️ 未修复 |
| F2 — `tlc_expiry_delay` f64 路径 | 🟢 Low (defense-in-depth) | ⚠️ 未修复 |
| F3 — 出/入校验不对称 | ℹ️ Info | ⚠️ 未修复 |
| F4 — debug-only no-onion 接受 | 🟢 Low | ⚠️ 未修复 |
| 整体严重 | 🟡 Medium | — |

## 6. 修复建议

```rust
// channel.rs: handle_add_tlc_peer_message
fn handle_add_tlc_peer_message(&self, state, add_tlc: AddTlc) {
    state.check_for_tlc_update(TlcUpdateAction::AddTlcPeer { amount: add_tlc.amount })?;
+   state.check_tlc_expiry(add_tlc.expiry)?;      // <-- 新增
    let tlc_info = state.create_inbounding_tlc(add_tlc.clone())?;
    state.check_insert_tlc(&tlc_info)?;
    state.tlc_state.add_received_tlc(tlc_info);
    state.increment_next_received_tlc_id();
    Ok(())
}
```

注意：MIN_TLC_EXPIRY_DELTA 下界对入站可能过严（peer 可能用对端节点的 expiry_delta 计算），实际可放宽为：

```rust
fn check_inbound_tlc_expiry(&self, expiry: u64) -> ProcessingChannelResult {
    let now = now_timestamp_as_millis_u64();
    if expiry <= now { Err(TlcExpirySoon) }       // 仅"必须未过期"
    if expiry >= now + MAX_PAYMENT_TLC_EXPIRY_LIMIT * 2 { Err(TlcExpiryTooFar) }
    Ok(())
}
```

至少要堵住 `u64::MAX` 这种极端值。

## 7. Follow-ups

- **AUDIT-LOGIC-002-FOLLOWUP-A**：PoC — 构造恶意 peer 在测试网通道上发送 `AddTlc { expiry: u64::MAX }`，验证 (a) TLC 进入本方 state、(b) 不被 `maintain_pending_tlcs` 清理、(c) 仅能通过 force-close 释放。
- **AUDIT-LOGIC-002-FOLLOWUP-B**：fuzz / property test —— `handle_add_tlc_peer_message` 在各种 `expiry × peeled.expiry × tlc_expiry_delta` 组合下的不变式 INV-3/INV-4。
- **AUDIT-LOGIC-002-FOLLOWUP-C**：将 `tlc_expiry_delay` 重写为 checked 整数运算，并加单测覆盖边界 epoch 值。
