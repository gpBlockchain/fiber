# AUDIT-LOGIC-007 — 通道关闭：协作关闭 / 强制关闭 / shutdown_script 校验

- **维度**: DIM-LOGIC（业务逻辑 / 状态机）
- **严重级别**: 🟠 High（Medium × 3 + Low × 3 + Info × 2; 1 个潜在 DoS）
- **审计 Session**: S6 (2026-05-13)
- **关联代码**:
  - `crates/fiber-lib/src/fiber/channel.rs:1622-1676` (`handle_shutdown_peer_message`)
  - `crates/fiber-lib/src/fiber/channel.rs:1970-2075` (`handle_shutdown_command`，含 force=true 分支)
  - `crates/fiber-lib/src/fiber/channel.rs:5303-5338` (`check_shutdown_fee_rate` — 本地)
  - `crates/fiber-lib/src/fiber/channel.rs:6189-6213` (`check_shutdown_fee_valid` — 对端)
  - `crates/fiber-lib/src/fiber/channel.rs:6215-6219` (`check_valid_to_auto_accept_shutdown`)
  - `crates/fiber-lib/src/fiber/channel.rs:6532-6620` (`maybe_transfer_to_shutdown`)
  - `crates/fiber-lib/src/fiber/channel.rs:8001-8112` (`build_shutdown_tx`)
  - `crates/fiber-lib/src/fiber/channel.rs:8315-8328` (`get_latest_commitment_transaction`)
  - `crates/fiber-lib/src/fiber/channel.rs:8489-8527` (`step_shutting_down` — 自动应答)
  - `crates/fiber-lib/src/fiber/channel.rs:4429-4450` (`occupied_capacity`)
  - `crates/fiber-lib/src/fiber/fee.rs:144-218` (`check_open_channel_parameters` — 开启时校验)
  - `crates/fiber-lib/src/fiber/network.rs:5074-5159` (`on_closing_transaction_pending/confirmed`)

## 1. 审计目标

验证通道关闭路径上的金额一致性、签名安全性与 DoS 抗性：

- 协作关闭（cooperative close）：双方 `Shutdown` 消息交换 → `ClosingSigned` 签名聚合 → 上链；
- 强制关闭（force close）：本地单方面广播最新 commitment tx；
- 关闭过程中的 `close_script` / `fee_rate` 是否经过严格校验，能否被对端利用作为 DoS 或资金外流向量；
- 关闭与 in-flight TLC 的交互（避免资金漏单）；
- 双方对关闭费用的承担方式是否对称、是否可被滥用。

## 2. 数据流与不变式

### 2.1 协作关闭流程

```
Local                                              Remote
─────                                              ──────
ChannelCommand::Shutdown{force=false, fee_rate, close_script}
  ↓ handle_shutdown_command (channel.rs:1970)
  │  ├─ require state == ChannelReady
  │  ├─ reject if any outbound TLC in LocalAnnounced       (line 2017-2027)
  │  ├─ check_shutdown_fee_rate(fee_rate, close_script)    (line 2047)
  │  │     ├─ fee_rate >= self.commitment_fee_rate  ✓
  │  │     ├─ fee := fee_rate * shutdown_tx_size
  │  │     └─ fee <= local_avail_max_fee
  │  ├─ store local_shutdown_info
  │  ├─ state = ShuttingDown(OUR_SHUTDOWN_SENT)
  │  └─ send Shutdown {close_script, fee_rate}  ────────────→  handle_shutdown_peer_message (channel.rs:1622)
  │                                                                   ├─ require ChannelReady or ShuttingDown\THEIR_SENT
  │                                                                   ├─ reject if any inbound RemoteAnnounced TLC
  │                                                                   ├─ check_shutdown_fee_valid(remote_fee_rate)   ← ❌ NO minimum fee_rate
  │                                                                   ├─ store remote_shutdown_info
  │                                                                   └─ step_shutting_down(flags)
  │                                                                         ├─ if auto-accept allowed (check_valid_to_auto_accept_shutdown
  │                                                                         │       requires fee_rate >= commitment_fee_rate)
  │                                                                         │   → reply Shutdown {fee_rate=0, ...}      ← F6
  │                                                                         └─ maybe_transfer_to_shutdown
  ↓                                                                                  ↓
  (await Shutdown from remote OR auto-fired by remote)        (computes shutdown_tx, partial-signs, sends ClosingSigned)
  ↓ handle_shutdown_peer_message
  ↓ maybe_transfer_to_shutdown
        ├─ require AWAITING_PENDING_TLCS && all TLCs settled
        ├─ build_shutdown_tx                                   (channel.rs:8001)
        │     ├─ local_fee  := calc(local_fee_rate, ...)
        │     ├─ remote_fee := calc(remote_fee_rate, ...)
        │     ├─ local_output.capacity  = local_reserved_ckb - local_fee
        │     ├─ remote_output.capacity = remote_reserved_ckb - remote_fee
        │     └─ output[i].lock = each party's close_script
        ├─ sign + send ClosingSigned
        └─ on remote's ClosingSigned: aggregate signatures → broadcast tx
```

### 2.2 强制关闭流程

```
ChannelCommand::Shutdown{force=true}
  ↓ handle_shutdown_command (channel.rs:1977-2012)
  │  ├─ require state == ChannelReady OR ShuttingDown(any)       ← F5
  │  ├─ tx := get_latest_commitment_transaction()                 ← F4 (.expect)
  │  ├─ broadcast tx (NetworkActorEvent::ClosingTransactionPending)
  │  └─ state = ShuttingDown(WAITING_COMMITMENT_CONFIRMATION)
```

### 2.3 关键不变式

| ID | 不变式 | 实现位置 | 状态 |
|---|---|---|---|
| INV-1 | 协作关闭：本地端发起前 `fee_rate >= commitment_fee_rate` | `channel.rs:5308-5313` | ✅ |
| INV-2 | 协作关闭：禁止在有 LocalAnnounced 出 TLC 时本地发起 | `channel.rs:2017-2027` | ✅ |
| INV-3 | 协作关闭：禁止在有 RemoteAnnounced 入 TLC 时接受对端 Shutdown | `channel.rs:1632-1642` | ✅ |
| INV-4 | 协作关闭：双方分别在自己的 reserved_ckb 中扣自己的 shutdown_fee | `channel.rs:8051, 8063, 8090, 8091` | ✅ |
| INV-5 | 协作关闭：必须等到所有 TLC settled 才推进到 build_shutdown_tx | `channel.rs:6544-6547` | ✅ (但见 F9 TODO) |
| INV-6 | 协作关闭：tx 必须经双方 MuSig2 部分签名聚合 | `channel.rs:6591-6602` | ✅ |
| INV-7 | 强制关闭：广播的 commitment tx 已含双方有效签名（latest_commitment_transaction）| `channel.rs:8315-8328` | ✅ |
| INV-8 | 自动应答：仅当对端 fee_rate >= commitment_fee_rate 时 auto-reply | `channel.rs:6215-6219` | ✅ |
| INV-9 | 开通时校验：`reserved_ckb_amount >= occupied_capacity(shutdown_script)`（严格 `<`） | `fee.rs:163-169`, `channel.rs:5281-5287` | ✅ |
| INV-10 | 协作关闭：`check_shutdown_fee_valid` 对端 fee_rate >= commitment_fee_rate | **❌ 未实现** | ⚠️ **F1** |
| INV-11 | 协作关闭：close_script 的 occupied_capacity 不得超过 reserved_ckb | `check_shutdown_fee_valid:6205-6210` 用 `saturating_sub` 退化为 0 | ⚠️ **F3** |

## 3. 发现

### 3.1 F1 (🟠 High → Medium 实际) — `check_shutdown_fee_valid` 未对对端 `fee_rate` 设最低限

**位置**：`channel.rs:6189-6213` vs `channel.rs:5303-5338`

**对照**：
```rust
// 本地侧（自检）：
fn check_shutdown_fee_rate(&self, fee_rate: FeeRate, close_script: &Script) -> ProcessingChannelResult {
    if fee_rate.as_u64() < self.commitment_fee_rate {     // ← 强制不低于
        return Err(...);
    }
    ...
}

// 对端侧（验对端发来的）：
fn check_shutdown_fee_valid(&self, remote_fee_rate: u64) -> bool {
    let remote_shutdown_fee = calculate_shutdown_tx_fee(remote_fee_rate, ...);  // ← 没下限
    let remote_available_max_fee = self.remote_reserved_ckb_amount.saturating_sub(occupied_capacity);
    remote_shutdown_fee <= remote_available_max_fee  // ← 只验上限
}
```

**问题 A — 对端可发 `fee_rate=0` 通过校验**：

- 对端发 `Shutdown{fee_rate=0}` → `handle_shutdown_peer_message:1662` 调用 `check_shutdown_fee_valid(0)`；
- `remote_shutdown_fee = 0`，必然 `<= remote_available_max_fee` → 返回 true → **接受**；
- 我方 `step_shutting_down` 调用 `check_valid_to_auto_accept_shutdown`：检查 `remote_fee_rate >= commitment_fee_rate` → false → **不自动应答**；
- 通道卡在 `ShuttingDown(THEIR_SHUTDOWN_SENT)` 状态。**本地用户必须手动 RPC 触发 shutdown** 才能推进。
- 当本地用户 `handle_shutdown_command` 触发：`check_shutdown_fee_rate` 强制本地 `fee_rate >= commitment_fee_rate`，然后 `build_shutdown_tx`：
  - `local_fee = local_fee_rate × tx_size`（足额）
  - `remote_fee = 0 × tx_size = 0`
  - 总 tx 费 = local_fee（仅）。如果 `commitment_fee_rate` 已经覆盖整笔 tx 体积下的网络最低 fee，则 tx 可上链 → **本地承担 100% 关闭 tx 费用**，对端零成本。

**问题 B — 协作关闭的费用承担不对称**：

LN BOLT-2 默认是 funder 出 shutdown_fee 全额，对端为 0。Fiber 设计为各自从 reserved_ckb_amount 扣自己的 fee（INV-4），但 INV-10 缺失使得对端可单方面把 fee 推给本地。

**严重级别**：🟡 Medium — 经济损失（commitment tx 体积通常 ~600 字节，按当前 fee rate 损失 < 1 CKB 级别），但**可重复利用**：恶意 peer 每次都用 `fee_rate=0` 发起，迫使另一方持续买单。结合 jamming/DoS 场景，可作为持续骚扰原语。

**建议**：

```rust
fn check_shutdown_fee_valid(&self, remote_fee_rate: u64) -> bool {
+   // Symmetry with check_shutdown_fee_rate: reject below-minimum fee_rate.
+   if remote_fee_rate < self.commitment_fee_rate {
+       return false;
+   }
    let remote_shutdown_fee = calculate_shutdown_tx_fee(...);
    ...
}
```

### 3.2 F2 (🟡 Medium) — `build_shutdown_tx` UDT 分支用 plain subtraction，依赖前置校验且校验有缺口

**位置**：`channel.rs:8051, 8063`

```rust
let local_capacity: u64 = self.local_reserved_ckb_amount - local_shutdown_fee;       // line 8051
...
let remote_capacity: u64 = self.remote_reserved_ckb_amount - remote_shutdown_fee;    // line 8063
```

- 本地侧由 `check_shutdown_fee_rate` 保护（`fee <= local_reserved_ckb_amount - occupied_capacity`）。如果 `funding_udt_type_script.is_some()`：`available_max_fee = local_reserved_ckb_amount - occupied_capacity`，所以 `local_shutdown_fee <= local_reserved_ckb_amount - occupied_capacity < local_reserved_ckb_amount` ✓。
- 对端侧由 `check_shutdown_fee_valid` 保护（line 6205-6210 `saturating_sub`），**但**：
  - 如果 `occupied_capacity > remote_reserved_ckb_amount`：`saturating_sub` 返回 0，`remote_shutdown_fee == 0` 仍然 `<= 0` 通过 → 进入 `build_shutdown_tx`；
  - 此时 `remote_reserved_ckb_amount - remote_shutdown_fee = remote_reserved_ckb_amount`（subtraction 不下溢）但 `< occupied_capacity` 即 **CKB 输出 cell capacity 不足以承载其自身**。

**触发场景**：对端的 close_script 与开通时的 shutdown_script 不同（开通时被 `check_open_channel_parameters:163-169` 校验严格 `<`，但 close 时可换 script），且新 script 的 args 较大（如 100 字节 args 的多签或合约脚本），使得 `occupied_capacity(new_close_script) > remote_reserved_ckb_amount`。

**后果**：
- 我方签名一个 capacity 不足的 CKB tx；
- 广播后被 CKB 节点拒（违反 capacity ≥ occupied_capacity 共识规则）；
- 通道卡在 `ShuttingDown(WAITING_COMMITMENT_CONFIRMATION)` 不前进。
- 需要本地 force close 才能恢复。

**严重级别**：🟡 Medium —— DoS 协作关闭流程；恢复需 force close（资源浪费 + 1 个 commitment delay epoch 等待）。

### 3.3 F3 (🟡 Medium) — `handle_shutdown_peer_message` 未对 close_script 做开通时同等强度校验

**位置**：`channel.rs:1622-1676`，对照 `fee.rs:163-169`

开通时 `check_open_channel_parameters` 用 **严格 `<` 比较** 校验 `reserved_ckb_amount >= occupied_capacity(shutdown_script)`：

```rust
if reserved_ckb_amount < occupied_capacity {
    return Err(...);
}
```

但 `handle_shutdown_peer_message` 接受的 `shutdown.close_script` **没有同等校验**。只有 `check_shutdown_fee_valid` 间接通过 `saturating_sub` 处理 `occupied_capacity` —— 退化为 0 而非拒绝。

**与 F2 协同形成完整 DoS**：

| 步骤 | 攻击者动作 | 我方反应 |
|---|---|---|
| 1 | 发 `Shutdown{close_script=<args=200B>, fee_rate=0}` | `check_shutdown_fee_valid` 通过（saturating_sub→0, fee=0≤0）|
| 2 | 等我方手动 shutdown | 我方 `check_shutdown_fee_rate` 通过（自身参数 OK）|
| 3 | — | `build_shutdown_tx` 产出对端 capacity < occupied_capacity 的 tx |
| 4 | — | 我方部分签名 + 聚合广播 → CKB 拒绝 |
| 5 | — | 通道卡死，需 force close |

**严重级别**：🟡 Medium —— DoS。修复见 F1/F2 联合补丁。

**建议**：

```rust
async fn handle_shutdown_peer_message(&self, state: &mut ChannelActorState, shutdown: Shutdown) {
    ...
+   // Validate close_script against remote's reserved CKB budget,
+   // mirroring check_open_channel_parameters.
+   let occupied = occupied_capacity(&shutdown.close_script, &state.funding_udt_type_script)
+       .map_err(|e| ProcessingChannelError::InvalidParameter(e.to_string()))?;
+   if state.remote_reserved_ckb_amount < occupied.as_u64() {
+       return Err(ProcessingChannelError::InvalidParameter(
+           "remote close_script occupied_capacity exceeds remote_reserved_ckb_amount".to_string()));
+   }
    ...
}
```

### 3.4 F4 (🟢 Low) — `get_latest_commitment_transaction` 使用 `.expect` 可 panic

**位置**：`channel.rs:8315-8328`

```rust
pub async fn get_latest_commitment_transaction(&self) -> Result<TransactionView, ProcessingChannelError> {
    let tx = self
        .latest_commitment_transaction
        .clone()
        .expect("latest_commitment_transaction should exist");   // ← panic source
    ...
}
```

调用点：`handle_shutdown_command(force=true)`（line 1996）。该函数前置校验 `state == ChannelReady || ShuttingDown`，正常情况下 `latest_commitment_transaction` 必为 Some。但：
- 若状态机演化或测试代码绕过校验，`expect` 会 panic 整个 actor → channel actor 重启 → 状态可能损坏；
- 若并发场景下 `latest_commitment_transaction` 临时为 None（如 reestablish 中），也会 panic。

**严重级别**：🟢 Low —— 当前 unreachable，但脆弱。

**建议**：

```rust
- let tx = self.latest_commitment_transaction.clone()
-     .expect("latest_commitment_transaction should exist");
+ let tx = self.latest_commitment_transaction.clone().ok_or_else(|| {
+     ProcessingChannelError::InvalidState(
+         "latest_commitment_transaction missing for force close".to_string())
+ })?;
```

### 3.5 F5 (🟢 Low) — 强制关闭可在 `ShuttingDown(WAITING_COMMITMENT_CONFIRMATION)` 中重复触发

**位置**：`channel.rs:1977-2012`

```rust
if command.force {
    match state.state {
        ChannelState::ChannelReady => { ... }
        ChannelState::ShuttingDown(flags) => {        // ← 允许任何 ShuttingDown flags
            debug!("Handling force shutdown command in ShuttingDown state, flags: {:?}", &flags);
        }
        _ => { return Err(...) }
    };
    let transaction = state.get_latest_commitment_transaction().await?;
    self.network.send_message(...ClosingTransactionPending(transaction, force=true));
    state.update_state(ChannelState::ShuttingDown(ShuttingDownFlags::WAITING_COMMITMENT_CONFIRMATION));
    return Ok(());
}
```

**场景**：协作关闭 `ClosingSigned` 已交换 + `shutdown_tx` 已广播 + `state == ShuttingDown(WAITING_COMMITMENT_CONFIRMATION)`，此时用户再调用 force shutdown：
- `get_latest_commitment_transaction` 取到原始 commitment tx；
- 广播 commitment tx —— 与 shutdown_tx **争抢同一个 funding cell input**；
- CKB 矿工只能确认其中一个，另一个被弃；
- 双方各损失被弃 tx 的广播费（但 fee 是从 capacity 内部扣，所以实际是放弃了原 tx 的资源占用）。

**严重级别**：🟢 Low —— 主要影响用户体验和资源效率；安全角度无资金损失（force close 仍能完成关闭）。

**建议**：

```rust
ChannelState::ShuttingDown(flags) => {
+   if flags.contains(ShuttingDownFlags::WAITING_COMMITMENT_CONFIRMATION) {
+       return Err(ProcessingChannelError::InvalidState(
+           "force close already in progress (WAITING_COMMITMENT_CONFIRMATION)".to_string()));
+   }
    debug!("Handling force shutdown command in ShuttingDown state, flags: {:?}", &flags);
}
```

### 3.6 F6 (🟢 Low) — 自动应答 shutdown 使用 `FeeRate::from_u64(0)`

**位置**：`channel.rs:8506`

```rust
if self.check_valid_to_auto_accept_shutdown() && should_we_reply_shutdown {
    let close_script = self.get_local_shutdown_script();
    self.network().send_message(...Shutdown {
        channel_id: self.get_id(),
        close_script: close_script.clone(),
        fee_rate: FeeRate::from_u64(0),    // ← 0
    }));
    self.local_shutdown_info = Some(ShutdownInfo {
        close_script,
        fee_rate: 0,
        signature: None,
    });
    ...
}
```

自动应答场景下，本节点声明 `fee_rate=0`，由对端独自承担整个 shutdown_tx fee。这是**有意识的设计**：
- 对端发起 shutdown（已支付了承诺 `fee_rate >= commitment_fee_rate`，参见 INV-8）；
- 本节点视作被动方，象征性 `fee_rate=0` 是"协作意愿表达"，由对端独自付费完成关闭；
- 与 LN BOLT-2 "non-funder is fee-free" 习惯一致。

**潜在问题**：如果对端的 `commitment_fee_rate` 刚好够单边支付 tx fee 而无 buffer，且 CKB 网络拥堵需更高 fee rate，则 tx 进不了 mempool。

**严重级别**：🟢 Low（设计权衡）—— 建议在文档明确说明，并可考虑在网络拥堵自适应场景下让自动应答方贡献最小 fee。

### 3.7 F7 (🟢 Low / 历史 TODO) — `step_shutting_down` 内有未解决的 pending TLC 处理 TODO

**位置**：`channel.rs:8520-8522`

```rust
// TODO: there maybe some tlcs still not settled when shutdown,
// we need to check if we need to trigger remove tlc for previous channel
// maybe could be done in cron task from network actor.
self.update_state(ChannelState::ShuttingDown(flags));
```

`maybe_transfer_to_shutdown:6544` 要求 `AWAITING_PENDING_TLCS && all TLCs settled` 才推进到 build_shutdown_tx。但中间状态下，如果作为 forwarding hop（即本节点中转中），下游通道的 TLC 没收到 RemoveTlcXxx，本节点 inbound TLC 也无法 settle。`maybe_transfer_to_shutdown` 会持续等待。

**风险**：
- 通道在 ShuttingDown 状态下保留所有 inbound TLC，资源被占用；
- 上游通道（向我方付款的那个）也无法关闭，因为 inbound TLC 处于"待 forward 结果"状态；
- TLC expiry 到期前 settle，通道卡死至 expiry，最终触发 force close 路径。

**严重级别**：🟢 Low（无资金损失，但运营层面影响：长期未 settle 的 TLC 会强制 force close → CSV delay）。

### 3.8 F8 (ℹ️ Info / Pass) — 协作关闭对 TLC 的对称保护

**位置**：`channel.rs:1632-1642` (peer-side) vs `channel.rs:2017-2027` (local-side)

- 本地侧：拒绝 LocalAnnounced 出 TLC 时发起 cooperative shutdown；
- 对端侧：拒绝 RemoteAnnounced 入 TLC 时接受对端 cooperative shutdown。

两侧对未签名的"半开"TLC做对称保护，确保关闭时所有 TLC 都已进入 commitment（一致状态）。**Pass**。

### 3.9 F9 (ℹ️ Info / Pass) — `get_latest_commitment_transaction` 始终返回非撤销版本

**位置**：`channel.rs:8315-8328`，结合 commitment_signed/revoke_and_ack 状态机

`latest_commitment_transaction` 字段只在 receive `commitment_signed` + verify peer signature 成功后更新（参见 LOGIC-003 中 commitment_number 单调递增的不变式 INV-1）。每次更新后，旧的 commitment tx 被 peer 持有的 `revocation_secret` 撤销（如果对端持有），但本节点持有的是带 peer 部分签名的**最新**版本。force close 广播此版本是安全的（**peer 无法用 revocation secret 攻击 own latest commitment**）。

**Pass**。这是 lightning 风格 commitment_number/revoke 机制的核心安全属性。

## 4. 结论

| 子项 | 严重级别 | 状态 |
|---|---|---|
| F1 — `check_shutdown_fee_valid` 缺少最低 fee_rate 校验 → fee 推卸 | 🟡 Medium | ⚠️ 未修复 |
| F2 — `build_shutdown_tx` plain sub + saturating_sub 漏洞窗口 | 🟡 Medium | ⚠️ 未修复 |
| F3 — `handle_shutdown_peer_message` 未严格校验 close_script.occupied_capacity | 🟡 Medium | ⚠️ 未修复 |
| F4 — `get_latest_commitment_transaction` 中 `.expect` | 🟢 Low | ⚠️ 未修复 |
| F5 — 力关可在 WAITING_COMMITMENT_CONFIRMATION 重复触发 | 🟢 Low | ⚠️ 未修复 |
| F6 — 自动应答 fee_rate=0 设计权衡 | 🟢 Low (design) | — |
| F7 — pending TLC 处理 TODO | 🟢 Low (existing TODO) | ⚠️ 未修复 |
| F8 — TLC 对称保护 | ℹ️ Info / Pass | — |
| F9 — `latest_commitment_transaction` 非撤销不变式 | ℹ️ Info / Pass | — |
| 整体严重 | 🟠 High (F1+F2+F3 协同) | — |

**协同攻击链**（F1 + F2 + F3）：恶意 peer 一次构造 `Shutdown{close_script=<oversize>, fee_rate=0}`：
1. F1: 我方接受 fee_rate=0（无下限校验）；
2. F3: 我方接受 oversize close_script（无 occupied_capacity 检查）；
3. 等待我方手动应答（auto-accept 不触发）；
4. F2: 我方应答后 build_shutdown_tx 产出无效 tx；
5. 广播被 CKB 拒；
6. 通道卡死 → 只能 force close。

**最终影响**：恶意 peer 无法窃取资金，但可单方面把通道推入 "**协作关闭不可达 → 强制关闭 → CSV delay 期资金锁定**"。结合 LOGIC-002.F1 / LOGIC-004.F1 的 jamming 原语，可形成"先 jam 再 deadlock close"的组合攻击。

## 5. Follow-ups

- **AUDIT-LOGIC-007-FOLLOWUP-A**：编写 PoC — 构造 oversize close_script + fee_rate=0 的 Shutdown，验证 F1+F2+F3 协同 DoS。
- **AUDIT-LOGIC-007-FOLLOWUP-B**：实施统一补丁（F1+F3）：在 `check_shutdown_fee_valid` 和 `handle_shutdown_peer_message` 中分别加 `fee_rate >= commitment_fee_rate` 和 `occupied_capacity(close_script) <= remote_reserved_ckb_amount` 严格校验。
- **AUDIT-LOGIC-007-FOLLOWUP-C**：F4 改 `.expect` 为 `Result`；F5 加 `WAITING_COMMITMENT_CONFIRMATION` 守卫。
- **AUDIT-LOGIC-007-FOLLOWUP-D**：解决 F7 pending TLC TODO —— 评估在 ShuttingDown 状态下如何向上游 channel 主动发起 RemoveTlcFail（"channel closing"错误码）。
