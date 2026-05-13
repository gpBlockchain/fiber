# AUDIT-LOGIC-001 — 通道状态机非法转移

| 字段 | 值 |
|---|---|
| 维度 | DIM-LOGIC + DIM-DOS |
| 优先级 | 🔴 P0-Critical |
| 状态 | **[~] Medium × 1, Low × 3, Info × 2; 大量 Pass** |
| 审计会话 | S3 (2026-05-13) |
| 审计方法 | (状态 × 消息) 矩阵审查 + 守卫一致性比对 + 边界路径推演 |

## 1. 范围

- `crates/fiber-types/src/channel.rs:236-298` — `ChannelState` 枚举 + 8 个 `*Flags` bitflag 子状态
- `crates/fiber-lib/src/fiber/channel.rs:448-828` — 唯一的 P2P 消息分发入口 `handle_peer_message`
- 各子处理函数 (`handle_*_peer_message`, `verify_commitment_signed_and_send_ack`, `handle_tx_collaboration_msg`, `handle_reestablish_channel_message`)
- TLC 操作状态守卫 (`check_for_tlc_update`)

## 2. 状态空间概览

`ChannelState` 8 个主状态：
```
NegotiatingFunding(flags) → CollaboratingFundingTx(flags) → SigningCommitment(flags)
  → AwaitingTxSignatures(flags) → AwaitingChannelReady(flags) → ChannelReady
  → ShuttingDown(flags) → Closed(flags)
```

每个 `*Flags` bitflag 内部又有 2-4 个进度位（如 `OUR_INIT_SENT | THEIR_INIT_SENT`）→ 真实状态空间 ≈ 60+ 个状态。

每条 P2P 消息类型（`FiberChannelMessage` 共 17 种）应只在特定状态子集内被接受。审计采用 (状态 × 消息) 矩阵评估守卫完备性。

## 3. (状态 × 消息) 矩阵审计

| 消息 | 守卫所在 | 守卫强度 | 备注 |
|---|---|---|---|
| `AnnouncementSignatures` | `handle_peer_message:484` | ✅ 显式状态白名单 + `is_public()` 检查 | 见 §4.F2 |
| `AcceptChannel` | `handle_accept_channel_message:6632` | ✅ 严格 `== NegotiatingFunding(OUR_INIT_SENT)` | Pass |
| `TxUpdate` / `TxComplete` | `handle_tx_collaboration_msg:6688` | ✅ 仅在 `CollaboratingFundingTx` 接受 | Pass |
| `CommitmentSigned` | `verify_commitment_signed_and_send_ack:6845-6896` | ✅ 完整 match，5 个允许的状态 + `ShuttingDownFlags::is_ok_for_commitment_operation` | Pass，非常好 |
| `TxSignatures` | `handle_peer_message:605-712` | ⚠️ **见 §4.F1** — `AwaitingTxSignatures` 状态前没有显式状态守卫，依赖 `funding_tx.is_none()` 与 `should_local_send_tx_signatures_first()` | Low |
| `RevokeAndAck` | `handle_revoke_and_ack_peer_message:7289` | ⚠️ 只检查 `tlc_state.waiting_ack`，未显式检查 `ChannelState` | 见 §4.F3 |
| `ChannelReady` | `handle_peer_message:730-754` | ✅ 显式 match，仅 `AwaitingTxSignatures(TX_SIGNATURES_SENT)` 与 `AwaitingChannelReady` 接受 | Pass |
| `UpdateTlcInfo` | `handle_peer_message:755-759` | ❌ **见 §4.F4** — 无状态守卫，任意状态下接受 | Medium |
| `AddTlc` / `RemoveTlc` | `handle_add_tlc_peer_message` → `check_for_tlc_update:6337` | ✅ 仅 `ChannelReady` 或部分 `ShuttingDown` 接受 | Pass |
| `Shutdown` | `handle_shutdown_peer_message:1622` | ✅ 显式 match，处理 `ChannelReady` 与 `ShuttingDown` 重复检测 | Pass |
| `ClosingSigned` | `handle_peer_message:780-803` | ❌ **见 §4.F5** — 注释自承认 *"We also didn't check the state here."* | Low |
| `ReestablishChannel` | `handle_reestablish_channel_message:7409` | ✅ 完整状态分流；早期通道状态会触发 abort | Pass |
| `TxAbort` | `handle_peer_message:816-822` | ⚠️ **见 §4.F6** — 状态不允许中止时静默忽略，无错误返回 | Low |
| `TxInitRBF` / `TxAckRBF` | `handle_peer_message:823-826` | ✅ 显式 unsupported，仅 warn | Pass (设计如此) |

### 3.1 Reestablishing 时的消息门控 (`handle_peer_message:454-473`)

```rust
if state.reestablishing {
    match message {
        FiberChannelMessage::ReestablishChannel(...) => {...}
        _ => { debug!("Ignoring message while reestablishing: {:?}", message); }
    }
    return Ok(());
}
```
**Pass**：连接重建期间所有非 `ReestablishChannel` 消息被静默丢弃，避免在不一致状态下处理用户消息。但有 §4.F7 子问题。

## 4. Findings

### F1 (🟢 Low) — `TxSignatures` 缺少显式 `ChannelState` 守卫

**位置**：`channel.rs:605-712`

```rust
FiberChannelMessage::TxSignatures(tx_signatures) => {
    // 三个分支：external_funding 接收方 / external_funding 发送方 / 普通 (else)
    if state.ephemeral_config.external_funding.enabled && ... { ... }
    if state.should_local_send_tx_signatures_first() { ... }
    else {
        state.handle_tx_signatures(Some(tx_signatures.witnesses))?;
    }
}
```

`handle_tx_signatures`（line 6959）内部检查状态，但**外层三个分支不做状态匹配**，假设：
1. external_funding 路径上，funding_tx 存在意味着状态正确（但不校验 `state.state` 本身）。
2. 普通路径下委托给 `handle_tx_signatures` 内部检查（line 6967 的 `match self.state`）。

**风险**：
- 在 `ChannelReady` 状态下若 peer 发 TxSignatures（不应发生），外层两个 `if` 不会触发；普通分支会进入 `handle_tx_signatures` 但其内部 match 也只允许 `AwaitingTxSignatures` 状态，所以最终被阻塞 → **当前实现是安全的**，但**防御层级单薄**：若未来 `handle_tx_signatures` 的状态检查被重构丢失，外层分支变成无守卫窗口。

**建议**：在 `handle_peer_message` 中预先匹配 `ChannelState::AwaitingTxSignatures(_)` 或 `NegotiatingFunding(AWAITING_EXTERNAL_FUNDING)`，拒绝其它状态。

### F2 (🟢 Low) — `AnnouncementSignatures` 验证 TODO 未完成

**位置**：`channel.rs:496`

```rust
// TODO: check announcement_signatures validity here.
let AnnouncementSignatures {
    node_signature,
    partial_signature,
    ..
} = announcement_signatures;
state.update_remote_channel_announcement_signature(
    node_signature,
    partial_signature,
);
```

收到 peer 的 `AnnouncementSignatures` 后，**直接存入状态而不校验签名**。后续 `maybe_public_channel_is_ready` 触发 gossip 广播时才会使用。

**风险**：
- 攻击者通道伙伴发送垃圾 `node_signature` / `partial_signature` → 写入状态 → 后续生成无效的 `ChannelAnnouncement` 广播 → 网络中传播。Gossip 接收端会校验签名（在 `gossip.rs` 中），所以**网络层不会接受**。但是：
  - 本地状态被污染，后续重启/恢复时仍包含垃圾签名；
  - 浪费 gossip 流量；
  - 可能误导某些诊断工具。

**建议**：在写入前调用 `verify_announcement_signatures(...)` 或在 `maybe_public_channel_is_ready` 中转化为错误（拒绝公告通道）。

### F3 (ℹ️ Info) — `RevokeAndAck` 未显式校验 `ChannelState`

**位置**：`channel.rs:7284-7308`

```rust
fn handle_revoke_and_ack_peer_message(&mut self, ...) -> ProcessingChannelResult {
    if !self.tlc_state.waiting_ack {
        return Err(InvalidState("unexpected RevokeAndAck"));
    }
    ...
    let sign_ctx = match self.get_revoke_sign_context(true) { ... };
}
```

只检查 `waiting_ack`。隐含状态守卫：`get_revoke_sign_context(true)` 在状态/承诺号不一致时返回 `None`，被映射为 InvalidState 错误。因此**逻辑安全**。

**Info**：与 `CommitmentSigned`（有显式 match）不对称。从可读性 / 防御深度角度，建议增加显式 `ChannelState::ChannelReady | ShuttingDown(_)` 匹配。

### F4 (🟡 Medium) — `UpdateTlcInfo` 完全无状态守卫

**位置**：`channel.rs:755-759`

```rust
FiberChannelMessage::UpdateTlcInfo(update_tlc_info) => {
    state.remote_tlc_info = Some(update_tlc_info.into());
    state.update_graph_for_remote_channel_change();
    Ok(())
}
```

**任何状态下**收到 `UpdateTlcInfo` 都会写入 `remote_tlc_info`。包括：
- `NegotiatingFunding`（通道尚未建立）
- `Closed(_)`（通道已关闭）
- `ShuttingDown(_)`（正在关闭）

`remote_tlc_info` 控制 TLC 转发参数（fee, expiry delta, htlc_minimum_msat 等）：
```rust
state.update_graph_for_remote_channel_change();   // 写入网络图
```

**风险**：
- Peer 在通道生命周期任意时刻发送 `UpdateTlcInfo` → 本节点的网络图被更新 → 用于路由决策。可被滥用：
  - 在 `Closed` 通道上发送 → 已关闭通道仍出现在图中并接受路由请求；
  - 在 `NegotiatingFunding` 阶段就操纵图条目（通道尚未真正可用）。
- 没有 `WaitingTlcAck` / `last_was_revoke` 节流，peer 可高频发送 `UpdateTlcInfo` → 网络图反复更新（性能 DoS）。

**建议**：
- 仅在 `ChannelReady` 与 `ShuttingDown(flags)` 且 `flags.is_ok_for_commitment_operation()` 时接受；
- 增加频率/版本号限速（如要求新 `UpdateTlcInfo` 严格递增版本号或时间戳）。

### F5 (🟢 Low) — `ClosingSigned` 自承认不校验状态

**位置**：`channel.rs:780-803`

```rust
// Note that we don't check the validity of the signature here.
// ...
// We also didn't check the state here.
if let Some(shutdown_info) = state.remote_shutdown_info.as_mut() {
    shutdown_info.signature = Some(partial_signature);
}
state.maybe_transfer_to_shutdown().await?;
```

注释明确指出未做状态检查与签名校验，仅依赖 `remote_shutdown_info.is_some()` 间接守卫（只有在 `Shutdown` 路径之后才有值）。

**风险**：
- 攻击者乱序发送 `ClosingSigned`（在未发送 `Shutdown` 前）→ `remote_shutdown_info` 是 `None`，`if let` 不进入 → 安全。
- 但调用 `state.maybe_transfer_to_shutdown().await?` 无条件执行 → 浪费 CPU；如果该函数对不当状态 panic，则有 DoS 风险（需查看实现，未审计到该深度）。
- 签名校验延迟到 shutdown tx 构建时 → 错误检测点远离接收点，调试更难。

**建议**：增加显式状态守卫 `ChannelState::ShuttingDown(_)`，立即拒绝其它状态。

### F6 (🟢 Low) — `TxAbort` 静默忽略不合适状态

**位置**：`channel.rs:816-822`

```rust
FiberChannelMessage::TxAbort(_) => {
    if state.state.can_abort_funding() {
        state.update_state(ChannelState::Closed(CloseFlags::FUNDING_ABORTED));
        myself.stop(Some("Funding abort".to_string()));
    }
    Ok(())
}
```

`can_abort_funding`（channel.rs:285-297，types crate）只在 `NegotiatingFunding | CollaboratingFundingTx | SigningCommitment | AwaitingTxSignatures(!OUR_TX_SIGNATURES_SENT)` 返回 true。

**问题**：其它状态下**静默吞掉错误**（`Ok(())`），不通知 peer 也不日志。

**风险**：
- 攻击者反复发送 `TxAbort` 探测节点状态（虽然没有可见 oracle，但可能影响 metrics / 日志）；
- 真正的 buggy peer 状态机不会得到反馈；
- 与同文件其它 unsupported 消息（`TxInitRBF` 等）的 `warn!` 不一致。

**建议**：未通过守卫时返回 `InvalidState`，或至少 `warn!` 记录。

### F7 (ℹ️ Info) — Reestablishing 时静默忽略消息

**位置**：`channel.rs:469-471`

```rust
_ => {
    debug!("Ignoring message while reestablishing: {:?}", message);
}
```

在 reestablish 期间收到 `AddTlc / RemoveTlc / CommitmentSigned` 全部丢弃，仅 `debug!`。这是合理的（避免一致性破坏），但：
- peer 不会被通知错误 → peer 继续按其状态推进，可能进一步发散；
- 没有计数 / 限速 → peer 可借此持续淹没本节点。

**建议**：
- Info 级别，主要是改进点：将 `debug!` 提升为 `warn!` 并增加计数器；
- 超阈值（如 > 100 消息）则强制断开连接。

## 5. 命令路径（出站）对偶

`handle_*_command` 系列在 `channel.rs:1882+`（`handle_add_tlc_command`, `handle_remove_tlc_command` 等）。命令路径同样调用 `check_for_tlc_update` 与 `is_waiting_tlc_ack` 守卫。注释明确（line 2389）：

```rust
// This is the dual of `handle_tx_collaboration_msg`. Any logic error here is likely
// to present in the other function as well.
```

**Pass**：守卫对称，未发现新缺口。

## 6. Pass 总结

- 重大状态转换由 `update_state(...)` 单一入口控制（grep 显示 ~20 处调用），便于审计；
- `CommitmentSigned` 与 `Shutdown` 守卫非常完整；
- `check_for_tlc_update` 集中校验 TLC 操作的 TLC 方向、状态、in-flight 限额、waiting_ack；
- `Reestablishing` 模式正确隔离非 reestablish 消息；
- `handle_reestablish_channel_message` 对 5 个主状态分别处理，包含 commitment 号差值校验（`abs_diff > 1` 拒绝）。

## 7. 修复建议总结

| # | 严重级别 | 建议 |
|---|---|---|
| F4 | 🟡 Medium | `UpdateTlcInfo` 增加 `ChannelState::ChannelReady` / `ShuttingDown` 守卫 + 版本号/时间戳防重 |
| F1 | 🟢 Low | `TxSignatures` 在 `handle_peer_message` 增加显式状态匹配 |
| F2 | 🟢 Low | `AnnouncementSignatures` 完成 TODO 标记的签名验证 |
| F5 | 🟢 Low | `ClosingSigned` 增加 `ChannelState::ShuttingDown(_)` 守卫 |
| F6 | 🟢 Low | `TxAbort` 不通过守卫时返回错误或 warn 日志 |
| F3 | ℹ️ Info | `RevokeAndAck` 增加显式状态匹配（防御深度） |
| F7 | ℹ️ Info | Reestablishing 期间静默丢弃 → warn + 计数器 + 限速 |

## 8. 结论

通道状态机**整体设计良好**，主要状态转换由 `update_state(...)` 集中处理，关键消息（`CommitmentSigned`, `Shutdown`, `AcceptChannel`, `ReestablishChannel`）均有显式 match-based 守卫。

主要风险点是 **F4 `UpdateTlcInfo`** —— 这是唯一一个**完全无状态守卫**的 P2P 消息，可被滥用来污染网络图或 DoS。建议优先修复。

其余 F1/F2/F5/F6 为"防御深度"与"卫生"类问题，单独不构成可利用漏洞，但应在常规清扫中修补。
