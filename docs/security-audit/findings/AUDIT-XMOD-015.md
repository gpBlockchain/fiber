# AUDIT-XMOD-015 — CKB tx_tracing ↔ Channel ↔ Watchtower ↔ Store 浅确认深度 + 无 reorg rollback

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟠 **High**（影响：funding/closing tx 在 channel-state 角度"消失"，资金 brick 或反 cheat 失效；触发：≥4-block CKB reorg，自发概率低但**网络分区 / selfish-mining / 矿池协同**可放大；综合"影响极重 × 触发非平凡"评 High，运营商应将其作为安全模型显式假设记录在案） |
| 状态 | [!] 发现弱设计（静态可达，依赖 CKB 共识层 reorg 深度；NC-Max 下 4-block reorg 罕见但非不可能） |
| 出处 | 本次跨模块审计新发现；横向回顾 `CKB_TX_TRACING_CONFIRMATIONS=4` 常量及其使用面 |
| 关联代码 | `crates/fiber-lib/src/fiber/network.rs:119`（`pub const CKB_TX_TRACING_CONFIRMATIONS: u64 = 4;`）<br>`crates/fiber-lib/src/fiber/network.rs:4324-4347`（`trace_tx`：funding 路径用 4 confs）<br>`crates/fiber-lib/src/fiber/network.rs:4349-4385`（`send_tx`：closing/settlement 路径同样用 4 confs）<br>`crates/fiber-lib/src/ckb/tx_tracing_actor.rs:65,272-278`（`tracer.confirmations` 比较 `tip_block_number - last_block ≥ confirmations` 后**立即 swap_remove 不可回退**）<br>`crates/fiber-lib/src/fiber/channel.rs:3054-3084`（`FundingTransactionConfirmed` → `state.funding_tx_confirmed_at = Some(...)` → 直接进 `AwaitingChannelReady` → 后续接受 TLC，**无 reorg 重新校验路径**）<br>`crates/fiber-lib/src/ckb/tx_tracing_actor.rs:250-285`（callback 已发后 tracer 从 `tx_tracers.tracers` swap_remove → 之后即便链上状态回退到 `Unknown`/`Rejected` 也无回调） |
| 关联 finding | AUDIT-LOGIC-003（watchtower revocation 覆盖式 + 上链路径），AUDIT-INPUT-005（watchtower lock_args 守卫），AUDIT-XMOD-006（反 cheat 链），AUDIT-XMOD-002（CCH 时序）|

## 1. 现象

`CKB_TX_TRACING_CONFIRMATIONS = 4` 是**唯一**控制 fiber 内部 "tx 已确认" 判定的常量；该常量同时被以下三类资金敏感事件复用：

1. **Funding tx**：`NetworkActorCommand::*` → `trace_tx(tx_hash, InFlightCkbTxKind::Funding(channel_id))` (`network.rs:3573, 4324-4347`)；
2. **Closing/Settlement tx**：`send_tx(tx, InFlightCkbTxKind::Closing(...))` (`network.rs:5090, 5334`)；
3. **测试快路径**：gossip `verify_and_save_broadcast_message` 测试桩 (`gossip.rs:2336-2340`, confirmations=0)。

CKB 主网典型出块时间 ≈ 10 秒，4 confirmations ≈ **40 秒**。对比 Bitcoin Lightning 通常 6 块 / 30~60 分钟，fiber 的默认置信窗口浅一个数量级。

`tx_tracing_actor.rs:269-278` 的关键逻辑：

```rust
if tracer.mask.contains((&tx_status).into())
    && tip_block_number.saturating_sub(tx_tracers.last_block) >= tracer.confirmations
{
    let tracer = tx_tracers.tracers.swap_remove(i);
    let _ = tracer.callback.send(result.clone());
}
```

一旦 callback 触发，`tracer` 即被 `swap_remove` 移除 — 后续即便链上回滚到 `Unknown`/`Rejected`，该 tracer 永不再触发；channel 也没有反向"撤销 confirmation"的 actor 消息（搜 `grep -rn "Reorg\|UnConfirmed\|rollback" crates/fiber-lib/src/fiber/` 0 命中业务路径）。

## 2. 跨模块攻击链

```
attacker 控制对端 / 受害者节点
        │
        ├─ (A) 与受害者 open channel，funding tx 上链到 block N
        │       │
        │       ▼ block N+4，tip = N+4
        │   tx_tracing_actor 触发 callback → InFlightCkbTxActor → NetworkActor
        │       │
        │       ▼ NetworkActorEvent::FundingTransactionConfirmed
        │   ChannelActor: state.funding_tx_confirmed_at = Some(...)
        │       │
        │       ▼ ChannelState::AwaitingChannelReady → ChannelReady
        │   双方开始发 TLC、累积 commitment_number
        │
        ├─ (B) ≥4 block reorg 把 N 块从链上剔除（受 CKB NC-Max 概率约束，但有 selfish-mining / 网络分区构造场景）
        │       │
        │       ▼ tx_tracing_actor 不再回调（tracer 已 swap_remove）
        │   ChannelActor 仍处于 ChannelReady，对外接受 / 转发 TLC
        │       │
        │       ▼ 攻击者发动 force-close 或合作 close
        │   broadcasts commitment_tx → 但 funding cell 不存在 → CKB 拒绝 tx
        │
        └─ (C) 受害者无法 force-close → 永久 brick（资金锁死直到 CSV 超时也不通——因为 input cell 不存在）
```

同样的链可作用于 closing/settlement tx：watchtower 在 cheat 检测后发 settlement，4 confs 后认为得手，但若 settlement 被 reorg 走、cheating tx 接着被另一条链 confirm，反 cheat **无重试逻辑**——形成 XMOD-006 反 cheat 链的另一种断裂方式。

## 3. 横向影响

| 资金事件 | 4-confs 路径 | reorg 后的后果 |
|---|---|---|
| Funding tx 确认 → ChannelReady | `network.rs:3573,4324` | 通道在"funding 已消失"的链上仍开放营业，最终 close 失败 → 资金 brick |
| Closing tx 确认 → 结算完成 | `network.rs:4349,5090` | watchtower / 用户认为已结算，但链上回滚后**对端可重新发起 cheat / 重花** |
| Settlement (watchtower) | 同 closing 路径 | 反 cheat 防线失效；与 XMOD-006 协同 |
| CCH order outgoing settle | CCH 依赖 channel close 事件链 | 与 XMOD-002 协同：24h 窗口 + reorg 撤销 settle → CCH 双向丢钱 |

跨模块边映射（对照 `MODULES.md` §3）：
- `ckb/tx_tracing` ↔ `InFlightCkbTxActor` (I5 死路 panic 已属 XMOD-009)；
- `InFlightCkbTxActor` ↔ `ChannelActor` (无反向 reorg 消息)；
- `ChannelActor` ↔ `Store` (持久化 `funding_tx_confirmed_at` 后无 unset 路径)；
- `WatchtowerActor` ↔ `ckb/client` (I8) 无 reorg rollback；
- `CchActor` ↔ Channel events 间接受影响（与 XMOD-002 协同）。

## 4. 与已有发现的区别

- **AUDIT-XMOD-006** 关注 watchtower 反 cheat 协同断裂的 *业务逻辑* 链（lock_args 守卫、revocation 覆盖、partial 不预校验）；本条聚焦 **chain reorg 维度** 的同一类断裂。
- **AUDIT-XMOD-002** 关注 CCH 与 HTLC final_expiry 的 *时序* 错配；本条关注 funding/closing confirmation depth 的 *深度* 错配。
- **AUDIT-LOGIC-003.F6** 处理 revocation_data 覆盖式存储；本条与之协同：reorg + 覆盖式 = 双重失效。
- 单独看 `network.rs:119` 只是一个常量；单独看 `tx_tracing_actor.rs` 只是一个 callback 触发器；单独看 `channel.rs::FundingTransactionConfirmed` 只是状态机推进 — **三者组合**才形成"reorg 后 channel 永久 brick / 反 cheat 防线断裂"。

## 5. 影响评估

- **资金 brick**（funding reorg-out）：受害者通道资金永久无法链上回收（input cell 不存在）；理论上 fiber 可以重发 funding，但当前实现把"已确认"作为不可逆状态机推进，无重发路径。
- **资金直损**（settlement reorg-out + cheating tx 反 confirm）：反 cheat 防线被绕过的窗口；与 XMOD-006 重叠但不依赖 lock_args 守卫缺失。
- **触发前提**：≥4-block CKB reorg。CKB NC-Max 共识下，自发 reorg 4 块概率 ~10^-3 量级（取决于哈希率分布），但 **网络分区 / 51% / selfish mining / 矿池协同** 可以放大；攻击者若控制少量算力可主动制造小幅 reorg。
- **触发成本**：远低于 BTC LN 同等场景（BTC LN 默认 6 块 / 1 小时窗口；fiber 4 块 / 40 秒）。

## 6. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | **P0** | `CKB_TX_TRACING_CONFIRMATIONS` 拆为三个独立常量并显著提高：`FUNDING_CONFIRMATIONS=24`（≈4 分钟）、`CLOSING_CONFIRMATIONS=12`、`SETTLEMENT_CONFIRMATIONS=24`；并允许在 `FiberConfig` 通过显式字段覆盖（且 schema 文档化最小值）。**升级注意事项**：(a) 这些常量目前**不进入持久化存储**（仅运行时判定 callback 时机），无 store migration 需求；(b) 重启后旧 channel state 的 `funding_tx_confirmed_at` 已设值，新阈值仅影响"尚未确认"的 in-flight tracer，故对已通过旧阈值确认的存量 channel 向后兼容；(c) RPC 与 yaml schema 文档化最小值 + `make gen-rpc-doc` 重生成（若新增公开字段）。 |
| F2 | **P0** | `tx_tracing_actor.rs` 在 callback 触发后**保留 tracer** 直到 `confirmations*2` 块仍处于 Committed；期间若 `tx_status` 回退到 `Unknown`/`Rejected`，发送 `Reorged(tx_hash)` 反向事件给订阅者。 |
| F3 | **P0** | 新增 `NetworkActorEvent::FundingTransactionReorged(channel_id)` / `SettlementTransactionReorged(channel_id)`；ChannelActor 收到后回退 `state.funding_tx_confirmed_at = None` 并拒绝新 TLC，进入 `ReorgRecovery` 子状态。 |
| F4 | P1 | watchtower `run_periodic_check` 在 reorg 事件下重新触发 cheat 扫描，禁止"已 settlement"作为永久判定。 |
| F5 | P1 | 文档化 *CKB reorg-depth 假设* 为审计可审查的协议级假设（与 SPEC-001 / SPEC-003 同处加章节），与 BOLT-04 `funding_locked` 6+ 块经验对齐。 |
| F6 | P2 | 集成测试：模拟 CKB reorg ≥ N 块（`ckb-testkit` / mock chain actor），断言 ChannelActor 进 `ReorgRecovery` 而非继续接收 TLC；watchtower 重新扫描。 |

## 7. 验证测试

- `channel::tests::test_funding_confirmation_reorg_recovery`：mock chain actor 在 callback 触发后报告 tx_status=`Unknown`，断言 ChannelActor 收 `FundingTransactionReorged`、拒绝下一个 `AddTlc`、状态变成 `ReorgRecovery`。
- `tx_tracing_actor::tests::test_reorg_after_callback_emits_reorged_event`：tracer 不在 callback 后立即移除；状态回退时回调订阅者新事件。
- `watchtower::tests::test_settlement_reorg_triggers_rescan`：settlement 4-confs 触发后链上 reorg 走，watchtower 重新扫描该 channel 的 commitment chain。
- `cch::tests::test_order_reorg_handling`：与 XMOD-002 协同测试 — order 已 settled 但 reorg 撤销 settlement，订单状态必须从 Success 回退。

## 8. 与 P0 修复合并建议

F1/F2/F3 应作为同一 PR：单独修 F1（提高 confs）只是延迟攻击窗口；F2/F3 才是结构性 fix。`MODULES.md` §3.2 在 I5/I8 边上需要补一句"reorg rollback 反向事件"作为信任不变量 INV-16 候选。

## 9. 状态

- F1+F2+F3 必须协同；其余补强。
- 关联 PR：暂无。
- 与 XMOD-002 / XMOD-006 共享反 cheat 防线修复路径，应在同一 Phase 1.5 → Phase 2 修复 sprint 内一并处理。
