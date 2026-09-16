# AUDIT-XMOD-001 — Payment ↔ Gossip 跨模块：TlcErr `channel_update` 经 `BroadcastMessages` 全网放大

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟠 **High**（slander 攻击的全网放大形态，对网络可用性高影响） |
| 状态 | [!] 发现弱设计（静态可达，无 PoC） |
| 出处 | 本次跨模块审计；基于 AUDIT-ERR-001.F2 / "graph slander attack" 记忆扩展 |
| 关联代码 | `crates/fiber-lib/src/fiber/payment.rs:1076-1117`<br>`crates/fiber-lib/src/fiber/network.rs:NetworkActorCommand::BroadcastMessages`<br>`crates/fiber-lib/src/fiber/gossip.rs:3121-3142`（消息扩散）<br>`crates/fiber-lib/src/fiber/history.rs:170-180`（正确范本） |
| 关联 finding | AUDIT-ERR-001.F2/F3、AUDIT-LOGIC-001 |

## 1. 现象

`update_graph_with_tlc_fail` 接收远程对端（任意中转 hop）解 sphinx 后的 `TlcErr`，对 `error_code.is_update()` 分支：

```rust
// payment.rs:1083-1098
if error_code.is_update() {
    if let Some(TlcErrData::ChannelFailed {
        channel_update: Some(channel_update),
        ..
    }) = &tlc_error_detail.extra_data
    {
        network
            .send_message(NetworkActorMessage::new_command(
                NetworkActorCommand::BroadcastMessages(vec![
                    BroadcastMessageWithTimestamp::ChannelUpdate(channel_update.clone()),
                ]),
            ))
            .expect(ASSUME_NETWORK_MYSELF_ALIVE);
    }
}
```

此处把 attacker-controlled `extra_data.channel_update` **直接转发到 gossip 广播**：
1. 不校验该 `channel_update` 所指通道是否属于本次 attempt 的 route；
2. 不校验该 `channel_update.signature` 是否能由通道任一端节点公钥验证（gossip 入站验证在另一边，但此处由本节点 *主动转发* — 后续邻居倾向于信任此广播来自本地，加速扩散）；
3. 不限速（每次失败转发一次）；
4. 错误处理用 `.expect(ASSUME_NETWORK_MYSELF_ALIVE)`（本地不可恢复）。

紧接其后 (line 1099-1116) 还会再无校验地 `mark_channel_failed` / `mark_node_failed`（这部分由 AUDIT-ERR-001.F2 已记载）。

## 2. 与已有发现的区别

`AUDIT-ERR-001.F2` 仅覆盖 *本地图* 的 slander（mark_channel_failed / mark_node_failed），影响范围 = 本节点路由选路。

本条 (XMOD-001) 覆盖 *跨模块* 升级：通过 `NetworkActorCommand::BroadcastMessages` 把 payment 模块的 TlcErr 处理副作用注入 **gossip 模块的广播池**。影响范围 = **全网下游邻居都会收到并按 gossip 协议二次扩散**，等于把一个 channel slander 攻击放大成 gossip 网络污染。

## 3. 攻击场景

**前提**：攻击者 A 是任意节点 V 的中转 hop。

1. V 发起一笔正常支付，A 在 sphinx 路径中。
2. A 不转发，构造 `TlcErr`：
   - `error_code = TlcErrorCode::TemporaryChannelFailure`（`.is_update() == true`，见 `payment.rs:TlcErrorCode::is_update` 与 `fiber/types/src/payment.rs:808-834`）
   - `extra_data = ChannelFailed { channel_outpoint: <某热门通道 C 的 outpoint>, node_id, channel_update: Some(<伪造 ChannelUpdate>) }`
3. A 把伪造的 `ChannelUpdate` 里设置 `channel_flags = DISABLED`（或 fee_rate 极端值），signature 字段填零。
4. V 解 sphinx → 进入 `update_graph_with_tlc_fail`：
   - V 本地图屏蔽 C（ERR-001.F2）
   - V **主动调用 gossip 广播** 该 `channel_update` 到所有邻居
5. 邻居节点的 gossip handler 接收 → 触发签名校验（gossip 侧 *可能* 验签拒绝 — 见 mitigation 评估）
   - 若 gossip 入站验签缺失或被绕过 → 全网污染
   - 若 gossip 入站验签生效 → 至少**单跳邻居**已耗费 CPU+解包带宽

**资源放大**：V 一次 TlcErr 处理 → 1 次 BroadcastMessages → gossip 默认 fanout 把消息推到 N 个邻居 → 每个邻居解 + 验签 + 入队 → 单节点工作量 × N 节点

## 4. 缓解评估

实际执行 BroadcastMessages 后，最终发出 (broadcast) 之前 gossip 子系统会有 `verify_channel_update` 验签步骤。但：

- **本地这一跳无验签 bypass**：`update_graph_with_tlc_fail` 直接构造 `BroadcastMessageWithTimestamp::ChannelUpdate(channel_update.clone())` 调 `BroadcastMessages`，本地图层的 `mark_channel_failed` 已先生效；
- **gossip 验签若失败**：消息被丢弃，但 V 节点本地图已被污染；
- **gossip 验签若通过**（攻击者拥有该通道签名权限 — 例如 A 自己是 C 的端点的另一种联合攻击）：全网污染成立。

即使 verify 成功，正常 gossip ChannelUpdate 需要 timestamp 单调 + 频率限制；本路径是否绕过了 timestamp 单调与频率限制需要进一步验证（gossip.rs:3121-3142）。

## 5. F-编号清单

| 编号 | 严重度 | 描述 |
|---|---|---|
| F1 | 🟠 High | `update_graph_with_tlc_fail` 把 attacker-controlled `channel_update` 转发到 gossip 广播池，无 route-membership 校验，无频率限制 |
| F2 | 🟡 Medium | gossip 入站验签 + timestamp 单调性是否在 BroadcastMessages **出站** 路径生效需要静态二次确认；若验签仅在 *入站* 侧，则本节点等于绕过自我验证 |
| F3 | 🟢 Low | `.expect(ASSUME_NETWORK_MYSELF_ALIVE)` 死路 panic — 与 actor mailbox 内存事实一致 |

## 6. 修复建议

**FOLLOWUP-A (🟠 High, 必修)**：在 `update_graph_with_tlc_fail` 转发 channel_update 之前，加入：
1. 检查 `channel_update.channel_outpoint` ∈ `attempt.route.hops.map(|h| h.channel_outpoint)`；不在则丢弃 + warn。
2. 检查 `channel_update.signature` 可由通道任一端节点公钥验证（同 gossip 入站校验路径，复用现成函数）。
3. 每条 channel 出站转发 `channel_update` 设速率限制（per channel_id 1/min），与 gossip 节流策略一致。

**FOLLOWUP-B (🟡 Medium)**：把 `update_graph_with_tlc_fail` 内两段逻辑（broadcast forward + 本地图标记）合并复用 `history.rs::record_payment_fail` 的 `error_index` 模板，做一次性 route-membership 检查。

**FOLLOWUP-C (🟢 Low)**：`.expect(ASSUME_NETWORK_MYSELF_ALIVE)` 改 `if let Err(e) = ... { error!("..."); }`，避免 PaymentActor panic。

## 7. 测试用例草案

1. **route-membership unit test**：构造一个 3-hop attempt，让中间 hop 返回 `TlcErr { extra_data: ChannelFailed { channel_outpoint: <off-route OP>, channel_update: Some(_) } }`，断言：
   - 本地图未 `mark_channel_failed`
   - 未发送 `BroadcastMessages`
2. **rate-limit unit test**：连续 10 次同 channel 失败，断言 BroadcastMessages 只发 1 次。
3. **signature verify unit test**：channel_update.signature 错误时直接拒绝。

## 8. 引用与跟踪

- 与 AUDIT-ERR-001.F2/F3 同源；本条独立提级是因为 *跨模块* 放大效应（payment → gossip）在 ERR-001 章节未充分量化。
- 与 AUDIT-MEM-001 (gossip OOM) 协同：若 F1 不修，攻击者通过 N × payment attempt 持续注入伪造 channel_update → gossip 入存池更快撑满。
- 与 AUDIT-LOGIC-001 (`UpdateTlcInfo` 无状态守卫) 思路一致：fiber 多处把"对端给的 channel_update / channel_announcement"信任了实际不应信任的字段。
