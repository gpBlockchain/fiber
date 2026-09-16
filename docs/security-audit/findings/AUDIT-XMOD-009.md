# AUDIT-XMOD-009 — RPC ↔ all-actors ↔ ractor 无超时 / 无界 mailbox 全栈冻结

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟠 **High**（远程一行 RPC → 进程冻结 / OOM；零授权可达） |
| 状态 | [!] 发现弱设计（静态可达，无 PoC） |
| 出处 | 本次跨模块审计补强；基于 MEM-003 + INPUT-003 + "actor mailbox dos" 记忆 |
| 关联代码 | `crates/fiber-lib/src/rpc/utils.rs:50-84`（`handle_actor_call!` 宏统一 `call!` 无超时；覆盖 channel / payment / invoice / peer / info / dev RPC）<br>`crates/fiber-lib/Cargo.toml:38-40`（ractor 0.15 仅 `async-trait` feature，MPSC mailbox 默认无界）<br>`crates/fiber-lib/src/fiber/network.rs:116, 123, 133-134, 3484-3490, 5944-5974`（`DEFAULT_CHAIN_ACTOR_TIMEOUT = 5min`；`.expect(ASSUME_CHAIN_ACTOR_ALWAYS_ALIVE_FOR_NOW)` 死路 panic）<br>`crates/fiber-lib/src/fiber/payment.rs:1423-1438`（`SendPaymentOnionPacket` 也 5min）<br>`crates/fiber-lib/src/fiber/gossip.rs:1197-1240, 1521-1546`（`NewSubscription` / `QueryBroadcastMessages` 全 `call!` 无超时）<br>`crates/fiber-lib/src/utils/actor.rs:1-54`（`ActorHandleLogGuard` 15s 阈值——只记录、不中断） |
| 关联 finding | AUDIT-MEM-003（mailbox 容量）、AUDIT-INPUT-003（RPC 限流）、AUDIT-LOGIC-006 |

## 1. 现象

fiber 的 RPC → Actor 调用链有 4 层独立失防：

| 层 | 表现 | 引用 |
|---|---|---|
| L1 RPC → Network | `handle_actor_call!` 全部 `call!` 无超时 | rpc/utils.rs:58-84 |
| L2 Network → Channel/Chain | `network.rs:116` 仅 `DEFAULT_CHAIN_ACTOR_TIMEOUT=5min`，且 `.expect()` 死路 | network.rs:3484-3490 |
| L3 Channel → Chain → CKB RPC | payment.rs:1423 `SendPaymentOnionPacket` 5min | payment.rs:1423-1438 |
| L4 Gossip 内部 | `NewSubscription` / `QueryBroadcastMessages` 无超时 | gossip.rs:1197, 1521 |

**+ ractor 0.15 默认 MPSC 无界 mailbox**（Cargo.toml:38-40 没启用 `bounded` 相关 feature）→ 攻击者持续发 RPC，mailbox 永远收下、永远不丢；
**+ `ActorHandleLogGuard` 只 *记录*（>15s 阈值），不 *中断***。

## 2. 跨模块攻击链

```
RPC client ──→ NetworkActor.call!(...) ──→ ChannelActor.call!(...) ──→ ChainActor.call!(...) ──→ CKB RPC
                  (no timeout)               (no timeout)              (5min default)        (慢响应或挂起)
```

任一节点慢响应：
1. 调用方堵在 `call!()`；
2. 上游 RPC 任务不返回；
3. jsonrpsee `Server::builder()` 默认 100 conns / 10MB body（INPUT-003），但每个 conn 可触发 actor 入队一条消息；
4. mailbox 无界 → 持续入队 → 内存爆炸（OOM）。

进一步：若 chain actor 意外退出，`network.rs:3490 .expect(ASSUME_CHAIN_ACTOR_ALWAYS_ALIVE_FOR_NOW)` 主动 panic NetworkActor → 整个 fiber 进程崩溃。

## 3. 攻击场景

### 3.1 单 RPC slow-loris
1. 攻击者建立 100 个 RPC 连接，每条发 `send_payment` (mut payment hash)。
2. NetworkActor 把每条 enqueue → ChannelActor enqueue → 任一通道慢响应 → 全链路堵塞。
3. 5 分钟后超时（仅 ChainActor 有），但期间 mailbox 已积压数千条。
4. 配合 INPUT-003 的"大 body 字符串"，mailbox 单条字节数也大 → OOM 加速。

### 3.2 故意慢 CKB peer
1. 攻击者作为 fiber peer，吸引 victim 发起 channel update。
2. victim NetworkActor 调 ChainActor 校验 CKB 链上 funding cell → 攻击者控制 CKB RPC 返回（如挂代理）→ ChainActor `call!` 5min 内无返回。
3. NetworkActor 持续 `call!` ChainActor → 全部堆积。

### 3.3 chain actor 死路 panic
- chain actor 因 CKB RPC 错误 / 状态异常退出 → NetworkActor `.expect()` panic → fiber 进程退出。

## 4. 与已有发现的区别

- MEM-003 单独点出 mailbox 容量问题；
- INPUT-003 单独点出 RPC 限流；
- 本条强调 "**RPC 全栈无 timeout** + **actor `.expect()` 死路** + **无界 mailbox**" 三者协同放大成"单 RPC 端点 → 全进程冻结/OOM/崩溃"。

## 5. 影响评估

- 远程零授权（私网默认无鉴权，浏览器 CORS 失效都可达）；
- 单连接即可触发显著延迟；
- 与 XMOD-005 鉴权穿透协同 → 浏览器 fetch 触发；
- 与 XMOD-006 反 cheat 协同：进程冻结期间 watchtower 也冻结 → 资金风险窗口。

## 6. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | P0 | `handle_actor_call!` 改用 `call_t!(actor, msg, timeout)`，每条 RPC 显式 30s 超时（可配置）。覆盖 6 个 RPC 模块。 |
| F2 | P0 | ractor 0.15 启用 bounded mailbox（或所有 actor 启动时显式 `set_supervision_strategy` + 限定 mailbox 容量 1024）。 |
| F3 | P0 | 全仓 `.expect(ASSUME_*ACTOR_ALWAYS_ALIVE*)` 改为 `if let Err(e) = ... { error!(); /* graceful degrade */ }`；至少 NetworkActor 不因 ChainActor 退出而 panic。 |
| F4 | P0 | `gossip.rs:1197, 1521` NewSubscription / QueryBroadcastMessages 加 timeout（30s）。 |
| F5 | P1 | INPUT-003 同步收紧 `RpcConfig.max_connections=20` 默认 + `max_body_size=64KB`。 |
| F6 | P1 | `ActorHandleLogGuard` 超阈值时增加 metric / alert hook，不只 log。 |

## 7. 验证测试

- `rpc::tests::test_payment_rpc_times_out`：mock NetworkActor 不响应，RPC 30s 后返回 timeout error，连接释放。
- `actor::tests::test_bounded_mailbox_drops_on_full`：填满 mailbox 后新消息 backpressure；调用方收到 Err 非阻塞。
- `network::tests::test_chain_actor_panic_does_not_kill_fiber`：chain actor 主动 panic，NetworkActor 进入 degraded 模式，不退出。

## 8. 状态

- F1+F2+F3+F4 必须**一起**合入；F5/F6 后置加固。
- 关联 PR：暂无。
