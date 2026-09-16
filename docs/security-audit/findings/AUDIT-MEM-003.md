# AUDIT-MEM-003 — Actor mailbox 阻塞与 RPC 入口背压

- **维度**: DIM-MEM（资源 / 并发 / DoS）
- **严重级别**: 🟡 Medium（Medium × 1 + Low × 2 + Info × 3 + Pass × 1）
- **审计 Session**: S23 (2026-05-14)
- **关联代码**:
  - `crates/fiber-lib/src/rpc/utils.rs:50-84` (`handle_actor_call!` 宏 — 关键)
  - 所有 RPC 模块（`channel.rs`, `payment.rs`, `invoice.rs`, `peer.rs`, `graph.rs`, `info.rs`, `dev.rs`）通过此宏调用 NetworkActor
  - `crates/fiber-lib/src/fiber/network.rs:116` (`DEFAULT_CHAIN_ACTOR_TIMEOUT=300_000`)
  - `crates/fiber-lib/src/fiber/network.rs:123` (`ACTOR_HANDLE_WARN_THRESHOLD_MS=15_000`)
  - `crates/fiber-lib/src/fiber/network.rs:3484-3490,3608-3616,5944-5974` (NetworkActor handle + call_t)
  - `crates/fiber-lib/src/fiber/payment.rs:1423-1438` (`SendPaymentOnionPacket` call_t with 5min timeout)
  - `crates/fiber-lib/src/fiber/gossip.rs:1197-1213` (subscribe 无超时 `call!`)
  - `crates/fiber-lib/src/fiber/gossip.rs:1221-1240` (`update_subscription`/`unsubscribe` 5s timeout — 正确)
  - `crates/fiber-lib/src/fiber/gossip.rs:1521-1546` (`QueryBroadcastMessages` `call!` 无超时)
  - `crates/fiber-lib/src/rpc/cch.rs:40,70-115` (`TIMEOUT=1000ms` for CchActor)
  - `crates/fiber-lib/src/utils/actor.rs:1-54` (`ActorHandleLogGuard` — observability)
  - `crates/fiber-lib/Cargo.toml:38-40` (`ractor = "0.15"`，仅启用 `async-trait` feature，无 `factory` / bounded mailbox)

## 1. 审计目标

- 验证 actor mailbox 是否有界 / 有背压机制；
- 验证 RPC / 跨 actor `call!` 是否设了超时；
- 验证恶意远程方能否通过填满 mailbox / 持有 `call!` 回复端口让节点 RPC 不可用；
- 验证慢 actor 是否会让 jsonrpsee 工作线程长期阻塞（jsonrpsee 默认 100 并发连接 + 10MB body，**见 AUDIT-INPUT-005 / AUDIT-NET-001**）。

## 2. ractor mailbox 模型

ractor 0.15 默认每个 actor 拥有一个 **MPSC 无界 channel**（`ractor::Message` queue）。本仓库 `Cargo.toml:38-40` 只启用了 `async-trait` feature，**未启用** `factory` / `cluster` / 任何 bounded mailbox 扩展。

`ActorRef::send_message`（即 `cast`）= push-to-queue，**不会阻塞、不会失败（除非 actor 已停止）**。`call!` / `call_t!` 宏在 push 完后 await 一个 oneshot reply port：
- `call!` (no timeout) → 永远等待，直到 actor 处理消息并回复，或 actor 死亡；
- `call_t!(actor, msg, timeout_ms, ...)` → 等待至 `timeout_ms`。

因此攻击面 = "凡是用 `call!`(无 timeout) 的入口，下游 actor 处理慢 / 死锁就直接 hang"。

## 3. 关键漏洞与建议

### F1 — `handle_actor_call!` 宏全部使用 `call!`(无超时) ⚠️ Medium

`crates/fiber-lib/src/rpc/utils.rs:58-84`：

```rust
#[macro_export]
macro_rules! handle_actor_call {
    ($actor:expr, $message:expr, $params:expr) => {
        match call!($actor, $message) {           // ← 无超时
            Ok(result) => match result { ... }
            Err(e) => log_and_error!($params, e.to_string()),
        }
    };
    // ...
}
```

**被以下 RPC 入口大面积使用**：

| 模块 | 行号 | 涉及方法 |
|---|---|---|
| `rpc/peer.rs` | :91,:105,:126,:133 | `connect_peer` / `disconnect_peer` / `list_peers` |
| `rpc/channel.rs` | (全文) | `open_channel` / `accept_channel` / `shutdown_channel` / `update_channel` / `list_channels` 等 |
| `rpc/payment.rs` | :231,:243,:271,:311 | `send_payment` / `build_router` / `get_payment` 等 |
| `rpc/invoice.rs` | :391 | `settle_invoice` |
| `rpc/info.rs` | :63 | `node_info` |
| `rpc/dev.rs` | :164,:196,:244,:293 | 内部命令 |

由于这些都是面向客户端（含潜在公网，参见 AUDIT-AUTH-003）的接口，**只要 NetworkActor 或下游 ChannelActor 在处理任意一条消息时陷入慢路径**（例如：

1. AUDIT-INPUT-002 触发 invoice parse panic 之前的慢路径；
2. ChannelActor 在 watchtower update / chain query 上等 CKB RPC 5 分钟（`DEFAULT_CHAIN_ACTOR_TIMEOUT=300_000`，见 `network.rs:3484-3490` 中的 `call_t!(...,DEFAULT_CHAIN_ACTOR_TIMEOUT,...).expect("chain actor alive")`）；
3. peer 恶意拖延 closing handshake 触发 ChannelActor 长时间循环；
4. RocksDB compaction / fsync 卡住），

**所有并发 RPC 调用都会同步 hang**，因为它们 await 在 NetworkActor 的 oneshot reply 上。jsonrpsee 服务器默认上限 100 并发连接（见 `rpc/config.rs` + INPUT-005 与 `rpc/mod.rs:160` 的 `Server::builder()` 默认），耗尽后整个 RPC 拒绝服务。这与 INPUT-005 / NET-001 形成放大链。

**缓解建议**：
- 在 `handle_actor_call!` 宏中改用 `call_t!(..., RPC_DEFAULT_TIMEOUT_MS, ...)`，例如 30s（远长于正常本地 actor 处理，但远短于 jsonrpsee 客户端超时）；
- 对长时间命令（如 `open_channel` 等需要 P2P 往返）单独设更长 timeout，但仍要有上限；
- 文档化 `RpcConfig::request_timeout_ms` 字段并暴露为配置项。

**严重级**：Medium。链上链下任何一个慢路径都能瘫痪 RPC，但不会损失资金。配合 INPUT-005 (无连接 / body 限速) → 远程攻击者 100 个 hold-open 连接即可锁死。

### F2 — `gossip.rs:1521 QueryBroadcastMessages` 无超时 `call!` ⚠️ Low

`crates/fiber-lib/src/fiber/gossip.rs:1521-1546`：

```rust
match call!(
    gossip_actor,
    GossipActorMessage::QueryBroadcastMessages,
    peer,
    queries.to_vec()
) { ... }
```

该路径在 `ExtendedGossipMessageStore` 后台任务中向 GossipActor 反查依赖消息时使用，下一条 `QueryBroadcastMessages` 会通过 `NetworkActor → tentacle → peer` 实际发请求。这是节点间 RPC，对端 peer 可任意延迟回复。

由于这是 background 任务（非 RPC 入口），影响：
- 单条 query 卡住 → 该 background 任务该次循环 stall；
- 不会直接阻塞 RPC，但 GossipActor mailbox 累积 `SaveMessages` 命令；

**严重级**：Low。后台任务是 spawn 出来的，不会卡到主 actor handle。但如对端故意 hold 住所有依赖查询 → GossipActor 入队消息 backlog。建议改 `call_t!` + 15-30s 上限。

### F3 — `gossip.rs:1197 NewSubscription call!` 无超时 ⚠️ Low

`gossip.rs:1188-1213` 的 `subscribe()` 内使用 `call!(..., NewSubscription, cursor)` 无超时。`subscribe` 由 `GossipActor::pre_start` 触发（`gossip.rs:975 .subscribe(filter_cursor, myself, ...).await.expect("subscribe store updates")`）。

如果 `ExtendedGossipMessageStoreActor` 在 startup 时卡住 → 节点启动 hang，最终被 supervision 超时杀掉。运行期不会触发因为只在 init 阶段调用一次。

**严重级**：Low（只影响启动，不影响运行时；配合 AUDIT-AUTH-002 init 路径 panic 已经有更直接的启动 DoS）。建议加 startup-friendly timeout（如 60s）。

### F4 — `rpc/cch.rs TIMEOUT=1000ms` 偏短 ℹ️ Info

`crates/fiber-lib/src/rpc/cch.rs:40` 定义 `const TIMEOUT: u64 = 1000;`(1 秒) 用于 `CchMessage::SendBTC` / `ReceiveBTC` / `GetCchOrder`。CchActor 内部会调用 LND gRPC（远程 BTC 节点），单趟 RTT + 服务端处理 1s 经常不够。

后果：用户用 RPC 发起 CCH 跨链，**频繁收到 actor timeout error** 但实际订单可能仍在后台执行（CchActor 内部不会因为 reply port drop 而中止）。这构成 UX 问题与状态-外部行为脱节风险。但不构成安全漏洞，对端不能利用此触发损害。

**严重级**：Info。建议 30s 或与 CCH 订单超时（36h）成比例。

### F5 — `DEFAULT_CHAIN_ACTOR_TIMEOUT=300_000ms (5min)` 配合 expect panic ℹ️ Info

`network.rs:116,133-134`:
```rust
pub const DEFAULT_CHAIN_ACTOR_TIMEOUT: u64 = 300000;
const ASSUME_CHAIN_ACTOR_ALWAYS_ALIVE_FOR_NOW: &str = "We currently assume that chain actor is always alive...";
```

`network.rs:3484-3490, 3608-3616, 5186`：
```rust
call_t!(self.chain_actor, CkbChainMessage::Sign, DEFAULT_CHAIN_ACTOR_TIMEOUT, funding_tx.into())
    .expect(ASSUME_CHAIN_ACTOR_ALWAYS_ALIVE_FOR_NOW)
```

- 5 分钟超时本身合理（CKB 节点提交 tx 可能慢）；
- 但 `.expect(...)` 在 actor 死亡时直接 panic NetworkActor → 节点级 DoS；
- 这是已知 TODO（注释明确说 "later we may find all references to this message to make sure that we handle the case where the chain actor is not alive"）。

`network.rs:5944-5974 handle` 通过 `ActorHandleLogGuard` warn 阈值 15s 来发现这种慢调用。但 5min × 上层调度 = 单条消息可吞掉 NetworkActor 长达数分钟，期间所有 `handle_actor_call!`(F1) 都 hang。

**严重级**：Info（已有 observability）。建议把所有 `expect(ASSUME_CHAIN_ACTOR_ALWAYS_ALIVE_FOR_NOW)` 改成 graceful shutdown / supervisor restart。

### F6 — Payment.rs:1423 SendPaymentOnionPacket 5min timeout ℹ️ Info

`crates/fiber-lib/src/fiber/payment.rs:1423-1438`：

```rust
match call_t!(
    self.network,
    |tx| NetworkActorMessage::new_command(NetworkActorCommand::SendPaymentOnionPacket(...)),
    DEFAULT_CHAIN_ACTOR_TIMEOUT      // ← 5min
).expect(ASSUME_NETWORK_ACTOR_ALIVE)
```

复用 `DEFAULT_CHAIN_ACTOR_TIMEOUT (5min)` 用于 P2P SendOnion 路径不甚合适（onion send 本质是本地 actor → peer 出站，正常 ms 级；5min 等于把单 attempt 慢路径暴露 5 分钟）。`PaymentSession.max_attempts=5`，最差耗时 25 分钟，期间其他 RPC handle_actor_call 全部 hang（F1 协同）。

**严重级**：Info。建议 SendPaymentOnionPacket 用 30-60s 上限。

### F7 — ActorHandleLogGuard 全覆盖 ✅ Pass

`crates/fiber-lib/src/utils/actor.rs:1-54` 实现的 `ActorHandleLogGuard` 在以下 actor 全部启用，统一 15s 阈值：

- `fiber/network.rs:5950-5955` (NetworkActor)
- `fiber/channel.rs:3814` (ChannelActor)
- `fiber/gossip.rs:765,1729,2781` (GossipActor / ExtendedGossipMessageStoreActor / NetworkSyncActor)
- `fiber/in_flight_ckb_tx_actor.rs:121`
- `ckb/actor.rs:126` (CkbChainActor)
- `watchtower/actor.rs:124`

→ **生产环境可以从 log 看到 "Actor handle took too long"，便于发现慢路径**（虽然不会自动 kill）。已经是良好实践。`metrics` feature 下额外 histogram 也已就位。

## 4. 与其他发现的协同

| 协同发现 | 协同机制 |
|---|---|
| **AUDIT-INPUT-002** (invoice DoS panic) | parse_invoice panic 触发前的慢路径 → F1 中所有 RPC handler 等待 NetworkActor reply hang → 节点 RPC 拒绝服务 |
| **AUDIT-INPUT-005** (RpcConfig 缺限速) | jsonrpsee 默认 100 并发 + 10MB body，攻击者 100 并发 RPC 调用 → F1 全部 hang → 完整 RPC DoS |
| **AUDIT-NET-001** (P2P 无 ban list) | 恶意 peer 大量推 FiberMessage 导致 NetworkActor mailbox 堆积 → 与 F1 协同 → RPC hang |
| **AUDIT-LOGIC-001** (channel 状态机) | ChannelActor 在异常状态长时间循环 → ChannelActor handle 慢 → 上层 RPC `handle_actor_call!` 排队 hang |
| **AUDIT-NET-001 P2P ban** | tentacle session pipeline 是唯一兜底背压，因为 ractor mailbox 无界 |

## 5. 修复建议优先级

| 优先级 | 修复点 |
|---|---|
| 🔴 P0 | F1：`handle_actor_call!` 全面切换到 `call_t!` + 默认 30s timeout（+ 暴露 `RpcConfig::actor_call_timeout_ms`） |
| 🟠 P1 | F5/F6：移除 `expect(ASSUME_CHAIN_ACTOR_ALWAYS_ALIVE_FOR_NOW)` 改 graceful，缩短 Payment SendOnion 超时 |
| 🟡 P2 | F2：`QueryBroadcastMessages` 加 30s 超时 |
| 🟢 P3 | F3：`NewSubscription` 加 60s 超时；F4：CCH RPC timeout 调到 ~30s |
| —— | F7：保持 |

## 6. 受影响版本

当前主线，无现成 fix 上游。
