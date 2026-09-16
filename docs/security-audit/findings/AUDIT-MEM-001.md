# AUDIT-MEM-001 — 资源耗尽 (Memory & Connection)

- **维度**: DIM-MEM（资源管理）
- **严重级别**: 🟠 High（High × 1 + Medium × 2 + Low × 3 + Pass × 2）
- **审计 Session**: S9 (2026-05-13)
- **关联代码**:
  - `crates/fiber-lib/src/fiber/gossip.rs:1339` (`messages_to_be_saved: HashMap<Pubkey, HashSet<BroadcastMessage>>` — 无上界)
  - `gossip.rs:1585-1646` (`insert_message_to_be_saved_list` — 入存前不验签)
  - `gossip.rs:1369-1425` (`prune_messages_to_be_saved` — 仅 Tick 间隔 20s 触发)
  - `gossip.rs:1476-1559` (`spawn_query_tasks` — MAX_NUM_CONCURRENT_QUERY_TASKS=10)
  - `gossip.rs:84-85` (MAX_NUM_OF_BROADCAST_MESSAGES=1000, DEFAULT_NUM_OF_BROADCAST_MESSAGE=100)
  - `gossip.rs:77-78` (PRUNE_STALE_BROADCAST_MESSAGES_INTERVAL=86400s = 1 day)
  - `network.rs:126` (`MAX_SERVICE_PROTOCOAL_DATA_SIZE = 130 KB`)
  - `network.rs:6053-6108` (`FiberProtocolHandle::received` — 无 rate-limit 推送至 actor mailbox)
  - `channel.rs:284` (`DEFAULT_MAX_TLC_VALUE_IN_FLIGHT: u128 = u128::MAX`)
  - `network.rs:6270-6354` (`ToBeAcceptedChannels` — 已正确限额 20 / 50KB per pubkey)
  - `fiber/config.rs:88,101-105` (DEFAULT_MAX_INBOUND_PEERS=16; gossip_store_maintenance_interval=20000ms)

## 1. 审计目标

- 验证 inbound peer 不能通过协议消息 (gossip + fiber protocol) 无界增长节点内存；
- 验证 actor mailbox 与 in-memory state 的上界；
- 验证 channel-level 资源参数 (TLC 数量/价值) 的默认上界；
- 验证 prune / TTL 机制覆盖所有累积结构。

## 2. 数据流与不变式

```
                    ┌────────────────────────────────────────────────────────────┐
[attacker peer] ──→ │ GossipProtocolHandle::received                             │
   gossip msg       │   parse via molecule (≤ 130 KB / protocol frame)            │
                    │   try_to_verify_and_save_broadcast_messages(originator, …) │
                    └───────────────────────┬────────────────────────────────────┘
                                            │  SaveMessages(peer, Vec<BroadcastMessage>)
                                            ▼
                    ExtendedGossipMessageStoreMessage::SaveMessages
                    └─→ insert_message_to_be_saved_list(pubkey, message)
                         ├─ HashSet de-dup per peer
                         ├─ get_existing_newer_broadcast_message store check  (cheap RocksDB lookup)
                         ├─ MessageTooNew timestamp check (future-only)
                         ├─ private-addr filter on NodeAnnouncement
                         └─ ★ NO SIGNATURE VERIFICATION ★ → store into RAM HashMap

                    Every 20 s (gossip_store_maintenance_interval):
                    ExtendedGossipMessageStoreMessage::Tick
                    ├─ prune_messages_to_be_saved():    verify+save messages with deps satisfied
                    └─ spawn_query_tasks():
                         │  iterate up to (10 - num_query_tasks_running) peers
                         │  for each: messages_to_be_saved.remove(&peer)
                         │  query peer for missing ChannelAnnouncement deps
                         │  results re-fed into SaveMessages
                         └─ peers beyond MAX_NUM_CONCURRENT_QUERY_TASKS stay in HashMap untouched
```

### 不变式

| ID | 不变式 | 实现 | 状态 |
|---|---|---|---|
| INV-1 | 同一 peer 发送相同 gossip 消息不重复占用内存 | `HashSet<BroadcastMessage>` 去重 | ✅ |
| INV-2 | gossip 消息入存前签名验证 | 仅在 `prune_messages_to_be_saved` 中验签（**接收→暂存→prune 时延 ≤ 20 s**）| **❌ F1** |
| INV-3 | `messages_to_be_saved` 每 peer 有大小上限 | 无 | **❌ F1** |
| INV-4 | 每 peer 入境 gossip 消息有速率上限 | 无 | ⚠️ F2 |
| INV-5 | actor mailbox 有 backpressure | ractor 默认 **unbounded** mailbox | ⚠️ F2 |
| INV-6 | 不完整依赖消息有最大滞留时间 | 仅靠 spawn_query_tasks 在 Tick 时 `.remove(&peer)`，且 ≤ 10 peers/Tick | ⚠️ F3 |
| INV-7 | OpenChannel 暂存有限额 | `ToBeAcceptedChannels` 默认 20 channel / 50 KB / per pubkey | ✅ F7 Pass |
| INV-8 | 节点 announcement 私网过滤 | `announce_private_addr=false` 时拒收 private-only NodeAnnouncement | ✅ F8 Pass |
| INV-9 | TLC in-flight value 默认有上限 | `DEFAULT_MAX_TLC_VALUE_IN_FLIGHT = u128::MAX` | ⚠️ F4 |
| INV-10 | `pending_save_peer_addresses` 仅 RPC 来源、受认证保护 | RPC `connect_peer(save:true)` 触发 | ✅ |

## 3. 发现

### 3.1 F1 (🟠 High) — 未验签 gossip 消息可在 RAM 中累积，触发 OOM

**位置**：`gossip.rs:1585-1646` `insert_message_to_be_saved_list` + `gossip.rs:1830-1853` `SaveMessages` 入口

**代码路径**（接收 → 入存）：

```rust
async fn insert_message_to_be_saved_list(
    &mut self, pubkey: &Pubkey, message: &BroadcastMessage,
) -> Result<InsertMessageStatus, GossipMessageProcessingError> {
    // 1. HashSet 去重 — 同 peer 同消息不重复
    if let Some(existing_messages) = self.messages_to_be_saved.get(pubkey) {
        if existing_messages.contains(message) { return Ok(InsertMessageStatus::Duplicate); }
    }
    // 2. 跨 peer 重复仅作 metric
    let duplicate_from_other_peer = self.messages_to_be_saved.iter()
        .any(|(peer, messages)| peer != pubkey && messages.contains(message));
    // 3. 已存 store 中且更新的检查 — 拒绝旧版本
    if let Some(existing_message) = get_existing_newer_broadcast_message(message, &self.store) {
        ...
    }
    // 4. timestamp 检查 — 仅拒绝未来 (timestamp > now + drift)
    if let Some(timestamp) = message.timestamp() {
        if timestamp > max_acceptable_gossip_message_timestamp() {
            return Err(GossipMessageProcessingError::MessageTooNew(...));
        }
    }
    // 5. NodeAnnouncement 私网地址过滤
    if !self.announce_private_addr {
        if let BroadcastMessage::NodeAnnouncement(node_announcement) = &message {
            if !node_announcement.addresses.iter().any(crate::utils::is_addr_reachable) {
                return Err(...);
            }
        }
    }
    // ★ 6. 直接插入 — 无签名验证 ★
    self.messages_to_be_saved.entry(*pubkey).or_default().insert(message.clone());
    Ok(...)
}
```

`SaveMessages` 入口：

```rust
ExtendedGossipMessageStoreMessage::SaveMessages(peer, messages) => {
    for message in messages {
        match state.insert_message_to_be_saved_list(&peer, &message).await { ... }
    }
}
```

**签名验证仅在 `Tick`**（20s 周期, `config.rs:101`）时由 `prune_messages_to_be_saved` 执行 `verify_and_save_broadcast_message` —— 且**只对依赖完整的消息验签**：

```rust
async fn prune_messages_to_be_saved(&mut self) -> Vec<BroadcastMessageWithTimestamp> {
    let mut complete_messages = HashSet::new();
    for messages in self.messages_to_be_saved.values() {
        for message in messages {
            if self.has_dependencies_available(message) {       // ← 依赖未到位的消息不进入验签
                complete_messages.insert(message.clone());
            }
        }
    }
    self.messages_to_be_saved.retain(...);                       // ← 已完成的清出，剩余继续滞留
    ...
}
```

**攻击模型**：

1. 攻击者建立 inbound 连接（结合 AUDIT-AUTH-002.F1，可控制最多 16 个 inbound 槽位）；
2. 每条 gossip 协议消息（≤ 130 KB 帧）可携带最多 1000 个 `BroadcastMessage`（`gossip.rs:84 MAX_NUM_OF_BROADCAST_MESSAGES = 1000`）；
3. 攻击者发送 `BroadcastMessagesFilterResult` 或在 active sync 响应中塞入大量**伪造**的 `ChannelUpdate`：
   - 每条 `ChannelUpdate` 引用攻击者**编造的 channel_outpoint**（链上不存在）；
   - 签名字段填 64 字节随机数据；
   - timestamp 取 `now()`（通过 MessageTooNew 校验）。
4. 入存后果：
   - `insert_message_to_be_saved_list` 不验签 → 直接进入 `HashSet<BroadcastMessage>`；
   - 每个 `ChannelUpdate` 在 Rust 内存中 ≈ 200–500 字节（含 secp256k1 签名 64 字节 + outpoint 36 字节 + flags + fee 字段）；
   - HashSet 仅按 `BroadcastMessage` 全字段去重，攻击者随机 `nonce`/`signature`/`outpoint` 即可生成无限唯一消息；
5. **关键**：`prune_messages_to_be_saved` 不清理这些消息：
   - `has_dependencies_available` 对孤儿 `ChannelUpdate`（引用不存在的 `ChannelAnnouncement`）返回 false → 不进入 `complete_messages` → 不被 retain 移除；
   - 唯一移除路径是 `spawn_query_tasks` 的 `messages_to_be_saved.remove(&peer)`，但：
     - `MAX_NUM_CONCURRENT_QUERY_TASKS = 10`（gossip.rs:96）→ 同时仅最多 10 个 peer 被处理；
     - 若 `num_query_tasks_running == 10`，任何 Tick 不会 remove 任何 entry（`gossip.rs:1477-1478`）；
     - 攻击者可以让 query 任务卡住：peer 响应 `BroadcastMessagesQueryResult` 时填入更多伪造消息，使 `SaveMessages` 再次回填 → 形成 saturate；
     - 即便 query 完成：被 `remove` 出来的 `incomplete_messages` 仍保存在 spawn 出来的 Future 局部变量中（`gossip.rs:1497`），直至该 task 结束。
6. **吞吐与累积**：
   - 单 inbound 连接：协议帧最大 130 KB，molecule 解码 ~1000 broadcasts；
   - 假设 10 Mbps inbound 带宽 → 8 帧/秒 → ~8000 broadcasts/秒 → ~3 MB RAM/秒（含 HashSet 容器 overhead）；
   - 16 个 inbound 连接：~50 MB RAM/秒；
   - 4 GB RAM 节点：约 80 秒 OOM；
   - `PRUNE_STALE_BROADCAST_MESSAGES_INTERVAL = 1 day`（`gossip.rs:78`）只清理已存 store 的过期消息，**不清理 `messages_to_be_saved` HashMap**。

**触发成本**：
- 攻击者只需 1–16 个 fresh secp256k1 keypair（结合 AUTH-002.F1 evict 现有 peer）；
- 无链上抵押；
- 不需要密钥即可生成"消息"，因为接收侧不验签；
- 带宽：分钟级 OOM 仅需 ~50 Mbps。

**后果**：
- 节点 OOM → 进程被 OS killer 终止 → 所有 channels 离线 → 通道伙伴在 expiry 内未收到 revoke / commitment_signed 信号；
- 与 AUDIT-AUTH-002.F1（inbound eviction）+ LOGIC-007（cooperative-close DoS）协同，可让目标节点持续不可用：每次重启后被立即 OOM。
- 攻击者可选择目标时机：例如在受害节点持有大额 in-flight TLC 时 OOM → 受害节点错过 `update_revocation` → watchtower 也未注册 → cheat 成功（与 AUTH-001.F1 standalone watchtower 共空命名空间叠加放大）。

**严重级别**：🟠 High —— 远程、可重复、几乎零成本，且与多个 Medium/High 弱点协同放大。

**修复建议**（最小改动）：

```rust
// 1. 在 insert_message_to_be_saved_list 入口加 per-peer 数量上限
const MAX_PENDING_MESSAGES_PER_PEER: usize = 1000;

if self.messages_to_be_saved.get(pubkey)
       .is_some_and(|s| s.len() >= MAX_PENDING_MESSAGES_PER_PEER)
{
    return Err(GossipMessageProcessingError::PendingQueueFull);
}

// 2. 入存前**先**做廉价的签名验证 (≈ 1 ms / message)
//    NodeAnnouncement.verify(), ChannelUpdate.verify_with_pubkey(known_node)
//    对于无法立即验签的 ChannelAnnouncement (需 on-chain lookup), 至少检查
//    其 secp256k1 签名格式合法 (DER/compact) 与 schnorr 签名格式
if let BroadcastMessage::NodeAnnouncement(na) = message {
    if !na.verify() {
        return Err(GossipMessageProcessingError::InvalidSignature);
    }
}
if let BroadcastMessage::ChannelUpdate(cu) = message {
    // pubkey 来自已知 ChannelAnnouncement 或暂存中的 ChannelAnnouncement
    if let Some(announcement) = find_channel_announcement(&cu.channel_outpoint) {
        let pubkey = if cu.is_node1() { announcement.node1_id } else { announcement.node2_id };
        if !cu.signature.verify(&pubkey, &cu.message_for_signing()) {
            return Err(GossipMessageProcessingError::InvalidSignature);
        }
    }
}

// 3. 在 spawn_query_tasks 中 saturate 时主动丢弃最老的 peer entry
if self.num_query_tasks_running >= MAX_NUM_CONCURRENT_QUERY_TASKS
    && self.messages_to_be_saved.len() > THRESHOLD
{
    // drop oldest / largest peer's pending messages
}
```

### 3.2 F2 (🟡 Medium) — actor mailbox 无 backpressure + 入站消息无速率限制

**位置**：
- `network.rs:6053-6108` `FiberProtocolHandle::received` / `connected` / `disconnected`
- `gossip.rs:2853-3060` Gossip 消息接收处理
- ractor 默认行为：actor mailbox `mpsc::unbounded_channel`

**问题**：

每收到一个 tentacle 协议消息，protocol handler 立即 `try_send_actor_message` → `NetworkActorMessage::new_event(...)`。Ractor 用 unbounded mpsc 作为 actor 邮箱（这是 ractor 框架的默认实现）。NetworkActor 单线程处理消息，若 attacker 以 N msgs/s 灌入而 actor 处理速度 < N，邮箱无限增长。

- **每条 message 内存占用**：`FiberMessage` enum 可达数 KB（commitment_signed 含签名、HTLC outputs、partial witness）；
- **无速率限制**：tentacle 层默认不限速（只有 `MAX_SERVICE_PROTOCOAL_DATA_SIZE = 130 KB` 单帧上限，但帧速率不限）；
- **无 mailbox 上限**：ractor 未配置 bounded mailbox；
- **无 per-peer quota**：所有 peer 共享 NetworkActor 单一邮箱。

**对比 F1**：F2 比 F1 更细微但同样不可控。F1 攻击 gossip 路径下的 `messages_to_be_saved`；F2 攻击 actor mailbox。F1 已有部分清理（Tick spawn_query_tasks），F2 完全没有清理（消息只能由 actor handler 拉取处理）。

**触发场景**：
- 攻击者反复发送语法合法但语义无效的 FiberMessage（例如对未知 channel_id 的 commitment_signed），NetworkActor 解析→路由到 channel actor→channel actor 也无 backpressure；
- 解析过程涉及 molecule 反序列化（CPU 密集），如果攻击速率 > 解析速率，邮箱积压。

**严重级别**：🟡 Medium —— ractor framework-level 限制，修复需更换 mailbox 类型或加上层速率限制；与 F1 协同放大但单独利用难度更高（需精细控制速率）。

**修复建议**：
- 在 `FiberProtocolHandle::received` 内增加 per-peer token bucket（如 100 msg/s × peer）；
- 或将 ractor mailbox 改为 bounded（需评估对其他 actor 的影响）；
- 至少为 gossip 协议处理引入 per-peer rate-limit（独立于 F1）。

### 3.3 F3 (🟡 Medium) — `incomplete_messages` 在 query task 中无总大小上限

**位置**：`gossip.rs:1491-1557` `spawn_query_tasks` 内 spawn 出来的 future

```rust
let incomplete_messages = self.messages_to_be_saved
    .remove(&peer)                         // ← 从 HashMap 完整移出 (无大小检查)
    .expect("peer is a key of hashmap");
...
let incomplete_messages = incomplete_messages.into_iter().collect::<Vec<_>>();

ractor::concurrency::spawn(async move {
    let n_queries = incomplete_messages.len();
    for messages in incomplete_messages.chunks(DEFAULT_NUM_OF_BROADCAST_MESSAGE as usize) {
        let queries = messages.iter().filter_map(...).collect::<Vec<_>>();
        ...
        match call!(gossip_actor, GossipActorMessage::QueryBroadcastMessages, peer, queries.to_vec()) {
            Ok(Ok(result)) => {
                let mut all_messages = result.messages;
                all_messages.extend(messages.iter().map(Clone::clone));
                myself.send_message(SaveMessages(peer, all_messages))     // ← 再次回灌
                    .expect("actor alive");
            }
            ...
        }
    }
    ...
});
```

**问题**：

1. **task 内 `incomplete_messages: Vec` 完整持有所有该 peer 的 pending 消息** —— 若 F1 攻击成功，单 peer 可能持有数十万条消息，spawn 后整个 Vec 在内存中存活到 future 结束；
2. **query 响应数据被 clone 并通过 SaveMessages 回灌**（`all_messages.extend(messages.iter().map(Clone::clone))`）—— 攻击者节点在 `QueryBroadcastMessages` 响应中再次回复更多伪造 `ChannelAnnouncement` 时，这些数据 + 原 incomplete_messages 又会被回灌到 `messages_to_be_saved`；
3. 最多 10 个 spawn 同时运行（`MAX_NUM_CONCURRENT_QUERY_TASKS=10`），每个独立的 future 持有独立 Vec → 内存放大系数 × 10；
4. 没有 query 超时之外的清理（`GET_REQUEST_TIMEOUT = 20s`，gossip.rs:92）—— 但请求处于"call"等待状态，期间消息一直在 future 栈上。

**严重级别**：🟡 Medium —— 是 F1 的二阶段放大器。单独不构成独立攻击（依赖 F1 制造大量 incomplete 消息），但显著降低 F1 的修复门槛。

**修复建议**：
- `spawn_query_tasks` 内 truncate `incomplete_messages` 到合理上限（如 1000）；
- query 响应回灌前先做签名验证；
- 检测对方多次返回未触发完成的响应时停止 query task 并丢弃。

### 3.4 F4 (🟢 Low) — `DEFAULT_MAX_TLC_VALUE_IN_FLIGHT = u128::MAX`

**位置**：`channel.rs:284`

```rust
pub const DEFAULT_MAX_TLC_VALUE_IN_FLIGHT: u128 = u128::MAX;
```

被 `network.rs:4075, 4188` 在 OpenChannel/AcceptChannel 默认参数中使用。`max_tlc_number_in_flight` 字段存在（`channel.rs:307`）但其默认未在本次查找中明确（默认值若也 u64::MAX 则同样问题）。

**问题**：
- 节点对 in-flight HTLC 总价值默认无上限 → 攻击者通过路由发送 HTLCs 锁定节点的整个 channel 容量；
- 与 LOGIC-004（`forward_amount=0` HTLC slot jamming）协同：lock 整个 channel 的资金，受害者无法转发其它支付，长达 expiry 时间（最长 14 天）；
- BOLT 02 推荐 `max_htlc_value_in_flight_msat` 应小于 channel capacity 的某个百分比（Lightning Network 习惯 10–50%）。

**严重级别**：🟢 Low —— 字段是协议规范字段，用户可配置；但默认值放任最坏情况。

**修复建议**：默认应取 channel capacity 的 90% 或显式要求用户在 OpenChannel 时配置。

### 3.5 F5 (🟢 Low) — `MAX_NUM_OF_BROADCAST_MESSAGES = 1000` 一帧批量过大

**位置**：`gossip.rs:84`

`MAX_NUM_OF_BROADCAST_MESSAGES = 1000` 用于 `GetBroadcastMessages` 请求数量上限。攻击者一帧（≤130 KB）可携带 1000 条伪造 broadcast → 配合 F1 的"无验签暂存"放大率高。若降至 100，单帧攻击吞吐降 10×。

**严重级别**：🟢 Low —— 调小可缓解 F1，但不是根本问题。

### 3.6 F6 (🟢 Low) — gossip prune_messages_to_be_saved 仅清理"已完成"消息

**位置**：`gossip.rs:1378-1383`

```rust
self.messages_to_be_saved.retain(|_, messages| {
    messages.retain(|message| !complete_messages.contains(message));
    !messages.is_empty()
});
```

**问题**：retain 只移除已完成（依赖到位）消息，对**永远不可能完成**的消息（攻击者构造的 outpoint 在链上不存在的 ChannelUpdate）没有 TTL 或最大计数。仅靠 `spawn_query_tasks` 的 `.remove` 间接清理，但 saturate 时不触发（见 F3）。

**修复建议**：为 HashSet 元素附加 inserted_at 时间戳，prune 时丢弃 > 10 分钟未完成的消息。

### 3.7 F7 (ℹ️ Pass) — `ToBeAcceptedChannels` 已正确限额

**位置**：`network.rs:6270-6354`

- `total_number_limit` 默认 20（per-pubkey 计数，`network.rs:6326-6335`）；
- `total_bytes_limit` 默认 50 KB；
- `try_insert` 拒绝越限的新 OpenChannel；
- channel 完成或 peer 断开均会清理。

Pass —— OpenChannel 暂存的资源管理是正确典范。

### 3.8 F8 (ℹ️ Pass) — NodeAnnouncement 私网过滤

**位置**：`gossip.rs:1621-1633`

```rust
if !self.announce_private_addr {
    if let BroadcastMessage::NodeAnnouncement(node_announcement) = &message {
        if !node_announcement.addresses.iter().any(crate::utils::is_addr_reachable) {
            return Err(GossipMessageProcessingError::ProcessingError("private address node announcement".to_string()));
        }
    }
}
```

在 `announce_private_addr=false` 时拒收仅含私网地址的 NodeAnnouncement，防止恶意污染网络图。Pass —— 但**注意**该过滤可被攻击者绕过：只需在伪造 NodeAnnouncement 中加一个公网格式（但路由不通）的地址。这部分将在 INPUT-002 内重新评估。

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — gossip `messages_to_be_saved` 无验签暂存 + 无大小上限 → 远程 OOM | 🟠 High | ⚠️ 未修复 |
| F2 — actor mailbox 无 backpressure / 入站消息无速率限制 | 🟡 Medium | ⚠️ 未修复 |
| F3 — `spawn_query_tasks` 内 incomplete_messages 无上限放大 F1 | 🟡 Medium | ⚠️ 未修复 |
| F4 — DEFAULT_MAX_TLC_VALUE_IN_FLIGHT = u128::MAX | 🟢 Low | ⚠️ 未修复 |
| F5 — MAX_NUM_OF_BROADCAST_MESSAGES=1000 单帧过大 | 🟢 Low | ⚠️ 未修复 |
| F6 — prune 无 TTL，永不完成的消息无清理路径 | 🟢 Low | ⚠️ 未修复 |
| F7 — ToBeAcceptedChannels 正确限额 | ℹ️ Pass | — |
| F8 — NodeAnnouncement 私网过滤 | ℹ️ Pass | — |
| 整体 | 🟠 High | — |

**总体评价**：链路层鉴权（secio + gossip 签名）保证了 peer 身份，但**鉴权之后**的资源管理存在系统性缺口。最严重的 F1 让攻击者绕过 gossip 的签名验证（验签延迟到 Tick 时段），将节点 RAM 当成攻击者的临时存储 —— 这是远程、零密码学成本、可重复触发的 DoS。F1 与 AUDIT-AUTH-002.F1 (inbound eviction)、AUDIT-AUTH-001.F1 (watchtower 多租户)、LOGIC-007 (cooperative-close DoS) 协同可形成持续不可用攻击链。

F4 和 BOLT 默认差异说明：fiber 选择"不限制"作为兼容性最大公约数，但生产环境应至少在配置文档中明示 max_tlc_value_in_flight 必须小于 channel capacity 的合理比例。

## 5. Follow-ups

- **AUDIT-MEM-001-FOLLOWUP-A (High, PoC + 修复)**: F1 修复 — `messages_to_be_saved` 引入 per-peer 数量上限 (`MAX_PENDING_MESSAGES_PER_PEER = 1000`)；入存路径加签名验证；构造 PoC：单个 inbound 连接 + 16 个伪造 `ChannelUpdate` 帧/秒 → 监控 RSS 达到 OOM 时间。
- **AUDIT-MEM-001-FOLLOWUP-B (Medium)**: F2 — 引入 per-peer FiberMessage rate-limit；或为 NetworkActor mailbox 设置上界。
- **AUDIT-MEM-001-FOLLOWUP-C (Medium)**: F3 — `spawn_query_tasks` 内 truncate incomplete_messages 上限；query 响应回灌前验签。
- **AUDIT-MEM-001-FOLLOWUP-D (Low)**: F4 — 调整 `DEFAULT_MAX_TLC_VALUE_IN_FLIGHT` 或文档强调用户须配置。
- **AUDIT-MEM-001-FOLLOWUP-E (Low)**: F5+F6 — 调小 MAX_NUM_OF_BROADCAST_MESSAGES（如 200）；prune 增加 TTL 字段。
- **关联**: 与 AUTH-002.F1 (inbound eviction) 联合修复路径——若资源管理修好则 F1 攻击需要更多 peer，eviction 修好后攻击 peer 数受限。
