# AUDIT-NET-001 — P2P 网络协议安全 (tentacle / secio / 流控 / 准入)

**审计目标**: 检查 fiber 在 tentacle p2p 栈上的传输层 / secio 握手层 / 协议层入口的安全配置 — 包括连接资源上限、握手鉴权、peer 准入与驱逐、错误后处置、UPnP/NAT 暴露面、protocol handler 的 backpressure 与 mailbox。与 AUDIT-AUTH-002 (peer 身份绑定 / onion) 互补：AUTH-002 关注 **secio 身份层**，本项关注**传输/会话层资源/准入治理**。

**Session**: S22

| 维度 | 内容 |
|---|---|
| 整体严重度 | 🟠 **High** (F1+F2+F3+F4 协同 → 远程零密钥成本的 socket-exhaustion + 路由器穿透 + admission bypass) |
| 关联代码 | `crates/fiber-lib/src/fiber/network.rs:120-160 (常量), 1744-1820 (Connect/Disconnect), 2030-2048 (CheckPeerInit), 4302-4322 (check_feature_compatibility), 4469-4512 (enforce_inbound_peer_budget), 4534-4545 (resume_peer_auto_reconnect), 4876-4950 (on_peer_connected), 5213-5262 (on_init_msg), 5572-5710 (ServiceBuilder + listen), 6029-6108 (FiberProtocolHandle::received)`, `gossip.rs:3121-3142 (Gossip received)`, `config.rs:88-251,551 (max_inbound_peers)`, `Cargo.toml:67-74 (tentacle features 含 upnp)`, tentacle 0.7.5 / tentacle-secio 0.6.7 |

---

## 攻击者模型

- **A1 (远程未认证)**: 任意可达 fiber 监听端口的网络对端 (默认 TCP `[::0]:8228`)。无密钥成本（不需要预先持有有效 secp256k1 keypair 即可发起 secio 握手；tentacle-secio 接受任意自签 keypair 作为对端身份）。
- **A2 (远程 + 多重身份)**: A1 加上"生成 N 个 fresh secp256k1 keypair"的能力。每个 keypair 在 fiber 视角是独立的 pubkey；零链上抵押。
- **A3 (本地路由)**: 与受害节点同 LAN，可监听 UPnP/NAT-PMP 广播。

## 主要发现

### F1 🟠 Medium — 无持久 ban 列表 / 协议违规无后果

**位置**: `network.rs:1798-1819 (DisconnectPeer handler)`, `:1803-1806 (requested_disconnect_peers 仅 Requested 分支)`, `:4534-4545 (resume_peer_auto_reconnect)`, `:5226-5242 (ChainHashMismatch 直接 DisconnectPeer)`, `:2035-2046 (InitMessageTimeout 直接 DisconnectPeer)`.

`requested_disconnect_peers: HashSet<Pubkey>` 仅在 `PeerDisconnectReason::Requested` (用户主动 RPC 触发) 分支被插入，作用是**抑制本节点自动重连尝试**；对**远端入站再 dial** 不生效。其余所有 `DisconnectPeer` 分支 (`ChainHashMismatch`, `InitMessageTimeout`, 协议错误, `enforce_inbound_peer_budget` 自动驱逐) 均**不插入 `requested_disconnect_peers`，也不存在任何替代的 ban-list / penalty-box / cooldown 数据结构**。

`grep -rn "ban_list\|banned_peer\|misbehavior\|ban_peer\|punish"` 在 `crates/fiber-lib/src/fiber/` 全 0 命中（仅 `DisconnectPeer` 自身）。

**后果**:
1. 攻击者用同一 pubkey 发送 `chain_hash` 错误 Init → 被踢 → 立即 reconnect → 再次踢 → 重复，对 `peer_session_map` 造成无尽 churn；与 `MAINTAINING_CONNECTIONS_INTERVAL = 1200s` 形成不对称：受害者每 20 分钟才主动维护一次正常连接，攻击者每秒可重连。
2. 配合 AUTH-002.F1 (eviction 顺序"踢老留新")：攻击者多个 fresh pubkey 反复进入 `peer_session_map`，每次进入都触发一次合法老 peer 的驱逐 — 即便每次 Init 都 timeout 被踢，攻击者已实现"踢人"目标。
3. 配合 LOGIC-008 (CCH) / MEM-001 (gossip OOM)：被踢的 peer 立即重连绕过 reconnect-backoff（只 throttle 本端 dial，不 throttle 远端入站）。

**修复建议**: 引入 `disconnected_peers: HashMap<Pubkey, DisconnectReason + Instant>`，对非 `Requested` 的 disconnect 写入。secio 握手完成后在 `on_peer_connected` 内查表，若 `now - disconnected_at < cooldown(reason)` 则立即 `disconnect(session_id)`。建议分级 cooldown：`ChainHashMismatch` 1h（chain 配置错误真实节点会重启 fix），`InitMessageTimeout`/`FeatureIncompatible` 5min，`ProtocolViolation` 30min。同时按 source IP 做次级限流（防 fresh-key Sybil）。

---

### F2 🟠 Medium — Tentacle ServiceBuilder 用全部默认 → max_connection_number=65535 / 无 yamux 窗口配置

**位置**: `network.rs:5614-5662 (native build), :5664-5673 (wasm build)`.

```rust
let mut builder = ServiceBuilder::default()
    .insert_protocol(fiber_handle.create_meta())
    .handshake_type(secio_kp.into());
// 仅 tcp_proxy_config / tcp_onion_config / forever(true on wasm)
builder.build(handle)
```

未调用任何 `set_max_connection_number(...)` / `set_session_open_timeout(...)` / `set_yamux_config(...)` / `set_send_buffer_size(...)` / `set_recv_buffer_size(...)`。Tentacle 0.7.5 `ServiceConfig` 默认值：
- `max_connection_number = 65535`（单端口同时连接数）
- `session_open_timeout = 10s`（secio + yamux 协商窗口）
- yamux stream window 默认 256 KB × 受限的 stream 数

`max_inbound_peers = 16` (config.rs:88 默认) 是 **fiber 应用层的 inbound budget**，**仅对完成 `on_peer_connected` 的 peer 生效**（详见 F3）。secio 握手中途 + 仅打开 gossip 协议（不打 fiber 协议）+ 协议未协商的会话 **不计入** `peer_session_map`，因此 fiber 层 budget 完全无视它们 — 但它们仍占用 tentacle/OS 级套接字、yamux 流、内存。

**后果**:
- 单 IP 攻击者可建立至 65535 个 TCP 连接，每个连接独立 secio 握手（CPU），独立 yamux 协商（~MB 内存）。在合理 CPU 上分钟级耗尽 fd 表 / 内存。
- 配合 AUTH-002.F1：攻击者首先用 ~50 个 fresh-key fiber-protocol 连接将 `max_inbound_peers=16` 槽位塞满并保持 churn；同时再开 1 万个仅完成 secio 但未协商任何 sub-protocol 的连接，占据 tentacle 层套接字 — 合法用户即便 LAN 也 dial 失败（`accept()` 队列满 / OS fd 耗尽）。

**修复建议**:
1. 显式 `set_max_connection_number(2 * max_inbound_peers + outbound_quota + headroom)`，例如 64（默认 inbound 16 + outbound 16 + transient 32）。
2. 暴露 `RpcConfig`/`FiberConfig` 字段：`max_total_connections`, `session_open_timeout`, `yamux_max_window`。
3. tentacle 0.7 增加 `set_io_idle_timeout`（如可用）防"已 secio 但 5 分钟无任何业务消息"的连接。

---

### F3 🟠 Medium — `enforce_inbound_peer_budget` 仅在 `on_peer_connected` 触发 + 只统计 fiber-protocol peer

**位置**: `network.rs:4469-4512 (enforce_inbound_peer_budget)`, `:4878-4886 (peer_session_map.insert in on_peer_connected)`, `:4902 (调用点)`.

```rust
async fn on_peer_connected(&mut self, ..., session: &SessionContext) {
    ...
    self.peer_session_map.insert(remote_pubkey, ConnectedPeer { ... });
    ...
    self.enforce_inbound_peer_budget().await;
    ...
}
```

`peer_session_map` 的填充只在 `FiberProtocolHandle::connected` (network.rs:6057-6070) 触发 — 即对端**主动打开 fiber-protocol 子流**。Tentacle 模型下，对端可以建 TCP → secio → yamux 后**只打开 gossip 子流**（或不打开任何子流仅维持 yamux），fiber 视角永远不会触发 `on_peer_connected` → `peer_session_map` 不增长 → `enforce_inbound_peer_budget` 永远不见到这类 peer → 不驱逐。

此外，admission control 仅在**新 peer 进入时**做点查（"len() <= max?"），没有定时复查；当 `max_inbound_peers=16` 槽位已满时新 peer 连接才触发驱逐 — 已被 ChainHashMismatch / InitMessageTimeout 等踢出的"前任老人"立即重连进入又会**再次触发驱逐**，但仅驱逐**当前在场的 16 个**之 oldest，导致 "频繁 churn + 总数动态平衡 16" — 攻击者通过新连接序列即可决定哪 16 个 pubkey 在场。

**后果**:
1. **gossip-only inbound flood**: 攻击者用 N 个 fresh keypair 完成 secio + yamux + 仅打开 gossip 子流，不打开 fiber-protocol。受害节点 `peer_session_map` 不计这些 peer，但 `MEM-001.F1` 路径下 gossip `messages_to_be_saved` 仍按 pubkey 分组 → per-peer 无上限累积；与 MEM-001.F1 协同形成**绕过 fiber 层 admission control 的 OOM 攻击**。
2. F3 + F1 + AUTH-002.F1 协同：让攻击者完全掌控 16 个 fiber-protocol inbound 槽位，合法用户 100% 无法对 fiber-protocol 入境。

**修复建议**:
1. `enforce_inbound_peer_budget` 改为**按 SessionId 而非 peer_session_map** 统计 — 直接询问 tentacle `control.session_list()` 中 inbound + 未打开 fiber 协议的 session，区分驱逐策略：未协商 fiber 协议 > 1 分钟 → 驱逐 (S2)；已协商 fiber 但未 Init > CHECK_PEER_INIT_INTERVAL → 驱逐 (S1)；已 Init 但 no-channel → 现有 LRU 驱逐。
2. Admission control 加入定时复查（与 `MAINTAINING_CONNECTIONS_INTERVAL` 对齐或更短）。
3. 驱逐顺序改为 **LIFO**（踢新留老）而非 FIFO（踢老留新），与 AUTH-002.F1 一致修复。

---

### F4 🟠 Medium — `tentacle` 启用 `upnp` feature 但未在 fiber 层配置 / 文档化

**位置**: `crates/fiber-lib/Cargo.toml:67-74 (features 含 "upnp")`. 全 `grep -rn "upnp"` 在 `crates/fiber-lib/src/` = 0 命中（仅 Cargo.toml 声明）。

Tentacle 0.7 在启用 `upnp` feature 时，对 `ServiceBuilder::listen(addr)` 给出的 **私网监听地址**（10/8, 172.16/12, 192.168/16, fe80::/10 等）会**主动尝试**用 UPnP IGD (Internet Gateway Device) 或 NAT-PMP 在用户家用/企业路由器上**自动开端口映射**，将路由器外网 IP:port 转发到内网监听端口。Fiber 默认 `listening_addr = "/ip4/0.0.0.0/tcp/8228"`（config.rs 默认），运行在 LAN/家用路由后的用户**预期是"局域网内可访问"**，但 UPnP 静默将其暴露到公网。

与 AUTH-002.F2 (`listen_on_onion=true` 仍开明文 TCP) 协同：用户自认为"只对外提供 .onion 服务"时，UPnP 又把明文 TCP 路由器穿透到公网 → 真实 IP + 真实 fiber 端口被指纹到内网，完全失去隐私保护。

**后果**:
1. 隐私目的 (隐藏真实 IP) 失效。
2. 受害者意外承担了"必须接受 internet 入站攻击面"的责任 (F1/F2/F3 等所有攻击面对公网 attacker 开放)。
3. 用户**无配置开关**可关闭 (fiber 层未暴露 `enable_upnp: bool`)；唯一关法是 fork 修改 Cargo.toml。

**修复建议**:
1. 立刻评估 fiber 是否真的需要 UPnP（Lightning 主网 LND/CLN 都默认不启用）。如不必要 → 从 `crates/fiber-lib/Cargo.toml:68` 移除 `"upnp"` feature。
2. 如保留，添加 `FiberConfig::enable_upnp: bool`（默认 false），仅在用户显式开启时启用 tentacle 的 upnp feature（需要构建期 cfg gate 或 runtime no-op）。
3. README 明确"如部署在 NAT/家用路由器后且不希望对外暴露真实 IP，请用 Tor/.onion 模式且 firewall 屏蔽 8228/tcp"。

---

### F5 🟢 Low — `CHECK_PEER_INIT_INTERVAL=20s` 配合 F3 形成"占槽-不 Init"DoS

**位置**: `network.rs:153`, `:2030-2048 (CheckPeerInit handler)`, `:4944-4949 (send_after schedule)`.

```rust
const CHECK_PEER_INIT_INTERVAL: Duration = Duration::from_secs(20);
```

Peer 在 `on_peer_connected` 后只需在 20s 内发送 Init 即可保住槽位；攻击者用 fresh keypair 占满 16 个 `inbound_no_channel_peers` 槽位、**故意不发 Init**，20s 后被踢，立即用新 keypair 重连。每槽位平均维持时间 20s，合法用户 reconnect 几乎不可能赢得空闲槽位。

虽然 AUTH-002.F1 的 LRU 驱逐已被独立标记为 Medium，但 F5 的特定弱点是：admission control 的"oldest by session_id"不偏向"oldest by lack-of-init"。一个 19s 未发 Init 的攻击者 session 在被新 peer 触发驱逐时，竟然被视为 "比新合法 peer 更应保留"。

**修复建议**: `enforce_inbound_peer_budget` 内对 `inbound_no_channel_peers` 子集**优先驱逐 features.is_none() (未 Init) 的 session**，再按 LRU 处理；或者把 inbound 槽位**进一步拆分**为 `pre-init` 与 `post-init` 两个独立 budget（前者 4 个，后者 12 个）。

---

### F6 🟢 Low — protocol `received` 解析失败无 misbehavior 计数

**位置**: `network.rs:6089-6105 (FiberProtocolHandle::received)`, `gossip.rs:3121-3138 (Gossip received)`.

```rust
async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: Bytes) {
    let msg = unwrap_or_return!(FiberMessage::from_molecule_slice(&data), "parse message");
    ...
}
```

Molecule 解析失败仅 `debug!` 日志 + 早返回。攻击者可发 130KB 垃圾字节流持续触发 molecule 解析（实际有一定 CPU 成本但 fiber 不计 — 没有 misbehavior counter / 累计阈值 / 协议违规 → 触发 F1 的 ban 表）。`MAX_SERVICE_PROTOCOAL_DATA_SIZE = 130KB` × 单线程 molecule decode (~10 µs/MB 估算) → 单 peer 全速发送 ~7000 frames/s 解析消耗，配合 F2 无 frame rate-limit → CPU starvation。

**修复建议**:
1. 在 `received` 内对 `from_molecule_slice` 失败次数计数（per-session），> N 次（如 16）后 `DisconnectPeer(ProtocolViolation)`。
2. 配合 F1 ban 列表，重复违规 peer 进入 cooldown。

---

### F7 🟢 Low — `try_send_actor_message` → 无界 mailbox + 无 backpressure (MEM-001.F2 加强)

**位置**: `network.rs:6093 (try_send_actor_message)`, `:6125-6145 (try_send_actor_message impl ASSUME_NETWORK_MYSELF_ALIVE)`.

ractor 0.15 默认 mailbox 是 unbounded mpsc；`try_send_actor_message` 把 protocol-level 帧直接转发给 NetworkActor 而无任何 backpressure，single peer flood 即可让 NetworkActor mailbox 无限增长。本条与 MEM-001.F2 同源；从 NET 维度补一刀强调：tentacle 提供了 `session.suspend()` API 可主动 backpressure 远端，但 fiber 完全没使用 — protocol handler 收到消息后无条件向 actor 转交，从未基于 mailbox 深度反压 transport。

**修复建议**: 在 NetworkActor 增加 mailbox 深度监控（如 `ractor::concurrency::mpsc_unbounded` 替换为 bounded），队列接近上限时调用 `context.session.suspend()` 暂停远端读；恢复后 `resume()`。

---

### F8 ✅ Pass — secio 握手强制 + chain_hash 强制 + Init 超时

- `handshake_type(secio_kp.into())` 是 tentacle 0.7 唯一对外暴露的握手类型枚举值（替代了 0.4 时代的 `with_secio_keypair` API），secio 强制启用，无明文 fallback。tentacle-secio 0.6.7 在 GHAD 无 CVE。
- `chain_hash` mismatch 立即 disconnect（network.rs:5226-5242）。
- 20s 内未发 Init → disconnect (`InitMessageTimeout`)。
- AUTH-002.F7 已验证 secio.remote_pubkey 与对端 keypair 绑定。

### F9 ✅ Pass — `check_feature_compatibility` 在 Init 之前拒绝其它 fiber 消息

`network.rs:4302-4322` — 非 Init 的 fiber 消息进入前先校验 `peer.features` 已设，未设则返回 `InvalidParameter`，**有效门控 OpenChannel/ChannelNormalOperation 等需要协议协商的入口**。

### F10 ℹ️ Info — `MAINTAINING_CONNECTIONS_INTERVAL=1200s` / `PEER_RECONNECT_BACKOFF_MAX=60s` 是节流值

本地 reconnect dial 路径有 1-60s exponential backoff（network.rs:177-253，MEM-002.F7 已 Pass），20 分钟一次主动维护连接 — 这些数值本身合理（与 LN 主网 LND 相近），但完全是**本端 outbound 节流**，对**远端 inbound 完全无效**（F1 主因）。

---

## 协同攻击链总结

| 链 | 步骤 | 关联 |
|---|---|---|
| **L1 socket-exhaustion** | (a) tentacle max=65535 (F2) → (b) attacker 单 IP 1 万 fd → (c) fiber 层 admission control 仅看 fiber-protocol peer (F3) → (d) OS fd 耗尽合法用户 dial 失败 | F2 + F3 |
| **L2 inbound 槽位 Sybil** | (a) attacker N×fresh keypair (F1 无 ban) → (b) 每个 send fiber-protocol → (c) AUTH-002.F1 LRU 踢老 → (d) 攻击者保持 16/16 占满，合法 user 入境失败 | F1 + F3 + F5 + AUTH-002.F1 |
| **L3 gossip OOM 绕过** | (a) attacker secio + 仅打 gossip 子流 (F3 不入 peer_session_map) → (b) 不触发 admission control → (c) `messages_to_be_saved` 按 pubkey 分组无上限累积 (MEM-001.F1) → (d) GB 级内存 OOM | F3 + MEM-001.F1 |
| **L4 UPnP 暴露**  | (a) 用户在家用路由后部署，预期 LAN-only → (b) tentacle upnp feature 默认开 (F4) → (c) 路由器外网 port forward → (d) 公网 attacker 走 L1/L2/L3 | F4 + (L1/L2/L3) |

---

## 总体评价

**Tentacle/secio 选型本身合理** — 自建 P2P 栈，secio 经 CKB 主网多年验证，handshake 流程 fiber 层做了 `chain_hash` + `Init` + `features` 三重过滤。问题集中在**配置层与运营层**：

1. **默认配置过宽**：tentacle 的 `max_connection_number=65535` 默认 + fiber 未显式覆盖 (F2)，与"小型 wallet/router 节点"语义脱节。
2. **admission control 颗粒度错**：fiber 把 budget 加在错误的层级（fiber-protocol 而非 transport/yamux），让 gossip-only / pre-Init / handshake-only 三类 ghost session 完全逃过限制 (F3)。
3. **缺持久 ban 机制**：协议违规 disconnect 后远端立即重连 (F1)。
4. **UPnP 静默暴露**：feature 启用但用户层无开关 (F4)。

修复成本：F1 (~50 行)、F2 (config 字段 + 调用 set_*，~30 行)、F3 (admission control 重写，~80 行)、F4 (Cargo.toml 一行 + config 字段，~10 行)。**优先级排序**：F4 > F2 > F3 > F1 > F5 > F6 > F7（F4 是即时 internet 暴露面收紧，F2 是即时 fd 耗尽防护，F3 是结构性 admission 重构）。

## 新增 Follow-ups

- **NET-001-FOLLOWUP-A (Medium, 优先级最高)**: 评估并默认禁用 tentacle `upnp` feature；如保留则提供 `enable_upnp` 配置项 (F4)。
- **NET-001-FOLLOWUP-B (Medium)**: 显式 `set_max_connection_number` + 暴露 `RpcConfig`/`FiberConfig` 字段；评估 tentacle 0.7 的 session/io idle timeout API (F2)。
- **NET-001-FOLLOWUP-C (Medium)**: 重写 admission control，按 tentacle session 而非 fiber `peer_session_map` 统计；区分 pre-secio / pre-init / post-init 三层 budget (F3 + F5)。
- **NET-001-FOLLOWUP-D (Medium)**: 引入 `disconnected_peers` cooldown 表，按 reason 分级 (F1)。
- **NET-001-FOLLOWUP-E (Low)**: protocol `received` 解析失败 misbehavior 计数 + 触发 ban (F6)。
- **NET-001-FOLLOWUP-F (Low)**: 探索 tentacle `session.suspend()` 集成 mailbox backpressure (F7 / MEM-001.F2)。
- **NET-001-FOLLOWUP-G (Info)**: 文档化"tentacle 默认配置"摘要 + fiber 覆盖项，供运维和后续审计 reference。
