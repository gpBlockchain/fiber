# AUDIT-AUTH-002 — Peer 身份绑定与 onion service

- **维度**: DIM-AUTH（认证与鉴权）
- **严重级别**: 🟡 Medium (Medium × 2 + Low × 4 + Pass × 4)
- **审计 Session**: S8 (2026-05-13)
- **关联代码**:
  - `crates/fiber-lib/src/fiber/network.rs:4460-4512` (`inbound_no_channel_peers_in_connected_order`, `enforce_inbound_peer_budget`)
  - `crates/fiber-lib/src/fiber/network.rs:4876-4950` (`on_peer_connected`, `peer_session_map.insert`)
  - `crates/fiber-lib/src/fiber/network.rs:6053-6108` (`FiberProtocolHandle::connected/disconnected/received` — secio remote_pubkey 路径)
  - `crates/fiber-lib/src/fiber/network.rs:5560-5710` (服务构建: secio handshake, 监听, onion)
  - `crates/fiber-lib/src/fiber/network.rs:1744-1797` (`ConnectPeer` / `ConnectPeerWithPubkey`)
  - `crates/fiber-lib/src/fiber/onion_service.rs:1-492` (Tor 控制端口 / hidden service / 密钥 IO)
  - `crates/fiber-lib/src/fiber/proxy.rs:1-50` (SOCKS5 配置)
  - `crates/fiber-lib/src/fiber/gossip.rs:2428-2615` (gossip 消息签名验证)
  - `crates/fiber-lib/src/fiber/config.rs:88,251-552` (`DEFAULT_MAX_INBOUND_PEERS = 16`, proxy/onion 配置)

## 1. 审计目标

- 验证 p2p 层 peer 身份绑定的密码学健全性（secio handshake 之后 Fiber 是否再次或重复信任 self-claimed pubkey）；
- 验证 Tor onion service 私钥 / 控制端口认证 / 密钥文件权限；
- 验证 inbound 连接管理对 Sybil/eviction 攻击的鲁棒性；
- 验证 gossip 消息签名验证完整性（防伪造广播）；
- 验证 SOCKS5 / Tor stream isolation 默认值；
- 验证 RPC `connect_peer` / `disconnect_peer` 与底层 peer 身份的一致性。

## 2. 数据流与不变式

```
Tentacle service (secio handshake)
   │  secio: X25519 ECDH + Ed25519 signature → authenticated remote_pubkey
   ▼
FiberProtocolHandle::connected(ctx) ─── ctx.session.remote_pubkey  (从握手得到, 已签名验证)
   │  pubkey_from_tentacle(remote_pubkey)
   ▼
NetworkActorEvent::PeerConnected(Pubkey, SessionContext)
   ▼
on_peer_connected(remote_pubkey, session) :  network.rs:4876
   ├─ peer_session_map.insert(remote_pubkey, ConnectedPeer{session_id, ty=Inbound/Outbound})  ⚠️ 覆盖旧 entry
   ├─ enforce_inbound_peer_budget()  →  inbound_no_channel_peers_in_connected_order()
   │      sort_by_key(|(_, sid)| *sid)     ascending (oldest first)
   │      .take(excess_peers).disconnect()        ⚠️ 踢老的, 留新的
   └─ send_fiber_message_to_pubkey(Init {features, chain_hash})

Onion service (optional, listen_on_onion=true):
   load_or_create_tor_secret_key(path)
   ├─ create: O_CREAT | O_TRUNC, unix 0o600        ✓
   └─ load:  std::fs::read_to_string(path)          ⚠️ 不校验权限
   TorController::new + authenticate(Null / HashedPassword / Cookie / SafeCookie)
   add_onion_v3(key, listeners[(onion_external_port, p2p_listen_address)])
```

### 不变式

| ID | 不变式 | 实现 | 状态 |
|---|---|---|---|
| INV-1 | remote_pubkey 来自 secio 握手（ed25519 签名验证）| `network.rs:6059, 6091` 直接读 `context.session.remote_pubkey` | ✅ |
| INV-2 | gossip NodeAnnouncement / ChannelAnnouncement / ChannelUpdate 均签名验证 | `gossip.rs:2428-2615` | ✅ |
| INV-3 | 同一 pubkey 单 session（无并发会话）| `peer_session_map.insert` blindly overwrites | ⚠️ F4 |
| INV-4 | inbound 容量满时，evict 最新（最可疑）连接 | `network.rs:4479` sort 升序 + take（evict 最老） | **❌ F1** |
| INV-5 | onion 私钥仅本节点可读 | create 0o600; load 不校验 | ⚠️ F2 |
| INV-6 | listen_on_onion=true 时禁止明文监听（隐私模式）| 未实现：明文 TCP + onion 并存 | ⚠️ F3 |
| INV-7 | Tor controller 凭据不留落地配置 | `tor_password` 明文 yaml | ⚠️ F5 |
| INV-8 | SOCKS5 stream isolation 默认开启 | `proxy_random_auth: true` 默认 | ✅ |

## 3. 发现

### 3.1 F1 (🟡 Medium) — Inbound peer 驱逐顺序使攻击者总能逐出合法连接

**位置**：
- `network.rs:4469-4481` `inbound_no_channel_peers_in_connected_order`
- `network.rs:4483-4512` `enforce_inbound_peer_budget`
- `network.rs:4902` `on_peer_connected` 调用 enforce
- 默认值：`fiber/config.rs:88: DEFAULT_MAX_INBOUND_PEERS = 16`

```rust
fn inbound_no_channel_peers_in_connected_order(&self) -> Vec<(Pubkey, SessionId)> {
    let mut peers = ...filter(|(_, peer)|
        peer.session_type == SessionType::Inbound && !self.session_has_channels(&peer.session_id)
    ).collect::<Vec<_>>();
    peers.sort_by_key(|(_, session_id)| *session_id);   // ← ASCENDING by session_id
    peers                                                //   smallest = oldest connection
}

async fn enforce_inbound_peer_budget(&mut self) {
    let inbound_no_channel_peers = self.inbound_no_channel_peers_in_connected_order();
    if inbound_no_channel_peers.len() <= self.max_inbound_peers { return; }
    let excess_peers = inbound_no_channel_peers.len() - self.max_inbound_peers;

    for (pubkey, session_id) in inbound_no_channel_peers.into_iter().take(excess_peers) {
        //                                                  ↑ take FROM THE OLDEST
        self.control.disconnect(session_id).await?;        //   → newest (attacker) survives
    }
}
```

`SessionId` 由 tentacle 单调递增分配（每个新接受的 session +1）。`sort_by_key` 升序 → `take(excess_peers)` 拿到最小 ID 集合 = 最早建立的 inbound 连接。注释 `inbound_no_channel_peers_in_connected_order` 暗示意图为 "connected order"（按建立顺序），但实际处置策略恰恰相反 —— 驱逐先到的合法连接，保留刚刚到的可疑连接。

**攻击模型**：
1. 节点配置 `max_inbound_peers = 16`（默认）；
2. 合法节点 A 在 t=0 时打开 inbound 会话，session_id=100，准备发起 OpenChannel 请求（尚未开通道）；
3. 攻击者 E（拥有任意私钥或一批 fresh keypair）在 t=1..t=N 时持续发起 inbound TCP 连接 + secio 握手 + Init 消息（每个 secio 握手成本 ≈ 1 个 X25519 ECDH，可控）；
4. 每个新连接都进入 `on_peer_connected` → `enforce_inbound_peer_budget`，判定 inbound-no-channel 数量超阈 → **驱逐 session_id 最小的 = 合法节点 A**；
5. 节点 A 在尚未完成 OpenChannel 握手前被踢，需 reconnect_backoff（默认指数退避）；
6. 攻击者只需以**慢于退避**的频率发起 16+1 个新连接，即可持续把所有 16 个 inbound-no-channel 槽位握在自己手里，**让任何潜在客户都打不开第一笔通道**。

**触发成本与隐蔽性**：
- 攻击者只需 N 个 secio keypair（可批量生成，无需链上注册），**无需链上抵押**；
- 每个连接被踢后立即重新发起 → 攻击峰值流量 ≈ 16 × secio_handshake / reconnect_backoff_interval —— 受害者侧每秒可能只看到 < 100 KB 流量，不会触发常规 DDoS 告警；
- 攻击者**不需要保持连接活跃**，仅需在 budget 重新触发的 race window 中先到；攻击者可以从地理上分布式发起进一步降低被识别概率；
- 已开通道的 inbound peer 不在 `inbound_no_channel_peers` 范围（`!self.session_has_channels`）→ 攻击不影响已有客户，但**阻止新客户上场**。

**后果**：
- 节点对新 peer 永久不可达；
- 通道 routing 网络的入度新增受阻 → Sybil 上游：攻击者通过同样手段阻止合法路由节点彼此连接，提高自身节点在拓扑中的中心性 → 长期 fee 收益 / 隐私分析能力提升。

**严重级别**：🟡 Medium —— 触发成本极低（无需密钥成本、无需链上费用），影响范围限定（不能盗资金，但 DoS 阻断 channel onboarding）。

**修复建议**：

```rust
- peers.sort_by_key(|(_, session_id)| *session_id);
+ peers.sort_by_key(|(_, session_id)| std::cmp::Reverse(*session_id));   // newest first
```

同时建议引入"已收到 Init / 已开始 OpenChannel 协商"的优先级标签，**优先驱逐刚握手未发任何业务消息的 session**（true spam 信号），其次按 session_id 倒序。可选：per-IP 限额，至少限制同 /24 / /48 网段的 inbound-no-channel 数量。

### 3.2 F2 (🟡 Medium) — `listen_on_onion=true` 时未关闭明文 TCP 监听

**位置**：
- `network.rs:5680-5710` 始终基于 `config.listening_addr()` 启动明文 TCP（及可选 WS）监听；
- `network.rs:5744-5773` 然后**额外**启动 onion service 转发到该明文端口。

```rust
let listening_addr = {
    let mut addresses_to_listen = vec![MultiAddr::from_str(config.listening_addr())...];
    ...
    for addr in addresses_to_listen.into_iter() {
        let mut current_addr = service.listen(addr).await...;       // ← 始终 listen
        ...
    }
    listening_addr
};

let onion_service_token = if config.onion.listen_on_onion {
    match self.start_onion_service(&config, &listening_addr, ...).await { ... }
};
```

**问题**：

用户启用 `listen_on_onion=true` 的合理预期是**隐私模式**——通过 Tor hidden service 接受连接，**不暴露真实 IP**。但当前实现：

1. 明文 TCP 端口仍打开（绑定到 `config.listening_addr()`），onion 仅是"额外通路"；
2. 若 `listening_addr = "0.0.0.0:8228"` 或类似 unspecified，节点的真实 IP 端口对全网开放；
3. `announce_listening_addr` / `announce_private_addr` 控制的是**广播**，不是**监听**；即使不广播，端口仍开，扫描者（如 Shodan）可发现并直接连接，让节点的 onion 化失去意义；
4. `is_addr_reachable` 仅过滤 announce 列表，监听端口本身不受影响。

**触发场景**：
- 部署在 cloud VPS 的节点 + `listen_on_onion=true` + 防火墙未单独配置 → 真实 IP 通过端口扫描被关联到 onion `.onion` 服务 → 隐私失效；
- Docker 容器中 `host` 网络模式 + onion → 真实主机 IP 暴露。

**后果**：
- 隐私目的破坏：onion 用户匿名性被打破；
- 不直接导致资金损失，但对依赖隐私部署的合规 / 商业场景为重大事故。

**严重级别**：🟡 Medium —— 隐私维度上为重要违反，但需运维配合（用户主观期望 + 网络配置）。

**修复建议**：

新增 `OnionConfig.onion_only: bool`（默认 false 保持兼容），当为 true 时 `addresses_to_listen` 只包含 `127.0.0.1:<port>`（仅 Tor 转发可达，外部不可达），同时强制 `announce_listening_addr = false`、`announce_private_addr = false`。或至少在 `listen_on_onion=true && listening_addr` 不是 loopback 时打 `warn!` 警告。

### 3.3 F3 (🟢 Low) — Onion 私钥文件加载不校验权限

**位置**：`onion_service.rs:475-491`

```rust
fn load_tor_secret_key(path: &str) -> Result<TorSecretKeyV3, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(std::fs::read_to_string(path).map_err(...)?)
        .map_err(...)?;
    if raw.len() != TOR_SECRET_KEY_LENGTH { return Err(...); }
    ...
}
```

**问题**：
- `create_tor_secret_key`（同文件 444-473 行）正确地用 `0o600` 创建文件 ✓；
- **但** `load_tor_secret_key` 直接 `read_to_string`，不检查权限。如果：
  - 管理员用 `cp -p` 从备份恢复源文件，源文件权限 0o644（常见 sftp/scp 默认）；
  - 文件最初由 root 写后 chowned 给运行用户但未 chmod；
  - 在容器 entrypoint 脚本中通过环境变量解码到挂载卷，宿主默认 umask 0022；
- 节点会**静默**加载世界可读的私钥，且控制台日志中只显示 `.onion` 地址，不警告。

**对比 OpenSSH**：`ssh` 在 known_hosts / private key 权限松散时拒绝加载并打印明确错误。该惯例对 onion v3 私钥同样适用——丢失意味着身份被冒用 + 流量被劫持。

**严重级别**：🟢 Low —— 需要本地多用户访问 + 错误权限配置同时发生。

**修复建议**：

```rust
#[cfg(unix)]
{
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(...)?;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "onion private key file {} has insecure mode {:o}; expected 0600",
            path, mode
        ));
    }
}
```

### 3.4 F4 (🟢 Low) — `peer_session_map.insert` 同 pubkey 第二次握手静默覆盖

**位置**：`network.rs:4878-4886`

```rust
self.peer_session_map.insert(
    remote_pubkey,
    ConnectedPeer { session_id: session.id, session_type: session.ty, address: session.address.clone(), features: None },
);
```

**问题**：
- 同一 pubkey 已有 entry 时，blindly overwrites，不调用旧 `session_id` 的 `disconnect` —— 旧 tentacle session 仍在传输层活着；
- 后续 `send_fiber_message_to_pubkey` 只走新 session；
- 旧 session 上 peer 可能发来的 reply 仍会触发 `FiberProtocolHandle::received` → 转发到 NetworkActor，被路由到新 session 对应的 channel actor —— **session 层 reorder / 双写竞争**。

**触发条件**：
- 必须能以同一 pubkey 完成 secio 握手 = **必须持有该 pubkey 对应的私钥**；
- 因此攻击者无法利用；仅在以下合法场景出现：
  - 节点运营者错误地用同一 secret-key 同时运行两个 fiber 实例；
  - 同节点经历 TCP 闪断 + 立即重连，旧 session 因 TCP keepalive 尚未清理；
  - NAT/防火墙状态过期导致同 pubkey 双 session。

**后果**：
- 非攻击者可利用，但 **legitimate reconnect-race** 下可能丢失正在传输的 commitment_signed / revoke_and_ack 消息，触发协议状态机错误（已被 LOGIC-006 报告的状态机 retry/idempotency 弱设计放大）。

**严重级别**：🟢 Low —— 非攻击通路；可作为 LOGIC-006 的子问题。

**修复建议**：

```rust
if let Some(existing) = self.peer_session_map.get(&remote_pubkey) {
    if existing.session_id != session.id {
        warn!("Duplicate session for pubkey {:?}: old {:?}, new {:?}; closing old",
              remote_pubkey, existing.session_id, session.id);
        let _ = self.control.disconnect(existing.session_id).await;
    }
}
self.peer_session_map.insert(remote_pubkey, ConnectedPeer { ... });
```

### 3.5 F5 (🟢 Low) — Tor controller 密码明文保存在配置文件

**位置**：
- `onion_service.rs:51-52`: `pub tor_password: Option<String>`
- `onion_service.rs:376-380`: 直接 `Cow::Owned(tor_password)` 传给 torut::authenticate

```rust
/// Tor controller plaintext password (for Tor's `HashedControlPassword`; Tor stores the hash in `torrc`)
pub tor_password: Option<String>,
```

**问题**：
- `fiber config.yml` 明文存储；
- 加载后 `OnionConfig` 字段保留在内存，无 `zeroize` / `secrecy::SecretString` 包装；
- 进程内存 dump（coredump / `/proc/<pid>/mem`、live migration、swap）即泄露；
- 比较其他凭据：`biscuit_public_key` 是公钥不敏感；CKB 私钥用专用 `read_or_generate_secret_key`（network.rs:5560）—— 但 tor_password 没有同等待遇。

**优先级降低因素**：
- 攻击者得到 tor 控制端口后果有限：可关闭 / 添加 onion，但本节点的 fiber 私钥不被影响；
- 通常 Tor cookie 文件路径同样需要保护，cookie 模式（默认）下根本不需要 password；
- HashedPassword 在 torrc 内仍是密码 hash，原始密码必须给客户端 —— 这是 Tor 上游协议设计。

**严重级别**：🟢 Low —— 信息泄漏 / 凭据卫生；可参考 secrecy crate。

**修复建议**：用 `secrecy::SecretString` 包装；在 logs 中保证不打印（已默认）；文档强调推荐使用 CookieAuthentication 而非 HashedPassword。

### 3.6 F6 (🟢 Low) — `connect_peer` RPC 在仅有 pubkey 时不查询 gossip 网络图

**位置**：`network.rs:1771-1797` `ConnectPeerWithPubkey`

```rust
let addresses = state.get_peer_addresses_by_pubkey(&pubkey);
// addresses 仅来自 state_to_be_persisted.persisted_peer_addresses (历史持久化)
let address = select_connect_peer_address(addresses.into_iter(), addr_type);
let Some(addr) = address else { ... return Error::PeerNotFound(pubkey); };
```

**问题**：
- gossip `NodeAnnouncement` 已收到的 peer addresses（保存在 `network_graph` / store）不会被查询；
- 用户在 RPC 中传 pubkey（如 invoice 来源 pubkey），若节点未曾连接过该 pubkey 但已 gossip 知晓，返回 `PeerNotFound` —— 用户体验不一致；
- 不构成安全漏洞，**但**用户可能误以为 "对方不在线" 而非 "我们的地址簿过时"，可能导致 ad-hoc 解决方案（如手工传 multiaddr）→ 增加 misconfiguration 风险。

**严重级别**：🟢 Low —— UX / 一致性。

**修复建议**：`ConnectPeerWithPubkey` 在本地未知地址时回退查询 `network_graph` 的 `NodeAnnouncement.addresses`。

### 3.7 F7 (ℹ️ Pass) — secio 握手对 remote_pubkey 的密码学绑定

`FiberProtocolHandle::connected/received/disconnected` 直接读 `context.session.remote_pubkey`，由 tentacle secio 协议在握手期完成：
- X25519 ECDH 派生共享密钥；
- 双方各自用 ed25519 签名挑战；
- 验证签名后写入 `remote_pubkey`。

Fiber 层后续所有 message routing（FiberMessage、Init、commitment_signed、revoke_and_ack 等）均基于此已签名 pubkey，**未引入任何 self-claimed 字段重新覆盖**。在 channel.rs 内 `ChannelActor::new(local_pubkey, remote_pubkey, ...)` 的 `remote_pubkey` 即来自 secio。Pass。

### 3.8 F8 (ℹ️ Pass) — Gossip 消息签名验证完备

- `verify_node_announcement`（gossip.rs:2593）：先比对 store 中同 cursor，再 `node_announcement.verify()` 验签；
- `verify_channel_announcement`（gossip.rs:2428）：双方 node 签名 + Schnorr ckb_signature 全验；
- `verify_channel_update`（gossip.rs:2535）：按方向选 pubkey 验签；
- 不存储未验证消息（除依赖未到时临时 hold），覆盖完整。

Pass。

**注**：缺少 per-pubkey NodeAnnouncement 频率上限 / 大小限制 → 属 AUDIT-MEM-002 范畴。

### 3.9 F9 (ℹ️ Pass) — SOCKS5 stream isolation 默认开启

`proxy/config.rs:11-25` 默认 `proxy_random_auth = true` —— 每个 tentacle 连接通过 SOCKS5 时使用随机 user/pass，让 Tor 客户端创建独立 circuit（stream isolation），防止 cross-channel correlation。Pass。

### 3.10 F10 (ℹ️ Pass) — Onion v3 私钥生成与存储

- 密钥由 `TorSecretKeyV3::generate()`（torut 库）生成，基于 OS CSPRNG；
- 文件写入用 `OpenOptions::create(true).truncate(true).write(true).mode(0o600)`（unix）；
- 长度校验 `TOR_SECRET_KEY_LENGTH = 64`；
- base64 编码持久化。

Pass —— 但参见 F3 关于 load 路径权限校验缺失。

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — Inbound peer eviction 顺序错（驱逐老连接）| 🟡 Medium | ⚠️ 未修复 |
| F2 — `listen_on_onion=true` 仍开明文监听 | 🟡 Medium | ⚠️ 未修复 |
| F3 — onion key load 不校验文件权限 | 🟢 Low | ⚠️ 未修复 |
| F4 — `peer_session_map.insert` 静默覆盖旧 session | 🟢 Low | ⚠️ 未修复 |
| F5 — tor_password 明文配置 | 🟢 Low | ⚠️ 未修复 |
| F6 — `connect_peer` 不查询 gossip 地址 | 🟢 Low | ⚠️ UX |
| F7 — secio remote_pubkey 绑定 | ℹ️ Pass | — |
| F8 — gossip 签名验证 | ℹ️ Pass | — |
| F9 — SOCKS5 stream isolation 默认 | ℹ️ Pass | — |
| F10 — onion v3 key 生成 / 写入 | ℹ️ Pass | — |
| 整体 | 🟡 Medium | — |

**总体评价**：peer 身份的**密码学绑定**层（secio + gossip 签名）非常严谨（F7/F8 Pass），无可被攻击者伪造 pubkey 的路径。问题集中在**资源管理与隐私模式实现**：

- F1 是可被无成本利用的 Sybil/eviction 攻击 —— 攻击者用随机 keypair 发起 inbound 连接，**总是淘汰合法老连接**，使节点对新客户长期不可达；
- F2 是隐私模式的**实现-期望落差**，onion 启用并不等价于"不暴露真实 IP"；
- F3-F6 是 defense-in-depth 缺失或 UX 不一致。

## 5. Follow-ups

- **AUDIT-AUTH-002-FOLLOWUP-A (Medium)**: F1 修复 — `sort_by_key` 反向；并加 per-IP/per-subnet 限额；构造 PoC 演示攻击者以 secp256k1 fresh keypair × 17 个 inbound 连接淘汰合法 inbound peer。
- **AUDIT-AUTH-002-FOLLOWUP-B (Medium)**: F2 修复 — 新增 `OnionConfig.onion_only` 配置；启用时强制 listening_addr 收缩至 loopback；运行期校验 announce 列表不泄露真实 IP。
- **AUDIT-AUTH-002-FOLLOWUP-C (Low)**: F3 修复 — `load_tor_secret_key` 加 unix mode 校验。
- **AUDIT-AUTH-002-FOLLOWUP-D (Low)**: F4 修复 — 与 LOGIC-006 状态机 retry/idempotency 联合处理 duplicate-session race。
- **AUDIT-AUTH-002-FOLLOWUP-E (Low)**: F5 `tor_password` 用 `secrecy::SecretString` 包装；文档推荐 cookie auth。
- **AUDIT-AUTH-002-FOLLOWUP-F (Low)**: F6 — `ConnectPeerWithPubkey` fallback 到 gossip 中的 NodeAnnouncement.addresses。
