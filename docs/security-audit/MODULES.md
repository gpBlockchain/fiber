# Fiber Network Node — 模块关系图（安全审计视角）

> 版本: **v2** | 最后更新: 2026-05-14 (S28) | 配套文档: [`SECURITY_AUDIT_TODO.md`](./SECURITY_AUDIT_TODO.md), [`REPORT.md`](./REPORT.md)

## 0. 文档目的

本文为安全审计的 *横向* 视角配套文档：

1. 给出 9 个 crates / 8 个核心子模块的**职责分工**与**调用方向**；
2. 在每条跨模块边上标注**信任级别**（攻击者控制度）、**关键序列化格式**、**actor 通信类型**；
3. 给所有已发现的 XMOD-001..011 跨模块攻击链**画出明确的连通边**，便于回归测试规划。

> **范围**：本文聚焦"攻击面图"，不重复每个 finding 的细节（细节看 `findings/AUDIT-*.md`）。

---

## 1. Crates 总览

| Crate | 角色 | 主要消费者 | 不可信输入面 |
|---|---|---|---|
| `fiber-bin` | 进程 entrypoint；解析配置；启动各 actor；JSON-RPC 服务器 | 操作员 | CLI args、配置文件、`FIBER_SECRET_KEY_PASSWORD` env |
| `fiber-lib` (**核心**) | 所有协议逻辑（fiber / ckb / cch / rpc / watchtower / store 适配 / invoice） | `fiber-bin`、`fiber-wasm` | P2P peer、JSON-RPC、CKB RPC、LND gRPC、磁盘 |
| `fiber-types` | 跨边界数据类型（`Pubkey` / `Privkey` / `Hash256` / Molecule schema） | `fiber-lib`、外部接口 | 序列化字节、远程对端构造的 secp256k1 点 |
| `fiber-store` | 持久化抽象层 + RocksDB/SQLite/browser 后端 + 迁移框架 | `fiber-lib` | 磁盘文件、跨版本旧数据、并发进程 |
| `fiber-json-types` | RPC JSON 模型（`bytes::Hex32` 等） | `fiber-lib::rpc`、外部 CLI | JSON RPC 调用方 |
| `fiber-cli` | 离线工具（生成密钥等） | 操作员 | — |
| `fiber-wasm` / `-wasm-db-worker` / `-wasm-db-common` | 浏览器/WASM 运行时绑定 | Web 前端 | 浏览器 evil tab / IndexedDB 跨 tab |

**外部依赖中"高风险"清单**（节选，详见 DEP-001..003）：`secp256k1 0.30` / `musig2 0.2.4` / `aes-gcm 0.10` / `scrypt 0.11` / `tentacle 0.7` / `ractor 0.15` / `jsonrpsee 0.25` / `biscuit-auth 6.0.0-beta.3` / `bincode 1.3.3` / `rocksdb` / `lightning-invoice 0.33` / `ckb-sdk 5`.

---

## 2. 核心子模块（`fiber-lib/src/*`）职责矩阵

```
                              ┌──────────────────────────────────────┐
                              │              fiber-bin               │
                              │  (main.rs: 解析 cfg → 启动各 actor)   │
                              └──────────────┬───────────────────────┘
                                             │
                  ┌──────────────────────────┴────────────────────────┐
                  │                                                   │
       ┌──────────▼──────────┐                            ┌───────────▼─────────────┐
       │      rpc            │  ────────── 调用 ────────►│    actors (网络层)        │
       │ (jsonrpsee 服务器)   │                            │  NetworkActor (network.rs)│
       │ mod.rs              │                            │  ChannelActor (channel.rs)│
       │ ├ middleware (auth) │                            │  GossipActor (gossip.rs)  │
       │ ├ biscuit           │                            │  PaymentActor (payment.rs)│
       │ ├ channel/payment/  │                            │  CkbChainActor (ckb/actor)│
       │ │ invoice/peer/info │                            │  WatchtowerActor          │
       │ │ graph/cch/        │                            │  InFlightCkbTxActor       │
       │ │ watchtower/dev    │                            │  CchActor (cch/actor.rs)  │
       │ └ utils.rs          │                            └─────────────┬─────────────┘
       └─────────────────────┘                                          │
                                                                        │
              ┌─────────────────────────────────────────────────────────┤
              ▼                                                         │
       ┌─────────────────┐    ┌──────────────────┐    ┌────────────────▼───────┐
       │   fiber/        │    │   ckb/           │    │   watchtower/          │
       │  ├ network.rs   │    │  ├ actor.rs      │    │  ├ actor.rs            │
       │  ├ channel.rs   │    │  ├ client.rs     │    │  ├ store.rs            │
       │  ├ gossip.rs    │◄──►│  ├ contracts.rs  │◄──►│  └ mod.rs              │
       │  ├ payment.rs   │    │  ├ funding/      │    └────────────────────────┘
       │  ├ graph.rs     │    │  ├ signer.rs     │
       │  ├ path.rs      │    │  └ tx_tracing    │
       │  ├ history.rs   │    └──────────────────┘
       │  ├ fee.rs       │              ▲
       │  ├ onion_service│              │
       │  ├ proxy.rs     │              │
       │  └ key.rs       │              │
       └────────┬────────┘              │
                │                       │
                ▼                       │
       ┌─────────────────┐    ┌─────────┴──────────┐    ┌──────────────────────┐
       │   cch/          │    │   invoice/         │    │   store/             │
       │  ├ actor.rs     │◄──►│  (CkbInvoice       │    │  (Store trait        │
       │  ├ scheduler.rs │    │   parse/encode)    │◄──►│   over fiber-store)  │
       │  ├ cch_fiber_*  │    └────────────────────┘    │  + schema.rs         │
       │  ├ order/       │                              └──────────────────────┘
       │  ├ trackers/    │
       │  ├ actions/     │
       │  └ config.rs    │
       └─────────────────┘
                │
                ▼
       ┌────────────────────┐
       │  LND gRPC (远端)   │
       └────────────────────┘
```

### 子模块清单（按入口位置）

| 子模块 | 入口路径 | 主要 actor / 类型 | 信任边界编号（见 TODO §信任边界） |
|---|---|---|---|
| **fiber/network** | `fiber-lib/src/fiber/network.rs` | `NetworkActor`、`NetworkActorCommand`、`NetworkActorMessage` | ① P2P |
| **fiber/channel** | `fiber-lib/src/fiber/channel.rs` | `ChannelActor`、`ChannelActorState`、`FiberChannelMessage` | ① P2P |
| **fiber/gossip** | `fiber-lib/src/fiber/gossip.rs` | `GossipActor`、`BroadcastMessageWithTimestamp` | ① P2P |
| **fiber/payment** | `fiber-lib/src/fiber/payment.rs` | `PaymentActor`、`PaymentSessionStatus`、`update_graph_with_tlc_fail` | ① + ⑦（invoice） |
| **fiber/graph** | `fiber-lib/src/fiber/graph.rs` | `NetworkGraph`、`mark_channel_failed/mark_node_failed` | ① P2P |
| **fiber/path** | `fiber-lib/src/fiber/path.rs` | 路由算法 + Sphinx 封装入口 | ⑧ Sphinx |
| **fiber/history** | `fiber-lib/src/fiber/history.rs` | `record_payment_fail`（评分路径，含 route-membership 校验范本） | ① + 内部 |
| **fiber/key** | `fiber-lib/src/fiber/key.rs` | scrypt + AES-GCM 钱包加解密 | ⑤ 钱包/密钥 |
| **ckb/actor** | `fiber-lib/src/ckb/actor.rs` | `CkbChainActor` | ③ CKB |
| **ckb/client** | `fiber-lib/src/ckb/client.rs` | CKB RPC 客户端 | ③ CKB |
| **ckb/contracts** | `fiber-lib/src/ckb/contracts.rs` | 链上脚本/合约句柄 | ③ CKB |
| **ckb/funding** | `fiber-lib/src/ckb/funding/funding_tx.rs` | funding tx 构造 | ③ CKB |
| **cch/actor** | `fiber-lib/src/cch/actor.rs` | `CchActor` | ④ CCH (LND) |
| **cch/scheduler** | `fiber-lib/src/cch/scheduler.rs` | `expire_order` / `is_final` | ④ CCH (时序) |
| **cch/order** | `fiber-lib/src/cch/order/` | 订单状态机 | ④ |
| **cch/trackers** | `fiber-lib/src/cch/trackers/` | 跨链跟踪 | ④ |
| **watchtower** | `fiber-lib/src/watchtower/actor.rs` | `WatchtowerActor`、`run_periodic_check` | ③ + ⑥ |
| **rpc** | `fiber-lib/src/rpc/` | jsonrpsee 模块树 + biscuit 鉴权 + middleware | ② RPC |
| **store** | `fiber-lib/src/store/` | 高层 Store trait（在 fiber-store 之上） | ⑥ |
| **invoice** | `fiber-lib/src/invoice/` | `CkbInvoice` 解析/编码（含 `lightning-invoice`） | ⑦ |

---

## 3. 跨模块边（信任 + 序列化 + actor 通信）

下表枚举所有"安全相关"的模块间边，每条边标注：**方向 / 攻击者控制度 / 数据格式 / 是否过滤校验**。

> 信任级别：🟥=远程不可信、🟧=链上不可信、🟨=本地非特权用户、🟦=本地特权操作员。

### 3.1 入站边（从信任边界进入 fiber 内核）

| # | 来源 | 目标模块 | 控制度 | 数据格式 | 校验状态 | 触及 finding |
|---|---|---|---|---|---|---|
| E1 | 远程 peer (tentacle session) | `fiber/network` `ServiceHandle` | 🟥 | tentacle session bytes | 部分（secio handshake）；admission gate 见 NET-001 | NET-001, MEM-001 |
| E2 | 远程 peer | `fiber/channel` (`FiberChannelMessage` via Molecule) | 🟥 | Molecule schema (`fiber-types/src/schema/fiber.mol`) | Molecule 自带长度守卫 ✓；语义校验缺位 | CRYPTO-004, LOGIC-001..007, XMOD-008, XMOD-010 |
| E3 | 远程 peer | `fiber/gossip` (`BroadcastMessage*`) | 🟥 | Molecule + 签名 | 入站验签 ✓；出站旁路 = XMOD-001 | MEM-001, XMOD-001 |
| E4 | 远程 peer | `fiber/payment` (sphinx unwrap → `TlcErr`) | 🟥 | sphinx + Molecule | sphinx 解密 ✓；TlcErr 内部字段无 route-membership 校验 | ERR-001, XMOD-001 |
| E5 | JSON-RPC client | `rpc/*` (jsonrpsee) | 🟥 / 🟨 | JSON-RPC + biscuit token | `is_public_addr` 单 gate；CORS fallback；XMOD-005 | INPUT-003, AUTH-001/003, XMOD-005 |
| E6 | CKB 节点 (HTTP RPC) | `ckb/client` | 🟧 | JSON-RPC | trust on bootstrap；`OutputData` lock_args 在 watchtower 路径无 len 守卫 | INPUT-005 |
| E7 | LND gRPC (上游) | `cch/actor.rs` (`receive_btc`) | 🟧（CCH 操作员未必信任 LND 上游用户） | gRPC + bolt11 | INPUT-002 共享 invoice panic 面；XMOD-004 | INPUT-002, XMOD-004 |
| E8 | 磁盘（keyfile / db） | `fiber/key`, `store` | 🟨 | scrypt 加密 / bincode | DB 目录 0o644/0o755；db-version 无 HMAC | CRYPTO-003, STORE-001, INPUT-004, XMOD-003 |
| E9 | 浏览器 IndexedDB / 跨 tab | `fiber-wasm-db-worker` | 🟨 | 自定义 batch | 单 worker 假设 / 无跨 tab 互斥 | WASM-001, WASM-002 |
| E10 | OS env (`FIBER_SECRET_KEY_PASSWORD`) | `fiber/key`, `fiber-bin` | 🟦 | 字符串 | — | CRYPTO-003 |

### 3.2 模块间边（fiber 内核内部 actor 消息流）

> 这些边**承载用户/网络/磁盘数据 → actor 副作用**，是 XMOD 攻击链的关键传播段。

| # | 起点 actor / 模块 | 终点 actor / 模块 | 触发数据来源 | 通信方式 | 安全审计要点 |
|---|---|---|---|---|---|
| I1 | `fiber/payment` (`update_graph_with_tlc_fail`) | `fiber/network` (`NetworkActorCommand::BroadcastMessages`) | E4 (远程 TlcErr) | `cast!` (`send_message`) | **XMOD-001**：attacker-controlled channel_update 进 gossip pool 无 route-membership 校验 |
| I2 | `fiber/payment` | `fiber/graph` (`mark_channel_failed/mark_node_failed`) | E4 | 直接函数调用 | **ERR-001.F2 / XMOD-001**：本地图 slander |
| I3 | `rpc/*` | 各 fiber actor (`ChannelActor`, `PaymentActor`, ...) | E5 | `handle_actor_call!` 宏 = `call!` 无 timeout | **XMOD-009**：全 RPC 路径无 actor timeout；mailbox 无界 |
| I4 | `rpc/cch.rs` (`receive_btc`) | `cch/actor.rs` | E5 + E7 | `call!` | **XMOD-004**：invoice panic 入口共享 |
| I5 | `fiber/network` | `ckb/actor.rs` (`CkbChainActor`) | E2 (funding 协商) | `call!` w/ `DEFAULT_CHAIN_ACTOR_TIMEOUT=5min` + `.expect()` | **XMOD-009.F3**：chain actor 死路 panic |
| I6 | `fiber/channel` | `watchtower/actor.rs` | force-close / settlement 事件 | `cast!` | **XMOD-006 / XMOD-011**：preimage 落地 watchtower → 日志 ERROR 级别打印 |
| I7 | `cch/scheduler` | `cch/actor` (`expire_order`) | 定时器 + E7 状态 | `cast!` | **XMOD-002**：order_expiry < htlc final_expiry 24h 窗口 |
| I8 | `watchtower/actor` (`run_periodic_check`) | `ckb/client` (E6) | 定时器 + E6 数据 | actor RPC | **XMOD-006**：lock_args slice 无守卫 |
| I9 | `fiber/network` (`on_peer_connected`) | session admission 内部 | E1 | callback | **NET-001 / XMOD-005**：admission gate 仅看 `peer_session_map`，ghost session 绕过 |
| I10 | `store/store_impl/mod.rs` (`auto_migrate`) | `fiber-store::migration` | E8 (磁盘 db-version key) | 直接函数调用 | **XMOD-003**：bincode prefix-overlap + db-version 无签名 |
| I11 | `fiber/channel` (`derive_tlc_pubkey`) | `fiber-types::primitives::Pubkey::tweak` | E2 (`tlc_basepoint`, `first_per_commitment_point`) | 内联函数 | **XMOD-010**：`.not_inf().expect` → channel state 已持久化先于 panic |
| I12 | `fiber/channel` (`AnnouncementSignatures`) | `fiber/gossip` (广播 channel_announcement) | E2 | `cast!` → broadcast | **XMOD-008.F3**：partial 不预校验 → gossip 污染入口 |

### 3.3 出站边

| # | 起点 | 终点 | 数据 | 备注 |
|---|---|---|---|---|
| O1 | `fiber/gossip` | 远程邻居 (tentacle) | `BroadcastMessage*` | 广播放大；与 I1 / I12 协同 |
| O2 | `ckb/funding`, `ckb/actor` | CKB 节点 (链上 tx) | molecule tx | 钱包私钥签名（受 ⑤ 保护） |
| O3 | `cch/actor` | LND gRPC (上游) | gRPC | 服务端到 LND；CCH 单边出资见 LOGIC-008 |
| O4 | `rpc/pubsub` | 订阅客户端 | JSON-RPC notification | 仅含已脱敏字段（待复审） |
| O5 | `tracing` / log fd | stderr / file | 任意 `{:?}` 格式化 | **XMOD-011**：watchtower preimage、biscuit token 等敏感字段进入 |

---

## 4. XMOD 攻击链的模块边映射

下表把每条已记录的 XMOD-001..011 映射到上文 §3 的边编号，方便回归测试覆盖。

| XMOD | 涉及边 | 模块链 | 备注 |
|---|---|---|---|
| **XMOD-001** | E4 → I2 + I1 → O1 | payment → graph + payment → network → gossip | channel_update slander 全网放大 |
| **XMOD-002** | E7 + I7 + I6 + I8 | cch ↔ watchtower ↔ channel ↔ ckb | order_expiry vs final_tlc_expiry 时序不变量 |
| **XMOD-003** | E8 + I10 | store ↔ migration | bincode 宽松 + db-version 无 HMAC + 0o644 |
| **XMOD-004** | E5 + E7 → invoice 模块 | rpc / cch / payment 三入口共享 invoice panic | INPUT-002 多路径 |
| **XMOD-005** | E5 + I9 | rpc auth gate + admission gate | CORS fallback + Host header + standalone watchtower |
| **XMOD-006** | I6 + I8 + 反 cheat 全链 | watchtower ↔ ckb ↔ channel ↔ gossip | 报告 §4 链 A |
| **XMOD-007** | E1 + chain hash 校验 + funding 构造 | network ↔ store ↔ ckb | Init 无规范文档 |
| **XMOD-008** | E2 (×3) + I12 → O1 | channel ↔ gossip ↔ network (×3 partial 路径) | MuSig2 partial 不预校验 |
| **XMOD-009** | E5 + I3 + I5 | rpc ↔ all-actors ↔ ractor ↔ chain | 全栈无 timeout + 无界 mailbox + `.expect()` |
| **XMOD-010** | E2 + I11 + 状态持久化 | primitives ↔ channel ↔ store | 单 OpenChannel 永久 brick |
| **XMOD-011** | E5 + I6 + O5 | rpc ↔ watchtower ↔ tracing | preimage 落地后 ERROR 级别打印 |
| **XMOD-012** | E2 (final-hop) + payment 错误码透传 | invoice ↔ channel ↔ payment | final-hop 错误码与 BOLT-04 偏离 → probing oracle |
| **XMOD-013** | E10 + 内部 signer + E8 | bin ↔ env ↔ key ↔ store ↔ ckb signer | 凭据生命周期跨 5 模块；env/内存/磁盘 3 个泄露面 |
| **XMOD-014** | E9 + 隐式跨 tab 边 | wasm-db ↔ store ↔ channel | 多 tab 双签 → 资金罚没 |

---

## 5. 信任不变量速查表（审计检查清单）

> 这是"应该但目前不一定满足"的模块间不变量，每条都被 ≥1 个 XMOD 违反。

| Inv | 描述 | 应在哪条边强制 | 现状 |
|---|---|---|---|
| **INV-1** | 远程 peer 提交的 `channel_outpoint` 必须在本次 attempt 的 route 上才允许 mark/转发 | I1, I2 | ❌ XMOD-001 |
| **INV-2** | CCH `order_expiry > BTC final_tlc * block_seconds + safety_margin` 必须在启动时强制 | I7 + 配置加载 | ❌ XMOD-002 |
| **INV-3** | `db-version` 不可被同主机非特权用户单方面写入（HMAC 或 0o600） | E8 + I10 | ❌ XMOD-003 |
| **INV-4** | 反序列化必须严格拒绝 trailing bytes + prefix-overlap | E1/E2/E8 全部 | ❌ XMOD-003, INPUT-004 |
| **INV-5** | invoice 解析路径不能 panic（远程可达字符串） | E5, E7, E2 (gossip) | ❌ XMOD-004 |
| **INV-6** | 所有敏感 RPC 模块（payment/channel/cch/watchtower）必须强制 biscuit，与 `is_public_addr` 解耦 | E5 middleware | ❌ XMOD-005 |
| **INV-7** | watchtower lock_args / witness 长度守卫优先于业务逻辑 | I8 | ❌ XMOD-006 / INPUT-005 |
| **INV-8** | `Init.chain_hash` 不匹配立即持久 ban，且 funding 路径再次校验 | E1 + O2 | ❌ XMOD-007 |
| **INV-9** | 所有对端 MuSig2 partial 必须先 `verify_partial` 再 aggregate；失败 ban peer | E2 5 处 partial 接收点 | ⚠️ 1/5 满足；XMOD-008 |
| **INV-10** | 每条 RPC actor 调用必须显式超时；actor mailbox 必须 bounded；fiber 内核任何 actor 不可 `.expect(ASSUME_*)` | I3, I5 | ❌ XMOD-009 |
| **INV-11** | 协议消息字段不可使 `Pubkey::tweak` 等"几乎全空间安全但有罕见 O 输入"原语 panic；调用方必须能优雅拒绝 | I11 + 状态持久化 | ❌ XMOD-010 |
| **INV-12** | `Preimage` 必须独立 newtype，`Debug` 默认 redact；所有 ERROR 级别打印不可包含 preimage / token / secret | O5 | ❌ XMOD-011 |
| **INV-13** | final-hop 错误响应必须与 BOLT-04 对齐，统一返回 `IncorrectOrUnknownPaymentDetails`，不暴露 invoice 状态分支 | E2 final-hop | ❌ XMOD-012 |
| **INV-14** | 钱包凭据（env / 内存 / 磁盘）全生命周期受保护：env 启动后清空 / `Privkey` Zeroize on Drop / DB 0o600 / dumpable=0 | E8 + E10 + 全内核 | ❌ XMOD-013 |
| **INV-15** | 浏览器场景下同一 wallet 在同一时刻仅允许一个 tab 持有写权限（Web Locks + commitment_number 回退检测） | E9 + I 跨 tab 边 | ❌ XMOD-014 |

---

## 6. 与 Phase 1 finding 的映射

> 本节让本文档与 [`SECURITY_AUDIT_TODO.md`](./SECURITY_AUDIT_TODO.md) 互通。

每个 INV 都至少对应一条 Phase 1 finding 或 XMOD：

- INV-1 ↔ ERR-001.F2 + AUDIT-XMOD-001
- INV-2 ↔ LOGIC-008 + AUDIT-XMOD-002
- INV-3 / INV-4 ↔ STORE-001 + INPUT-004 + AUDIT-XMOD-003
- INV-5 ↔ INPUT-002 + AUDIT-XMOD-004
- INV-6 ↔ AUTH-001 + AUTH-003 + INPUT-003 + AUDIT-XMOD-005
- INV-7 ↔ INPUT-005 + LOGIC-003 + AUDIT-XMOD-006
- INV-8 ↔ SPEC-001.F7 + AUTH-002.F8 + AUDIT-XMOD-007
- INV-9 ↔ CRYPTO-004.F2 + AUDIT-XMOD-008
- INV-10 ↔ MEM-003 + INPUT-003 + AUDIT-XMOD-009
- INV-11 ↔ AUDIT-XMOD-010（新发现）
- INV-12 ↔ ERR-002 + AUDIT-XMOD-011（新发现）
- INV-13 ↔ ERR-001 + AUDIT-XMOD-012（新发现）
- INV-14 ↔ CRYPTO-003 + STORE-001 + AUDIT-XMOD-013（新发现）
- INV-15 ↔ WASM-001/002 + STORE-001 + AUDIT-XMOD-014（新发现）

---

## 7. 后续工作

- **回归测试矩阵**：以 §3 的边编号 (E1..E10 / I1..I12) 为测试目标，每条边至少有一个集成测试覆盖正向 + 至少一个负向 PoC（与 XMOD 列表对齐）；
- **新模块加入清单**：未来引入新协议消息或新 actor 时，本文档 §3 表必须同步追加边记录 + 评估是否触发新 INV 违反；
- **审计版本快照**：本文件版本号与 `SECURITY_AUDIT_TODO.md` 同步演进。
