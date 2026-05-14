# Fiber Network Node — Phase 1 Security Audit Report

| 字段 | 值 |
|---|---|
| 项目 | gpBlockchain/fiber (Fiber Network Node, FNN) |
| 分支/快照 | `copilot/create-security-audit-plan` (HEAD at audit close) |
| 审计周期 | 2026-05-13 至 2026-05-14 (S1-S29, 29 个会话；Phase 1 = S1-S26 33 项 + Phase 1.5 = S27-S29 跨模块 XMOD-001..016 补强 + 模块关系文档) |
| 审计范围 | 工作区全部 9 crates ~144k 行 Rust；Cargo.lock 锁定的依赖图 |
| 审计方法 | 静态阅读 + ripgrep + 编译期类型/匹配收口 + bincode/molecule 实测 (`/tmp/bctest`)，**无动态 PoC** (所有 ⚠️ 标 "[?]" 的项明确标识 "需动态验证") |
| 工具 | GitHub Advisory DB (DEP-001)、`grep`/`view` + 仓库自带 fuzz 目标审阅 |
| 总 TODO | 33 项，**100% 完成 Phase 1 (33/33)** |

---

## 1. 执行摘要 (Executive Summary)

Fiber 是 CKB 之上的 Layer-2 支付网络节点（Lightning Network 类设计），引入 MuSig2 协同签名、PTLC、CCH 跨链 HTLC、Trampoline 路由、Sphinx 洋葱多跳等特性。本次 Phase 1 静态审计覆盖了 10 个安全维度 (DIM-CRYPTO / -LOGIC / -INPUT / -AUTH / -NET / -MEM / -ERRINFO / -DEPS / -SPEC / -STORE / -WASM) 共 33 个细分项，最终所有项目均产出 finding 文件。

### 关键定性结论

| 维度 | 总体评级 | 简评 |
|---|---|---|
| 密码学核心 (MuSig2/PTLC/Sphinx/Invoice 签名) | **🟢 设计严谨** | 协议层正确；唯一 H/Critical 候选 (CRYPTO-001 MuSig2 nonce 复用) 需动态验证 |
| 业务逻辑 / 状态机 | **🟠 局部 High** | LOGIC-007 (协作关闭 DoS 链) / LOGIC-008 (CCH expire_order 资金直损) 是设计性问题 |
| 输入解析 / 反序列化 | **🟠 High** | INPUT-002 invoice / INPUT-005 watchtower 链上数据两处 `.expect()` 远程 panic 链 |
| 认证 / 鉴权 / P2P 网络栈 | **🟠 High** | AUTH-001 standalone watchtower 多租户 / AUTH-002 inbound 驱逐顺序 / NET-001 admission 绕过 |
| 资源/算术/错误信息 | **🟠 High → 🟡 Medium** | MEM-001 gossip OOM (High)；ERR-001 final-hop 错误码 probing；MEM-003 actor mailbox |
| 持久化 / 迁移 | **🟡 Medium** | STORE-001 DB 权限 0644 + SQLite 无 advisory lock + INPUT-004 bincode 反序列化 |
| 规范一致性 | **🟡 Medium** | SPEC-001/002/003 实现守住协议核心，规范层欠债 |
| 依赖供应链 | **ℹ️ Info** | DEP-001 12 个高敏依赖无 CVE；DEP-002/003 pre-release/git-rev pin 弱化扫描信号 |
| WASM 浏览器路径 | **🟡 Medium** | WASM-001/002 单 worker 假设 + Batch 非原子 + 跨 tab 无互斥 |

### 严重度汇总

| 严重度 | 计数 | 主要条目 |
|---|---|---|
| 🔴 **Suspected H/Critical** (需动态 PoC) | 1 | **AUDIT-CRYPTO-001** MuSig2 nonce 派生确定性 |
| 🟠 **High** (静态可达 / 协同 High) | 6 | **AUDIT-LOGIC-007**, **AUDIT-LOGIC-008**, **AUDIT-INPUT-002**, **AUDIT-INPUT-005**, **AUDIT-AUTH-001**, **AUDIT-MEM-001**, **AUDIT-NET-001** *(6 条总评 High，包含 2 条"协同 High"用统计 6 项)* |
| 🟡 **Medium** (单点中等) | 大量 | LOGIC-001..006, CRYPTO-002/004/005, INPUT-001/003/004, AUTH-002/003, MEM-002/003, ERR-001/002, STORE-001, SPEC-001/002/003, WASM-001/002 |
| 🟢 **Low** | 多处 | 散布各 finding 内 F-编号 |
| ℹ️ **Info / Pass** | 多处 | DEP-001/002/003、各 finding 内 Pass 条目 |
| ⚠️ **Improvement only** | 2 | CRYPTO-003 (wallet encryption)、INPUT-001 (fuzz 覆盖) |

> 注：本审计 **未发现已确认的资金直损 0-day 漏洞**（CRYPTO-001 是疑似，需 PoC）；但**多条高严重度发现的"协同链"可实现资金损失**（典型链：LOGIC-008 一条独立可达；INPUT-005.F1 + LOGIC-003.F6 + CRYPTO-004.F2 = "poison-revocation + watchtower panic + cheat success"）。

---

## 2. 项目概况 (Project Profile)

| 维度 | 内容 |
|---|---|
| 语言 / 工具链 | Rust 1.93.0 (`rust-toolchain.toml`), 兼容 `wasm32-unknown-unknown` |
| 构建 / 测试 | Cargo workspace (9 crates), nextest, Makefile (`make check`, `make clippy`, `make check-migrate`, `make gen-rpc-doc`) |
| 项目性质 | **区块链节点 / P2P 支付网络 / Layer-2 协议实现**（资金敏感） |
| 代码规模 | ~144,000 行 Rust，214 源文件，53 测试文件，已有 `crates/fiber-lib/fuzz/` (9 个 target) |
| `unsafe` | 极少：`fiber-store/src/browser*.rs` 2 处 Send/Sync impl + `tests/test_utils.rs` 1 处 |
| 编译选项 | `[profile.release] overflow-checks = true` ✅ |
| 高敏依赖 (节选) | `secp256k1 0.30`, `musig2 0.2.4`, `aes-gcm 0.10`, `scrypt 0.11`, `bitcoin 0.32`, `fiber-sphinx 2.3`, `lightning-invoice 0.33`, `ckb-sdk 5`, `molecule 0.9`, `bech32 0.9`, `tentacle 0.7`, `jsonrpsee 0.25`, `biscuit-auth 6.0.0-beta.3`, `ractor 0.15`, `rocksdb` |

### 信任边界 (Trust Boundaries)

| # | 边界 | 入口位置 | 不可信输入 | 主审计项 |
|---|---|---|---|---|
| ① | P2P 网络 (tentacle) | `fiber/{network,channel,gossip,onion_service}.rs` | 远程 peer 字节序列、Molecule 二进制消息、gossip 广播 | LOGIC-001..007, CRYPTO-002/004/005, INPUT-001, AUTH-002, MEM-001, NET-001 |
| ② | JSON-RPC | `rpc/*` + `biscuit.rs` | 本地/远程 HTTP/WS 调用方 | INPUT-003, AUTH-001/003, ERR-002 |
| ③ | CKB 链数据 | `ckb/{actor,client,contracts,signer}.rs`, `funding/` | 链上 cell/tx、CKB 节点响应 | INPUT-005, LOGIC-003/006 |
| ④ | 跨链 HTLC (CCH) | `cch/*` (gRPC with LND) | LND 上游 invoice / preimage / outgoing payment 事件 | LOGIC-008, SPEC-003 |
| ⑤ | 钱包/密钥 | `ckb/config.rs::read_secret_key`, `utils/encrypt_decrypt_file.rs`, `fiber/key.rs` | 磁盘 keyfile、`FIBER_SECRET_KEY_PASSWORD` env | CRYPTO-003 |
| ⑥ | 存储/迁移 | `store/`, `migrate_archive/`, `fiber-store/src/{rocksdb,sqlite,browser}.rs` | 用户数据目录、跨版本数据 | STORE-001, INPUT-004, WASM-001/002 |
| ⑦ | Invoice/Bech32 | `invoice/*` (含 `lightning-invoice`) | 用户/对端粘贴字符串 | INPUT-002, SPEC-002 |
| ⑧ | Sphinx 洋葱包 | `fiber-sphinx` + `path.rs`, `channel.rs` (PTLC/TLC) | 多跳路由洋葱密文 | CRYPTO-002, LOGIC-005, ERR-001 |

---

## 3. 重点发现明细 (Top Findings)

> 每条发现在 [`findings/`](./findings/) 下有独立 markdown 文件含 PoC 思路、修复 patch 草案与跟踪项编号。下表只列严重度 ≥ Medium 的核心条目。

### 3.1 🔴 Suspected H/Critical (需动态验证)

| ID | 标题 | 风险 | 关键位置 |
|---|---|---|---|
| **AUDIT-CRYPTO-001** | MuSig2 nonce 派生纯确定性 (seckey + 静态 context，无 message / agg-pubkey / 随机熵) | 同 `(commitment_number, context)` 下用不同 message 重复签名可泄露 funding key（理论攻击需 PoC：`restore_missing_revocation_send_nonce` reestablish 重放路径）→ **资金直损** | `fiber-types/src/channel.rs:1279,1240`, `fiber-lib/src/fiber/channel.rs:5398,6019,6038,6047,7956` |

> Phase 2 应优先 PoC：(a) 控制双 peer 在 reestablish 中诱导本节点对同 nonce 不同 commitment 二次签名；(b) `get_or_create_local_channel_announcement_signature` 缓存 invalidation 路径。

### 3.2 🟠 High (静态可达 / 协同 High)

| ID | 标题 | 攻击者前提 | 影响 |
|---|---|---|---|
| **AUDIT-LOGIC-008** | CCH `expire_order` 不区分订单 status；默认 36h order_expiry < 60h TLC_expiry 留 24h 窗口 | 用户发起一笔合法 SendBTC/ReceiveBTC，在窗口末延迟支付 | CCH 在 outgoing 流程中强制 Failed 订单 → preimage 事件被 `get_active_order_or_none` 丢弃 → CCH 未 settle incoming → **CCH 资金全损**；模块完全无 cancel_invoice/cancel_payment 调用路径 |
| **AUDIT-INPUT-002** | Invoice `From<InvoiceAttr>` 三处 `.expect()` (Description/FallbackAddr UTF-8 + PayeePublicKey from_slice) + `ar_decompress().expect()` | 任意可向公开 `parse_invoice` / `send_payment` / `cch.receive_btc` 提交字符串的远程方 | 单次合法 bech32m 字符串 → **整个 fiber 进程 panic**；CCH 受 BTC LN 用户输入直接打击；私网默认无鉴权 |
| **AUDIT-INPUT-005** | watchtower `lock_args[0..20]`/`lock_args[28..36]` slice 无 `commitment_lock.code_hash()` 校验且无长度守卫；`Htlc::build_from_witness` 全 unwrap | cheating peer 把短 args 的 commitment tx 上链（任意第三方亦可放任意 lock 触发） | watchtower spawn_blocking panic → 该轮全 channel 跳过 → 反 cheat 防线断裂 → **60h+ 后 cheat 成功 → 受害者全额损失** |
| **AUDIT-AUTH-001** | standalone watchtower `enable_auth=false` 时 `require_rpc_context` 注入 `NodeId::local()` (空 Vec) → 所有客户端共享同 keyspace | 多租户 watchtower 部署 + 已知受害者 channel_id (gossip 公开) | 攻击者 `update_revocation(victim_channel_id, ...)` 覆盖 → watchtower 在 cheat 发生时广播错误 revocation tx → **受害者无法反 cheat** |
| **AUDIT-MEM-001** | gossip `messages_to_be_saved` 入存不验签 + 无 per-peer 上限 + prune 不清理孤儿；`spawn_query_tasks` 内 incomplete_messages 完整 clone × 10 放大 | 1 个 inbound peer | ~50 MB/s RAM 增长 → **分钟级 OOM** |
| **AUDIT-LOGIC-007** | 协作关闭三处缺校验：`check_shutdown_fee_valid` 缺 fee_rate 下限 / `build_shutdown_tx` UDT saturating_sub 漏洞窗口 / `handle_shutdown_peer_message` 不校验 close_script.occupied_capacity | 通道对端 | 构造 `Shutdown{close_script=200B args, fee_rate=0}` → 通过我方校验 → tx 广播被链拒 → **通道卡死，只能 force-close → CSV 锁资金** |
| **AUDIT-NET-001** | tentacle `ServiceBuilder` 全默认 (max_connection=65535)；`enforce_inbound_peer_budget` 仅看 `peer_session_map` → secio-only/gossip-only/pre-Init 三类 ghost session 逃过 admission；`upnp` feature 静默公网暴露 | 远程 Sybil | L1-L4 协同链：socket 耗尽 / Sybil 槽位 / gossip OOM 绕过 / UPnP 公网暴露 → **节点对新 peer 不可达 → onboarding 阻断** |

### 3.3 🟡 Medium (集中视图)

| ID | 概要 |
|---|---|
| AUDIT-CRYPTO-004 | MuSig2 partial signature 在 ClosingSigned/RevokeAndAck/AnnouncementSignatures 三处缺预校验 → channel-stuck DoS |
| AUDIT-CRYPTO-005 | `Pubkey::tweak` `.expect("valid public key")` + OpenChannel 双 attacker-controlled (tlc_basepoint + first_per_commitment_point) → 永久 brick 通道 |
| AUDIT-LOGIC-001 | `UpdateTlcInfo` 完全无状态守卫 → 网络图污染 |
| AUDIT-LOGIC-002 | 入站 `AddTlc` 缺 `check_tlc_expiry` → peer 锁定 TLC 额度直至强关 |
| AUDIT-LOGIC-003 | watchtower `lock_args[28..36]` 缺长度检查 + revocation_data 覆盖式 → 选择性上链旧 commitment 可能逃罚 |
| AUDIT-LOGIC-004 | `forward_amount == 0` 未拒绝 → HTLC slot jamming |
| AUDIT-LOGIC-005 | MPP `total_amount` 无上界 → 任意倍超付资金注水 |
| AUDIT-INPUT-003 | `graph_nodes/channels`/`list_payments` `limit: u64::MAX` 无上界 → RPC 资源耗尽 |
| AUDIT-INPUT-004 | bincode 1.3 默认接受 trailing bytes + struct prefix-overlap，migration "已迁移"判定脆弱；`db-version` key 无完整性签名 |
| AUDIT-AUTH-002 | inbound 驱逐顺序倒置（踢老留新）+ `listen_on_onion=true` 仍开明文 TCP → Sybil eviction DoS + 隐私破坏 |
| AUDIT-AUTH-003 | `cors_enabled=true && cors_allowed_origins=[]` fall-through 到全通配 + 无 Host header allowlist (DNS rebinding) |
| AUDIT-MEM-002 | check_tlc_limits/build_settlement_data/commitment_fee*2 三处算术未 checked （fold + 链式 +/-） |
| AUDIT-MEM-003 | ractor 0.15 默认无界 mailbox + RPC `call!` 无超时 → 远程拖累 hang RPC 全线 |
| AUDIT-ERR-001 | final-hop `InvoiceExpired/InvoiceCancelled/FinalIncorrect{TlcAmount,ExpiryDelta}` 偏离 BOLT-04 折叠 → 远程零授权 invoice probing |
| AUDIT-ERR-002 | watchtower ERROR 级别 `{preimage:?}` 默认输出；`{token}` 进 anyhow Display 远程回显 |
| AUDIT-STORE-001 | DB 目录默认 0644/0755（vs onion key 0600）；SQLite 无 advisory lock 多实例双写竞态 |
| AUDIT-SPEC-001/002/003 | P2P 消息/Invoice/Trampoline+CCH 规范多处与实现失同步；spec-as-contract 缺位 |
| AUDIT-WASM-001 | `unsafe impl Send/Sync for Store` 无 SAFETY 注释；wasm threads 落地会引入 wasm-bindgen 句柄表 UB |
| AUDIT-WASM-002 | `Batch::commit` 拆 delete+put 非原子 + 同 origin 多 tab 无互斥 |

---

## 4. 协同攻击链 (Cross-Finding Attack Chains)

以下三条静态可达链不需要动态 PoC，是审计期间发现的最具威胁的"协同"组合：

### 链 A：watchtower 反 cheat 防线断裂（最致命）
**资金直损路径**：
1. AUTH-002.F1 + NET-001.F1 — 攻击者通过 Sybil eviction / no-ban-list 把合法 peer 推出节点视野
2. INPUT-005.F1 — cheating peer 把旧 commitment_tx 上链时使用 `lock_args.len() < 36` 的 lock script
3. watchtower `run_periodic_check` panic → 整轮全 channel 跳过
4. LOGIC-003.F6 + CRYPTO-004.F2 — revocation_data 覆盖式存储 + MuSig2 partial 未预校验 → 即便其他轮也无法构造正确反惩罚
5. 60h+ revocation 窗口过期 → cheat 成功 → **受害者全额损失**

**关键缓解**：INPUT-005.F1/F2 长度守卫 + AUTH-002.F1 反序驱逐 + CRYPTO-004.F2 verify_partial。

### 链 B：CCH 双向资金抽干
**资金直损路径**：
1. LOGIC-008.F1 — 用户在窗口末 (T=36h-ε) 才付 incoming
2. CCH 在 T=36h 强制 status=Failed
3. 用户在收款端 claim outgoing 揭示 preimage
4. `get_active_order_or_none` 返回 None → preimage 事件被丢弃
5. incoming TLC/HTLC 60h 后超时退还付款方 → 用户同时获得 outgoing 真金 + 退回的 incoming
6. **CCH 损失全额**；SendBTC/ReceiveBTC 双向均可利用

**关键缓解**：LOGIC-008.F1 修复 `expire_order` 兼容订单 status + 强制 `order_expiry > tlc_final_expiry`。

### 链 C：Wallet Drainer（浏览器端）
**资金间损路径**：
1. INPUT-003.F5 — 私网/loopback 监听默认 `enable_auth=false`
2. AUTH-003.F1 — `cors_enabled=true && cors_allowed_origins=[]` fall-through 到全通配
3. AUTH-003.F4 — 无 Host header allowlist (DNS rebinding 防御缺失)
4. 用户访问 evil.com → JS `fetch("http://127.0.0.1:port/", POST, RPC json)`
5. CORS preflight 通配 → biscuit 无鉴权 → 任意敏感 RPC (`send_payment`/`shutdown_channel`/`cancel_invoice`)

**关键缓解**：AUTH-003.F1 默认收紧（`cors_enabled` 启用时空列表 fail-fast）+ INPUT-003.F5 loopback 也强制鉴权。

---

## 5. 维度评分 (Per-Dimension Scorecard)

| 维度 | 总评 | 主要 finding | Phase 2 建议 |
|---|---|---|---|
| DIM-CRYPTO | 🟢 严谨（1 项疑似 H 待 PoC） | CRYPTO-001..005 | PoC MuSig2 nonce 复用；加 verify_partial 一致性 |
| DIM-LOGIC | 🟠 局部 High | LOGIC-001..008 | LOGIC-007/008 优先修复 |
| DIM-INPUT | 🟠 High | INPUT-002, INPUT-005 | `.expect→?` 重构 + watchtower len 守卫 |
| DIM-AUTH | 🟠 High | AUTH-001..003 | standalone watchtower fail-fast + Host header allowlist |
| DIM-NET | 🟠 High | NET-001 | UPnP 开关 + tentacle 配置收紧 + admission 提早 |
| DIM-MEM | 🟠 High (MEM-001) | MEM-001..003 | gossip per-peer 上限 + ractor mailbox 上界 + RPC `call_t!` |
| DIM-ERRINFO | 🟡 Medium | ERR-001/002 | 错误码折叠 + 日志 redaction |
| DIM-DEPS | ℹ️ Info | DEP-001/002/003 | CI cargo audit + biscuit-auth pin |
| DIM-SPEC | 🟡 Medium | SPEC-001/002/003 | 规范升级为 spec-as-contract + CI lint |
| DIM-STORE | 🟡 Medium | STORE-001, INPUT-004 | DB 0o700 + SQLite advisory lock + bincode strict |
| DIM-WASM | 🟡 Medium | WASM-001/002 | Batch atomic IPC + 跨 tab 互斥 |

---

## 6. 修复优先级 (Recommended Fix Priorities)

### P0 — 立即修复（建议在下个 release 前）
1. **AUDIT-LOGIC-008.F1** — CCH `expire_order` 跳过非 final 订单 + 默认 `order_expiry > tlc_final_expiry` 强制（资金直损）
2. **AUDIT-INPUT-002.F1/F2/F3** — Invoice `From → TryFrom`、`ar_decompress().expect → ?`（远程进程崩）
3. **AUDIT-INPUT-005.F1/F2** — watchtower `lock_args` / witness 长度守卫 + `Htlc::build_from_witness → Option<Self>`（反 cheat 防线）
4. **AUDIT-AUTH-001.F1** — standalone watchtower 启用时若 `biscuit_public_key.is_none() && require_rpc_context` 则 `bail!`（多租户密钥空间冲突）
5. **AUDIT-MEM-001.F1** — gossip `messages_to_be_saved` 入存验签 + per-peer 上限（远程 OOM）

### P1 — Phase 1.5（短期，4-6 周）
6. AUDIT-CRYPTO-001 PoC 与必要时的 nonce 派生加固
7. AUDIT-LOGIC-007.F1/F2/F3 协同补丁（shutdown DoS）
8. AUDIT-CRYPTO-004.F1/F2/F3 partial signature 一致 verify_partial
9. AUDIT-NET-001.F4 加 `enable_upnp` 开关（默认关）+ F2 tentacle 配置收紧
10. AUDIT-MEM-003.F1/F5 RPC `call_t!(...)` 超时 + ractor mailbox 上界
11. AUDIT-STORE-001.F1 DB 目录 0o700 + F2 SQLite advisory lock

### P2 — Phase 2（中期，2-3 个月）
12. AUDIT-INPUT-003/004 RPC 限速 + bincode strict
13. AUDIT-AUTH-002/003 CORS/onion/inbound 驱逐顺序
14. AUDIT-ERR-001/002 错误码折叠 + log redaction
15. AUDIT-LOGIC-001..006 防御纵深各 Medium
16. AUDIT-SPEC-001/002/003 规范升级
17. AUDIT-WASM-001/002 浏览器持久化加固

### P3 — Phase 3（长期）
18. AUDIT-CRYPTO-003 P2P key 加密化 + zeroize
19. AUDIT-INPUT-001 fuzz 覆盖 + CI cron
20. AUDIT-DEP-002/003 依赖供应链工程化

---

## 7. Phase 2 路线图 (Roadmap)

| 阶段 | 范围 | 交付物 |
|---|---|---|
| Phase 1 ✅ | 静态审计 (33 项) | 33 个 finding + 本报告 + ~60 个 follow-up |
| **Phase 2 (建议)** | 动态 PoC 与漏洞确认 | 重点 PoC：CRYPTO-001 nonce 复用 / LOGIC-008 24h 窗口实战 / INPUT-002 panic 一行 RPC / INPUT-005 watchtower panic / AUTH-001 standalone watchtower 多租户 / MEM-001 50 MB/s OOM 实测 |
| Phase 2.5 | 修复 + 回归 | 补丁实施 + 每条 finding 的回归测试用例 + 重审 |
| Phase 3 | 三方独立复核 | 邀请外部审计方对 P0/P1 修复独立验证 |
| 持续 | CI 集成 | `cargo audit` 定期、`cargo deny check`、fuzz cron、spec-as-contract lint |

---

## 8. 审计执行日志摘要

| 会话 | 日期 | 主要审计项 | 备注 |
|---|---|---|---|
| S1 | 2026-05-13 | CRYPTO-001, CRYPTO-003, DEP-001 | 框架建立 + Recon |
| S2 | 2026-05-13 | CRYPTO-002, INPUT-001 | Sphinx + fuzz |
| S3-S4 | 2026-05-13 | LOGIC-001, LOGIC-003, LOGIC-002, LOGIC-006 | 状态机/序号 |
| S5-S6 | 2026-05-13 | LOGIC-004, LOGIC-005, LOGIC-007 | 多跳/MPP/关闭 |
| S7-S8 | 2026-05-13 | AUTH-001, AUTH-002 | 鉴权 + peer 身份 |
| S9-S10 | 2026-05-13 | MEM-001, MEM-002 | 资源/算术 |
| S11 | 2026-05-13 | LOGIC-008 | CCH High |
| S12-S14 | 2026-05-14 | INPUT-002, ERR-001, STORE-001 | 输入 + 错误 + 持久化 |
| S15-S22 | 2026-05-14 | INPUT-003, INPUT-004, INPUT-005, ERR-002, AUTH-003, MEM-003, CRYPTO-004, CRYPTO-005, NET-001 | 输入纵深 + 算术 + 鉴权纵深 + P2P |
| S23-S25 | 2026-05-14 | SPEC-001, SPEC-002 | 规范 |
| **S26** | **2026-05-14** | **DEP-002, DEP-003, SPEC-003, WASM-001, WASM-002** | **Phase 1 收尾** |

> 完整逐项执行日志：见 [`SECURITY_AUDIT_TODO.md` 附录 A](./SECURITY_AUDIT_TODO.md#附录-a：审计执行日志)。
> 完整 follow-up 列表：见 [`SECURITY_AUDIT_TODO.md` 附录 B](./SECURITY_AUDIT_TODO.md#附录-b：新增项跟踪-phase-1-中发现的新攻击面)。

---

## 9. 范围与方法论 (Scope & Methodology)

**Phase 1 in scope**：
- 全 9 crates 源码静态阅读
- Cargo.lock 锁定依赖图 (GitHub Advisory DB 比对)
- `crates/fiber-lib/fuzz/` 现有 9 个 fuzz target 审阅
- `docs/specs/` 全部规范 vs 实现对照

**Phase 1 out of scope**：
- 动态 PoC（所有 ⚠️/[?] 标识的项均明确标注"需动态验证"）
- `fiber-sphinx 2.3` 上游 crate 源码深审（CRYPTO-002.FOLLOWUP-B 单独立项）
- 链上 commitment-lock 合约源码（[fiber-scripts](https://github.com/nervosnetwork/fiber-scripts), LOGIC-003.FOLLOWUP-A 单独立项）
- 跨链 LND 上游 bolt11 解析（CCH 假定 LND 端正确）
- 生产部署/运维配置审计（systemd unit / k8s manifest / Tor 上游）

**方法论局限**：
- 本审计**全部基于静态阅读**；标"H/Critical"或"High"的项目，若标注"需动态验证"，**应被视为高优先级假设**而非已确认漏洞。
- 多处发现依赖"协同链"成立；单独某项可能仅 Medium，组合后上升到 High（已在 §4 列出三条主链）。
- 依赖扫描仅覆盖 GitHub Advisory DB；未覆盖 RustSec advisory-db 全量历史（建议 Phase 2 引入 `cargo audit`）。

---

## 10. 致谢与署名

本次审计由 GitHub Copilot Agent 在 26 个会话内基于仓库静态阅读完成。每个 finding 包含独立的关联代码引用、风险描述、修复建议草案与跟踪项编号。最终建议在 Phase 2 引入外部独立审计方对 P0/P1 修复进行复核。

**联系 / 反馈**：请通过本 PR 评论或在 `docs/security-audit/SECURITY_AUDIT_TODO.md` 附录 B 中补充新发现 / follow-up。

---

*报告版本：v1.3（Phase 1 final + Phase 1.5 跨模块审计补强 XMOD-001..016 + MODULES.md v3）*  *最后更新：2026-05-14 (S29)*  *分支：`copilot/create-security-audit-plan`*

---

## 11. Phase 1.5 — 跨模块审计补强 (XMOD)

> Phase 1 按"维度 × 章节"完成 33 项静态审计后，本节做一次**横向**复盘：把那些"单 finding 严重度只 Medium、组合后 High"的攻击面提级为独立的 XMOD 项，方便修复规划与回归测试。详见 [`SECURITY_AUDIT_TODO.md` 附录 C](./SECURITY_AUDIT_TODO.md#附录-c跨模块审计-phase-15)；XMOD-001 ~ XMOD-016 每条均有独立 finding 文件，见 [`findings/AUDIT-XMOD-001.md`](./findings/AUDIT-XMOD-001.md) … [`findings/AUDIT-XMOD-016.md`](./findings/AUDIT-XMOD-016.md)。模块间关系与不变量速查见 [`MODULES.md`](./MODULES.md)。

### 11.1 XMOD 项概览

| ID | 跨越模块 | 严重度 | 关键链/事实 | Phase 1 来源 |
|---|---|---|---|---|
| **XMOD-001** | payment → gossip → network | 🟠 High | `update_graph_with_tlc_fail` 经 `BroadcastMessages` 把 attacker-controlled `channel_update` 推进全网 gossip | ERR-001.F2, MEM-001 |
| **XMOD-002** | cch ↔ watchtower ↔ channel | 🟠 High | order_expiry=36h vs TLC final_expiry=60h，24h 窗口内 CCH 强标 Failed 而 watchtower preimage 已落地 | LOGIC-008, INPUT-005 |
| **XMOD-003** | store ↔ migration ↔ bin | 🟡 Medium | 0o644 + db-version 无签名 + bincode trailing-bytes/prefix-overlap 默认接受 → 同主机离线攻击 | STORE-001.F1, INPUT-004.F1/F2 |
| **XMOD-004** | rpc ↔ invoice ↔ cch | 🟠 High | INPUT-002 panic 面共享 4 个入口：`parse_invoice`/`send_payment`/`cch.receive_btc`/（潜在 gossip） | INPUT-002, SPEC-002.F6/F7 |
| **XMOD-005** | rpc ↔ auth ↔ biscuit | 🟠 High | `is_public_addr` 单 gate + CORS 全通配 fallback + 无 Host allowlist + standalone watchtower `NodeId::local()` | INPUT-003.F5, AUTH-001/003 |
| **XMOD-006** | watchtower ↔ ckb ↔ channel ↔ gossip | 🟠 High | 反 cheat 链 (报告 §4 链 A) — 修复必须四模块同步 | INPUT-005, LOGIC-003, CRYPTO-004, AUTH-002, NET-001 |
| **XMOD-007** | network ↔ spec ↔ store | 🟡 Medium | Init `chain_hash` 规范缺位 → 第三方实现漏校 → 跨网攻击 | SPEC-001.F7, AUTH-002.F8 |
| **XMOD-008** | channel ↔ gossip ↔ network | 🟠 High | 5 处 MuSig2 partial 接收中 4 处缺 `verify_partial`（ClosingSigned×2 / RevokeAndAck / AnnouncementSignatures）；仓库内 4732-4737 TODO 已知该 bug | CRYPTO-004.F2, LOGIC-007, MEM-001 |
| **XMOD-009** | rpc ↔ all-actors ↔ ractor | 🟠 High | RPC `handle_actor_call!` 全 `call!` 无 timeout + ractor 0.15 默认无界 mailbox + `.expect(ASSUME_*)` 死路 panic | MEM-003, INPUT-003 |
| **XMOD-010** | primitives ↔ channel ↔ store | 🟡 Medium | `Pubkey::tweak` `.not_inf().expect` + 同条 `OpenChannel` 两 attacker-controlled 公钥无关系校验 + channel state 已持久化先于 panic → 重启再 panic = **永久 brick** | （新发现，与 CRYPTO-001 同模块但不同问题） |
| **XMOD-011** | watchtower ↔ tracing ↔ rpc | 🟡 Medium | `watchtower/actor.rs:181` 主动 ERROR 级别打印 `preimage:?` 全 hex；`Preimage` 复用 `Hash256` 类型系统无防护；biscuit token Display | （新发现：日志卫生） |
| **XMOD-012** | invoice ↔ channel ↔ payment | 🟡 Medium | fiber 在 BOLT-04 之外引入 `InvoiceExpired=PERM|16` / `InvoiceCancelled=PERM|17` / `FinalIncorrect*` 四类细分 → probing oracle 泄露 invoice 状态 | ERR-001, ERR-002 |
| **XMOD-013** | bin ↔ env ↔ key ↔ store ↔ ckb signer | 🟡 Medium | 钱包凭据端到端生命周期跨 5 模块；env 残留 / 0o644 DB / 无 zeroize / 无 mlock / dumpable=1 | CRYPTO-003, STORE-001 |
| **XMOD-014** | fiber-wasm-db-* ↔ store ↔ channel | 🟠 **High** | 浏览器多 tab 同 wallet → 各自 ChannelActor 推进 commitment number → 最后写者赢 → 旧 commitment 重签后被对端视为 cheat → **资金罚没**；migration 非原子；无 Web Locks | WASM-001, WASM-002, STORE-001 |
| **XMOD-015** | network ↔ ckb/tx_tracing ↔ channel ↔ watchtower ↔ store | 🟠 **High** | `CKB_TX_TRACING_CONFIRMATIONS=4` (~40s) + tracer 回调后立即 `swap_remove` 不回退；funding/closing/settlement 三类资金 tx 共用同一浅深度；无 `FundingTransactionReorged` 反向事件 → ≥4-block CKB reorg 后 channel 状态机推进不可逆 → funding reorg-out 资金 brick / settlement reorg-out 反 cheat 失效 | LOGIC-003, XMOD-002, XMOD-006 |
| **XMOD-016** | onion_service ↔ network ↔ gossip ↔ rpc | 🟡 Medium | `announced_addrs: Vec<Multiaddr>` 把 clearnet listening + 配置 + onion 三类地址合并；`get_or_create_new_node_announcement_message` 全量签名进 NodeAnnouncement gossip 全网广播；`NodeInfo` RPC 同样回全量 → Tor 隐私模式失效（pubkey ↔ clearnet IP ↔ .onion 三元关联） | AUTH-002.F2/F3 |

### 11.2 跨模块协同链 — 扩展（§4 链 A/B/C 之外的链 D/E/F）

#### 链 D：payment-driven gossip pollution（XMOD-001 + MEM-001）

```
attacker (mid-hop)  ──TlcErr+channel_update──>  victim sender
                                                      │
                                                      ▼ (无 route-membership 校验)
                                              BroadcastMessages
                                                      │
                                                      ▼
                                                gossip pool (无验签 / 验签延迟)
                                                      │
                                                      ▼ N 邻居扩散
                                                cluster-wide channel disable
```

**资金间损**：被诬陷的通道在全网被标 disabled → 该通道在网络中"消失" → 后续 N hop 路由失败 → fiber 网络可用性退化。

**核心修复**：XMOD-001.FOLLOWUP-A 在 BroadcastMessages 之前加 route-membership 校验。

#### 链 E：cross-chain preimage 失窃（XMOD-002 + LOGIC-008）

`cch_order_expiry < htlc_final_expiry` 是协议层的**时序不变量违反**：
- T=36h：CCH `expire_order` 强制 Failed（即便 InFlight）→ `get_active_order_or_none` → None
- T=36h..60h：watchtower 检测到链上 cheat / settlement → preimage 落地 watchtower DB
- T>36h：CCH 收到 `preimage_revealed` 事件 → 因订单 Failed 丢弃 → **跨链 settle 失败 → CCH 单边亏损**

**核心修复**：(a) 启动时强制 `order_expiry > btc/ckb_final_tlc + safety_margin`；(b) `expire_order` 仅对 status==Pending 生效；(c) preimage 事件即便订单 Failed 也必须持久化重放。

#### 链 F：offline persistence corruption（XMOD-003）

同主机非特权用户（无 root）：
1. STORE-001.F1：DB 目录 0o755 + 文件 0o644 → 可写
2. INPUT-004.F2：`db-version` 无 HMAC/签名 → 改写到 `LATEST_DB_VERSION` 字面值
3. INPUT-004.F1：bincode 1.x 默认 trailing-bytes-tolerant + struct-prefix-overlap → 重启后 OLD bytes 静默被反序列化为 NEW 类型字段（删字段 mig 永不重跑）
4. 节点静默运行错位 schema → channel state 错位 → 后续 commitment 签名异常 → force-close
5. **资金间损**（force-close penalty + CSV 锁定）

**核心修复**：STORE-001.F1 (0o700/0o600) + INPUT-004.F1 (`reject_trailing_bytes`) + db-version HMAC。

#### 链 G：MuSig2 partial-sig DoS 双向（XMOD-008 + LOGIC-007 + XMOD-006）

```
attacker (channel 对端)
   │
   ├─ ClosingSigned { bad partial } ──> 我方 (792-803) ──> remote_shutdown_info.signature = bad
   │                                         │
   │                                         ▼ build_shutdown_tx 阶段 aggregate 失败
   │                                   channel stuck ShuttingDown
   │                                         │
   │                                         ▼ (+ LOGIC-007 fee_rate=0 / 200B args)
   │                                   force-close + CSV 锁资金
   │
   ├─ RevokeAndAck { bad partial } ──> 我方 (7301) ──> aggregate 失败 / 错值写入 store
   │                                         │
   │                                         ▼ (+ LOGIC-003.F6 revocation 覆盖式)
   │                                   反 cheat 防线断裂 (与链 A 协同)
   │
   └─ AnnouncementSignatures { bad partial } ──> 我方 (4720) ──> aggregate 失败 + warn! 不 ban
                                             │
                                             ▼ (无 NET-001.F1 持久 ban)
                                       重连 + 重发 → channel 公开 DoS + gossip 入存放大
```

**资金间损**：(a) 协作关闭被坏 partial 阻断 → force-close penalty；(b) revocation 链污染 → 反 cheat 防线断（与链 A 同址）。

**核心修复**：XMOD-008.FOLLOWUP-A（3 处统一 `verify_partial`）+ FOLLOWUP-B（失败 ban 对端，依赖 NET-001.F1）。

#### 链 H：单一 RPC 端点 → 全 fiber 进程冻结（XMOD-009 + INPUT-003）

```
attacker  ─jsonrpsee TCP─>  rpc/channel.rs  ─handle_actor_call!─>  NetworkActor
                                                                        │ (无 timeout)
                                                                        ▼
                                                                  ChannelActor (无 timeout)
                                                                        │
                                                                        ▼
                                                                  ChainActor (DEFAULT_CHAIN_ACTOR_TIMEOUT=5min)
                                                                        │ chain RPC 慢/挂
                                                                        ▼
                                                            network.rs:3490 `.expect()` → panic 全 NetworkActor
                                                                        │
                                                                        ▼
                                                                fiber 进程 crash
```

并发的 attacker：
- INPUT-003 默认 100 connections / 10MB body → 100 个慢请求并发
- ractor 0.15 默认无界 mailbox → 每个 actor 收件箱不断膨胀 → 进程 OOM 在 panic 之前到达

**资金间损**：节点不可用期间无法响应 watchtower preimage、无法 honest force-close、watchtower 子流程亦 panic（与链 A 协同）。

**核心修复**：XMOD-009.FOLLOWUP-1..4（RPC 显式 timeout + ractor bounded mailbox + 移除 `.expect(ASSUME_*)`）。

#### 链 I：单条 P2P 消息永久 brick 通道（XMOD-010）

```
attacker (open channel side)
   │
   └─ OpenChannel {
        tlc_basepoint = T,  ← 构造 s·G
        first_per_commitment_point = Q,  ← 任选 secp256k1 点
        // 满足 T + blake2b(Q)·G = O
      }
              │
              ▼  channel.rs:8748-8762 无两公钥关系校验
        ChannelActorState 持久化到 store
              │
              ▼  首次 derive_tlc_pubkey (channel.rs:6097-6126)
        Pubkey::tweak (primitives.rs:511-519) → result == O
              │
              ▼  `.not_inf().expect("valid public key")`
        ChannelActor panic
              │
              ▼  重启
        Store 重新加载 state → 再次 derive_tlc_pubkey → 再次 panic
              │
              ▼
        **永久 brick：无法收发 TLC，force-close 也走不通签名路径**
```

**资金间损**：通道资金锁死直到链上 commitment 强制 timeout（CSV）。

**核心修复**：XMOD-010.FOLLOWUP-1..3（`Pubkey::tweak` 改 Result + handler 持久化前预派生 + 启动加载若派生失败标 bricked 而非 panic）。

#### 链 J：浏览器多 tab wallet 资金罚没（XMOD-014 + STORE-001 + WASM-001/002）

```
                     tab A                              tab B
                       │                                  │
                  open wallet                       open same wallet (re-visit)
                       │                                  │
                       ▼                                  ▼
            ChannelActor 实例 A                ChannelActor 实例 B
            (memory: cn = N)                   (memory: cn = N，刚从 IndexedDB 读)
                       │                                  │
              send_payment → 推进                       send_payment → 推进
              cn = N+1, 签名 commit_N+1               cn = N+1, 签名 commit_N+1
                       │                                  │
              IndexedDB put cn=N+1 ✓                IndexedDB put cn=N+1 ✓ (覆盖)
                       │                                  │
              对端先收到 A 的 sig                    对端后收到 B 的 sig (相同 cn, 不同 commitment_tx)
                       │                                  │
                       └──────────────┬───────────────────┘
                                      ▼
                            对端视为 cheat：同一 commitment_number 出现两个签名 → 广播 revocation tx
                                      ▼
                            **资金罚没**（不是 brick，是 *直接* 损失）
```

资金直损模型：浏览器 wallet 是 fiber 最广泛的用户接入入口，损失阈值（开通通道的 wallet 余额）由用户掌控，攻击门槛仅"用户在两个 tab 打开同一钱包"或"前端 SPA 路由刷新触发新 ChannelActor 实例"。

**核心修复**：
- XMOD-014.FOLLOWUP-A：`navigator.locks.request` 启动独占锁，第二 tab 仅观察；
- XMOD-014.FOLLOWUP-B：browser 后端 IndexedDB transaction 包裹 migration + state 写入；
- XMOD-014.FOLLOWUP-C：启动时检测 `commitment_number` 回退即主动 force-close。

#### 链 K：CKB chain reorg 资金 brick / 反 cheat 防线断裂（XMOD-015 + LOGIC-003 + XMOD-006）

```
attacker 与受害者 open channel + 4-confs 推进
                │
                ▼  network.rs:119 CKB_TX_TRACING_CONFIRMATIONS=4 (~40s)
       tx_tracing_actor.rs:269-278  callback 触发 → tracer swap_remove (不可回退)
                │
                ▼
       NetworkActorEvent::FundingTransactionConfirmed
                │
                ▼  channel.rs:3054-3084  state.funding_tx_confirmed_at = Some(...)
       ChannelActor → AwaitingChannelReady → ChannelReady
                │
                ▼  双方累积 commitment_number / TLC
                │
        ╔═══════╧═══════╗
        ▼               ▼
   场景 K1：              场景 K2：
   funding tx 被 ≥4-blk    settlement / closing tx 被 ≥4-blk
   reorg 走                 reorg 走 (watchtower 路径)
        │                   │
        ▼                   ▼
   channel 状态仍 "Ready"     反 cheat 已"完成"标记，但链上回退
   后续 force-close 无 input    cheating tx 在另一条链上 confirm
        │                   │
        ▼                   ▼
   **资金永久 brick**         **资金直损**（与链 A 协同）
```

**资金直损 / brick 双链路**：fiber 4-confs (≈40s) 比 BTC LN 6-confs (≈60min) 浅一个数量级；CKB NC-Max 下自发深 reorg 概率低但**网络分区 / selfish-mining / 矿池协同**可以放大；攻击者制造小幅 reorg 的代价远低于此。

**核心修复**：XMOD-015.FOLLOWUP-1 提高并分拆 `FUNDING_CONFIRMATIONS=24` / `CLOSING_CONFIRMATIONS=12` / `SETTLEMENT_CONFIRMATIONS=24`；F2/F3 引入 `FundingTransactionReorged` 反向事件 + ChannelActor `ReorgRecovery` 子状态；F4 watchtower 收到 reorg 事件重新扫描。

#### 链 L：Tor 隐私模式下 NodeAnnouncement 主动泄露 clearnet 身份（XMOD-016 + AUTH-002）

```
deployer 配置 listen_on_onion=true（预期：Tor-only）
                │
                ▼  network.rs:5676-5742
   announced_addrs.push(clearnet_listen_addr)      ← announce_listening_addr 默认 true
   announced_addrs.extend(config.announced_addrs)  ← yaml 显式
                │
                ▼  network.rs:5744-5765
   announced_addrs.push(onion_addr)                ← 追加，不替换
                │
                ▼  network.rs:3734-3760  + gossip 出站
   NodeAnnouncement.addresses = [clearnet_ip:port, onion_addr.onion:port]
                │  (节点 secp256k1 签名)
                ▼  gossip 全网邻居持久化 save_node_announcement
   任一邻居：pubkey ↔ clearnet IP ↔ onion 三元组永久关联
                │
                ▼
   1) AUTH-002.F2/F3 同时未关闭明文 TCP → 直连验证 IP 真实可达；
   2) 即便防火墙堵入站，主动广播仍泄露；
   3) `info_node` RPC 同样回 full Vec → 鉴权穿透 (XMOD-005) 时二次泄露。
```

**隐私穿透**：fiber 节点 onion 化的核心承诺被破坏。运营商、活动人士、记者、审查环境用户预期"Tor-only" 时仍泄露真实 IP，与其它服务关联扩大攻击面。

**核心修复**：XMOD-016.FOLLOWUP-1 加 `OnionServiceConfig::tor_strict_mode`；F2 出站 NodeAnnouncement / `node_info` 过滤；F3 把 `announced_addrs` 类型重构为 `AnnouncedAddrs { tor, clearnet }` 在编译期强制分流。

### 11.3 修复优先级（含 XMOD）

合并 §6 与 XMOD 后的统一 P0/P1 列表：

#### P0 — 立即修复
- LOGIC-008.F1（CCH expire_order 仅 Pending）— **包含在 XMOD-002**
- INPUT-002.F1/F2/F3（Invoice panic）— **多入口共享，XMOD-004 强调跨模块**
- INPUT-005.F1/F2（watchtower len 守卫）— **包含在 XMOD-006**
- AUTH-001.F1（standalone watchtower）— **包含在 XMOD-005**
- MEM-001.F1（gossip 入存验签 + per-peer 上限）— **与 XMOD-001 协同**
- **XMOD-001.FOLLOWUP-A**（route-membership 校验 + 速率限制 channel_update 出站转发）
- **XMOD-008.FOLLOWUP-A**（3 处 MuSig2 partial 统一 `verify_partial` 预校验）
- **XMOD-009.FOLLOWUP-1..3**（RPC 显式 timeout + ractor bounded + 移除 `.expect(ASSUME_*)`）
- **XMOD-014.FOLLOWUP-A/B**（浏览器 Web Locks + IndexedDB transaction 包裹 migration）
- **XMOD-015.FOLLOWUP-1..3**（confs 提高并分拆 + `FundingTransactionReorged` 反向事件 + ChannelActor `ReorgRecovery` 子状态）

#### P1
- CRYPTO-001 PoC（同 §6）
- LOGIC-007 协同补丁（同 §6；与 XMOD-008 同 PR 提交）
- CRYPTO-004 verify_partial（同 §6；合并到 XMOD-008.FOLLOWUP-A）
- **XMOD-005**：敏感模块强制 biscuit + CORS 启用空列表 fail-fast + Host allowlist
- **XMOD-003**：store 0o700/0o600 + bincode strict + db-version HMAC
- **XMOD-010**：`Pubkey::tweak` 返回 Result + handler 预派生验证
- **XMOD-013**：钱包凭据生命周期硬化（zeroize + mlock + dumpable=0 + env 立即清空）
- **XMOD-014.FOLLOWUP-C/D**：commitment_number 回退检测 + SQLite advisory lock
- **XMOD-015.FOLLOWUP-4..5**：watchtower 收到 reorg 事件重新扫描 + 文档化 reorg-depth 假设
- **XMOD-016.FOLLOWUP-1..3**：`tor_strict_mode` + NodeAnnouncement/RPC 出站过滤 + `AnnouncedAddrs` 编译期分流
- NET-001.F4（UPnP 开关）/ MEM-003 / STORE-001（同 §6）
- NET-001.F1 持久 ban list（XMOD-006 和 XMOD-008 都依赖）

#### P2
- **XMOD-007**：SPEC-001 规范补 Init chain_hash + funding 双校验
- **XMOD-011**：`Preimage` newtype + 日志 redact + biscuit token 移除 Display
- **XMOD-012**：final-hop 错误码与 BOLT-04 对齐 + 差分时序防御
- **XMOD-016.FOLLOWUP-4..6**：规范层补 *节点身份与广播地址隐私* 章节、`info_node` RPC 隐私策略、启动检测警告

### 11.4 Phase 1.5 交付

| 项 | 状态 |
|---|---|
| TODO 附录 C（16 条 XMOD 项 + 链 D/E/F/G/H/I/J/K/L 链路图） | ✅ 本提交（v29） |
| `findings/AUDIT-XMOD-001.md`（payment ↔ gossip slander 放大） | ✅ S27 |
| `findings/AUDIT-XMOD-008.md`（MuSig2 partial-sig 不一致） | ✅ S28 |
| `findings/AUDIT-XMOD-015.md`（CKB reorg ↔ channel ↔ watchtower 4-confs + 无 rollback） | ✅ 本提交（S29） |
| `findings/AUDIT-XMOD-016.md`（onion_service ↔ network ↔ gossip Tor 隐私边界） | ✅ 本提交（S29） |
| `MODULES.md`（模块关系图 + 入出站边表 + 17 条 INV 不变量） | ✅ 本提交（v3） |
| XMOD-002..007 / 009..014 是否需要独立 finding 文件 | 后续按需补；当前 TODO 附录 C 详细节 + MODULES.md 边映射足以追踪 |
| Phase 2 PoC 列表 | 在 §7 路线图基础上追加：(a) channel_update gossip 放大 PoC (b) cch 24h 窗口实战 PoC (c) **ClosingSigned bad partial channel-stuck PoC** (d) **OpenChannel `(T,Q)` 构造永久 brick PoC** (e) **慢响应 chain actor 触发 RPC 雪崩 PoC** (f) **final-hop 错误码 probing oracle PoC** (g) **浏览器双 tab wallet revocation 罚没 PoC** (h) **CKB ≥4-block reorg → funding/closing reorg-out PoC**（mock chain actor）(i) **listen_on_onion=true 下 NodeAnnouncement clearnet 泄露断言 PoC** |

