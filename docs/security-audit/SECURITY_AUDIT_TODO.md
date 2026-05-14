# Fiber Network Node 安全审计 TODO

> 版本: **v17** | 最后更新: 2026-05-14 | 状态: 进行中 (Phase 1 — Session 17 完成)

## 项目概况 (Project Profile)

| 维度 | 内容 |
|---|---|
| 语言 | Rust 1.93.0 (`rust-toolchain.toml`), 兼容 `wasm32-unknown-unknown` |
| 构建 | Cargo workspace (9 crates), nextest, Makefile |
| 项目类型 | **区块链节点 / P2P 支付网络 / Layer-2 协议实现** (资金敏感) |
| 代码规模 | ~144,000 行 Rust，214 源文件，53 测试文件，已有 `crates/fiber-lib/fuzz/` |
| `unsafe` | 极少：`fiber-store/src/browser*.rs` (2 处 Send/Sync impl) + `tests/test_utils.rs` 1 处 |
| 编译选项 | `[profile.release] overflow-checks = true` ✅ |
| 高敏依赖 (节选) | `secp256k1 0.30`, `musig2 0.2.4`, `aes-gcm 0.10`, `scrypt 0.11`, `bitcoin 0.32`, `fiber-sphinx 2.3`, `lightning-invoice 0.33`, `ckb-sdk 5`, `molecule 0.9`, `bech32 0.9`, `tentacle 0.7`, `jsonrpsee 0.25`, `biscuit-auth 6.0.0-beta.3`, `ractor 0.15`, `rocksdb` |

### 信任边界 (Trust Boundaries)

| # | 边界 | 入口位置 | 不可信输入 |
|---|---|---|---|
| ① | P2P 网络 (tentacle) | `fiber-lib/src/fiber/{network,channel,gossip,onion_service}.rs` | 远程 peer 任意字节序列、Molecule 二进制消息、广播 gossip |
| ② | JSON-RPC | `fiber-lib/src/rpc/*` (jsonrpsee) + `biscuit.rs` 鉴权 | 本地/远程 HTTP/WS 调用方 |
| ③ | CKB 链数据 | `fiber-lib/src/ckb/{actor,client,contracts,signer}.rs`, `funding/` | 链上 cell/tx、CKB 节点响应 |
| ④ | 跨链 HTLC (CCH) | `fiber-lib/src/cch/*` (grpc with LND) | LND 上游 invoice / preimage |
| ⑤ | 钱包/密钥 | `fiber-lib/src/ckb/config.rs::read_secret_key`, `utils/encrypt_decrypt_file.rs`, `fiber/key.rs` (scrypt + AES-GCM) | 磁盘 keyfile、`FIBER_SECRET_KEY_PASSWORD` env |
| ⑥ | 存储/迁移 | `store/`, `migrate_archive/`, `fiber-store/src/{rocksdb,sqlite,browser}.rs` | 用户数据目录、跨版本数据 |
| ⑦ | Invoice/Bech32 | `fiber-lib/src/invoice/*` (含 `lightning-invoice`) | 用户/对端粘贴字符串 |
| ⑧ | Sphinx 洋葱包 | `fiber-sphinx` + `fiber/path.rs`, `channel.rs` (PTLC/TLC) | 多跳路由洋葱密文 |

---

## 审计进度

- **总 TODO 项**: 32
- ✅ 通过: 0
- ⚠️ 建议改进: 2 (AUDIT-CRYPTO-003, AUDIT-INPUT-001)
- ❌ 发现疑似漏洞: 1 (AUDIT-CRYPTO-001 — 需动态验证)
- ⚠️ 发现弱设计: 19 (AUDIT-CRYPTO-002, AUDIT-LOGIC-001..008, AUDIT-INPUT-002, AUDIT-AUTH-001, AUDIT-AUTH-002, AUDIT-MEM-001, AUDIT-MEM-002, AUDIT-ERR-001, AUDIT-STORE-001, AUDIT-INPUT-003, AUDIT-ERR-002, AUDIT-AUTH-003)
- ℹ️ 信息性: 1 (AUDIT-DEP-001)
- ⏳ 待审计: 9

**状态标记**: `[ ]` 待审 ｜ `[~]` 审计中 ｜ `[x]` 通过 ｜ `[!]` 发现问题 ｜ `[?]` 疑似/需动态验证 ｜ `[i]` 信息性

**优先级**: 🔴 P0-Critical ｜ 🟠 P1-High ｜ 🟡 P2-Medium ｜ 🟢 P3-Low

---

## 第 1 章 DIM-CRYPTO 密码学

- [?] 🔴 **AUDIT-CRYPTO-001** MuSig2 协同签名实现与 nonce 管理 — **疑似 H/Critical**
  - **关联代码**: `crates/fiber-types/src/channel.rs:1279` (`derive_musig2_nonce`), `:1240` (`musig2_base_nonce` 派生); `crates/fiber-lib/src/fiber/channel.rs:5398` (`get_channel_announcement_musig2_secnonce`), `:6019`, `:6038`, `:6047`, `:7956`
  - **审计内容**:
    - [x] nonce 派生是否纯确定性？(✅ 是 — `seckey + 静态 context 字符串`，无 message / aggregated-pubkey / 随机熵)
    - [x] 是否可能在相同 `(commitment_number, context)` 下用不同 message 重复签名？(疑似可能 — 见 findings)
    - [x] 现有测试覆盖：通道重连/重启路径有压力测试但**无对抗性 nonce 复用测试**
  - **发现记录**: 见 [`findings/AUDIT-CRYPTO-001.md`](./findings/AUDIT-CRYPTO-001.md)

- [!] 🔴 **AUDIT-CRYPTO-002** Sphinx 洋葱包解封与回放保护 — **Medium × 1, Low × 1, Info × 1**
  - **关联代码**: `crates/fiber-types/src/onion.rs`, `crates/fiber-lib/src/fiber/channel.rs:1279-1380`, `network.rs:2960-3110`
  - **审计内容**:
    - [x] assoc_data 绑定 payment_hash ✓
    - [x] peel 错误统一映射 `InvalidOnionPayload` ✓ (无 oracle 泄露)
    - [x] trampoline peel 失败 → `TemporaryNodeFailure` ✓
    - [x] 错误包反向传播 (`TlcErrPacket::backward`) 符合 spec ✓
    - [!] **F1 (Medium)**: 缺少应用层 shared-secret / 临时公钥 replay 缓存 (跨通道重放风险)
    - [!] **F2 (Low)**: `TlcErrPacket::decode` 时间填充在 success/fail 路径不对称、用零密钥
    - [i] **F3 (Info)**: `fiber-sphinx 2.3` 内部 HMAC 恒定时间、replay 原语需上游审计
  - **发现记录**: 见 [`findings/AUDIT-CRYPTO-002.md`](./findings/AUDIT-CRYPTO-002.md)

- [⚠️] 🔴 **AUDIT-CRYPTO-003** 钱包私钥加密/解密 — **多项建议改进**
  - **关联代码**: `crates/fiber-lib/src/utils/encrypt_decrypt_file.rs`、`crates/fiber-lib/src/ckb/config.rs:114-146` (`read_secret_key`)、`crates/fiber-lib/src/fiber/key.rs` (P2P key, **明文落盘**)
  - **审计内容**:
    - [x] scrypt 参数 → `Params::recommended()` ✅
    - [x] AES-GCM nonce 唯一性 → 12-byte CSPRNG random，OK
    - [x] VERSION 字节读但**从未校验** ❌ (medium)
    - [x] 缺少长度校验 → 短文件触发 panic ❌ (medium DoS / robustness)
    - [x] `fs::read(...).unwrap()` panic 而非返回 Err ❌ (low)
    - [x] 不 zeroize 派生 key、密码、明文 ❌ (low — 代码自身 TODO 注释也承认)
    - [x] `read_secret_key` 中 hex 明文遗留路径在加密迁移后未删除/覆盖明文 ❌ (low — 文件被 truncate-write，磁盘磁道残留风险较小但仍建议显式 fsync + 多次覆写)
    - [x] `fiber/key.rs::KeyPair` (节点身份密钥) 仍是**明文写盘**，无加密 ⚠️ (medium — 设计性)
  - **发现记录**: 见 [`findings/AUDIT-CRYPTO-003.md`](./findings/AUDIT-CRYPTO-003.md)

- [ ] 🟠 **AUDIT-CRYPTO-004** 签名验证完整性 (gossip / commitment / shutdown)
  - **关联代码**: `fiber/gossip.rs`、`fiber/channel.rs`
  - **审计内容**: 所有外部消息分支强制签名校验；恶意 peer 是否能命中未验证路径；曲线点/标量有效性

- [ ] 🟠 **AUDIT-CRYPTO-005** PTLC 点/标量代数操作
  - **关联代码**: `fiber/channel.rs`, `fiber/types.rs`
  - **审计内容**: 点加 / 标量乘 是否处理 identity / order-边界；scalar tweak 域分离

## 第 2 章 DIM-LOGIC 业务逻辑 / 状态机

- [~] 🔴 **AUDIT-LOGIC-001** 通道状态机非法转移 — **Medium × 1, Low × 3, Info × 2; 大量 Pass**
  - **关联代码**: `crates/fiber-types/src/channel.rs:236-298`, `crates/fiber-lib/src/fiber/channel.rs:448-828`
  - **审计内容**: 17 种 P2P 消息的 (状态 × 消息) 矩阵
  - **审计内容**:
    - [x] `CommitmentSigned` / `Shutdown` / `AcceptChannel` / `ReestablishChannel` 守卫完整 ✓
    - [x] `check_for_tlc_update` 集中校验 TLC 操作 ✓
    - [x] Reestablishing 时正确门控非 reestablish 消息 ✓
    - [!] **F4 (Medium)**: `UpdateTlcInfo` 完全无状态守卫 (channel.rs:755-759) — 任意状态下污染 `remote_tlc_info` + 网络图
    - [!] **F1/F2/F5/F6 (Low × 4)**: `TxSignatures` / `AnnouncementSignatures` / `ClosingSigned` / `TxAbort` 缺少显式状态匹配或静默忽略
    - [i] **F3/F7 (Info × 2)**: `RevokeAndAck` 缺显式状态匹配；reestablishing 期间静默丢弃消息无限速
  - **发现记录**: 见 [`findings/AUDIT-LOGIC-001.md`](./findings/AUDIT-LOGIC-001.md)
- [!] 🔴 **AUDIT-LOGIC-002** TLC / PTLC 生命周期与时间锁 — **Medium × 1, Low × 2, Info × 1; 大量 Pass**
  - **关联代码**: `crates/fiber-lib/src/fiber/channel.rs:1279-1564, 1575-1591, 1882-1929, 2697-2765, 6221-6250, 4453-4458`, `crates/fiber-lib/src/fiber/config.rs:38-58`, `crates/fiber-lib/src/fiber/fee.rs:144-228`, `crates/fiber-lib/src/fiber/network.rs:5263-5283`
  - **审计内容**:
    - [x] 出站 `check_tlc_expiry` 三项边界检查（MIN/MAX/epoch buffer）✓
    - [x] `commitment_delay_epoch` 在出站 + 入站 OpenChannel 两处都强制 `is_well_formed()`（length>0）✓
    - [x] `maintain_pending_tlcs` 正确清理过期 received TLC + 强关 offered TLC ✓
    - [x] `forward_amount + fee <= received_amount` 防 underflow ✓
    - [!] **F1 (Medium)**: 入站 `handle_add_tlc_peer_message` 完全不调用 `check_tlc_expiry` — peer 可发送 `expiry = u64::MAX` 锁定本方 TLC 额度直至强关
    - [!] **F2 (Low)**: `tlc_expiry_delay` 用 f64 除法，`length==0 → NaN as u64 = 0`（当前协议层不可达但缺防御）
    - [i] **F3 (Info)**: 出/入 expiry 校验不对称（相对 vs 绝对）
    - [!] **F4 (Low)**: debug 编译下接受无 onion 的 TLC（生产路径正确拒绝）
  - **发现记录**: 见 [`findings/AUDIT-LOGIC-002.md`](./findings/AUDIT-LOGIC-002.md)
- [!] 🔴 **AUDIT-LOGIC-003** Commitment 序号 & revocation key — **Medium × 3, Low × 2; 协议层 Pass**
  - **关联代码**: `crates/fiber-types/src/channel.rs:308-346`, `channel.rs:5524-5640, 6841-6937, 7270-7407, 7409-7587`, `watchtower/actor.rs:230-330`
  - **审计内容**:
    - [x] 序号增长对称性 (6 个 increment 点全部分析) ✓
    - [x] `reestablish` 边界 `abs_diff <= 1` ✓
    - [x] `last_revoke_ack_msg` 缓存重发避免 nonce 复用 ✓
    - [x] revocation_data 通知链路 (actor → event → watchtower) ✓
    - [!] **F3 (Medium)**: watchtower `lock_args[28..36]` 缺长度检查 → 协作关闭 close_script 短 args 可触发 panic-DoS，注释 `"checked length"` 误导
    - [!] **F6 (Medium)**: watchtower revocation_data 仅存最新一轮，覆盖式写入 — 若链上 commitment-lock 合约绑定 commitment_number，peer 选择性上链更早旧 commitment 可能逃避惩罚
    - [!] **F1 (Medium)**: `CommitmentNumbers::increment_*` 用裸 `+= 1` 无溢出检查
    - [!] **F2 (Low)**: `get_*_commitment_number() - 1` 用裸 `-1`，当前路径不可达但缺防御
    - [!] **F4 (Low)**: watchtower 只查询最新 1 笔 tx，无 confirmation 阈值/历史去重
  - **发现记录**: 见 [`findings/AUDIT-LOGIC-003.md`](./findings/AUDIT-LOGIC-003.md)
- [!] 🟠 **AUDIT-LOGIC-004** 多跳支付转发金额/费用一致性 — **Medium × 1 + Low × 3 + Info × 2**
  - **关联代码**: `crates/fiber-lib/src/fiber/channel.rs:1382-1421, 1882-1929, 2185-2222, 6252-6284`, `fee.rs:115-142`, `network.rs:3042-3157`, `utils/payment.rs:15-41`
  - **审计内容**:
    - [x] Forwarding hop `received_amount >= forward_amount` 防资金凭空生成 ✓
    - [x] `forward_fee = saturating_sub` 防 underflow + 出站 `check_tlc_forward_amount` 双向校验 ✓
    - [x] `calculate_fee_with_base` 用 `checked_mul` + 余数向上取整防舍入嫖 ✓
    - [x] Trampoline 严格 fee 等式 `available == build_max_fee_amount` ✓
    - [x] `try_to_settle_down_tlc` 只在 onion last hop 触发，防 forward-preimage 抢付 ✓
    - [!] **F1 (Medium)**: `forward_amount == 0` 未拒绝 → 攻击者可制造大量零值 TLC 挤占 `max_tlc_number_in_flight` slot (HTLC slot jamming)
    - [!] **F3 (Low)**: `tlc_fee_proportional_millionths` 缺上界 → peer 可广告 `ppm = u128::MAX` 自损式 DoS 通道
    - [!] **F6 (Low)**: `try_to_settle_down_tlc_without_invoice` 全局 preimage 命中即 fulfill 的测试 hazard
    - [i] **F4 (Pass)**: trampoline 严格等式是有意识的安全设计
    - [i] **F5 (Pass)**: `is_invoice_fulfilled` 单 TLC 调用安全，但建议 `checked_add`
  - **发现记录**: 见 [`findings/AUDIT-LOGIC-004.md`](./findings/AUDIT-LOGIC-004.md)
- [!] 🟠 **AUDIT-LOGIC-005** MPP / Trampoline 拆分一致性 — **Medium × 1 + Low × 3 + Info × 2**
  - **关联代码**: `crates/fiber-lib/src/fiber/settle_tlc_set_command.rs (全文件)`, `channel.rs:1148-1229, 1425-1564`, `network.rs:3042-3157`, `types.rs:1700-1815`
  - **审计内容**:
    - [x] MPP `total_amount` 一致性校验 (`verify_mpp_tlcs_have_consistent_total_amount`) ✓
    - [x] MPP `payment_secret` 与 invoice 匹配（每 shard 单独校验）✓
    - [x] Hold TLC `hold_expire_at <= tlc.expiry` 保护 ✓
    - [x] Trampoline 内层 onion 用 `payment_hash` 做 tweak，绑定内外 onion ✓
    - [x] Trampoline 转发起的新支付复用 payment_hash（协议核心机制）✓
    - [!] **F1 (Medium)**: `leave_just_fulfilled_tlcs_for_mpp_invoice` 接受任意倍超付（`total_amount = invoice.amount * N`），可触发资金注水 + overpaid 错误码用 `HoldTlcTimeout` 语义错位
    - [!] **F3 (Low)**: `apply_final_hop_tlc_onion_packet:1513` FIXME — MPP invoice + 单 TLC 无 MPP record 当前允许（技术债）
    - [!] **F4 (Low)**: `verify_mpp_consistent` 未显式校验 `payment_secret` 一致性（个体已检查，但 defense-in-depth）
    - [!] **F5 (Low)**: Hold `expire_at` 继承 LOGIC-002.F1 inbound expiry 问题
    - [i] **F2/F6/F7 (Pass)**: len==1 跳过校验已验证安全；trampoline tweak/preimage 设计正确
  - **发现记录**: 见 [`findings/AUDIT-LOGIC-005.md`](./findings/AUDIT-LOGIC-005.md)
- [!] 🟠 **AUDIT-LOGIC-006** Watchtower 反应路径（剩余面）— **Low × 4, Info × 2; 大量 Pass**
  - **关联代码**: `crates/fiber-lib/src/watchtower/actor.rs:486-667 (try_settle_commitment_tx), 669-810 (find_preimages), 794-1500 (build_settlement_tx), 1555-1788 (parsers)`
  - **审计内容**:
    - [x] `SettlementWitness` / `Unlock` 解析器长度检查正确（INV-1/2/3）✓
    - [x] `unlock.preimage.unwrap()` 由 `with_preimage` 不变式保证（INV-4）✓
    - [x] preimage hash 前缀匹配（20-byte 截断 vs 32-byte hash）✓
    - [x] Per-commitment 搜索 prefix 正确隔离（lock_args[0..36] 含 commitment_number）✓
    - [!] **F1 (Low)**: `try_settle_commitment_tx:500` `lock_args[0..36]` 缺独立长度检查（与 LOGIC-003.F3 同源）
    - [!] **F2 (Low)**: tx-pinning loop 无总迭代上限；`Err` 路径不 break 导致 RPC 失败时潜在死循环
    - [!] **F3 (Low)**: `Htlc::build_from_witness` 用 `unwrap`，调用方安全但 refactor 风险
    - [!] **F5 (Low)**: RPC 失败/非 Committed 状态用 `error!` 噪音；无重试机制
    - [i] **F4 (Info/Pass)**: 跨 channel preimage 复用为预期行为
    - [i] **F6 (Info)**: `sw.update() == false` 兜底路径待跟进
  - **发现记录**: 见 [`findings/AUDIT-LOGIC-006.md`](./findings/AUDIT-LOGIC-006.md)
- [!] 🟠 **AUDIT-LOGIC-007** 通道关闭 — 协作关闭 / 强制关闭 / shutdown_script 校验 — **整体 High (协同) / Medium × 3 + Low × 3 + Info × 2**
  - **关联代码**: `crates/fiber-lib/src/fiber/channel.rs:1622-1676 (handle_shutdown_peer_message), 1970-2075 (handle_shutdown_command + force), 5303-5338 (check_shutdown_fee_rate), 6189-6213 (check_shutdown_fee_valid), 6532-6620 (maybe_transfer_to_shutdown), 8001-8112 (build_shutdown_tx), 8315-8328 (get_latest_commitment_transaction), 8489-8527 (step_shutting_down), 4429-4450 (occupied_capacity)`, `fee.rs:144-218 (check_open_channel_parameters)`, `network.rs:5074-5159 (on_closing_transaction_pending/confirmed)`
  - **审计内容**:
    - [x] 协作关闭 TLC 对称保护：本地禁 LocalAnnounced / 对端禁 RemoteAnnounced ✓
    - [x] 开通时 `reserved_ckb >= occupied_capacity(shutdown_script)` 严格 `<` 校验 ✓
    - [x] MuSig2 部分签名聚合后才广播 shutdown_tx ✓
    - [x] 强制关闭广播 `latest_commitment_transaction`（非撤销版本）✓
    - [x] 自动应答仅当 `remote_fee_rate >= commitment_fee_rate` ✓
    - [!] **F1 (Medium)**: `check_shutdown_fee_valid` 对对端 fee_rate **没有最低限制**（不对称于 `check_shutdown_fee_rate`），peer 可发 `fee_rate=0` 通过校验 → 推卸 100% shutdown tx fee 给本节点
    - [!] **F2 (Medium)**: `build_shutdown_tx` UDT 分支 `local_reserved_ckb - local_shutdown_fee` 用 plain sub；`check_shutdown_fee_valid` 用 `saturating_sub(occupied_capacity)` 退化为 0 而非拒绝，留下 capacity < occupied_capacity 输出 cell 漏洞窗口
    - [!] **F3 (Medium)**: `handle_shutdown_peer_message` 未对 `shutdown.close_script` 做开通时同等强度（严格 `<`）的 `occupied_capacity ≤ remote_reserved_ckb` 校验，与 F1/F2 协同形成完整 DoS 链
    - [!] **F4 (Low)**: `get_latest_commitment_transaction` 用 `.expect(...)` panic
    - [!] **F5 (Low)**: 力关可在 `ShuttingDown(WAITING_COMMITMENT_CONFIRMATION)` 重复触发
    - [!] **F7 (Low)**: `step_shutting_down:8520` TODO — pending TLC 在 ShuttingDown 时缺少向上游回 RemoveTlcFail
    - [i] **F6 (Pass-by-design)**: 自动应答 `fee_rate=0` 是 LN BOLT-2 风格的有意识设计
    - [i] **F8/F9 (Pass)**: TLC 双向对称保护；`latest_commitment_transaction` 非撤销性
  - **协同攻击链**：F1 + F2 + F3 → peer 发 `Shutdown{close_script=<oversize args>, fee_rate=0}` → 通过我方所有校验 → 我方手动应答触发 `build_shutdown_tx` 产无效 CKB tx → 广播被拒 → 通道卡死 → 只能 force close → CSV delay 资金锁定
  - **发现记录**: 见 [`findings/AUDIT-LOGIC-007.md`](./findings/AUDIT-LOGIC-007.md)
- [!] 🟠 **AUDIT-LOGIC-008** CCH 跨链 HTLC 依赖与到期 — **整体 High / High × 1 + Low × 1 + Info × 1 + Pass × 3**
  - **关联代码**: `crates/fiber-lib/src/cch/scheduler.rs:262-301` (`expire_order` 不区分 status), `cch/actor.rs:459-473` (`schedule_job_for_non_final_order`), `cch/actor.rs:450-457` (`get_active_order_or_none` 过滤 final), `cch/order/state_machine.rs:44-65,68-84` (preimage hash 校验 + `_ → Failed` 总是允许), `cch/actions/settle_incoming_invoice.rs:124-126` (settle 需 `OutgoingSuccess`), `cch/actor.rs:560,655-674` (静态 half check), `cch/actions/send_outgoing_payment.rs:180-281` (动态 half check), `cch/config.rs:6-12` (`order_expiry=36h` < TLC_expiry=60h), `docs/specs/cch-expiry-dependency.md`
  - **审计内容**:
    - [!] **F1 🟠 High — 致命竞态 / 直接资金损失**: `expire_order` 仅 `is_final()` 跳过 Success/Failed，未跳过 `IncomingAccepted / OutgoingInFlight / OutgoingSuccess`。默认 `order_expiry_delta_seconds=36h` < `ckb_final_tlc_expiry_delta_seconds=60h` (或 BTC `360 blocks ≈ 60h`)，留 24h 攻击窗口。攻击路径：用户故意延迟到 T≈36h−ε 才付 incoming → CCH 派发 outgoing → T=36h 调度器强制 status=Failed → 用户在收款端 claim outgoing 揭示 preimage → `handle_tracking_event` 经 `get_active_order_or_none` 返回 None → preimage 事件被丢弃 → CCH 未 settle incoming → incoming TLC/HTLC 60h 后超时退还付款方 → **用户同时获得 outgoing 真金 + 退回的 incoming，CCH 损失全额**。SendBTC 与 ReceiveBTC 双向均可利用。**`grep cancel_invoice|CancelInvoice|cancel_payment` 在 `crates/fiber-lib/src/cch` 下 0 命中**，确认无对称取消路径。即便已到达 `OutgoingSuccess`（preimage 已存入 order），`SettleIncomingInvoiceDispatcher::should_dispatch` 要求 `status==OutgoingSuccess`，被强制改 Failed 后 settle action 链经 retry 也被 `get_active_order_or_none` 阻断。
    - [!] **F2 🟢 Low**: `actor.rs:560` 与 `send_outgoing_payment.rs:249` 的 `invoice.min_final_cltv_expiry_delta() * 600` 未 checked/saturating，与同文件 line 205 的 `saturating_mul(600)` 不一致；攻击者构造极大 `min_final_cltv` 致 u64 wrap → 静态 half check 误通过 → 订单僵尸（DoS/资源消耗，非直接资金损失，因下游 LND/bolt11 会拒）。
    - [i] **F3 ℹ️ Info**: BTC 块时间固定 600 s/block 假设，在持续偏快块速下可能压缩 half-budget 余量；建议文档化并允许部署方下调安全系数。
    - [✓] **F4 ✅ Pass**: `state_machine.rs:49-54` 对 outgoing preimage SHA256 校验后才接受 → 防伪造 preimage。
    - [✓] **F5 ✅ Pass**: 静态 half-budget check（SendBTC `actor.rs:557-564`、ReceiveBTC `actor.rs:655-674` 含 `checked_mul`）。
    - [✓] **F6 ✅ Pass**: 动态 half-budget + max_outgoing limit + `check_expiry_or_fail` (`send_outgoing_payment.rs:180-281`)，使用 `elapsed = now − created_at` 保守下界，`remaining / 2` 切分，并把 `tlc_expiry_limit` / `cltv_limit` 下放给后端。
  - **总体评价**: 协议层（preimage 验签、双重 half-budget、单调状态机）设计**严格遵循 LN 跨链 HTLC 标准**，但**运营层调度器**与**协议层状态机**之间存在严重接口失配：`expire_order` 把 wall-clock 订单过期与 HTLC 时序协调混为一谈，默认配置下 24h 攻击窗口默认开启。这是本审计目前**最严重的 LOGIC 类发现**，优先级高于 AUDIT-LOGIC-007。
  - **发现记录**: 见 [`findings/AUDIT-LOGIC-008.md`](./findings/AUDIT-LOGIC-008.md)

## 第 3 章 DIM-INPUT / DIM-SERDE 输入与反序列化

- [~] 🔴 **AUDIT-INPUT-001** P2P 消息解析 (Molecule) 抗畸形 — **Low × 1, Improvement × 3; 大部分通过**
  - **关联代码**: `crates/fiber-lib/src/fiber/types.rs:933`, `network.rs:126`, `gossip.rs:3123`
  - **审计内容**:
    - [x] 帧上限 130 KB 在 tentacle 层强制 ✓
    - [x] Molecule `from_slice` 内部长度校验稳健 ✓
    - [x] Onion hop_data 长度头 (`checked_add`/`try_from`) ✓
    - [x] 现有 9 个 fuzz 目标覆盖：fiber/gossip 消息、TlcErr、Pubkey、Cursor、HopData、Sphinx packet、Invoice、Bincode store ✓
    - [!] **Low**: `MAX_SERVICE_PROTOCOAL_DATA_SIZE` 常量拼写错误 (cosmetic)
    - [⚠️] **Improvement A**: `fuzz_molecule_types` 仅覆盖 4/~17 个 fiber/gossip 子类型的二阶 TryFrom
    - [⚠️] **Improvement B**: CI 中缺少 weekly fuzz cron / OSS-Fuzz 集成
    - [⚠️] **Improvement C**: 缺少 `TlcErrPacket::decode` / store migration / RPC JSON 参数的 fuzz 目标
  - **发现记录**: 见 [`findings/AUDIT-INPUT-001.md`](./findings/AUDIT-INPUT-001.md)
- [!] 🟠 **AUDIT-INPUT-002** Invoice 解析 (bech32m / molecule / CkbInvoice) — **整体 High / High × 1 + Medium × 2 + Low × 2 + Info × 1 + Pass × 2**
  - **关联代码**: `crates/fiber-types/src/invoice.rs:865-907` (`from_str`), `:887` (`ar_decompress(...).expect`), `:1018-1064` (`From<InvoiceAttr>`), `:1024,1042,1052` (utf8/pubkey expect), `:1085,1088` (store path u5/from_base32_checked expect), `:610` (`panic!`); `crates/fiber-lib/src/rpc/invoice.rs:289` (`parse_invoice` RPC), `cch/actor.rs:628` (`receive_btc`), `cch/actions/send_outgoing_payment.rs:254`, `cch/cch_fiber_agent.rs:115`, `fiber/payment.rs:359` (`build_send_payment_data`), `fuzz_targets/fuzz_invoice.rs`
  - **审计内容**:
    - [!] **F1 🟠 High — `From<InvoiceAttr> for Attribute` 三处 `.expect()` 远程 DoS**: `String::from_utf8(value).expect(...)` for `Description` (line 1024) / `FallbackAddr` (line 1042); `PublicKey::from_slice(...).expect(...)` for `PayeePublicKey` (line 1052)。Molecule 表层只校验 `Bytes` 表头，**不校验 UTF-8 / pubkey 长度**。攻击者绕过 `InvoiceBuilder` 直接构造 `RawInvoiceData` molecule 字节（如 Description.value = `\xff\xff`），ar_encompress + bech32m 包装 → 单次 `parse_invoice({invoice: S})` / `send_payment` / `cch.receive_btc(fiber_pay_req)` → 整个 fiber 进程 panic。`parse_invoice` 是公开只读 RPC 通常无授权，CCH receive_btc 接受跨链用户的 fiber_pay_req → **零成本零授权远程 DoS**。
    - [!] **F2 🟡 Medium — `ar_decompress(&data_part).expect("decompress invoice data")` 远程 DoS** (line 887): `arcode::ArithmeticDecoder::decode` 返回 `IoResult`，位流耗尽未读到 EOF 时返回 Err → panic。攻击者只需合法 bech32m 外壳 + 任意非合法压缩负载即可触发，比 F1 更易构造。修复：改 `.expect()` 为 `?`，新增 `InvoiceError::DecompressionError`。
    - [!] **F3 🟡 Medium — `invoice_data.try_into().expect("pack invoice data")`** (line 902): 当前 `TryFrom<RawInvoiceData> for InvoiceData` 实现体只是 `Ok(...)` 不会失败，`.expect()` 暂未可触发；但 F1 修复后（`From → TryFrom`）此处会变成第二个真实 panic 点。需联动改 `?`。
    - [!] **F4 🟢 Low — `panic!("no other error may occur, got {:?}", e)`** (line 610): `check_signature` 中对 secp256k1 错误用 `panic!` 表达不变式。当前不可触发但脆弱；secp256k1 升级或新增错误变体时会突然可触发。改 `Err(_) => return Err(InvoiceError::InvalidSignature)`。
    - [!] **F5 🟢 Low — Duplicate attribute 不拒绝**: 所有 attr accessor 用 `.iter().filter_map().next()` 只读首个；但 `hash()` 把所有 attrs 入签名 → 用户可见与系统认知可能不一致。`InvoiceError::DuplicatedAttributeKey` 已定义但**全代码 0 命中** → 设计意图未实施。
    - [i] **F6 ℹ️ Info — `fuzz_invoice` 结构性盲区**: 直接喂随机字节给 `from_str`，99.99% 被 bech32 checksum 拒绝；几乎无法穿透 ar_decompress 到达 attr 转换 panic 点。建议新增 `fuzz_invoice_data` (直接 fuzz `RawInvoiceData::from_slice`) 与 `fuzz_invoice_attr` (直接 fuzz `Attribute::from`)，并以现有 `tests/invoice_impl.rs` 中合法 invoice 字符串作为 corpus 种子。
    - [✓] **F7 ✅ Pass**: bech32m 强制（line 871-873）拒绝 bech32 变体，避免与 LN BOLT11 invoice 混淆。
    - [✓] **F8 ✅ Pass**: `check_signature` + `validate_signature` 在签名存在时强制校验，hash 覆盖全部 attrs。
  - **总体评价**: 信号层（bech32m / 签名 / HRP / 长度边界）扎实；**异常处理层充满 `.expect()`/`panic!`**，且这些 panic 全部位于用户可达的 RPC / CCH 入口。**单次合法格式的 RPC 请求 → 节点崩溃**。修复成本极低（`.expect → ?` + `From → TryFrom`），是除 LOGIC-008 之外最严重的 DoS 类发现。与 INPUT-001 (P2P 帧) 形成镜像：P2P 受 tentacle 长度限 + molecule 表层保护，但 invoice 入口同等攻击面**未受同等保护**。
  - **发现记录**: 见 [`findings/AUDIT-INPUT-002.md`](./findings/AUDIT-INPUT-002.md)
- [!] 🟡 **AUDIT-INPUT-003** JSON-RPC 参数校验 — **整体 Medium / Medium × 2 + Low × 4 + Info × 1 + Pass × 3**
  - **关联代码**: `crates/fiber-lib/src/rpc/mod.rs:124-408` (start_server + start_rpc + is_public_addr), `config.rs:1-38` (RpcConfig), `middleware.rs:42-114` (BiscuitAuthMiddleware + inject_rpc_context), `invoice.rs:289-300` (parse_invoice), `:302-369` (.expect("no invoice status found")), `payment.rs:315-343` (list_payments limit), `graph.rs:128-184` (graph_nodes/channels limit), `cch.rs:68-115` (send_btc/receive_btc pay_req)
  - **审计内容**:
    - [!] **F1 🟡 Medium**: `invoice.parse_invoice` / `cch.receive_btc` / `payment.send_payment(invoice)` 是 INPUT-002 invoice DoS 的远程触发入口 — 单条合法 bech32m 字符串即让节点 panic；私网默认无鉴权 / CCH 网关接收跨链用户输入 → 零成本零授权 DoS
    - [!] **F2 🟡 Medium**: `graph_nodes`/`graph_channels` (`limit: Option<u64>` 默认 500) 与 `list_payments` (`limit: Option<u64>` 默认 15) **无显式上界** — 攻击者 `{ "limit": 18446744073709551615 }` → 全量遍历 + clone + JSON 序列化 → 数十 MB 响应 + 大量 store 读 I/O；jsonrpsee 默认 100 并发连接 → 单 IP 即占满
    - [!] **F3 🟢 Low**: `invoice.rs:312, 338` 中 `get_invoice`/`cancel_invoice` 用 `.expect("no invoice status found")` — `insert_invoice` 双 put 非原子，IO 故障或 STORE-001.F4 mid-migration 可让 INVOICE 存在但 STATUS 缺失 → 远程触发 RPC panic
    - [!] **F4 🟢 Low**: jsonrpsee `Server::builder()` 用默认配置（10MB body / 100 connections / 无 per-IP-QPS / 无 receive timeout），且 `RpcConfig` **不暴露**这些字段给运维收紧；与 F1/F2 协同放大 DoS
    - [!] **F5 🟢 Low**: `is_public_addr` 仅检查公网监听强制鉴权；私网/loopback 监听默认 `enable_auth=false` → 同主机多租户（共享 dev/CI/k8s sidecar）任意用户可读所有 RPC（`cancel_invoice`/`shutdown_channel`/`send_payment` 等敏感方法）
    - [i] **F6 ℹ️ Info**: `middleware.rs:55` `inject_rpc_context` 用 `to_raw_value(...).expect("serialize injected params")` — 当前不可触发，但 RpcContext schema 调整时易引入隐式 panic（防御性建议）
    - [✓] **F7 ✅ Pass**: Pubkey/Hash256/Privkey/Multiaddr 解析全部走 `try_from`/`parse` + `?` 传播，无 `.expect` 在解码路径
    - [✓] **F8 ✅ Pass**: `DevRpc` (`add_tlc`/`remove_tlc`/`submit_commitment_transaction` 等危险方法) `#[cfg(debug_assertions)]` release build 自动剔除 ✓
    - [✓] **F9 ✅ Pass**: 公网监听 (`is_public_addr`) + 未配置 `biscuit_public_key` 时启动 fail-fast，防止公网零鉴权暴露
  - **总体评价**: RPC 层**类型解析**严谨（Pubkey/Hash256 全部 fallible，公网强制鉴权，DevRpc 编译期剔除），但在**用户字符串透传**（F1，与 INPUT-002 共生）和**集合 size 边界**（F2，零成本资源耗尽）两个面有重要缺口。F3/F4/F5 是防御纵深问题，与 STORE-001/MEM-001/AUTH-001/002 协同放大攻击面。修复成本低（F1 依赖 INPUT-002 主修复；F2/F3 各 < 10 行；F4/F5 小幅 RpcConfig 扩展 + tower middleware）。
  - **发现记录**: 见 [`findings/AUDIT-INPUT-003.md`](./findings/AUDIT-INPUT-003.md)
- [ ] 🟠 **AUDIT-INPUT-004** 存储反序列化 (bincode) 与迁移
- [ ] 🟡 **AUDIT-INPUT-005** CKB Tx / Cell 数据

## 第 4 章 DIM-AUTH 认证与鉴权

- [!] 🔴 **AUDIT-AUTH-001** Biscuit RPC 鉴权 — **整体 High / High × 1 + Medium × 2 + Low × 5 + Pass × 2**
  - **关联代码**: `crates/fiber-lib/src/rpc/biscuit.rs:75-262 (build_rules + BiscuitAuth + extract_node_id)`, `middleware.rs:1-205 (BiscuitAuthMiddleware)`, `mod.rs:124-296 (start_server + CORS + is_public_addr + auth 装配)`, `fiber-types/src/primitives.rs:90-99 (NodeId::local)`, `rpc/watchtower.rs:147-275 (require_rpc_context handlers)`, `bin/main.rs:235-293 (standalone watchtower)`
  - **审计内容**:
    - [x] biscuit ed25519 签名 + 撤销列表 + 时间约束（test 覆盖完整）✓
    - [x] 公网监听强制要求 biscuit 公钥（`mod.rs:285-287`）✓
    - [x] `is_public_addr` IPv4/IPv6 私网判定保守取严 ✓
    - [!] **F1 (High)**: `enable_auth=false` 时 `require_rpc_context` 注入 `NodeId::local()`（空 Vec<u8>）→ standalone watchtower 多租户场景下所有客户端共享同一 store keyspace → 攻击者可 `update_revocation`/`remove_watch_channel`/`remove_preimage` 覆盖受害者的 watchtower entry → watchtower 反惩罚失效，资金损失
    - [!] **F2 (Medium)**: `auth_call` local-bypass 分支对**未注册规则的方法 fail-open**（`middleware.rs:107-111` 返回 true），与 `enable_auth=true` 分支 fail-closed 不一致；当前未注册示例：`unsubscribe_store_changes`
    - [!] **F3 (Medium)**: CORS 默认 `Any` (allow_origin + allow_headers 全开) → 任意网站 JS 可携带 `Authorization: Bearer` 跨域调用（结合 token 泄漏即 CSRF）
    - [!] **F4 (Low)**: 撤销 token 错误信息泄露完整 token 到 `tracing::debug!` 和 `anyhow::Error`（`biscuit.rs:234-235`）
    - [!] **F5 (Low)**: `auth_notify` 无 `enable_auth=false` local 旁路 → 本地模式 notifications 一律失败
    - [!] **F6 (Low)**: `BEARER_PREFIX` 大小写敏感（违反 RFC 7235 §2.1）
    - [!] **F7 (Low)**: `extract_node_id` 在每次 require_rpc_context 调用打 `tracing::warn!` → 日志噪音 + node_id metadata 泄漏
    - [!] **F8 (Low)**: 无 rate-limit / 失败黑名单 → 撤销 token 字典攻击 + DoS 预热
    - [i] **F9/F10 (Pass)**: biscuit 签名/撤销/超时机制；`is_public_addr` 私网判定（取严）
  - **最严重场景 (F1)**: 自建 watchtower 集群 standalone 模式（私网/容器）无 biscuit 公钥配置时，攻击者只需访问 watchtower RPC 端口 + 已知受害者 channel_id（gossip 公开）即可调用 `update_revocation(victim_channel_id, attacker_crafted_revocation)` 覆盖 → watchtower 在 cheat 发生时广播错误的 revocation tx → 受害者无法反制 cheat
  - **发现记录**: 见 [`findings/AUDIT-AUTH-001.md`](./findings/AUDIT-AUTH-001.md)
- [ ] 🟠 **AUDIT-AUTH-002** Peer 身份绑定与 onion service — **整体 Medium / Medium × 2 + Low × 4 + Pass × 4**
  - **关联代码**: `crates/fiber-lib/src/fiber/network.rs:4460-4512 (enforce_inbound_peer_budget + inbound_no_channel_peers_in_connected_order)`, `network.rs:4876-4950 (on_peer_connected)`, `network.rs:6053-6108 (FiberProtocolHandle remote_pubkey)`, `network.rs:5560-5710 (secio handshake + listen + onion start)`, `network.rs:1744-1797 (ConnectPeer/ConnectPeerWithPubkey)`, `fiber/onion_service.rs:1-492 (Tor controller + key IO)`, `fiber/proxy.rs:1-50 (SOCKS5)`, `fiber/gossip.rs:2428-2615 (gossip signature verify)`, `fiber/config.rs:88,251-552 (DEFAULT_MAX_INBOUND_PEERS=16)`
  - **审计内容**:
    - [x] secio 握手对 `remote_pubkey` 的 ed25519 签名绑定（F7 Pass）✓
    - [x] gossip NodeAnnouncement / ChannelAnnouncement / ChannelUpdate 签名验证（F8 Pass）✓
    - [x] SOCKS5 stream isolation 默认开启（F9 Pass：`proxy_random_auth = true`）✓
    - [x] Onion v3 私钥生成 / 0o600 写入（F10 Pass）✓
    - [!] **F1 (Medium)**: `inbound_no_channel_peers_in_connected_order` 升序排序 + `take(excess_peers)` 驱逐 → **总是踢老的，留新的**。攻击者用 N 个 fresh secp256k1 keypair 发起 inbound 连接即可逐出 16 个合法 inbound-no-channel peer，阻止任何新客户上场；Sybil/eviction DoS，无链上抵押成本
    - [!] **F2 (Medium)**: `listen_on_onion=true` 仍同时打开明文 TCP 监听（`network.rs:5680` 始终基于 `config.listening_addr()`），无 `onion_only` 模式 → 端口扫描可关联真实 IP 与 `.onion` → 隐私模式失效
    - [!] **F3 (Low)**: `load_tor_secret_key`（onion_service.rs:475-491）不校验文件权限 → 备份恢复 / `cp -p` 引入 0o644 onion 私钥不报警
    - [!] **F4 (Low)**: `peer_session_map.insert`（network.rs:4878-4886）同 pubkey 静默覆盖旧 session_id，旧 tentacle session 未 disconnect → reconnect race 下消息可能分裂；非攻击通路（需私钥）
    - [!] **F5 (Low)**: `tor_password` 明文存于 config，无 `secrecy::SecretString` / zeroize
    - [!] **F6 (Low/UX)**: `ConnectPeerWithPubkey` 仅查 `state_to_be_persisted.persisted_peer_addresses`，不回退查询 gossip `NodeAnnouncement.addresses` → 用户体验不一致
    - [i] **F7-F10 (Pass)**: secio remote_pubkey 绑定；gossip 三类消息签名验证；SOCKS5 stream isolation 默认；onion v3 key 生成
  - **最严重场景 (F1)**: 攻击者用 17 个 fresh keypair 同时 dial 受害节点的 p2p 端口；每次 secio 握手完成后 `enforce_inbound_peer_budget` 被触发，由于 `peers.sort_by_key(|(_, sid)| *sid)` 升序 + `.take(1).disconnect()`，**最老的合法 inbound-no-channel session 被踢**。合法节点 reconnect 后再次成为最老，再次被踢。攻击者只需 < 100 KB/s 流量持续轮转，即可让节点对任何新 peer 不可达，阻断 channel onboarding 与 gossip 同步入度
  - **发现记录**: 见 [`findings/AUDIT-AUTH-002.md`](./findings/AUDIT-AUTH-002.md)
- [!] 🟡 **AUDIT-AUTH-003** RPC CORS / Tower-http 配置 — **整体 Medium / Medium × 1 + Low × 2 + Info × 2 + Pass × 4**
  - **关联代码**: `crates/fiber-lib/src/rpc/config.rs:23-31` (cors_enabled/cors_allowed_origins), `crates/fiber-lib/src/rpc/mod.rs:76,128-129,207-235` (CorsLayer 构造), `crates/fiber-lib/src/rpc/mod.rs:248-264,285-287` (is_public_addr + biscuit gate), `crates/fiber-lib/src/rpc/middleware.rs:30-40` (auth_token Bearer-only), `crates/fiber-lib/Cargo.toml:63,87-88` (hyper 1.5 / tower 0.5 / tower-http 0.6 / jsonrpsee 0.25.1)
  - **审计内容**:
    - [!] **F1 🟡 Medium**: `cors_enabled=true && cors_allowed_origins=[]` fall-through 到 `CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any)` (rpc/mod.rs:211-216)，运营者直觉为"空 = 拒绝全部"但实际通配所有源；配合 INPUT-003.F5 (loopback no-auth default) 形成 classic wallet drainer pattern：用户访问 evil.com → JS `fetch("http://127.0.0.1:<port>/", POST, json)` → CorsLayer preflight 通配 → biscuit `enable_auth=false` → `send_payment`/`shutdown_channel`/`cancel_invoice` 任意调用。Bitcoin/Ethereum 节点 2014 前经历过相同攻击模板
    - [!] **F2 🟢 Low**: `allow_methods(Any).allow_headers(Any)` 即便 origin 受限仍过宽 — JSON-RPC 仅需 POST + OPTIONS + Content-Type/Authorization
    - [!] **F3 🟢 Low**: `cors_allowed_origins.iter().filter_map(|o| o.parse().ok())` (rpc/mod.rs:220-223) — parsing 失败静默丢弃 (trailing slash / path / 空格 typo)；最坏情况 3 个 origin 全部 typo → `AllowOrigin::list(vec![])` 拒绝一切请求且运营者不知道
    - [i] **F4 ℹ️ Info**: 无 Host header allowlist / DNS rebinding 防御 — jsonrpsee 0.25 自身无 host validation；fiber 也未集成 (geth 用 `--http.vhosts localhost` 默认)。即便 cors_enabled=false，攻击者控制 evil.com TTL=0 → 浏览器 rebound 到 127.0.0.1 视为 same-origin → CORS preflight skip → Host header 是 evil.com 但 fiber 不校验 → 配合 INPUT-003.F5 攻击成立。CORS 不能防 DNS rebinding（CORS 是 same-origin 例外机制；rebinding 把跨域伪装为 same-origin）
    - [i] **F5 ℹ️ Info**: `auth_token` 仅读 `Authorization: Bearer` header 不读 Cookie/Query (middleware.rs:30-40) — 好的设计应文档化：浏览器**不会**为跨域请求**自动**附加 token (cookie 才会被浏览器跨域自动附加)，从根本上消除"凭证被被动盗用"CSRF 向量
    - [✓] **F6 ✅ Pass**: `cors_enabled: false` 默认 (config.rs:24)
    - [✓] **F7 ✅ Pass**: `allow_credentials` 未启用 + tower-http 0.6 默认 false → 浏览器不会跨域自动携带 Cookie/HTTP-Auth credentials
    - [✓] **F8 ✅ Pass**: CORS layer 在 biscuit middleware 外层，OPTIONS preflight 在 CorsLayer 直接返回（符合 CORS 规范），实际 POST RPC 经 biscuit 鉴权
    - [✓] **F9 ✅ Pass**: tower-http 0.6 / jsonrpsee 0.25.1 无已知 CVE（AUDIT-DEP-001 覆盖）
  - **总体评价**: CORS/browser-side 攻击面整体保护良好：默认安全 (cors_enabled=false)、设计安全 (Bearer-only auth)、层级正确 (CorsLayer 外/biscuit 内)、依赖安全 (无 CVE)。主要缺口两处：F1 (Medium) "反直觉默认" + INPUT-003.F5 形成 wallet drainer 路径；F4 (Info) 缺 Host header allowlist 让 DNS rebinding 绕过 CORS。F2/F3 工程化改进，F5 是好设计需文档化。整体相比 AUTH-001/AUTH-002 属于"配置可加固但默认OK"的中等级别。
  - **发现记录**: 见 [`findings/AUDIT-AUTH-003.md`](./findings/AUDIT-AUTH-003.md)

## 第 5 章 DIM-MEMORY 数值与资源

- [!] 🔴 **AUDIT-MEM-001** 资源耗尽 (Memory & Connection) — **整体 High / High × 1 + Medium × 2 + Low × 3 + Pass × 2**
  - **关联代码**: `crates/fiber-lib/src/fiber/gossip.rs:1339 (messages_to_be_saved)`, `gossip.rs:1585-1646 (insert_message_to_be_saved_list)`, `gossip.rs:1369-1425 (prune)`, `gossip.rs:1476-1559 (spawn_query_tasks)`, `gossip.rs:84 (MAX_NUM_OF_BROADCAST_MESSAGES=1000)`, `network.rs:126 (MAX_SERVICE_PROTOCOAL_DATA_SIZE=130KB)`, `network.rs:6053-6108 (FiberProtocolHandle::received)`, `channel.rs:284 (DEFAULT_MAX_TLC_VALUE_IN_FLIGHT=u128::MAX)`, `network.rs:6270-6354 (ToBeAcceptedChannels Pass)`, `fiber/config.rs:101 (gossip_store_maintenance=20s)`
  - **审计内容**:
    - [!] **F1 (High)**: gossip `messages_to_be_saved: HashMap<Pubkey, HashSet<BroadcastMessage>>` 在 `insert_message_to_be_saved_list` 入存时**不验签**且**无 per-peer 大小上限**。签名验证延迟到 20s 间隔的 Tick 中 `prune_messages_to_be_saved` 才执行，且仅对依赖完整的消息验签 → 攻击者伪造孤儿 `ChannelUpdate`（不存在的 channel_outpoint）永远不会被 `has_dependencies_available` 通过，仅靠 `spawn_query_tasks` 的 `.remove(&peer)` 间接清理但 `MAX_NUM_CONCURRENT_QUERY_TASKS=10` saturate 时停止移除。单 inbound 连接 ~3 MB RAM/s，16 个 inbound (配合 AUTH-002.F1) ~50 MB/s → 4 GB 节点 80 秒 OOM。零密码学成本、远程、可重复。
    - [!] **F2 (Medium)**: ractor actor mailbox 默认 unbounded mpsc；`FiberProtocolHandle::received` 无 per-peer rate-limit，攻击者可灌入语法合法的 FiberMessage 至 mailbox 累积 OOM
    - [!] **F3 (Medium)**: `spawn_query_tasks` 内 `incomplete_messages: Vec` 完整 clone 单 peer 的全部 pending 消息，task 内存放大 × 10；query 响应回灌前不验签 → F1 的二阶段放大器
    - [!] **F4 (Low)**: `channel.rs:284 DEFAULT_MAX_TLC_VALUE_IN_FLIGHT = u128::MAX` 默认放任 in-flight HTLC 总价值无限制（与 LOGIC-004 协同锁住整 channel 容量长达 14 天）
    - [!] **F5 (Low)**: `MAX_NUM_OF_BROADCAST_MESSAGES = 1000`，单 gossip 协议帧最大携带量过大，10× 放大 F1
    - [!] **F6 (Low)**: `prune_messages_to_be_saved` 的 retain 仅清理"已完成"消息，对永远不可能完成的消息无 TTL
    - [i] **F7 (Pass)**: `ToBeAcceptedChannels` 正确限额 20 channel / 50 KB / per pubkey
    - [i] **F8 (Pass)**: NodeAnnouncement 在 `announce_private_addr=false` 时拒收私网-only address
  - **最严重场景 (F1)**: 攻击者建立 inbound 连接（配合 AUTH-002.F1 控制 16 槽位），通过 `BroadcastMessagesFilterResult` 持续推送伪造 `ChannelUpdate`（随机签名 + 不存在的 channel_outpoint）。每帧 130 KB 携带 1000 条 broadcast，`insert_message_to_be_saved_list` 不验签直接入 HashSet。`prune` 不清理（依赖未到位），`spawn_query_tasks` saturate 后停止 remove。50 MB/s RAM 增长，分钟级 OOM；与 AUTH-001.F1 (watchtower 多租户) 协同：受害节点 OOM 时错过 revocation 信号 → cheat 成功
  - **发现记录**: 见 [`findings/AUDIT-MEM-001.md`](./findings/AUDIT-MEM-001.md)
- [!] 🟠 **AUDIT-MEM-002** 数值溢出与边界 — **整体 Medium / Low × 3 + Info × 2 + Pass × 4**
  - **关联代码**: `crates/fiber-lib/src/fiber/fee.rs:115-135` (`calculate_fee_with_base`), `fee.rs:188` (`commitment_fee * 2 未检查`), `channel.rs:5518` (`get_liquid_capacity 未检查 +`), `channel.rs:6425-6450` (`check_tlc_limits .fold 未 checked_add`), `channel.rs:8266-8272` (`build_settlement_data 链式 +/-未检查`), `channel.rs:5320-5329` (`available_max_fee u128 as u64 截断`), `channel.rs:5824-5849` (`apply_remove_tlc checked_* 典范`), `channel.rs:4408-4413` (`funding_amount < u64::MAX cap`), `channel.rs:6410-6411` (`add_amount==0 拒绝`), `payment.rs:196`, `graph.rs:1538,1543,1984`, `types.rs:2070` (含 u64::MAX overflow 单元测试), `settle_tlc_set_command.rs:174` (`MPP saturating_add`), `network.rs:177-253` (`retry/backoff saturating_*`)
  - **审计内容**:
    - [!] **F1 (Low)**: `channel.rs:6425-6431 / 6444-6450 check_tlc_limits` 内 `.fold(0_u128, |sum, tlc| sum + tlc.amount) + add_amount` 使用 unchecked u128 累加。当用户配置 `max_tlc_value_in_flight < u128::MAX` 时理论上可 wrap → 绕过 limit；默认 `u128::MAX` 时无业务后果。属"depth in defense"缺口。
    - [!] **F2 (Low)**: `channel.rs:8266-8272 build_settlement_data` 链式 `to_local_amount + received_fulfilled - offered_pending - offered_fulfilled` 4 个加减全部未 checked，release 下静默 wrap。依赖状态机不变式；与状态机 bug 协同可产生异常 settlement output；对端可能利用差异化拒绝（force-close 路径）。最有价值的修复：改造成与 `apply_remove_tlc:5824-5849 checked_*` 风格一致。
    - [!] **F3 (Low)**: F3a `fee.rs:188 commitment_fee * 2 > reserved_fee` u64 unchecked mul，攻击者可设 `commitment_fee_rate = u64::MAX` 触发 wrap → 接受异常 fee_rate → 后续 commitment_tx 上链失败 (DoS / channel-stuck)；F3b `channel.rs:5324 self.to_local_amount as u64` 静默截断高 64 位，依赖 line 4408 的 funding < u64::MAX 不变式。
    - [i] **F4 (Info)**: `channel.rs:5824-5849 apply_remove_tlc` 注释明确"double confirm everything is correct with checked_* methods" 是正面典范。
    - [i] **F5 (Info)**: `channel.rs:4408 get_funding_and_reserved_amount` 显式拒绝 `total_amount >= u64::MAX` for native CKB，保证 u128→u64 截断安全。
    - [✓] **F6 (Pass)**: payment/graph/onion 输入 checked_add 完整 — `payment.rs:196`, `graph.rs:1538,1543,1984`, `types.rs:2070` (含 `test_unpack_hop_data_v0_u64_max_overflow` 单元测试)。
    - [✓] **F7 (Pass)**: 时间戳与指数退避 saturating — `network.rs:177-253 funding_retry_delay / compute_peer_reconnect_delay` shift cap + saturating/checked_mul + min(MAX)。
    - [✓] **F8 (Pass)**: MPP `settle_tlc_set_command.rs:174 accumulated_amount.saturating_add`。
    - [✓] **F9 (Pass)**: `channel.rs:6410 check_tlc_limits` 显式拒绝 `add_amount == 0`。
  - **总体评价**: 与 MEM-001 形成鲜明对比 —— 数值算术整体**接近正确**。`apply_remove_tlc` 注释清楚说明 "deep defense" 意图；HopData 解析甚至有针对 u64::MAX overflow 的专门单元测试。3 个 Low 均属 "defense-in-depth" 缺口，实际触发需要前置状态机 bug。
  - **发现记录**: 见 [`findings/AUDIT-MEM-002.md`](./findings/AUDIT-MEM-002.md)
- [ ] 🟡 **AUDIT-MEM-003** Actor mailbox 阻塞

## 第 6 章 DIM-ERRINFO 错误信息与隐私

- [!] 🟠 **AUDIT-ERR-001** 支付错误码与 payment probing — **整体 🟡 Medium (Medium × 2 + Low × 3 + Info × 1 + Pass × 2)**
  - **关联代码**: `crates/fiber-types/src/payment.rs:793-852,161-285,273-278`, `crates/fiber-types/src/onion.rs:31-145,124`, `crates/fiber-lib/src/fiber/channel.rs:830-906,1148-1206,1333-1564`, `crates/fiber-lib/src/fiber/payment.rs:603-614,1076-1117,1728-1758`, `crates/fiber-lib/src/fiber/history.rs:167-307`, `crates/fiber-lib/src/fiber/graph.rs:1091-1122`
  - **审计内容**:
    - [x] 错误码语义颗粒度 vs BOLT-04 → ❌ fiber 引入 `InvoiceExpired`/`InvoiceCancelled` 且保留 `FinalIncorrect{TlcAmount,ExpiryDelta}` 细分 → payment probing
    - [x] final-hop 错误生成站点是否折叠 → ❌ `get_tlc_error` (channel.rs:840-844) + `try_to_settle_down_tlc_with_invoice` (channel.rs:1156-1170) 都显式区分
    - [x] 中转 hop `extra_data.node_id`/`channel_outpoint` 是否在本地图更新前校验 route 成员 → ❌ `update_graph_with_tlc_fail` 无校验，history 路径有校验（不对称）
    - [x] `update_graph_with_tlc_fail` 三处 `.expect(...)` → ⚠️ 在攻击者构造 `extra_data` 缺失时 PaymentActor panic
    - [x] sphinx error packet timing padding `ERROR_DECODING_PASSES=27` → ⚠️ release build 上是否被 LLVM 优化消除需动态验证
    - [x] `TlcErr::serialize` `.expect(...)` 反模式 → 与 INPUT-002.F4 同质
    - [x] sphinx 加密 / HMAC + `record_payment_fail` route-membership 校验 → ✅
  - **发现记录**: 见 [`findings/AUDIT-ERR-001.md`](./findings/AUDIT-ERR-001.md)
- [!] 🟡 **AUDIT-ERR-002** 日志/tracing 中的敏感信息 — **整体 Medium / Medium × 1 + Low × 3 + Info × 2 + Pass × 3**
  - **关联代码**: `crates/fiber-bin/src/main.rs:84-89` (EnvFilter::from_default_env), `crates/fiber-types/src/primitives.rs:215-217,358-369` (Privkey/Hash256 Debug), `crates/fiber-lib/src/watchtower/actor.rs:181,740`, `crates/fiber-lib/src/rpc/biscuit.rs:234,260`, `crates/fiber-lib/src/rpc/middleware.rs:88`
  - **审计内容**:
    - [!] **F1 🟡 Medium**: `watchtower/actor.rs:181` `tracing::error!("CreatePreimage with wrong preimage, payment_hash: {payment_hash:?} preimage: {preimage:?}")` — ERROR 级别默认输出，远程 `create_preimage` RPC 可诱导，preimage 字节进入 log aggregator/Datadog/Loki；与 STORE-001.F1 / INPUT-003.F5 协同 → 本地用户拼接 log+store 即可枚举 preimage/payment_hash 对
    - [!] **F2 🟢 Low**: `rpc/biscuit.rs:260` `tracing::warn!("fetch {id:?} {node_id:?}")` leftover 调试 — WARN 级别默认输出，每次 watchtower 鉴权 RPC 一条 → 噪声 + node_id 枚举
    - [!] **F3 🟢 Low**: `rpc/biscuit.rs:234-235` `anyhow!("Token is in revocation list: {token}")` — token 进入 Error Display → 远程 JSON-RPC error response 回显（AUTH-001.F4 镜像，从 ERR 维度补强）
    - [!] **F4 🟢 Low**: `Hash256` Debug 完整 hex + `Preimage` 与公开 hash 共用 `Hash256` 类型（无独立 `PaymentPreimage` newtype）→ 未来 `preimage:?` log 隐患（F1 是已知实例）；LN 主网 rust-lightning 用独立 `PaymentPreimage` newtype redact
    - [i] **F5 ℹ️ Info**: `EnvFilter::from_default_env()` 在 `RUST_LOG` 未设时为 ERROR-only — debug! 默认安静 ✓ 但可观测性差，运维易 `RUST_LOG=debug` 激活 F2/F3
    - [i] **F6 ℹ️ Info**: 缺少 JSON formatter / redaction layer / 字段级过滤；当前 `pretty()` 多行人类可读不便机器化二次过滤
    - [✓] **F7 ✅ Pass**: `Privkey(SecretKey)` `#[derive(Debug)]` 委托 secp256k1 0.30 `SecretKey::Debug` finish_non_exhaustive → "Privkey(SecretKey { .. })" ✓
    - [✓] **F8 ✅ Pass**: `commitment_seed` 与 wallet `password` 全局 grep 0 处 `tracing::*!` 引用 ✓
    - [✓] **F9 ✅ Pass**: Rust panic backtrace 不展开 local 变量；`expect("...")` 字符串均为静态文本或类型边界值（line numbers / lengths），不携带 secret ✓
  - **总体评价**: 日志层"机密性维度"基础保护良好（核心密钥类型不流入日志、secp256k1 0.30 redaction、默认 ERROR 限制 debug! 泄露）。主要缺口集中三处：F1 watchtower 一处 ERROR 级别 preimage 字面值（唯一明确的"敏感字节进入默认输出"路径）、F2 biscuit leftover 调试、F3 token 通过 anyhow 远程回显（AUTH-001.F4 同条）。结构性缺口 F4/F6 是缺少 `PaymentPreimage` newtype 与 redaction layer 的工程化保护，导致未来易再发生类似 F1 的模式。修复成本：F1/F2/F3 各 1-3 行；F4 需类型重构（中期）；F5/F6 是 UX/工程改进。
  - **发现记录**: 见 [`findings/AUDIT-ERR-002.md`](./findings/AUDIT-ERR-002.md)

## 第 7 章 DIM-DEPS 依赖安全

- [i] 🟠 **AUDIT-DEP-001** GitHub Advisory DB 比对 — **本轮 surveyed 12 个高敏依赖均无已知 CVE**
  - **审计内容**: `Cargo.lock` 中 `secp256k1`, `musig2`, `aes-gcm`, `scrypt`, `bitcoin`, `fiber-sphinx`, `lightning-invoice`, `jsonrpsee`, `biscuit-auth` (beta), `tentacle`, `molecule`, `bech32` 全部比对 → 见 [`findings/AUDIT-DEP-001.md`](./findings/AUDIT-DEP-001.md)
  - **后续**: 建议将 `cargo audit` 固化为 CI 步骤；建议每月重跑（公共数据库每日更新）

- [ ] 🟡 **AUDIT-DEP-002** `biscuit-auth = 6.0.0-beta.3` (pre-release) 评估
- [ ] 🟡 **AUDIT-DEP-003** `pprof` git rev pin (feature `pprof`) 评估

## 第 8 章 DIM-SPEC 规范一致性

- [ ] 🟠 **AUDIT-SPEC-001** P2P 消息规范对照 (`docs/specs/p2p-message.md` vs 实现)
- [ ] 🟠 **AUDIT-SPEC-002** Invoice 协议对照 (`docs/specs/payment-invoice.md` vs `invoice/`)
- [ ] 🟡 **AUDIT-SPEC-003** Trampoline / CCH 规范对照

## 第 9 章 跨平台 (WASM)

- [ ] 🟡 **AUDIT-WASM-001** `fiber-store` 浏览器 `unsafe impl Send/Sync` 不变量
- [ ] 🟡 **AUDIT-WASM-002** WASM 持久化 / IndexedDB 读写一致性

## 第 10 章 DIM-STORE 持久层与迁移

- [!] 🟠 **AUDIT-STORE-001** 持久层与迁移安全 — **整体 🟡 Medium (Medium × 2 + Low × 4 + Info × 1 + Pass × 2)**
  - **关联代码**: `crates/fiber-store/src/native.rs:17-105`, `crates/fiber-store/src/sqlite.rs:20-181`, `crates/fiber-store/src/browser.rs:84-198`, `crates/fiber-store/src/migration.rs:213-312`, `crates/fiber-store/src/migrations/mig_20260511_channel_connectivity_state.rs:30-93`, `crates/fiber-lib/src/store/store_impl/mod.rs:121-132,166-320`, `crates/fiber-bin/src/main.rs:121-129`
  - **审计内容**:
    - [x] 后端实现 (RocksDB/SQLite/WASM) 一致性 + I/O 错处理 → ⚠️ 全部 `.expect`/`panic!` 抬升至进程崩溃
    - [x] `serialize_to_vec`/`deserialize_from` panic 表面 → ⚠️ 任何损坏记录永久 boot-loop
    - [x] Migration 原子性 → ⚠️ 非 transaction，依赖 bincode 非自描述边界做"幂等"
    - [x] DB 目录文件权限 → ⚠️ 0644/0755 默认，未与 onion key (0600)/wallet 对称
    - [x] SQLite 并发开 DB → ⚠️ 无独占 advisory lock
    - [x] `pending.is_empty()` 路径无条件升版本号 → ⚠️ 隐式掩盖缺失迁移
    - [x] `cli_confirm` 非交互环境 → ⚠️ systemd/k8s 升级体验
    - [x] `check_validate` 启动校验 → 默认未调用 + 默认分支 `_ => {}` 漏检
    - [x] `INIT_DB_VERSION` 拒绝越过 epoch → ✅
    - [x] Gossip 入 DB 前已验签（来自 MEM-001.F1 分析）→ ✅
  - **最严重场景 (F1)**: 同主机多租户/共享托管环境下，非 root 用户可直读 `<store>/CHANNEL_ACTOR_STATE_PREFIX/...` 中的 `commitment_seed` 与 watchtower `Privkey`/preimage — 拿到 commitment_seed 等价于完全失去反 cheat 能力（HKDF 派生历史 revocation secret）。修复成本极低（5 行 `set_permissions(0o700)`）。
  - **F2 协同场景**: SQLite 后端无独占 advisory lock + systemd 重启竞态/容器 OOM 重启 → 两实例同时迁移并双写 `MIGRATION_VERSION_KEY` 与 ChannelActorState → revocation 历史不一致 → cheat 成功
  - **发现记录**: 见 [`findings/AUDIT-STORE-001.md`](./findings/AUDIT-STORE-001.md)

---

## 附录 A：审计执行日志

| 日期 | 会话 | 审计项 | 发现摘要 | 状态 |
|---|---|---|---|---|
| 2026-05-13 | S1 | AUDIT-CRYPTO-001 | MuSig2 nonce 纯确定性派生，缺少 message/agg-pubkey/随机熵混合；存在与不同 message 重复签名场景下泄露 funding key 的设计性风险 | [?] 疑似 H/Critical — 需动态验证 |
| 2026-05-13 | S1 | AUDIT-CRYPTO-003 | 钱包加密文件 VERSION 字段未校验；缺少长度检查触发 panic；`fs::read().unwrap()` 不优雅；无 zeroize；P2P 节点密钥 (`fiber/key.rs`) 仍明文落盘 | [!] Medium × 2，Low × 3 |
| 2026-05-13 | S1 | AUDIT-DEP-001 | 12 个高敏依赖经 GitHub Advisory DB 检查无已知 CVE | [i] 信息性 |
| 2026-05-13 | S2 | AUDIT-CRYPTO-002 | Sphinx peel 主路径稳健 (assoc_data ✓, 错误码统一 ✓)；但缺少 shared-secret 跨通道 replay 去重；`TlcErrPacket::decode` 时间填充实现不完美 | [!] Medium × 1, Low × 1, Info × 1 |
| 2026-05-13 | S2 | AUDIT-INPUT-001 | 现有 9 个 fuzz 目标覆盖广泛；二阶 TryFrom 子类型 fuzz 较浅；CI 未集成定期 fuzz | [~] Low × 1, Improvement × 3 |
| 2026-05-13 | S3 | AUDIT-LOGIC-001 | 17 种 P2P 消息状态守卫矩阵 — 大部分有显式 match；`UpdateTlcInfo` 完全无状态守卫；4 处缺少显式状态匹配；Reestablishing 期间静默丢弃无限速 | [~] Medium × 1, Low × 4, Info × 2 |
| 2026-05-13 | S3 | AUDIT-LOGIC-003 | Commitment 序号管理协议层严谨；watchtower 层有两个 Medium：`lock_args[28..36]` 缺长度检查 (panic-DoS)、revocation_data 覆盖式存储可能无法惩罚选择性上链 | [!] Medium × 3, Low × 2 |
| 2026-05-13 | S4 | AUDIT-LOGIC-002 | 入站 `AddTlc` 缺 `check_tlc_expiry` (Medium) — peer 可锁定 TLC 额度；`tlc_expiry_delay` f64 路径协议层不可达但缺防御；debug-only 接受无 onion TLC | [!] Medium × 1, Low × 2, Info × 1 |
| 2026-05-13 | S4 | AUDIT-LOGIC-006 | Watchtower 剩余面（settlement tx 构造/preimage 收集/parsers）安全 — 仅 4 个 Low：lock_args[0..36] 长度（同 003.F3）、tx-pinning loop 无上限、Htlc parser unwrap、RPC 错误处理；解析器整体 panic-safe | [~] Low × 4, Info × 2 |
| 2026-05-13 | S5 | AUDIT-LOGIC-004 | 多跳支付转发金额/费用一致性整体严谨；F1 Medium: `forward_amount == 0` 未拒绝可 HTLC slot jamming；F3 Low: ppm 缺上界 | [!] Medium × 1, Low × 3, Info × 2 |
| 2026-05-13 | S5 | AUDIT-LOGIC-005 | MPP 一致性核心校验完备；F1 Medium: `total_amount` 无上界接受任意倍超付（资金注水 + 错误码语义错位）；trampoline 内外 onion 用 payment_hash tweak 绑定 ✓ | [!] Medium × 1, Low × 3, Info × 2 |
| 2026-05-13 | S6 | AUDIT-LOGIC-007 | 通道关闭路径整体严谨；F1+F2+F3 协同：`check_shutdown_fee_valid` 缺 fee_rate 下限 + `build_shutdown_tx` saturating_sub 漏洞窗口 + `handle_shutdown_peer_message` 未校验 close_script.occupied_capacity → 可构造 DoS 链让协作关闭不可达 | [!] Medium × 3, Low × 3, Info × 2 (整体 High) |
| 2026-05-13 | S7 | AUDIT-AUTH-001 | biscuit ed25519/撤销/时间机制健壮；F1 High: standalone watchtower `enable_auth=false` 时所有客户端共享 NodeId::local() 空命名空间，攻击者可覆盖受害者 revocation_data；F2/F3 Medium: middleware fail-open + CORS Any | [!] High × 1, Medium × 2, Low × 5, Pass × 2 |
| 2026-05-13 | S8 | AUDIT-AUTH-002 | secio + gossip 签名验证完整；F1 Medium: inbound 驱逐顺序倒置(踢老留新)→ Sybil eviction DoS；F2 Medium: `listen_on_onion=true` 仍开明文 TCP 监听，隐私模式失效；F3-F6 Low: tor key 权限/session 覆盖/tor_password 明文/connect_peer 不查 gossip | [!] Medium × 2, Low × 4, Pass × 4 |
| 2026-05-13 | S9 | AUDIT-MEM-001 | F1 High: gossip `messages_to_be_saved` 入存不验签 + 无 per-peer 上限 + prune 不清理孤儿消息 → 50 MB/s RAM 增长可分钟级 OOM；F2 Medium: ractor mailbox unbounded + 入站无 rate-limit；F3 Medium: spawn_query_tasks 内 incomplete_messages 完整 clone × 10 放大 F1；F4-F6 Low: TLC_VALUE_IN_FLIGHT=u128::MAX / 单帧 1000 broadcasts / prune 无 TTL；F7-F8 Pass: ToBeAcceptedChannels 限额、NodeAnnouncement 私网过滤 | [!] High × 1, Medium × 2, Low × 3, Pass × 2 |
| 2026-05-13 | S10 | AUDIT-MEM-002 | 整体 Medium，数值算术接近正确：F1 Low: check_tlc_limits fold 未 checked_add (max_tlc_value_in_flight 默认 u128::MAX 时无后果)；F2 Low: build_settlement_data 链式 +/- 未 checked，依赖状态机不变式 (force-close 路径最有价值修复)；F3 Low: commitment_fee*2 未 checked_mul / u128 as u64 截断；F4 Info: apply_remove_tlc checked_* 正面典范；F5 Info: funding < u64::MAX 显式 cap；F6-F9 Pass: payment/graph/onion checked_add 完整、retry/backoff saturating、MPP saturating_add、add_amount==0 拒绝 | [!] Low × 3, Info × 2, Pass × 4 |
| 2026-05-13 | S11 | AUDIT-LOGIC-008 | 整体 High — F1 High: `expire_order` 不区分订单 status，默认 order_expiry=36h < TLC_expiry=60h 留 24h 窗口可让调度器在 outgoing 流程中强制 Fail 订单导致 preimage 事件被 `get_active_order_or_none` 丢弃 → CCH 直接资金损失（SendBTC/ReceiveBTC 双向均可利用）；模块完全无 cancel_invoice / cancel_payment 调用路径 (grep 0 命中)。F2 Low: `min_final_cltv_expiry_delta() * 600` 两处未 checked/saturating，与同文件 line 205 `saturating_mul` 不一致。F3 Info: BTC 600s/block 固定假设。F4-F6 Pass: preimage SHA256 hash 校验、静态 half-budget check（含 checked_mul）、动态 half-budget + max_outgoing limit + check_expiry_or_fail | [!] High × 1, Low × 1, Info × 1, Pass × 3 |
| 2026-05-14 | S12 | AUDIT-INPUT-002 | 整体 High — F1 High: `From<InvoiceAttr>` 三处 `.expect()` (Description/FallbackAddr UTF-8、PayeePublicKey from_slice) 远程 DoS，攻击者绕过 Builder 构造 RawInvoiceData → `parse_invoice` / `send_payment` / `cch.receive_btc` 单次合法格式 RPC 即崩进程。F2 Medium: `ar_decompress(...).expect()` 同攻击面。F3 Medium: `from_str` line 902 `.expect("pack invoice data")` 在 F1 修复后变可触发。F4 Low: `panic!("no other error...")` 反模式。F5 Low: duplicate attribute 不拒绝，`DuplicatedAttributeKey` 错误定义但 grep 0 命中。F6 Info: 现有 `fuzz_invoice` 99.99% 被 bech32m checksum 拒绝，永远不到 attr 转换层。F7-F8 Pass: bech32m vs bech32 强制；签名校验路径完整。攻击面：parse_invoice (无授权)、send_payment、cch.receive_btc、cch_fiber_agent。修复成本极低 (`.expect → ?` + `From → TryFrom`) | [!] High × 1, Medium × 2, Low × 2, Info × 1, Pass × 2 |
| 2026-05-14 | S13 | AUDIT-ERR-001 | 整体 Medium — F1 Medium: fiber 在 BOLT-04 之外引入独立 final-hop 错误码 `InvoiceExpired=PERM\|16`/`InvoiceCancelled=PERM\|17` 并保留 `FinalIncorrect{TlcAmount,ExpiryDelta}` 细分（LN 主网已折叠为 `IncorrectOrUnknownPaymentDetails`），攻击者用 1-sat 探测 TLC 即可远程零授权获取 invoice 状态/金额/cltv 匹配判定 = 商业隐私泄露 (channel.rs:840-844, 1156-1170)。F2 Medium: `update_graph_with_tlc_fail` (payment.rs:1099-1116) 信任 attacker-controlled `extra_data.node_id`/`channel_outpoint` 直接调 `mark_node_failed`/`mark_channel_failed`，未校验 ID 属于本次 attempt route → 中转 hop 可让发送方在本地图屏蔽任意目标；`record_payment_fail` (history.rs:170-180) 评分路径上有正确校验但 graph 路径未对称复用。F3 Low: `update_graph_with_tlc_fail` 三处 `.expect()` panic PaymentActor。F4 Low: `GetPaymentResult.failed_error: String` 直接透出错误码字面量。F5 Low: `TlcErr::serialize` `.expect()` 反模式。F6 Info: `ERROR_DECODING_PASSES=27` dummy XOR 在 release build 是否被 LLVM 优化消除待反汇编验证。F7-F8 Pass: Sphinx onion error encryption + history slander 防护。修复成本极低 (<50 行) | [!] Medium × 2, Low × 3, Info × 1, Pass × 2 |
| 2026-05-14 | S14 | AUDIT-STORE-001 | 整体 Medium — F1 Medium: DB 目录/文件权限默认 0644/0755，store 中含 `ChannelActorState.commitment_seed` (HKDF 派生历史 revocation secret 种子) + watchtower `ChannelData.Privkey` + preimage 三类高敏数据；与 onion key/wallet 已 enforce 0o600 对称性差距明显，同主机多租户场景下非 root 用户可直读。F2 Medium: SQLite 后端无独占 advisory lock，`Connection::open + WAL` 允许多进程同开，systemd 重启竞态/容器 OOM 重启 → 两实例双写 `MIGRATION_VERSION_KEY` + ChannelActorState → revocation 历史不一致 → cheat 成功 (RocksDB 用 LOCK 文件不受影响)。F3 Low: `deserialize_from` 全局 `panic!` 让单条字节损坏永久 boot-loop。F4 Low: Migration 逐条 put 非原子 + bincode 默认不拒绝尾随字节 → mid-crash 后"幂等"误判致永久跳过迁移。F5 Low: `pending.is_empty()` 路径无条件升版本号掩盖缺失迁移。F6 Low: `cli_confirm` 在非 TTY 挂起。F7 Low: 后端 `.expect` 把 I/O 错抬升 panic 无 graceful flush。F8 Info: `check_validate` 默认分支 `_ => {}` 漏检未来前缀。F9-F10 Pass: INIT_DB_VERSION 拒绝跨 epoch + gossip 验签后才入 DB | [!] Medium × 2, Low × 4, Info × 1, Pass × 2 |

## 附录 B：新增项跟踪 (Phase 1 中发现的新攻击面)

| 日期 | 新增项 ID | 来源 | 描述 |
|---|---|---|---|
| 2026-05-13 | AUDIT-CRYPTO-001-FOLLOWUP-A | S1 / AUDIT-CRYPTO-001 | 需评估 `restore_missing_revocation_send_nonce` (`channel.rs:4638`) 在 reestablish 路径是否可被恶意 peer 触发重发不同的 commitment message，从而触发同 nonce 不同 message 签名 |
| 2026-05-13 | AUDIT-CRYPTO-001-FOLLOWUP-B | S1 / AUDIT-CRYPTO-001 | 需评估 `get_or_create_local_channel_announcement_signature` 缓存逻辑：缓存 invalidation 时是否可在不同 `message_to_sign` 下复用同一 secnonce |
| 2026-05-13 | AUDIT-CRYPTO-003-FOLLOWUP-A | S1 / AUDIT-CRYPTO-003 | `fiber/key.rs::KeyPair` (P2P node identity key) 明文落盘 — 评估是否纳入加密路径 |
| 2026-05-13 | AUDIT-INPUT-006 | S1 / AUDIT-CRYPTO-003 | 钱包加密文件存在 panic 路径 (decrypt_from_file)；归入 DIM-INPUT/DIM-SERDE 同时审查所有 `fs::read().unwrap()` |
| 2026-05-13 | AUDIT-CRYPTO-002-FOLLOWUP-A | S2 / AUDIT-CRYPTO-002 | 动态验证 — 控制双 peer，向本节点的两条入站通道发送相同 onion，观察是否被分别处理（cross-channel replay oracle） |
| 2026-05-13 | AUDIT-CRYPTO-002-FOLLOWUP-B | S2 / AUDIT-CRYPTO-002 | 单独立项审计 `fiber-sphinx 2.3` 上游源码：HMAC 比较恒定时间、replay 原语、`xor_cipher_stream(zero_key)` 是否被编译器优化 |
| 2026-05-13 | AUDIT-CRYPTO-002-FOLLOWUP-C | S2 / AUDIT-CRYPTO-002 | 新增 fuzz 目标 `fuzz_tlc_err_packet_decode`（输入：onion_packet 字节 + session_key + hops） |
| 2026-05-13 | AUDIT-INPUT-001-FOLLOWUP-A | S2 / AUDIT-INPUT-001 | 扩展 `fuzz_molecule_types` 覆盖剩余 ~13 个 fiber/gossip 子类型的二阶 TryFrom |
| 2026-05-13 | AUDIT-INPUT-001-FOLLOWUP-B | S2 / AUDIT-INPUT-001 | CI 中集成 weekly fuzz cron 或采纳 OSS-Fuzz / ClusterFuzzLite |
| 2026-05-13 | AUDIT-INPUT-001-FOLLOWUP-C | S2 / AUDIT-INPUT-001 | 新增 fuzz 目标：store 跨版本迁移、RPC JSON-RPC 参数 |
| 2026-05-13 | AUDIT-LOGIC-003-FOLLOWUP-A | S3 / AUDIT-LOGIC-003 | **动态验证** — 检查链上 commitment-lock 合约源码 ([fiber-scripts](https://github.com/nervosnetwork/fiber-scripts))：lock_args 中 commitment_number 是否与 witness 中 commitment_number 做绑定比对，决定 F6 是否成立 |
| 2026-05-13 | AUDIT-LOGIC-003-FOLLOWUP-B | S3 / AUDIT-LOGIC-003 | **PoC** — 构造 peer 在协作关闭中提供 < 36 字节 `close_script.args`，观测受害方 watchtower 是否 panic |
| 2026-05-13 | AUDIT-LOGIC-001-FOLLOWUP-A | S3 / AUDIT-LOGIC-001 | **PoC** — `UpdateTlcInfo` 在 `NegotiatingFunding` / `Closed` 状态下发送，验证 `remote_tlc_info` / 网络图是否被污染 |
| 2026-05-13 | AUDIT-LOGIC-002-FOLLOWUP-A | S4 / AUDIT-LOGIC-002 | **PoC** — 恶意 peer 发送 `AddTlc { expiry: u64::MAX }`，验证 (a) TLC 进入 state、(b) 不被 `maintain_pending_tlcs` 清理、(c) 仅能通过 force-close 释放 |
| 2026-05-13 | AUDIT-LOGIC-002-FOLLOWUP-B | S4 / AUDIT-LOGIC-002 | 新增 fuzz / property test：`handle_add_tlc_peer_message` 在各种 `expiry × peeled.expiry × tlc_expiry_delta` 组合下的不变式 INV-3/INV-4 |
| 2026-05-13 | AUDIT-LOGIC-002-FOLLOWUP-C | S4 / AUDIT-LOGIC-002 | 将 `tlc_expiry_delay` 重写为 checked 整数运算（消除 f64 NaN/Inf footgun）|
| 2026-05-13 | AUDIT-LOGIC-006-FOLLOWUP-A | S4 / AUDIT-LOGIC-006 | 完整核对 `build_settlement_tx` 在 `sw.update() == false` 时的兜底路径（unreachable / 静默退出 / 错误处理）|
| 2026-05-13 | AUDIT-LOGIC-006-FOLLOWUP-B | S4 / AUDIT-LOGIC-006 | 在测试网构造 1000+ 个 dust cell 匹配某 channel commitment prefix，量化 tx-pinning 单次 PeriodicCheck 耗时 |
| 2026-05-13 | AUDIT-LOGIC-006-FOLLOWUP-C | S4 / AUDIT-LOGIC-006 | 评估独立部署 watchtower 客户端（`watchtower.rs`）相同问题适用性 |
| 2026-05-13 | AUDIT-LOGIC-004-FOLLOWUP-A | S5 / AUDIT-LOGIC-004 | **PoC** — `forward_amount=0` HTLC slot jamming：测试网构造，量化 slot 占用时长 |
| 2026-05-13 | AUDIT-LOGIC-004-FOLLOWUP-B | S5 / AUDIT-LOGIC-004 | 为 `tlc_fee_proportional_millionths` 设软上界（如 100_000 = 10%）在 `graph.rs:783` |
| 2026-05-13 | AUDIT-LOGIC-004-FOLLOWUP-C | S5 / AUDIT-LOGIC-004 | `is_invoice_fulfilled` 用 `checked_add` 替代 `+=`，并直接复用 SettleTlcSetCommand 已校验的 total |
| 2026-05-13 | AUDIT-LOGIC-005-FOLLOWUP-A | S5 / AUDIT-LOGIC-005 | **PoC** — MPP 100x 超付：构造 `total_amount = invoice.amount * 100`，验证接收方 fulfill 全部 |
| 2026-05-13 | AUDIT-LOGIC-005-FOLLOWUP-B | S5 / AUDIT-LOGIC-005 | 加 `total_amount <= invoice.amount * accept_overpay_factor` 限额 + overpaid 错误码改 `IncorrectOrUnknownPaymentDetails` |
| 2026-05-13 | AUDIT-LOGIC-005-FOLLOWUP-C | S5 / AUDIT-LOGIC-005 | 解决 `apply_final_hop_tlc_onion_packet:1513` FIXME（MPP invoice 是否强制要求 MPP record）|
| 2026-05-13 | AUDIT-LOGIC-005-FOLLOWUP-D | S5 / AUDIT-LOGIC-005 | `verify_mpp_tlcs_have_consistent_total_amount` 加 `payment_secret` 一致性断言 |
| 2026-05-13 | AUDIT-LOGIC-005-FOLLOWUP-E | S5 / AUDIT-LOGIC-005 | 审计 `graph.rs:1451` trampoline 选路 `build_max_fee_amount` 总预算约束 |
| 2026-05-13 | AUDIT-LOGIC-007-FOLLOWUP-A | S6 / AUDIT-LOGIC-007 | **PoC** — 构造 `Shutdown{close_script=<args=200B>, fee_rate=0}`，验证 F1+F2+F3 协同 DoS（协作关闭不可达 → 必须 force close）|
| 2026-05-13 | AUDIT-LOGIC-007-FOLLOWUP-B | S6 / AUDIT-LOGIC-007 | 实施统一补丁：`check_shutdown_fee_valid` 加 `remote_fee_rate >= commitment_fee_rate`；`handle_shutdown_peer_message` 加 `occupied_capacity(close_script) <= remote_reserved_ckb` 严格 `<` 校验 |
| 2026-05-13 | AUDIT-LOGIC-007-FOLLOWUP-C | S6 / AUDIT-LOGIC-007 | F4: `get_latest_commitment_transaction` `.expect` → `Result`；F5: force close 加 `WAITING_COMMITMENT_CONFIRMATION` 守卫 |
| 2026-05-13 | AUDIT-LOGIC-007-FOLLOWUP-D | S6 / AUDIT-LOGIC-007 | 解决 `step_shutting_down:8520` TODO — 在 ShuttingDown 状态下主动向上游 RemoveTlcFail（"channel closing"错误码）|
| 2026-05-13 | AUDIT-AUTH-001-FOLLOWUP-A | S7 / AUDIT-AUTH-001 | **PoC + 修复** — F1 High: standalone watchtower `enable_auth=false` 多租户 NodeId 冲突；在 `mod.rs:285` 加判断：若 watchtower 模块启用且 `biscuit_public_key.is_none()` 则 `bail!`；或将 `require_rpc_context && !enable_auth` 改为拒绝 |
| 2026-05-13 | AUDIT-AUTH-001-FOLLOWUP-B | S7 / AUDIT-AUTH-001 | F2: middleware fail-open 改为 fail-secure（未注册方法 `return false`）；考虑用 enum 替代 `&'static str` 强制 build_rules 完备 |
| 2026-05-13 | AUDIT-AUTH-001-FOLLOWUP-C | S7 / AUDIT-AUTH-001 | F3: CORS `allow_origin=Any` 默认收紧 —— 启动期拒绝 `cors_enabled=true && cors_allowed_origins.is_empty()`，或至少 `allow_headers` 排除 `AUTHORIZATION` |
| 2026-05-13 | AUDIT-AUTH-001-FOLLOWUP-D | S7 / AUDIT-AUTH-001 | F4/F5/F6/F7 一并：token 日志脱敏；`auth_notify` 加 local 旁路；BEARER 前缀 case-insensitive；`extract_node_id` 日志降级到 trace |
| 2026-05-13 | AUDIT-AUTH-001-FOLLOWUP-E | S7 / AUDIT-AUTH-001 | F8: 引入 tower-governor / per-IP failed-auth 计数 |
| 2026-05-13 | AUDIT-AUTH-002-FOLLOWUP-A | S8 / AUDIT-AUTH-002 | **PoC + 修复** — F1 Medium: inbound eviction 反序 (`sort_by_key(Reverse)`) + per-subnet 限额；构造 PoC：17 个 fresh secp256k1 keypair 持续逐出合法 inbound peer |
| 2026-05-13 | AUDIT-AUTH-002-FOLLOWUP-B | S8 / AUDIT-AUTH-002 | F2 Medium: 新增 `OnionConfig.onion_only`，启用时 `listening_addr` 收缩到 loopback；启动期校验 announce 不暴露真实 IP |
| 2026-05-13 | AUDIT-AUTH-002-FOLLOWUP-C | S8 / AUDIT-AUTH-002 | F3 Low: `load_tor_secret_key` 加 unix mode 校验（0o600 否则拒绝） |
| 2026-05-13 | AUDIT-AUTH-002-FOLLOWUP-D | S8 / AUDIT-AUTH-002 | F4 Low: `peer_session_map.insert` 显式 disconnect 旧 session_id（与 LOGIC-006 状态机 idempotency 联合处理）|
| 2026-05-13 | AUDIT-AUTH-002-FOLLOWUP-E | S8 / AUDIT-AUTH-002 | F5 Low: `tor_password` 用 `secrecy::SecretString` 包装；文档推荐 cookie auth |
| 2026-05-13 | AUDIT-AUTH-002-FOLLOWUP-F | S8 / AUDIT-AUTH-002 | F6 Low/UX: `ConnectPeerWithPubkey` 回退查询 gossip `NodeAnnouncement.addresses` |
| 2026-05-13 | AUDIT-MEM-001-FOLLOWUP-A | S9 / AUDIT-MEM-001 | **PoC + 修复** — F1 High: `messages_to_be_saved` 加 per-peer 上限 + 入存验签；PoC 单 inbound × 16 帧/秒灌入伪造 ChannelUpdate，监控 RSS 增长 / OOM 时间 |
| 2026-05-13 | AUDIT-MEM-001-FOLLOWUP-B | S9 / AUDIT-MEM-001 | F2 Medium: 引入 per-peer FiberMessage rate-limit 或 NetworkActor mailbox 上界 |
| 2026-05-13 | AUDIT-MEM-001-FOLLOWUP-C | S9 / AUDIT-MEM-001 | F3 Medium: `spawn_query_tasks` 内 truncate `incomplete_messages` 上限；query 响应回灌前验签 |
| 2026-05-13 | AUDIT-MEM-001-FOLLOWUP-D | S9 / AUDIT-MEM-001 | F4 Low: 重设 `DEFAULT_MAX_TLC_VALUE_IN_FLIGHT` 为 channel capacity 比例；文档强制配置 |
| 2026-05-13 | AUDIT-MEM-001-FOLLOWUP-E | S9 / AUDIT-MEM-001 | F5+F6 Low: 调小 `MAX_NUM_OF_BROADCAST_MESSAGES` (1000→100/200)；prune 增加 TTL 字段清理永不完成消息 |
| 2026-05-13 | AUDIT-MEM-002-FOLLOWUP-A | S10 / AUDIT-MEM-002 | F1 Low: `check_tlc_limits` fold 改 `try_fold` + `checked_add`，与 `apply_remove_tlc` 风格一致 |
| 2026-05-13 | AUDIT-MEM-002-FOLLOWUP-B | S10 / AUDIT-MEM-002 | **最有价值修复** — F2 Low: `build_settlement_data` 链式 +/- 拆分为分步 `checked_*` + 返回 `InternalError` (force-close 路径) |
| 2026-05-13 | AUDIT-MEM-002-FOLLOWUP-C | S10 / AUDIT-MEM-002 | F3 Low: `fee.rs:188 commitment_fee.checked_mul(2)`；`channel.rs:5324 u64::try_from(to_local_amount)` 替代 `as u64` |
| 2026-05-13 | AUDIT-MEM-002-FOLLOWUP-D | S10 / AUDIT-MEM-002 | (维护) 评估在 release profile 启用 `overflow-checks = true`，权衡性能代价 ~5% 与消除静默 wrap 风险 |
| 2026-05-13 | AUDIT-LOGIC-008-FOLLOWUP-A | S11 / AUDIT-LOGIC-008 | **🟠 High 必修** — `expire_order` 仅当 `order.status == Pending` 时强制 Failed；为非 Pending 订单设计基于 TLC/HTLC 实际剩余时间的独立调度作业 |
| 2026-05-13 | AUDIT-LOGIC-008-FOLLOWUP-B | S11 / AUDIT-LOGIC-008 | **🟠 High 必修** — 实现 LND `CancelInvoice` 与 Fiber invoice cancel 反向路径；CCH 决定 fail 已 IncomingAccepted 订单时主动取消两侧 HTLC/TLC 避免单边占用 |
| 2026-05-13 | AUDIT-LOGIC-008-FOLLOWUP-C | S11 / AUDIT-LOGIC-008 | (Medium, 防御性恢复) `handle_tracking_event` 收到 `PaymentChanged{payment_preimage:Some(_)}` 但订单已 Failed 时旁路写入 "orphaned_preimages" 表 / 显著日志，并尝试一次 best-effort settle |
| 2026-05-13 | AUDIT-LOGIC-008-FOLLOWUP-D | S11 / AUDIT-LOGIC-008 | (Low) 将 `actor.rs:560` 与 `send_outgoing_payment.rs:249` 的 `min_final_cltv_expiry_delta() * 600` 统一为 `saturating_mul(600)` / `checked_mul` |
| 2026-05-13 | AUDIT-LOGIC-008-FOLLOWUP-E | S11 / AUDIT-LOGIC-008 | (Info, 文档) 在 `cch-expiry-dependency.md` 中明确 BTC 600 s/block 假设；提供持续偏快块速下下调 `btc_final_tlc_expiry_delta_blocks` 的指导 |
| 2026-05-13 | AUDIT-LOGIC-008-FOLLOWUP-F | S11 / AUDIT-LOGIC-008 | (Low, 配置校验) 启动时拒绝 `order_expiry_delta_seconds >= min(ckb_final_tlc_expiry_delta_seconds, btc_final_tlc_expiry_delta_blocks * 600)` 的危险配置组合 |
| 2026-05-14 | AUDIT-INPUT-002-FOLLOWUP-A | S12 / AUDIT-INPUT-002 | **🟠 High 必修** — `From<InvoiceAttr> for Attribute` → `TryFrom<InvoiceAttr>`；新增 `InvoiceError::MalformedAttribute(String)` 变体；联动改 `InvoiceData::try_from`、`from_str` line 902、line 1085/1088 store 路径所有 `.expect()` 为 `?` |
| 2026-05-14 | AUDIT-INPUT-002-FOLLOWUP-B | S12 / AUDIT-INPUT-002 | **🟡 Medium 必修** — `ar_decompress(...).expect()` (line 887) 改 `?`；新增 `InvoiceError::DecompressionError(String)` |
| 2026-05-14 | AUDIT-INPUT-002-FOLLOWUP-C | S12 / AUDIT-INPUT-002 | (Low) `check_signature` 中 `panic!("no other error...")` (line 610) 改为 `Err(_) => return Err(InvoiceError::InvalidSignature)` 兜底 |
| 2026-05-14 | AUDIT-INPUT-002-FOLLOWUP-D | S12 / AUDIT-INPUT-002 | (Low) `InvoiceData::try_from` 中加 attribute discriminant 去重，使用既有 `InvoiceError::DuplicatedAttributeKey` 变体（当前 grep 0 命中） |
| 2026-05-14 | AUDIT-INPUT-002-FOLLOWUP-E | S12 / AUDIT-INPUT-002 | (Info, 测试) 新增 fuzz target `fuzz_invoice_data` (`RawInvoiceData::from_slice`) 和 `fuzz_invoice_attr` (`Attribute::from`) 穿透 bech32m / ar_decompress 层；提供合法 invoice 字符串作为 corpus 种子 |
| 2026-05-14 | AUDIT-INPUT-002-FOLLOWUP-F | S12 / AUDIT-INPUT-002 | (Low, 防御) 在 RPC handler 与 actor 入口包裹 `catch_unwind` 或建立 panic-hook，确保单次解析 panic 不击垮整个 fiber 进程（临时措施） |

## 附录 C：修复建议

| 审计项 | 严重级别 | 建议方案 | 修复状态 |
|---|---|---|---|
| AUDIT-CRYPTO-001 | 🔴 Suspected H/Critical | 在 `SecNonceBuilder` 调用处补全 `with_message(...)` (≥ commitment tx 摘要) + `with_aggregated_pubkey(...)` + `with_extra_input(<random_32_bytes>)`；并在持久化中加入"已签 message 摘要 → nonce 用量"的反重放表 | 未修复 (审计中) |
| AUDIT-CRYPTO-003.a | 🟡 Medium | 在 `decrypt_from_file` 顶部断言 `file_bytes[0] == VERSION` 并返回 Err；为旧版本预留升级通道 | 未修复 |
| AUDIT-CRYPTO-003.b | 🟡 Medium | 在分片 (`salt/nonce/ct`) 前显式校验 `file_bytes.len() >= 1+SALT_LEN+NONCE_LEN+16` (16 = AES-GCM tag) | 未修复 |
| AUDIT-CRYPTO-003.c | 🟢 Low | 将 `fs::read(file).unwrap()` 替换为 `?`/`map_err` | 未修复 |
| AUDIT-CRYPTO-003.d | 🟢 Low | 引入 `zeroize` crate；将 scrypt 输出、解密后明文、密码字节包装为 `Zeroizing<Vec<u8>>` | 未修复 |
| AUDIT-CRYPTO-003.e | 🟡 Medium (设计) | 评估 P2P 身份密钥 `fiber/key.rs::KeyPair` 是否应同样加密保存 | 未修复 |
| AUDIT-DEP-001 | 🟢 Low | 在 CI 中加入 `cargo audit` 或 `cargo deny advisories` 步骤；建议在 PR 标签或 weekly cron 触发 | 未实施 |
| AUDIT-CRYPTO-002.F1 | 🟡 Medium | 增加 `seen_onion_ephemeral_keys: LruCache<PublicKey, Instant>` 跨通道 replay 去重；命中返回 `InvalidOnionPayload` | 未修复 |
| AUDIT-CRYPTO-002.F2 | 🟢 Low | 重写 `TlcErrPacket::decode` 填充：success/fail 对称、用非零密钥、`subtle` 恒定时间原语；硬上限 path_hops ≤ 27 | 未修复 |
| AUDIT-INPUT-001.Low | 🟢 Low | 重命名 `MAX_SERVICE_PROTOCOAL_DATA_SIZE` → `MAX_SERVICE_PROTOCOL_DATA_SIZE` | 未修复 |
| AUDIT-INPUT-001.Improvement | ⚠️ | 扩展 `fuzz_molecule_types` + CI weekly fuzz cron + 新增三个 fuzz 目标 | 未实施 |
| AUDIT-LOGIC-001.F4 | 🟡 Medium | `UpdateTlcInfo` 增加 `ChannelState::ChannelReady`/`ShuttingDown` 守卫 + 版本号防重 | 未修复 |
| AUDIT-LOGIC-001.F1/F2/F5/F6 | 🟢 Low | `TxSignatures` / `AnnouncementSignatures` / `ClosingSigned` / `TxAbort` 增加显式状态匹配；`AnnouncementSignatures` 完成签名验证 TODO | 未修复 |
| AUDIT-LOGIC-003.F3 | 🟡 Medium | watchtower 在 `lock_args[28..36]` 切片前显式 `if lock_args.len() < 36 { continue }`；修正注释 | 未修复 |
| AUDIT-LOGIC-003.F6 | 🟡 Medium | watchtower `revocation_data` 改为 `BTreeMap<commitment_number, RevocationData>`，按链上 commitment_number 精确查找 | 未修复 (待动态验证链上脚本) |
| AUDIT-LOGIC-003.F1 | 🟡 Medium | `CommitmentNumbers::increment_*` 改为 `checked_add(1)`；溢出时强制 close 通道 | 未修复 |
| AUDIT-LOGIC-003.F2 | 🟢 Low | `get_*_commitment_number() - 1` 改为 `checked_sub(1).ok_or(InvalidState)?` | 未修复 |
| AUDIT-LOGIC-003.F4 | 🟢 Low | watchtower 添加 confirmation 阈值 + 历史 tx 去重缓存 | 未修复 |
| AUDIT-LOGIC-002.F1 | 🟡 Medium | `handle_add_tlc_peer_message` 入口加 `check_inbound_tlc_expiry`（至少防 u64::MAX 极端值 + `expiry > now`）| 未修复 |
| AUDIT-LOGIC-002.F2 | 🟢 Low | `tlc_expiry_delay` 改为 checked u128 整数运算 | 未修复 |
| AUDIT-LOGIC-002.F4 | 🟢 Low | 将 `cfg!(debug_assertions)` no-onion 分支改为 `#[cfg(test)]` 强限定 | 未修复 |
| AUDIT-LOGIC-006.F1 | 🟢 Low | `try_settle_commitment_tx` 顶部 `lock_args.len() < 36 { return }` | 未修复 |
| AUDIT-LOGIC-006.F2 | 🟢 Low | 添加 `MAX_CELLS_PER_PERIODIC_CHECK = 1000` 总上限；`Err` 路径 `break` | 未修复 |
| AUDIT-LOGIC-006.F3 | 🟢 Low | `Htlc::build_from_witness` 改为返回 `Option<Self>` | 未修复 |
| AUDIT-LOGIC-006.F5 | 🟢 Low | 非 Committed 状态降为 `debug!`；Err 加指数退避重试 | 未修复 |
| AUDIT-LOGIC-004.F1 | 🟡 Medium | `apply_add_tlc_operation_with_peeled_onion_packet` 加 `forward_amount > 0` 守卫 | 未修复 |
| AUDIT-LOGIC-004.F3 | 🟢 Low | 对 `tlc_fee_proportional_millionths` 设上界（如 100_000 = 10%）| 未修复 |
| AUDIT-LOGIC-005.F1 | 🟡 Medium | `leave_just_fulfilled_tlcs_for_mpp_invoice` 加 `total <= invoice.amount * accept_overpay_factor` 限额 + overpaid 错误码改 `IncorrectOrUnknownPaymentDetails` | 未修复 |
| AUDIT-LOGIC-005.F3 | 🟢 Low | 解决 `apply_final_hop_tlc_onion_packet:1513` FIXME | 未修复 |
| AUDIT-LOGIC-005.F4 | 🟢 Low | `verify_mpp_consistent` 加 payment_secret 一致性断言 | 未修复 |
| AUDIT-LOGIC-007.F1 | 🟡 Medium | `check_shutdown_fee_valid` 加 `remote_fee_rate >= commitment_fee_rate` 下限 | 未修复 |
| AUDIT-LOGIC-007.F2 | 🟡 Medium | `build_shutdown_tx` 改用 `checked_sub` 或在前置校验中拒绝 saturating-to-0 路径 | 未修复 |
| AUDIT-LOGIC-007.F3 | 🟡 Medium | `handle_shutdown_peer_message` 加 `occupied_capacity(close_script) <= remote_reserved_ckb` 严格 `<` 校验 | 未修复 |
| AUDIT-LOGIC-007.F4 | 🟢 Low | `get_latest_commitment_transaction` `.expect` → `Result` | 未修复 |
| AUDIT-LOGIC-007.F5 | 🟢 Low | force close 加 `WAITING_COMMITMENT_CONFIRMATION` 守卫 | 未修复 |
| AUDIT-AUTH-001.F1 | 🟠 High | standalone watchtower 强制要求 biscuit_public_key（启动期 bail!），或拒绝 `enable_auth=false && require_rpc_context` 调用 | 未修复 |
| AUDIT-AUTH-001.F2 | 🟡 Medium | middleware `auth_call` 未注册规则的方法 `return false`（fail-secure）| 未修复 |
| AUDIT-AUTH-001.F3 | 🟡 Medium | 默认禁止 `cors_enabled=true && cors_allowed_origins.is_empty()`，或排除 AUTHORIZATION 头 | 未修复 |
| AUDIT-AUTH-001.F4 | 🟢 Low | 撤销 token 错误信息脱敏 | 未修复 |
| AUDIT-AUTH-001.F5/F6/F7 | 🟢 Low | auth_notify local 旁路；BEARER 大小写不敏感；extract_node_id 日志降级 | 未修复 |
| AUDIT-AUTH-001.F8 | 🟢 Low | 引入失败鉴权速率限制 | 未修复 |
| AUDIT-AUTH-002.F1 | 🟡 Medium | inbound eviction 反序 + per-subnet 限额 | 未修复 |
| AUDIT-AUTH-002.F2 | 🟡 Medium | `OnionConfig.onion_only` 模式（限制明文监听）| 未修复 |
| AUDIT-AUTH-002.F3 | 🟢 Low | onion key load 校验 unix 0o600 | 未修复 |
| AUDIT-AUTH-002.F4/F5/F6 | 🟢 Low | session 覆盖显式 disconnect / tor_password secrecy / connect_peer fallback gossip | 未修复 |
| AUDIT-MEM-001.F1 | 🟠 High | gossip `messages_to_be_saved` 入存验签 + per-peer 上限 | 未修复 |
| AUDIT-MEM-001.F2/F3 | 🟡 Medium | mailbox/incoming-rate 限制；spawn_query_tasks truncate + 验签 | 未修复 |
| AUDIT-MEM-001.F4/F5/F6 | 🟢 Low | TLC_VALUE_IN_FLIGHT 默认 / 单帧 broadcast 数 / prune TTL | 未修复 |
| AUDIT-MEM-002.F1/F2/F3 | 🟢 Low | check_tlc_limits fold checked_add / build_settlement_data checked_* / commitment_fee*2 checked_mul + u128→u64 try_from | 未修复 |
| AUDIT-LOGIC-008.F1 | 🟠 **High** | CCH `expire_order` 仅 status==Pending 才 Fail；新增 LND/Fiber 对称 cancel 路径；handle_tracking_event 旁路写入 finalized 订单的 preimage | **未修复（直接资金损失）** |
| AUDIT-LOGIC-008.F2 | 🟢 Low | `min_final_cltv_expiry_delta() * 600` 两处统一为 saturating_mul / checked_mul | 未修复 |
| AUDIT-INPUT-002.F1 | 🟠 **High** | `From<InvoiceAttr> for Attribute` → `TryFrom`；Description/FallbackAddr UTF-8 + PayeePublicKey from_slice 三处 `.expect → ?`；联动改 store path line 1085/1088 | **未修复（远程零成本零授权 DoS）** |
| AUDIT-INPUT-002.F2 | 🟡 Medium | `ar_decompress(...).expect()` (line 887) → `?`；新增 `InvoiceError::DecompressionError` | 未修复 |
| AUDIT-INPUT-002.F3 | 🟡 Medium | `from_str` line 902 `.expect("pack invoice data")` → `?` (与 F1 联动) | 未修复 |
| AUDIT-ERR-001.F1 | 🟡 Medium | Final-hop `InvoiceExpired`/`InvoiceCancelled`/`FinalIncorrectTlcAmount`/`FinalIncorrectExpiryDelta` 折叠为 `IncorrectOrUnknownPaymentDetails` (channel.rs:840-844, 1156-1170) | 未修复 |
| AUDIT-ERR-001.F2 | 🟡 Medium | `update_graph_with_tlc_fail` 加 route-membership 校验（复用 history.rs:170-180 模板） | 未修复 |
| AUDIT-ERR-001.F3 | 🟢 Low | `update_graph_with_tlc_fail` 三处 `.expect(...)` 改防御式 `if let Some(...)` | 未修复 |
| AUDIT-ERR-001.F5 | 🟢 Low | `TlcErr::serialize` `.expect()` → `unwrap_or_else(unreachable!())` 或 Result | 未修复 |
| AUDIT-ERR-001.F6 | ℹ️ Info | release build 反汇编验证 `ERROR_DECODING_PASSES=27` dummy XOR 未被优化消除 | 待动态验证 |
| AUDIT-STORE-001.F1 | 🟡 Medium | DB 目录/文件权限强制 0700/0600 (与 onion key/wallet 对称) — 修复 `open_db` 后 `fs::set_permissions` | 未修复 |
| AUDIT-STORE-001.F2 | 🟡 Medium | SQLite 后端添加 `fd_lock`/`fs2` 独占 advisory lock 防多实例并发 | 未修复 |
| AUDIT-STORE-001.F3 | 🟢 Low | `deserialize_from` panic 改为 Result + quarantine 损坏记录 | 未修复 |
| AUDIT-STORE-001.F4 | 🟢 Low | Migration 用 `store.batch()` 原子化 + bincode 配 `reject_trailing_bytes` | 未修复 |
| AUDIT-STORE-001.F5 | 🟢 Low | `pending.is_empty()` 时报 MissingMigration 而不是隐式升版本 | 未修复 |
| AUDIT-STORE-001.F6 | 🟢 Low | 添加 `--auto-confirm-migration` flag + 非 TTY 默认拒绝 | 未修复 |
| AUDIT-STORE-001.F7 | 🟢 Low | 后端 trait 改 Result<...> 提供 graceful flush 钩子（大重构） | 未修复 |
| AUDIT-STORE-001.F8 | ℹ️ Info | `check_validate` 默认分支报告 unknown prefix counts | 未修复 |
| AUDIT-INPUT-003.F1 | 🟡 Medium | `parse_invoice`/`cch.receive_btc`/`payment.send_payment(invoice)` 是 INPUT-002 远程触发面 — 修复依赖 INPUT-002 主修复 | 未修复 |
| AUDIT-INPUT-003.F2 | 🟡 Medium | `graph_nodes`/`graph_channels`/`list_payments` `limit: Option<u64>` 加显式 `MAX_LIMIT` 上界 + 检查 `list_channels`/`list_peers` | 未修复 |
| AUDIT-INPUT-003.F3 | 🟢 Low | `get_invoice`/`cancel_invoice` `.expect("no invoice status found")` → `ok_or_else(|| rpc_error(...))` | 未修复 |
| AUDIT-INPUT-003.F4 | 🟢 Low | `RpcConfig` 暴露 `max_connections`/`max_request_body_size`/`per_ip_qps`；引入 `tower-governor` 限速；hyper keep_alive_timeout | 未修复 |
| AUDIT-INPUT-003.F5 | 🟢 Low | `is_public_addr` 不再唯一 gate；启用敏感模块 (payment/channel/cch/watchtower) 时一律强制 biscuit；或 `force_auth: bool` 默认 true | 未修复 |
| AUDIT-INPUT-003.F6 | ℹ️ Info | `middleware.inject_rpc_context.expect("serialize injected params")` 改 Result 传播 | 未修复 |
| AUDIT-ERR-002.F1 | 🟡 Medium | `watchtower/actor.rs:181` `error!` 移除 `preimage:?` 字段，仅保留 payment_hash + preimage_len | 未修复 |
| AUDIT-ERR-002.F2 | 🟢 Low | `rpc/biscuit.rs:260` leftover `warn!("fetch {id:?} {node_id:?}")` 改 `trace!` 或删除 | 未修复 |
| AUDIT-ERR-002.F3 | 🟢 Low | `rpc/biscuit.rs:234-235` `anyhow!("Token is in revocation list: {token}")` 改前缀 hash（与 AUTH-001.F4 合并） | 未修复 |
| AUDIT-ERR-002.F4 | 🟢 Low | 引入 `PaymentPreimage` newtype + 自定义 Debug redact；逐步迁移 `payment_preimage: Hash256` 字段 | 未修复（中期重构） |
| AUDIT-ERR-002.F5 | ℹ️ Info | 默认 filter 升 `info` + 文档说明 `RUST_LOG=debug` 激活字段 | — |
| AUDIT-ERR-002.F6 | ℹ️ Info | 加 `--log-format json` + redaction tracing layer（扫描 `Hash256(0x...)` × 字段名 preimage/secret） | — |

---

## Phase 1 — 下一步建议 (Session S17)

按 SKILL §三选取规则，S17 计划：

1. **AUDIT-AUTH-003** — RPC CORS / Tower-http 配置（已部分覆盖于 AUTH-001.F3 与 INPUT-003.F5，需补充 Origin allow-list 与 CSRF 防御纵深审计）
2. **AUDIT-INPUT-004** — 存储反序列化 (bincode) 与迁移（已部分覆盖于 STORE-001.F3/F4，需补充 cross-version replay / downgrade 测试）
3. **AUDIT-NET-001** — P2P 网络协议安全（peer 流控、握手鉴权、tentacle/secio 配置）

跟进遗留（按优先级）：
- **AUDIT-INPUT-002-FOLLOWUP-A/B (highest, 远程零成本零授权 DoS 修复)** — `From<InvoiceAttr> → TryFrom` + `ar_decompress` 错误传播（同时解锁 INPUT-003.F1）
- **AUDIT-LOGIC-008-FOLLOWUP-A/B (high, 直接资金损失修复)** — `expire_order` Pending-only gating + LND/Fiber 对称 cancel 路径
- **AUDIT-INPUT-003-FOLLOWUP-A (medium, 零成本 DoS 修复)** — list-type RPC `limit` 上界
- **AUDIT-ERR-002-FOLLOWUP-A (medium, preimage 字面值移除)** — `watchtower/actor.rs:181` `error!` 字段裁剪
- **AUDIT-ERR-001-FOLLOWUP-A/B (medium, probing + slander 修复)** — 折叠 final-hop 错误码 + `update_graph_with_tlc_fail` 加 route-membership 校验
- **AUDIT-STORE-001-FOLLOWUP-A/B (medium, deployment hardening)** — DB 文件权限 0700/0600 + SQLite 独占 advisory lock
- **AUDIT-MEM-001-FOLLOWUP-A** — gossip OOM PoC + 修复
- **AUDIT-AUTH-001-FOLLOWUP-A** — standalone watchtower NodeId 冲突 PoC + 修复
- **AUDIT-AUTH-002-FOLLOWUP-A** — inbound eviction Sybil PoC + 修复
- **AUDIT-LOGIC-007-FOLLOWUP-A** — 协同 DoS PoC
- **AUDIT-INPUT-002-FOLLOWUP-C/D/E/F** — panic 反模式 / dup attr / fuzz 改进 / catch_unwind 防御
- **AUDIT-INPUT-003-FOLLOWUP-B/C/D/E/F** — `.expect` 防御化 + RpcConfig 字段扩展 + force_auth + inject_rpc_context Result + catch_unwind
- **AUDIT-ERR-002-FOLLOWUP-B/C/D/E/F** — biscuit leftover warn / token 前缀 hash / PaymentPreimage newtype / 默认 info / redaction layer
- **AUDIT-LOGIC-008-FOLLOWUP-C** — orphaned-preimage 旁路
- **AUDIT-MEM-002-FOLLOWUP-B** — `build_settlement_data` checked_* 改造
- **AUDIT-LOGIC-005/004/002-FOLLOWUP-A** — MPP / slot jamming / expiry PoC
- **AUDIT-LOGIC-003-FOLLOWUP-A** — 链上 commitment-lock 合约源码审计
- **AUDIT-ERR-001-FOLLOWUP-C/D/E** — `.expect` 防御化 + timing padding 反汇编验证 + slander PoC 测试
- **AUDIT-STORE-001-FOLLOWUP-C/D/E/F/G/H** — migration batch + bincode strict / deserialize Result / MissingMigration / auto-confirm / backend Result trait / check_validate unknown-prefix
- **AUDIT-CRYPTO-001/002-FOLLOWUP-A** — MuSig2 nonce-reuse / cross-channel onion replay 动态验证

## Phase 1 — Session 16 已完成

按计划完成：
- ✅ **AUDIT-ERR-002** — 日志/tracing 敏感信息。发现 **F1 🟡 Medium — `watchtower/actor.rs:181` `tracing::error!` 输出 preimage 全文**：ERROR 级别默认输出（任何 RUST_LOG 设置），远程 watchtower `create_preimage` RPC 可诱导，preimage 字节进入 log aggregator (Datadog/Loki/etc)；该分支 preimage 对**目标支付**无效，但字节本身可能用作其它 payment 的 preimage（caller-任选随机字节），与 STORE-001.F1 (DB 0644)/INPUT-003.F5 (同主机多租户) 协同 → 本地 user 拼 log+store 即可枚举 preimage/payment_hash 对。**F2 🟢 Low — `rpc/biscuit.rs:260` `tracing::warn!("fetch {id:?} {node_id:?}")` leftover 调试代码**：每次 watchtower 鉴权 RPC 都生成 WARN 行（默认输出），噪声 + node_id 枚举便利。**F3 🟢 Low — `rpc/biscuit.rs:234-235` `anyhow!("Token is in revocation list: {token}")`**：token 进入 Error Display → 远程 JSON-RPC error response 回显（AUTH-001.F4 镜像，从 ERR 维度补强）。**F4 🟢 Low — `Hash256` Debug 完整 hex + `Preimage` 与 payment_hash/channel_id 共用 `Hash256` 类型，无独立 `PaymentPreimage` newtype**：未来 `preimage:?` log 仍然类型系统无防护（F1 是已知实例）；LN 主网 rust-lightning 用独立 `PaymentPreimage` newtype redact 中段。**F5 ℹ️ Info — `EnvFilter::from_default_env()` 默认 ERROR-only**：debug! 默认安静 ✓ 但运维易 `RUST_LOG=debug` 激活 F2/F3。**F6 ℹ️ Info — 缺 JSON formatter / redaction layer / 字段级过滤**：当前 `pretty()` 多行人类可读不便机器化二次过滤。**F7 ✅ Pass — `Privkey(SecretKey)` Debug 委托 secp256k1 0.30 `finish_non_exhaustive` → "Privkey(SecretKey { .. })" ✓**。**F8 ✅ Pass — `commitment_seed`/wallet `password` 全局 grep 0 处 `tracing::*!` 引用 ✓**。**F9 ✅ Pass — Rust panic backtrace 不展开 local 变量；`expect("...")` 字符串均为静态文本不携带 secret ✓**。整体评价：日志层"机密性维度"基础保护良好（核心密钥不流入日志、secp256k1 0.30 redaction、默认 ERROR 限制 debug! 泄露面），主要缺口集中三处（F1 唯一明确"敏感字节进入默认输出"路径 + F2 leftover + F3 token 远程回显），结构性缺口 F4/F6 是缺少 `PaymentPreimage` newtype 与 redaction layer 工程化保护。修复成本：F1/F2/F3 各 1-3 行；F4 类型重构（中期）；F5/F6 UX/工程。新增 6 个 follow-ups（A 必修 Medium，B/C/D 防御 Low，E/F 工程 Info）。

## Phase 1 — Session 15 已完成

按计划完成：
- ✅ **AUDIT-INPUT-003** — JSON-RPC 参数校验。发现 **F1 🟡 Medium — `parse_invoice`/`cch.receive_btc`/`payment.send_payment(invoice)` 是 INPUT-002 invoice DoS 的远程触发面**：单条合法 bech32m 字符串即让节点 panic；私网默认无鉴权 / CCH 网关接收跨链用户输入 → 零成本零授权 DoS。本条主要起入口标记作用，修复依赖 INPUT-002 主修复。**F2 🟡 Medium — `graph_nodes`/`graph_channels`/`list_payments` 的 `limit: Option<u64>` 无显式上界**：`unwrap_or(default)` 仅对缺省有效，攻击者显式传 `u64::MAX` → 全量遍历 + clone + JSON 序列化 → 数十 MB 响应；jsonrpsee 默认 100 并发即被单 IP 占满。**F3 🟢 Low — `get_invoice`/`cancel_invoice` `.expect("no invoice status found")`**：`insert_invoice` 双 put 非原子，IO 故障或 STORE-001.F4 mid-migration 可让 INVOICE 存在但 STATUS 缺失 → 远程触发 panic。**F4 🟢 Low — jsonrpsee `Server::builder()` 用默认配置 + RpcConfig 不暴露 max_connections/max_body/qps**：与 F1/F2 协同放大 DoS。**F5 🟢 Low — `is_public_addr` 仅检查公网监听强制鉴权；私网/loopback 默认 `enable_auth=false`**：同主机多租户（共享 dev/CI/k8s sidecar）任意用户可读所有 RPC，与 STORE-001.F1 文件权限问题对称。**F6 ℹ️ Info — `middleware.inject_rpc_context` 用 `.expect("serialize injected params")`**：当前不可触发，防御性建议改 Result 传播。**F7-F9 ✅ Pass**：Pubkey/Hash256/Multiaddr 解析全部走 `try_from` + `?`；DevRpc `#[cfg(debug_assertions)]` release 剔除；公网监听 `is_public_addr` + biscuit 强制 fail-fast。整体评价：RPC 层**类型解析**严谨（Pubkey/Hash256 全部 fallible，公网强制鉴权，DevRpc 编译期剔除），但在**用户字符串透传**（F1）和**集合 size 边界**（F2）两个面有重要缺口；F3/F4/F5 是防御纵深，与 INPUT-002/STORE-001/MEM-001/AUTH-001 协同放大攻击面。修复成本低（F2/F3 各 < 10 行）。新增 6 个 follow-ups（A 必修 Medium，B/C/D 防御 Low，E 维护 Info，F 临时 catch_unwind）。

## Phase 1 — Session 14 已完成

按计划完成：
- ✅ **AUDIT-STORE-001** — 持久层与迁移安全。发现 **F1 🟡 Medium — DB 目录/文件权限默认 0644/0755**：`open_db` 用 `create_dir_all` + `DB::open` 不设权限，store 中含 `ChannelActorState.commitment_seed`（HKDF 派生历史 revocation secret 的种子，等价完全失去反 cheat 能力）+ watchtower `ChannelData.Privkey` + preimage 三类高敏数据。与 `onion_service.rs:485-491` 已 enforce 0o600 / wallet 已 enforce 0o600 的对称性差距显著。同主机多租户/共享托管/容器编排场景下非 root 用户可直读。**F2 🟡 Medium — SQLite 后端无独占 advisory lock**：`rusqlite::Connection::open` + `journal_mode = WAL` 允许多进程同时打开同一文件。systemd 重启竞态/容器 OOM 重启可让两实例同时迁移并双写 `MIGRATION_VERSION_KEY`，revocation 历史不一致 → cheat 成功。RocksDB 用 LOCK 文件强制独占，不受影响。**F3 🟢 Low — `deserialize_from` 全局 `panic!`**：30+ 调用点任何一条记录字节级损坏 → 永久 boot-loop。watchtower 受同一函数影响 → 攻击者可在 cheat 前制造 torn write 让 watchtower 反复 boot-fail。**F4 🟢 Low — Migration 非原子**：`m.migrate(store)` 内逐条 `store.put` 无 batch / transaction；mid-crash 后依赖 `if let Ok(_new) = bincode::deserialize::<NewChannelActorData>` 做"幂等"，而 bincode 1.x 默认 `DefaultOptions` 不拒绝尾随字节 → 旧字节流末尾恰好是合法 enum 变体即被误判为新格式 → 永久跳过迁移 → 后续读 panic。**F5 🟢 Low — `pending.is_empty()` 时无条件升 db_version**：构建错误（latest 升了但忘加 migration）被掩盖。**F6 🟢 Low — `cli_confirm` 非交互环境**：systemd/k8s 升级体验差。**F7 🟢 Low — 后端 `.expect` 把 I/O 错抬升为 panic**：disk-full/IO error 即崩溃，无 graceful flush，commitment state 一致性受损。**F8 ℹ️ Info — `check_validate` 默认分支 `_ => {}`**：未来新前缀盲检。**F9-F10 ✅ Pass**：`INIT_DB_VERSION` 拒绝跨 epoch + gossip 验签后才入 DB（来自 MEM-001.F1 分析）。整体评价：持久层保守可用，但机密性维度 (F1) 与一致性维度 (F2/F4/F7) 存在改进空间。F1 修复成本极低（5 行）。新增 8 个 follow-ups（A/B 必修 Medium，C-G Low 防御 + UX，H Info 维护性）。

## Phase 1 — Session 13 已完成

按计划完成：
- ✅ **AUDIT-ERR-001** — 支付错误码与 payment probing。发现 **F1 🟡 Medium — Final-hop 错误码细分构成 payment probing oracle**：fiber 在 BOLT-04 之外引入 `InvoiceExpired`(16)/`InvoiceCancelled`(17) 独立终态码，并保留 `FinalIncorrectTlcAmount`(19)/`FinalIncorrectExpiryDelta`(18) 细分（LN 主网已折叠到 `IncorrectOrUnknownPaymentDetails`）。攻击者用 1-sat 探测 TLC 即可远程确认 merchant 的 invoice 状态（存在/已取消/已过期/金额匹配/cltv 匹配）= 商业隐私泄露。零成本零授权。**F2 🟡 Medium — graph slander**：`update_graph_with_tlc_fail` 信任 attacker-controlled `extra_data.node_id`/`channel_outpoint` 标记本地图为 disabled，未校验 ID 属于本次 attempt 的 route。`history.rs::record_payment_fail` 评分路径有正确校验模板 — graph 路径未复用。中转 hop 可让发送方在本地"屏蔽"任意目标节点的所有通道。**F3 🟢 Low — `.expect` panic** 三处：`update_graph_with_tlc_fail` 在攻击者构造 `extra_data` 缺失时 PaymentActor panic → 单笔 payment 卡死。**F4 🟢 Low — `GetPaymentResult.failed_error` 透出错误码字面量加重 F1**（F1 修复后自动消解）。**F5 🟢 Low — `TlcErr::serialize` `.expect` 反模式**（与 INPUT-002.F4 同质）。**F6 ℹ️ Info — `ERROR_DECODING_PASSES=27` dummy XOR 在 release build 上是否被 LLVM 优化消除需反汇编验证**。**F7-F8 ✅ Pass**：sphinx error 加密完备、history 评分路径有 route-membership 校验。整体评价：错误处理框架结构良好（BOLT-04 位掩码、sphinx encryption、constant-time padding 设计、history slander 防护），但存在隐私维度 (F1) 与可用性维度 (F2/F3) 两个规范/对称性差距。修复成本极低（<50 行 Rust）。新增 5 个 follow-ups（A/B 必修 Medium，C/D 防御 Low，E 测试）。

## Phase 1 — Session 12 已完成

按计划完成：
- ✅ **AUDIT-INPUT-002** — Invoice 解析（bech32m / molecule / CkbInvoice）。发现 **F1 🟠 High — `From<InvoiceAttr> for Attribute` 三处 `.expect()` 远程 DoS**：单次合法格式的 `parse_invoice` / `send_payment` / `cch.receive_btc` RPC 调用即可 panic 整个 fiber 进程。攻击者绕过 `InvoiceBuilder` 构造 `RawInvoiceData` molecule 字节（如 Description.value = 非 UTF-8、PayeePublicKey.value = 非合法 pubkey），通过 `ar_encompress + bech32m` 包装 → 节点崩溃。F2 Medium: `ar_decompress(...).expect()` 同攻击面更易构造。F3 Medium: `from_str` line 902 在 F1 修复后变可触发。F4-F5 Low: panic 反模式 + duplicate attr 不拒绝。F6 Info: 现有 `fuzz_invoice` 99.99% 被 bech32m checksum 拒绝、永远到不了 attr 转换层 → 结构性盲区。F7-F8 Pass: bech32m vs bech32 强制；签名校验路径完整。**修复成本极低**（`.expect → ?` + `From → TryFrom`），是除 LOGIC-008 之外最严重的 DoS 类发现。新增 6 个 follow-ups（A/B 必修 High/Medium，C/D/F 防御 Low，E 测试改进 Info）。

## Phase 1 — Session 11 已完成

按计划完成：
- ✅ **AUDIT-LOGIC-008** — CCH 跨链 HTLC 依赖与到期。发现 **F1 🟠 High — `expire_order` 与 outgoing 流程的致命竞态**：默认配置 (order_expiry=36h < TLC_expiry=60h) 下，攻击者可通过控制 incoming 支付时刻让调度器在 outgoing 流程中强制 Fail 订单，导致 preimage 事件被 `get_active_order_or_none` 丢弃 → CCH 未 settle incoming → 24h 后退款。CCH 模块**完全没有** cancel_invoice / cancel_payment 调用路径（grep 0 命中）。**这是当前审计中最严重的 LOGIC 类发现**，优先级高于 LOGIC-007。新增 6 个 follow-ups（A/B 必修：限定 Pending only + 实现对称取消；C 防御性恢复；D Low fix；E/F 文档与配置加固）。

## Phase 1 — Session 10 已完成

按计划完成：
- ✅ **AUDIT-MEM-002** — 数值溢出与边界审计（fee 计算、HTLC amount、capacity、状态机数值），发现 F1-F3 Low（防御深度缺口）+ F4-F5 Info + F6-F9 Pass。整体评价：与 MEM-001 形成鲜明对比，数值算术整体接近正确（`apply_remove_tlc` checked_* 是典范，HopData 解析有 u64::MAX overflow 单元测试）。

## Phase 1 — Session 9 已完成

按计划完成：
- ✅ **AUDIT-MEM-001** — 资源耗尽审计（gossip 暂存层、actor mailbox、TLC 默认值、channel pending limits），发现 F1 High（gossip `messages_to_be_saved` 远程 OOM）+ F2/F3 Medium + F4-F6 Low + F7/F8 Pass

## Phase 1 — Session 8 已完成

按计划完成：
- ✅ **AUDIT-AUTH-002** — Peer 身份绑定与 onion service 完整审计（secio + gossip 签名 ✓、inbound eviction、onion service 隐私模式、tor key 权限、session 覆盖、tor_password 明文），发现 F1 Medium（inbound eviction Sybil DoS）+ F2 Medium（隐私模式实现-期望落差）+ F3-F6 Low

## Phase 1 — Session 7 已完成

按计划完成：
- ✅ **AUDIT-AUTH-001** — Biscuit RPC 鉴权完整审计（biscuit/middleware/start_server/CORS/standalone watchtower 多租户），发现 F1 High 漏洞链（standalone watchtower NodeId::local 共享命名空间）+ F2/F3 Medium

## Phase 1 — Session 6 已完成

按计划完成：
- ✅ **AUDIT-LOGIC-007** — 通道关闭路径完整审计（cooperative + force + shutdown_script 校验），发现 F1+F2+F3 协同 DoS 链

## Phase 1 — Session 5 已完成

按计划完成：
- ✅ **AUDIT-LOGIC-004** — 多跳支付转发金额/费用一致性（含 HTLC slot jamming 风险）
- ✅ **AUDIT-LOGIC-005** — MPP / Trampoline 拆分一致性（含 N 倍超付风险）

## Phase 1 — Session 4 已完成

按计划完成：
- ✅ **AUDIT-LOGIC-002** — TLC / PTLC 生命周期与时间锁（含入站 expiry 校验缺失）
- ✅ **AUDIT-LOGIC-006** — Watchtower 反应路径剩余面（settlement / preimage / parsers）

## Phase 1 — Session 3 已完成

按计划完成：
- ✅ **AUDIT-LOGIC-001** — 通道状态机非法转移（17 种消息状态守卫矩阵）
- ✅ **AUDIT-LOGIC-003** — Commitment 序号 & revocation key（含 watchtower 链上反应路径）

## Phase 1 — Session 2 已完成

按计划完成：
- ✅ **AUDIT-CRYPTO-002** — Sphinx 洋葱包解封与回放保护
- ✅ **AUDIT-INPUT-001** — P2P Molecule 消息抗畸形 + fuzz 覆盖度评估
