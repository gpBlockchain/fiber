# Fiber Network Node 安全审计 TODO

> 版本: **v2** | 最后更新: 2026-05-13 | 状态: 进行中 (Phase 1 — Session 2 完成)

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

- **总 TODO 项**: 31
- ✅ 通过: 0
- ⚠️ 建议改进: 2 (AUDIT-CRYPTO-003, AUDIT-INPUT-001)
- ❌ 发现疑似漏洞: 1 (AUDIT-CRYPTO-001 — 需动态验证)
- ⚠️ 发现弱设计: 1 (AUDIT-CRYPTO-002 — Sphinx replay / timing)
- ℹ️ 信息性: 1 (AUDIT-DEP-001)
- ⏳ 待审计: 26

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

- [ ] 🔴 **AUDIT-LOGIC-001** 通道状态机非法转移
- [ ] 🔴 **AUDIT-LOGIC-002** TLC / PTLC 生命周期与时间锁
- [ ] 🔴 **AUDIT-LOGIC-003** Commitment 序号 & revocation key
- [ ] 🟠 **AUDIT-LOGIC-004** 多跳支付转发金额/费用一致性
- [ ] 🟠 **AUDIT-LOGIC-005** MPP / Trampoline 拆分一致性
- [ ] 🟠 **AUDIT-LOGIC-006** Watchtower 反应路径
- [ ] 🟡 **AUDIT-LOGIC-007** CCH 跨链 HTLC 依赖与到期

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
- [ ] 🔴 **AUDIT-INPUT-002** Invoice 解析 (bech32 / lightning-invoice)
- [ ] 🟠 **AUDIT-INPUT-003** JSON-RPC 参数校验
- [ ] 🟠 **AUDIT-INPUT-004** 存储反序列化 (bincode) 与迁移
- [ ] 🟡 **AUDIT-INPUT-005** CKB Tx / Cell 数据

## 第 4 章 DIM-AUTH 认证与鉴权

- [ ] 🔴 **AUDIT-AUTH-001** Biscuit RPC 鉴权
- [ ] 🟠 **AUDIT-AUTH-002** Peer 身份绑定与 onion service
- [ ] 🟡 **AUDIT-AUTH-003** RPC CORS / Tower-http 配置

## 第 5 章 DIM-MEMORY 数值与资源

- [ ] 🟠 **AUDIT-MEM-001** 金额 / 费用 / 高度数值溢出
- [ ] 🟠 **AUDIT-MEM-002** P2P / RPC 资源耗尽
- [ ] 🟡 **AUDIT-MEM-003** Actor mailbox 阻塞

## 第 6 章 DIM-ERRINFO 错误信息与隐私

- [ ] 🟠 **AUDIT-ERR-001** 支付错误码与 payment probing
- [ ] 🟡 **AUDIT-ERR-002** 日志/tracing 中的敏感信息

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

---

## 附录 A：审计执行日志

| 日期 | 会话 | 审计项 | 发现摘要 | 状态 |
|---|---|---|---|---|
| 2026-05-13 | S1 | AUDIT-CRYPTO-001 | MuSig2 nonce 纯确定性派生，缺少 message/agg-pubkey/随机熵混合；存在与不同 message 重复签名场景下泄露 funding key 的设计性风险 | [?] 疑似 H/Critical — 需动态验证 |
| 2026-05-13 | S1 | AUDIT-CRYPTO-003 | 钱包加密文件 VERSION 字段未校验；缺少长度检查触发 panic；`fs::read().unwrap()` 不优雅；无 zeroize；P2P 节点密钥 (`fiber/key.rs`) 仍明文落盘 | [!] Medium × 2，Low × 3 |
| 2026-05-13 | S1 | AUDIT-DEP-001 | 12 个高敏依赖经 GitHub Advisory DB 检查无已知 CVE | [i] 信息性 |
| 2026-05-13 | S2 | AUDIT-CRYPTO-002 | Sphinx peel 主路径稳健 (assoc_data ✓, 错误码统一 ✓)；但缺少 shared-secret 跨通道 replay 去重；`TlcErrPacket::decode` 时间填充实现不完美 | [!] Medium × 1, Low × 1, Info × 1 |
| 2026-05-13 | S2 | AUDIT-INPUT-001 | 现有 9 个 fuzz 目标覆盖广泛；二阶 TryFrom 子类型 fuzz 较浅；CI 未集成定期 fuzz | [~] Low × 1, Improvement × 3 |

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

---

## Phase 1 — 下一步建议 (Session S3)

按 SKILL §三选取规则（P0 > P1；底层 > 上层；外部输入 > 内部；资金/密钥 > 数据），S3 计划：

1. **AUDIT-LOGIC-001** — 通道状态机非法转移（State 枚举与 `handle_*` 路径）
2. **AUDIT-LOGIC-003** — Commitment 序号 & revocation key（旧 commitment 重放、watchtower 通知漏失）

同时跟进 S1/S2 遗留：
- **AUDIT-CRYPTO-001-FOLLOWUP-A/B** — 动态验证 MuSig2 nonce-reuse 是否可达；与 fiber 维护者确认设计
- **AUDIT-CRYPTO-002-FOLLOWUP-A** — 动态验证 cross-channel onion replay 是否可达
- **AUDIT-CRYPTO-002-FOLLOWUP-B** — 单独立项审计 `fiber-sphinx 2.3` 上游源码

## Phase 1 — Session 2 已完成

按计划完成：
- ✅ **AUDIT-CRYPTO-002** — Sphinx 洋葱包解封与回放保护
- ✅ **AUDIT-INPUT-001** — P2P Molecule 消息抗畸形 + fuzz 覆盖度评估
