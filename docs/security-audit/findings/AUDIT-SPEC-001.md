# AUDIT-SPEC-001 — P2P 消息规范 (`docs/specs/p2p-message.md`) 与实现 (`crates/fiber-types/src/schema/fiber.mol` + `crates/fiber-lib/src/fiber/*`) 一致性

- **Session**: S24
- **Date**: 2026-05-14
- **Auditor**: Phase 1 iterative audit
- **Dim**: DIM-SPEC (规范一致性)
- **Status**: ⚠️ Spec-implementation drift (no direct funds at risk, but **wire-incompatibility & probing surfaces for downstream integrators**)
- **Severity**: 整体 🟡 Medium / 🟡 Medium × 5 + 🟢 Low × 3 + ℹ️ Info × 1

## 范围

对照 `docs/specs/p2p-message.md` (376 行, "work in progress" 声明) 与权威实现 `crates/fiber-types/src/schema/fiber.mol`（Molecule schema，305 行），并交叉验证 `crates/fiber-lib/src/fiber/{network,channel,types}*.rs` 中的实际处理路径。

审计目标：识别**规范-实现漂移**作为攻击面 — 任何独立实现 fiber 协议的第三方节点若严格按 `p2p-message.md` 编码，会产生：
- 线缆级不兼容（解析失败 / 字段缺失 / 字段错位） → DoS 互联失败；
- **协议设计差异** → 第三方实现遗漏关键安全字段（如 musig2 nonce 传递、加密错误码）；
- 公共文档落后于实现导致整合者引入漏洞模式。

## 漂移清单

实现取自 `crates/fiber-types/src/schema/fiber.mol`，规范取自 `docs/specs/p2p-message.md`。

### F1 🟡 Medium — `RevokeAndAck` 规范描述的是 lightning per-commitment-secret 揭示方案，实现是 musig2 partial signature 方案

- **Spec** (`p2p-message.md:328-338`):
  ```
  table RevokeAndAck {
      channel_id:                 Byte32,
      per_commitment_secret:      Byte32,
      next_per_commitment_point:  Byte33,
      next_local_nonce:           Byte66,
  }
  ```
  描述: "per_commitment_secret: Secret used to generate the revocation secret key for the previous commitment transaction." → 经典 BOLT-03 / LN revocation 方案（揭示对方持有的 secret 让对方学到 cheat penalty key）。

- **Impl** (`fiber.mol:137-142`):
  ```
  struct RevokeAndAck {
      channel_id:                         Byte32,
      revocation_partial_signature:       Byte32,
      next_per_commitment_point:          Pubkey,
      next_revocation_nonce:              PubNonce,
  }
  ```
  无 `per_commitment_secret`，改为 `revocation_partial_signature` — musig2 部分签名（参与 AUDIT-CRYPTO-004 F2 / AUDIT-LOGIC-003 已覆盖的 cheat-penalty 流程）。

- **影响**:
  - 任何第三方实现严格按 spec：(a) 无法生成 musig2 revocation_partial_signature → 互联失败 ;(b) 若误读为 "需要揭示某 secret"，会**直接广播给 peer**一个其它字节作为 "per_commitment_secret"，被恶意 peer 收集后用于反推/破坏对端 cheat penalty 路径（细节取决于第三方误实现）。
  - 已与 AUDIT-CRYPTO-004 F2 (`channel.rs:7301-7356` 缺 `verify_partial` 预校验) 同源 — 规范缺失也意味缺乏明确的 partial-sig 校验要求。
  - 这是协议设计本身的差异，不是字段命名差异 → 修复 = 重写 §"RevokeAndAck" 一节。

### F2 🟡 Medium — `RemoveTlc` `RemoveTlcFail` 规范定义 plaintext `error_code: Uint32`，实现使用加密 `TlcErrPacket`

- **Spec** (`p2p-message.md:362-365`):
  ```
  struct RemoveTlcFail {
      error_code:         Uint32,
  }
  ```
  无加密、无 onion-wrap，任何路径上 hop 都可读 → **payment probing**。

- **Impl** (`fiber.mol:148-155`):
  ```
  table TlcErrPacket { onion_packet: Bytes, }
  union RemoveTlcReason { RemoveTlcFulfill, TlcErrPacket, }
  ```
  正确使用 BOLT-04 风格 onion-encrypted 错误回包（与 AUDIT-CRYPTO-002 / AUDIT-ERR-001 一致）。

- **影响**: 规范引导的第三方实现会**直接退化为明文错误码**，让中转节点和外部观察者枚举支付状态（与 AUDIT-ERR-001 F2/F3 的 final-hop 错误码探测同源，但放大到**整条链路任意 hop**）。下游一旦上线即引入 payment-probing 漏洞。

### F3 🟡 Medium — `AddTlc` 规范缺 `hash_algorithm` 与 `onion_packet`

- **Spec** (`p2p-message.md:309-316`): 只声明 `channel_id, tlc_id, amount, payment_hash, expiry`。
- **Impl** (`fiber.mol:125-135`): 多 `hash_algorithm: byte`（防止跨哈希算法 cross-payment 重放，AUDIT-LOGIC-002 相关）、`onion_packet: Bytes`（多跳转发载体）。
- **影响**:
  - 缺 `onion_packet` → 整个**多跳路由层**不在规范中 → 第三方实现既无法转发也无法解析 final-hop（AUDIT-CRYPTO-002 Sphinx 协议完全无文档化）。
  - 缺 `hash_algorithm` → 第三方默认 SHA-256，与本实现的 CKBHash/SHA-256 算法选择脱节 → AUDIT-LOGIC-002 已知的 hash-algorithm 边界检查（`channel.rs:2950-2980` 等位置）在跨实现交互时失效。

### F4 🟡 Medium — `TxSignatures` 规范包含 `tx_hash`，实现已移除

- **Spec** (`p2p-message.md:140-145`):
  ```
  table TxSignatures {
      channel_id: Byte32,
      tx_hash:    Byte32,
      witnesses:  BytesVec,
  }
  ```
- **Impl** (`fiber.mol:72-75`):
  ```
  table TxSignatures {
      channel_id: Byte32,
      witnesses:  BytesVec,
  }
  ```
- **影响**: 严格按 spec 实现的 peer 在 wire level 上 Molecule 解析失败 (TxSignatures 多 32B `tx_hash` 字段) → channel funding 流程**硬不兼容**。Molecule schema 的 forward-compat（table 添加末尾字段）无法保护"中间字段差异"场景 — 规范多余字段被 deserializer 当作非法数据。
- 评级: Medium（不是 funds 直损，但建网必踩，且双向不兼容 — 双方版本管理失败时会以 corruption 告终）。

### F5 🟡 Medium — `TxComplete` 规范无 `next_commitment_nonce`，实现要求

- **Spec** (`p2p-message.md:197-201`):
  ```
  table TxComplete { channel_id: Byte32, }
  ```
- **Impl** (`fiber.mol:86-89`):
  ```
  struct TxComplete {
      channel_id:                       Byte32,
      next_commitment_nonce:            PubNonce,
  }
  ```
- **影响**:
  - **MuSig2 nonce 协议关键**: `TxComplete` 在签 commitment-tx 前夹带 nonce → 第三方按 spec 实现既不发也不期待 nonce → 在收到 fiber 实现的 `TxComplete` 时 Molecule 解析失败，或在发出 fiber 实现期待的 `TxComplete` 时 fiber 端 expect-nonce 失败 → channel open hard-fail。
  - 与 AUDIT-CRYPTO-001（musig2 nonce 管理）的 P0 命题直接关联 — spec 隐藏了 nonce hand-off 关键时机，让协议安全审计本身困难。

### F6 🟢 Low — `OpenChannel` / `AcceptChannel` 规范字段表与实际多处不匹配

具体差异（spec → impl）：

| Spec 字段 | Impl 字段 | 备注 |
|---|---|---|
| `funding_type_script: ScriptOpt` | `funding_udt_type_script: ScriptOpt` | 重命名 |
| `min_tlc_value: Uint128` | _移除_ | impl 不再支持单 channel 最小 TLC 值（与 `UpdateTlcInfo.tlc_minimum_value` 流动配置替代） |
| `to_self_delay: Uint64` | _移除_ | 描述里却写成 "commitment_delay_epoch" (spec 文本 line 78) — 规范**自身**前后矛盾 |
| _无_ | `shutdown_script: Script` | LOGIC-007 强约束的 shutdown 脚本上传时机 |
| _无_ | `reserved_ckb_amount: Uint64` | CKB cell 占位 |
| _无_ | `commitment_delay_epoch: Uint64` | 字段确实在 impl，但 spec 字段表无 |
| `next_local_nonce: Byte66` | `channel_announcement_nonce: PubNonceOpt, next_commitment_nonce: PubNonce, next_revocation_nonce: PubNonce` | impl 三 nonce 显式分类（musig2 三组独立用途）— spec 折叠为单 nonce |
| (AcceptChannel) `payment_basepoint, delayed_payment_basepoint, min_tlc_value` | _移除_ | impl 不再使用 LN 风格 4-basepoint 派生 |

- **影响**: 第三方实现产出的字段集合与 fiber 实现集合在 Molecule wire 上完全不同 → channel-open 阶段 100% 解析失败。属于"基础设施漂移"，**所有**新接入实现都会立即遇到 — 实战首道挡板。
- 仅评 Low 因为：(a) 一旦使用，第三方实现者会在 5 分钟内意识到 → 攻击者难以"隐身"利用；(b) Molecule 解析失败 fail-fast 不留状态污染。Risk 主要在文档可信度本身。

### F7 🟢 Low — Init / 特性协商完全缺失文档

- **Impl** (`fiber.mol:23-26, 203-223 FiberMessage union`):
  ```
  table Init { features: Bytes, chain_hash: Byte32, }
  ```
  + `network.rs` 中 `check_feature_compatibility` 强门控所有后续业务消息（AUDIT-NET-001 F9 Pass）。
- **Spec**: 0 命中（`grep -n Init docs/specs/p2p-message.md` 仅匹配 §"Tx Init RBF"）。
- **影响**:
  - `features` 字节集合及位语义无文档 → 跨实现feature negotiation 不可能；
  - `chain_hash` 校验是 AUDIT-NET-001 F1 / AUDIT-AUTH-002 F8 cross-chain replay 的第一防线，规范却完全无文档 → 新实现可能跳过此校验。
- Low 因为 fiber 实现侧（network.rs）正确处理，但**第三方不知道存在**这一字段的语义集合 → 跨链 chain_hash 错配可能被引入。

### F8 🟢 Low — UpdateTlcInfo / ReestablishChannel / AnnouncementSignatures 完全无规范

- **Impl** (`fiber.mol:116-123, 163-167, 169-174`)：三条消息均存在且被 active 处理：
  - `UpdateTlcInfo` — 通道 TLC 流量参数动态广播；
  - `ReestablishChannel` — 重连协议（AUDIT-LOGIC-003 引用 `local_commitment_number / remote_commitment_number` 双向对账）；
  - `AnnouncementSignatures` — gossip channel_announcement 三签名收集（AUDIT-CRYPTO-004 F3 / F8 直接覆盖）。
- **Spec**: 0 命中。
- **影响**:
  - `ReestablishChannel` 是 channel-stuck 恢复的**唯一**双向对账渠道 → 第三方无法实现重连 → AUDIT-NET-001 F1 关停后再连后**永久卡死**（远高于规范缺失感）。
  - `AnnouncementSignatures` 缺文档则 AUDIT-CRYPTO-004 F3 (`channel.rs:4720-4737` 缺 verify_partial) 的修复方向无规范支撑 — 修哪个签名、按什么顺序、若失败如何 ban peer，全无文档。
- Low 因为 fiber 实现侧本身已通过其它审计项处理。

### F9 ℹ️ Info — 规范开篇 "work in progress and may be updated at any time" 声明 + `Secret Derivations` 外链至 lnbook

- `p2p-message.md:7` 明确 disclaimer，对外承诺较弱；
- `p2p-message.md:376` `[Secret Derivations]: lnbook` 外链 — fiber 实际派生路径与 LN basepoint 派生有差异（见 F6 AcceptChannel 4-basepoint 移除），外链可能误导。
- 仅作记录，不构成漏洞。

## ✅ Pass / 一致项

- **ChannelReady** (`p2p-message.md:157-159` vs `fiber.mol:77-79`): 仅 `channel_id`，匹配 ✓
- **ClosingSigned** (`p2p-message.md:269-273` vs `fiber.mol:111-114`): 字段名 `partial_signature: Byte32` 匹配 ✓
- **Shutdown** (`p2p-message.md:255-260` vs `fiber.mol:105-109`): 字段集合 `{channel_id, close_script, fee_rate}` 一致（字段顺序差异 — Molecule table 序列化包含字段索引，顺序由 schema 决定 → 实际 wire 仍以 impl 顺序 `{channel_id, fee_rate, close_script}` 为准；spec 字段顺序无实际影响） ✓
- **TxAbort, TxInitRBF, TxAckRBF**: 字段一致 ✓

## 协同攻击链

- **L1 (spec-following peer DoS)**: 第三方按 spec 实现 → F4 (TxSignatures.tx_hash 多 32B) / F5 (TxComplete 缺 nonce) 任意一处都让 channel-open Molecule 失败 → 100% 接入失败。攻击者**无意**实现的 peer 即触发，无法定向恶意。Severity Low（拒绝服务但是 spec-following 节点自伤）。
- **L2 (downstream payment probing)**: F2 第三方实现 plaintext `error_code: Uint32` → 接入 fiber 主网后该节点充当中转 hop → 每次转发都从 RemoveTlcFail.error_code 直接读取 final-hop 错误 → 网络性 payment probing。**该节点用户**遭隐私损失，fiber 本身免疫。
- **L3 (revocation scheme误植入)**: F1 第三方按 lightning 风格"per_commitment_secret reveal"实现 → 实际 wire 是 musig2 partial_signature → 多种结果，最严重是该节点把 32B 任意字节当作 `per_commitment_secret` 广播 → 协议层无定义结果，可能让 fiber 实现侧解析为 partial_sig 后 musig2 聚合失败而 force-close，但**字节本身**若是 fiber peer 期待的某种密钥派生中间量，理论上可导致 revocation 路径误启用 → 需要协议+实现交叉建模才能排除资金风险 → 保守评 Medium。

## 修复建议（按优先级）

| ID | 优先级 | 描述 | 工作量 |
|---|---|---|---|
| FOLLOWUP-A | Medium | 重写 `p2p-message.md` §RevokeAndAck — 删除 `per_commitment_secret`，引入 musig2 `revocation_partial_signature` 与 `next_revocation_nonce`；明确签名要求 verify_partial。 | 1-2 小时文档 |
| FOLLOWUP-B | Medium | 重写 §RemoveTlc — 替换 `RemoveTlcFail.error_code: Uint32` 为 `TlcErrPacket { onion_packet: Bytes }`，并指向独立的 onion-error 加密章节（与 BOLT-04 对齐）。 | 1 小时文档 |
| FOLLOWUP-C | Medium | 在 §AddTlc 增加 `hash_algorithm`, `onion_packet` 字段说明 + 新增独立 §"Onion routing & Sphinx error" 节，规范化 fiber-sphinx 加密协议（与 AUDIT-CRYPTO-002 结合） | 半天文档（需 ASCII 图） |
| FOLLOWUP-D | Medium | §TxSignatures 删除 `tx_hash` 字段；§TxComplete 增加 `next_commitment_nonce`；明确 nonce hand-off 时机（与 AUDIT-CRYPTO-001 协调） | 半小时文档 |
| FOLLOWUP-E | Medium | §OpenChannel / AcceptChannel 全字段重写对齐 impl；显式列出 musig2 三 nonce (`channel_announcement_nonce / next_commitment_nonce / next_revocation_nonce`) 的语义边界；修复 spec 内 `to_self_delay` vs `commitment_delay_epoch` 自相矛盾 | 1 小时文档 |
| FOLLOWUP-F | Low | 新增 §Init 章节，列举 features 位语义与 chain_hash 校验要求 | 半小时文档 |
| FOLLOWUP-G | Low | 新增三节：§UpdateTlcInfo / §ReestablishChannel / §AnnouncementSignatures | 1 小时文档 |
| FOLLOWUP-H | Info | 移除 `Secret Derivations` 外链至 lnbook；改为内联描述 fiber 实际 basepoint 派生（与 LN 4-basepoint 的差异） | 半小时文档 |
| FOLLOWUP-I | Info | 引入 spec versioning（如 `version: 2026-05`），定期与 `fiber.mol` git tag 对齐；CI 增加 `tools/check-spec-impl-drift.sh` 简单字段名 grep 一致性脚本 | 2 小时工程 |

## 整体评价

`docs/specs/p2p-message.md` 现状是 **2024 早期设计快照**，相对当前 `fiber.mol` 已出现 **5 处中等漂移**（F1/F2/F3/F4/F5，均含安全语义）和 **3 处低危漂移**（F6/F7/F8，主要是 fiber 自有扩展未文档化）。

**正面**:
- 实现侧**正确**而规范侧落后 — 不存在"规范正确但实现偏离规范"导致 fiber 自身漏洞的情形；
- Molecule schema 是事实上的权威，fiber-types crate 序列化 ABI 由 schema 编译产生，避免了"代码与 schema 漂移"二次风险。

**负面**:
- 公共规范文档的可信度低 → 第三方实现接入门槛被规范误导提高，生态扩展不利；
- 对 AUDIT-CRYPTO-001 / 002 / 004 与 AUDIT-LOGIC-003 / 007 的关键修复方向无规范背书，将来跨实现协议升级（如 PTLC）讨论难锚定；
- 规范本身（F6 内部矛盾）说明长期没有 doc-review 流程。

无直接资金风险；本审计项的核心 deliverable 是为 **AUDIT-SPEC-002 / 003** 后续审计与项目方向给出 **9 项 follow-ups** 的修复路线图。
