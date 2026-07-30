# AUDIT-XMOD-007 — Chain hash 校验防线跨模块缺位

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟡 Medium（规范层防御纵深；当前实现已守住） |
| 状态 | [!] 发现规范缺位（实现侧 OK，规范侧无强制要求） |
| 出处 | 本次跨模块审计补强；基于 SPEC-001.F7 + AUTH-002.F8 + NET-001.F9 |
| 关联代码 | `crates/fiber-lib/src/fiber/network.rs`（`Init` 消息处理与 `check_feature_compatibility` 路径）<br>`crates/fiber-types/src/schema/fiber.mol`（Init 消息 schema）<br>`docs/specs/p2p-message.md`（SPEC-001.F7：`Init` 消息规范缺失）<br>`crates/fiber-lib/src/ckb/funding/funding_tx.rs:404-407, 494`（funding tx 构造路径） |
| 关联 finding | AUDIT-SPEC-001.F7（Init 规范缺失）、AUDIT-AUTH-002.F8（chain_hash 校验实现侧）、AUDIT-NET-001.F9 |

## 1. 现象

`Init` 消息携带 `chain_hash` 字段用于宣告 peer 所在的 CKB 链；fiber 当前实现侧 (`network.rs::check_feature_compatibility`) 已经校验该字段与本地 `genesis_block_hash` 匹配，不匹配则拒绝握手。

但：

1. **规范文档 `docs/specs/p2p-message.md` 未规定 `Init` 字段表**（SPEC-001.F7）。第三方实现 / 工具节点可能漏校 `chain_hash`，在 mainnet ↔ testnet 之间错误握手。
2. **funding tx 构造路径** (`ckb/funding/funding_tx.rs:404-407, 494`) 不二次校验 chain_hash；依赖上游 `NetworkActor` 在 peer 建立时拒绝。
3. **没有**因 chain_hash 不匹配而**持久 ban** 对端的设施（与 NET-001.F1 持久 ban list 共享依赖）。

## 2. 跨模块攻击场景

虽然 fiber 自己 OK，但跨网攻击仍可发生于：

1. **第三方实现 peer**：未来出现 fiber 兼容实现漏校 chain_hash → 攻击者构造 dual-network peer 让该实现误以为同链。
2. **配置错误的 fiber 节点**：用户误把 testnet genesis 配在 mainnet 上 → fiber 仍允许握手且尝试 funding（funding tx 因链上拒绝失败，但 channel 状态机已推进）→ 状态不一致。
3. **MITM 篡改 Init**：tentacle secio 之上的握手层若有 downgrade（未验证）→ Init 字段被改 → 错误链交易构造。

## 3. 与已有发现的区别

- AUTH-002.F8 / NET-001.F9 关注实现侧"是否校验" — 当前✅。
- 本条关注**规范侧**与**多模块协同**：spec 缺位 → 第三方实现风险；funding 路径缺二次校验 → 防御纵深不足；无 ban 设施 → 攻击者可反复试。

## 4. 影响评估

- 当前 fiber 主实现影响低；
- 一旦多实现并存（如 ckb-light-client / 移动端 SDK），影响升级；
- 与 XMOD-013（钱包凭据）协同：跨链误用同 secret key 后果较重。

## 5. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | P2 | SPEC-001 补 `Init` 消息字段表，**显式标注 `chain_hash` 必须 strict equal 本端 genesis；不等立即关闭连接并标 ban**。 |
| F2 | P2 | `network.rs` chain_hash 不匹配时调 ban list（依赖 NET-001.F1）+ 记录 `incompatible_chain` 指标。 |
| F3 | P2 | `funding/funding_tx.rs` 构造前再校验 `chain_hash`（深度防御）；不匹配 abort funding 流程。 |
| F4 | P3 | 增加跨实现 conformance test：用恶意 Init `chain_hash=ALL_ZEROES` / mainnet-on-testnet 测试本端是否正确拒绝。 |

## 6. 验证测试

- `network::tests::test_init_wrong_chain_hash_disconnect`：发送 Init with wrong chain_hash → peer disconnected + (after F2) ban list 包含该 peer_id。
- `ckb::funding::tests::test_chain_hash_double_check`：funding tx 构造路径接收伪造 chain_hash → 拒绝构造。

## 7. 状态

- 实现侧低风险，规范侧 F1 应尽快补。
- 关联 PR：暂无。
