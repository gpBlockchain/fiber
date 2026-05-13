# AUDIT-INPUT-001 — P2P Molecule 消息解析抗畸形

| 字段 | 值 |
|---|---|
| 维度 | DIM-INPUT + DIM-SERDE |
| 优先级 | 🔴 P0-Critical |
| 状态 | **[~] 大部分通过；Low × 1，Improvement × 2** |
| 审计会话 | S2 (2026-05-13) |
| 审计方法 | Fuzz harness 覆盖度评估 + 长度上限审查 + 解析入口审查 |

## 1. 范围

来自 P2P 的"任意字节"输入路径：

| # | 入口 | 调用栈 |
|---|---|---|
| ① Fiber 协议 | `FiberMessage::from_molecule_slice` | `network.rs:6090` → `molecule_fiber::FiberMessage::from_slice` → `TryInto` 各子类型 |
| ② Gossip 协议 | `GossipMessage::from_molecule_slice` | `gossip.rs:3123` → `molecule_gossip::GossipMessage::from_slice` → `TryInto` 各子类型 |
| ③ 洋葱内 hop_data | `PaymentHopData::deserialize` / `TrampolineHopPayload::deserialize` | 通过 `peel_sphinx_onion` 间接调用 |
| ④ TlcErrPacket | `TlcErr::deserialize` | `TlcErrPacket::decode` / `is_plaintext` 后切片 |
| ⑤ 存储反序列化 | `bincode::deserialize::<*>` | RocksDB 读 + WAL 回放 |
| ⑥ Invoice 字符串 | `CkbInvoice::from_str` | bech32m + molecule |
| ⑦ Cursor | `Cursor::from_bytes` | gossip `GetBroadcastMessages` 请求中 |

## 2. 现有 fuzz harness 覆盖度

`crates/fiber-lib/fuzz/fuzz_targets/` 已存在 **9 个目标**，覆盖良好：

| Fuzz 目标 | 入口 | 备注 |
|---|---|---|
| `fuzz_fiber_message.rs` | `FiberMessage::from_molecule_slice` | ① ✓ |
| `fuzz_gossip_message.rs` | `GossipMessage::from_molecule_slice` | ② ✓ |
| `fuzz_molecule_types.rs` | TlcErr / NodeAnnouncement / ChannelAnnouncement / ChannelUpdate 的 molecule→Rust 转换 | ② ✓ 细化 |
| `fuzz_onion_packet.rs` | `PaymentHopData::deserialize` + `TrampolineHopPayload::deserialize` + roundtrip | ③ ✓ |
| `fuzz_sphinx_packet.rs` | `OnionPacket::from_bytes` | ⑧ ✓ |
| `fuzz_store_deserialize.rs` | bincode for `ChannelActorState`, `PersistentNetworkActorState`, `PaymentSession`, `TimedResult`, `CkbInvoice`, `CkbInvoiceStatus`, `BroadcastMessage`, `PaymentCustomRecords` | ⑤ ✓ |
| `fuzz_invoice.rs` | `CkbInvoice::from_str` | ⑥ ✓ |
| `fuzz_pubkey.rs` | `Pubkey::from_slice` + roundtrip | 子模块 ✓ |
| `fuzz_cursor.rs` | `Cursor::from_bytes` + roundtrip | ⑦ ✓ |

**结论**：fuzz 覆盖度超出 Phase-0 评估的预期。
**Phase-0 中"需评估目标覆盖"的论断需要修正**，已在 TODO 附录 B 中记录。

### 2.1 缺口

| # | 缺口 | 建议 |
|---|---|---|
| G1 | `TlcErrPacket::decode(session_key, hops_public_keys)`（两参数 fuzz）未覆盖 | 新增 fuzz target；记入 AUDIT-CRYPTO-002-FOLLOWUP-C |
| G2 | `peel` 完整路径（onion 字节 + privkey + assoc_data）作为结构化 fuzz 输入 | 在已有 `fuzz_sphinx_packet` 基础上扩展（构造合法 privkey 用于 peel） |
| G3 | 旧版本 → 新版本 store 数据**迁移**路径未 fuzz（`migrate_archive/`） | 新增 fuzz target，输入 = 旧版 bincode bytes，调用 migration 链 |
| G4 | RPC JSON-RPC 参数（jsonrpsee）未在仓库 fuzz harness 中 | 新增 fuzz target，输入 = JSON 字符串 |

记入新增项 **AUDIT-INPUT-001-FOLLOWUP-A** 与并入 **AUDIT-INPUT-004 (store/migrate)**。

## 3. 解析入口的鲁棒性审查

### 3.1 ✅ 帧大小上限存在

`crates/fiber-lib/src/fiber/network.rs:126`：
```rust
pub const MAX_SERVICE_PROTOCOAL_DATA_SIZE: usize = 1024 * (128 + 2);   // 130 KB
```
- 在 tentacle `meta_builder().max_frame_length(MAX_SERVICE_PROTOCOAL_DATA_SIZE)` 处生效（network.rs:6041，gossip.rs:2640）。
- 任何超长帧在到达 `FiberMessage::from_molecule_slice` 之前已被 tentacle 拒绝 → 不存在"无限大消息触发 OOM"路径。

**Finding**：常量名拼写错误 `PROTOCOAL` (应为 `PROTOCOL`)。
**严重级别**：🟢 Low (cosmetic / 仅影响代码可读性)
**修复**：重命名为 `MAX_SERVICE_PROTOCOL_DATA_SIZE` + deprecate 旧别名（如果在公共 API 中暴露）。

### 3.2 ✅ Molecule 内部长度校验

`molecule 0.9` 在 `from_slice` 时检查 table header 与字段偏移，越界返回 `Err` 而非 panic。`fuzz_fiber_message` 一年多没有发现新 panic（参见 corpus），佐证此点。

### 3.3 ✅ Onion hop_data 长度头解析（onion.rs:486-515）

`len_with_u64_header` 使用 `checked_add(HOP_DATA_HEAD_LEN)`，并 `usize::try_from(u64)` 防止 64→size_t 截断。
`molecule_table_data_len` 拒绝 `len < NUMBER_SIZE` 的畸形头。
**Pass**。

### 3.4 ⚠️ Improvement — 子类型 `TryFrom<molecule_*>` 二阶解析

`from_molecule_slice` 在 `molecule::from_slice` 之后调用 `TryInto`。该层 TryFrom 实现散布在 `fiber/types.rs` 和 `fiber-types/src/*.rs`：

```rust
// fiber-lib/src/fiber/types.rs:933
pub fn from_molecule_slice(data: &[u8]) -> Result<Self, Error> {
    molecule_gossip::GossipMessage::from_slice(data)
        .map_err(Into::into)
        .and_then(TryInto::try_into)
}
```

`fuzz_molecule_types` 当前只覆盖 `TlcErr / NodeAnnouncement / ChannelAnnouncement / ChannelUpdate` 四个子类型的二阶 TryFrom。**其它子类型**（如 `OpenChannel`, `AcceptChannel`, `CommitmentSigned`, `RevokeAndAck`, `ChannelReady`, `Shutdown`, `TxSignatures`, `TxUpdate`, `TxComplete`, `AnnouncementSignatures`, `AddTlc`, `RemoveTlc`, `TlcAck`, `ReestablishChannel`, `ClosingSigned`）——
入口在 `FiberMessage::try_from(molecule_fiber::FiberMessage)`——
通过 `fuzz_fiber_message` 间接覆盖，但 `fuzz_fiber_message` 输入直接是 `FiberMessage` 整体字节，**覆盖路径较浅**（一旦 outer parse 失败就早退）。

**严重级别**：⚠️ Improvement (非 finding)
**建议**：在 `fuzz_molecule_types` 中扩展，对每个 fiber/gossip 子类型独立 fuzz：
```rust
if let Ok(mol) = molecule_fiber::AddTlc::from_slice(data) { let _ = AddTlc::try_from(mol); }
if let Ok(mol) = molecule_fiber::CommitmentSigned::from_slice(data) { ... }
// ... 全部 17 个子类型
```
理由：二阶 TryFrom 可能含 panic 路径（如 `expect`、`unwrap`、未检查切片）。

记入新增项 **AUDIT-INPUT-001-FOLLOWUP-B**。

### 3.5 ⚠️ Improvement — fuzz CI 集成

仓库 `crates/fiber-lib/fuzz/` 存在但 **CI 中未观察到定期 fuzz cron**（仅在 PR 触发？需确认）。

**建议**：
1. 增加 weekly GitHub Actions：`cargo +nightly fuzz run <target> -- -max_total_time=600`，每目标 10 分钟。
2. 使用 OSS-Fuzz / ClusterFuzzLite 持续运行（fiber 类项目适合）。
3. 把发现的回归输入纳入 `corpus/` 并随仓库分发。

记入 **AUDIT-INPUT-001-FOLLOWUP-C**。

## 4. 关键代码引用

```rust
// crates/fiber-lib/src/fiber/network.rs:126
pub const MAX_SERVICE_PROTOCOAL_DATA_SIZE: usize = 1024 * (128 + 2);
// 拼写：PROTOCOAL → PROTOCOL
```

```rust
// crates/fiber-lib/src/fiber/network.rs:6090
let msg = unwrap_or_return!(FiberMessage::from_molecule_slice(&data), "parse message");
```

## 5. 修复建议总结

| # | 严重级别 | 建议 |
|---|---|---|
| Low | 🟢 | 重命名 `MAX_SERVICE_PROTOCOAL_DATA_SIZE` → `MAX_SERVICE_PROTOCOL_DATA_SIZE` |
| Improvement | ⚠️ | 扩展 `fuzz_molecule_types` 覆盖所有 17 个 fiber/gossip 子类型 |
| Improvement | ⚠️ | CI 中集成 weekly fuzz cron（或采纳 OSS-Fuzz） |
| Improvement | ⚠️ | 增加 `TlcErrPacket::decode`、迁移路径、RPC JSON 参数三个 fuzz 目标 |

## 6. 结论

P2P 消息解析层 **整体稳健**：
- 帧上限存在并强制；
- Molecule 内部经过广泛测试；
- 已存在 9 个 fuzz 目标，覆盖率超出 Phase 0 评估。

主要改进空间在 **fuzz 深度（二阶 TryFrom 子类型）** 与 **CI 集成（持续 fuzz）**。无可利用漏洞发现。
