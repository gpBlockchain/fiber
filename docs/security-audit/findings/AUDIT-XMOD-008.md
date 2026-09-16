# AUDIT-XMOD-008 — Channel ↔ Gossip MuSig2 partial-signature 预校验不一致

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟠 **High**（channel-stuck DoS；3 条消息路径单 partial 攻击均可阻塞协议关键步骤） |
| 状态 | [!] 发现弱设计（静态可达，无 PoC） |
| 出处 | 本次跨模块审计补强；基于 "musig2 partial signature verification" 记忆扩展 |
| 关联代码 | `crates/fiber-lib/src/fiber/channel.rs:792-803` (`ClosingSigned`)<br>`crates/fiber-lib/src/fiber/channel.rs:4720-4737` (`AnnouncementSignatures`)<br>`crates/fiber-lib/src/fiber/channel.rs:6591-6598` (`ClosingSigned` 第二处)<br>`crates/fiber-lib/src/fiber/channel.rs:7301-7356` (`RevokeAndAck`)<br>`crates/fiber-lib/src/fiber/channel.rs:8339-8340` (`CommitmentSigned.verify_and_complete_tx` — **正确范本**) |
| 关联 finding | AUDIT-CRYPTO-001 (MuSig2 nonce 派生)、AUDIT-CRYPTO-004 (`verify_partial`)、AUDIT-LOGIC-007 (协作关闭 DoS 链)、AUDIT-MEM-001 (gossip 池) |

## 1. 现象

MuSig2 `aggregate_partial_signatures` 在 `musig2 0.2.4` 的语义仅校验**聚合后**签名能否对消息验证通过，**不**逐一校验每个 partial signature 自身的合法性。要保证"是哪一方提交了坏 partial"以及"不让坏 partial 把好 partial 也带进无效集合"，调用方必须在 aggregate 之前对每个对端 partial 显式调用 `verify_partial`。

`crates/fiber-lib/src/fiber/channel.rs` 中**共 5 处**会接收对端 partial 并聚合：

| 路径 | 行号 | 是否调用 `verify_partial` |
|---|---|---|
| `CommitmentSigned.verify_and_complete_tx` | 8339-8340 | ✅ **正确范本** |
| `ClosingSigned` (写 `remote_shutdown_info.signature`) | 792-803 | ❌ 直接存入待后续 aggregate |
| `ClosingSigned` (后续 build_shutdown_tx 用) | 6591-6598 | ❌ 直接 aggregate |
| `RevokeAndAck` (per-commitment revocation) | 7301-7356 | ❌ 直接 aggregate |
| `AnnouncementSignatures` (channel announcement) | 4720-4737 | ❌ 直接 aggregate，且 4732-4737 的 TODO 注释**已知该 bug**："we should ban remote peer if we fail to aggregate the signature since the error is caused by the wrong nonce" |

## 2. 与已有发现的区别

- **AUDIT-CRYPTO-001**：MuSig2 *nonce* 派生确定性（疑似 nonce-reuse，待 PoC）；本条与 nonce 派生无关，是**预校验缺失**。
- **AUDIT-CRYPTO-004.F2**：单独点出 `RevokeAndAck` 路径无 `verify_partial`；本条把它合并入"3 个共面问题"并升级为跨模块 (channel ↔ gossip ↔ network) 维度，因为 `AnnouncementSignatures` 的产物直接进 gossip 广播池。
- **AUDIT-LOGIC-007**：协作关闭 DoS 链；本条是"协作关闭 partial-sig 不预验"的密码学侧，与 LOGIC-007 三个 fee/script 校验问题正交。

## 3. 攻击场景

### 3.1 ClosingSigned partial 注入（DoS 协作关闭）

**前提**：通道双方已进入 Shutdown 协商。

1. 攻击者 (channel 对端) 收到我方 `Shutdown` 后回 `ClosingSigned { partial_signature = <随机 64B 或 nonce 错配的 partial> }`。
2. 我方 `handle_peer_message` (792-803) 不做 `verify_partial`，写 `remote_shutdown_info.signature = Some(garbage_partial)`。
3. 后续 `maybe_transfer_to_shutdown` 进入 build_shutdown_tx (6591-6598) `aggregate_partial_signatures` → 失败 / 或 aggregate 成功但 outer-sig verify 失败。
4. 此时状态机已记录 remote partial 已收到，但合法 partial 永远进不来 → **通道在 `ShuttingDown` 状态 stuck**。

**后果**：必须 force-close → CSV 锁定资金，与 LOGIC-007 复合 → P0 资金间损。

### 3.2 RevokeAndAck partial 注入（污染 revocation 链）

**前提**：双方持续推进 commitment number；攻击者 peer 在某一轮提交坏 partial。

1. 攻击者发 `RevokeAndAck { ..., new_commitment_partial_signature: <bad> }`。
2. 我方 (7301-7356) 直接 aggregate → 失败/坏 aggregate 写入 store。
3. revocation chain 中本应"按 commitment_number 严格递增"的 partial 被坏值替换 → **未来 watchtower 提交的 revocation tx 上链可能因签名错被链拒** → 反 cheat 防线断裂（与 LOGIC-003.F6 revocation_data 覆盖式协同）。

### 3.3 AnnouncementSignatures partial → gossip 污染

**前提**：通道开放 `is_public=true`，正在生成 channel_announcement。

1. 攻击者 peer 发 `AnnouncementSignatures { partial = <bad> }`。
2. 我方 (4720-4737) 直接 aggregate → 注释里的 TODO 已承认会失败但仅 `warn!()`，不 ban。
3. 攻击者**重复**发起开放 + 坏 partial → 周而复始消耗对端 nonce 状态 + 日志泛滥 + 永久阻塞该 channel 进入公开 gossip 池（被诚实 peer 看作不公开通道）。

**与 XMOD-001 协同**：被阻塞的诚实通道 + XMOD-001 的 channel_update slander → 攻击者既能阻止合法 channel 进入 gossip，又能给已存在通道注入伪造 update → 双向污染。

## 4. F-编号清单

| 编号 | 严重度 | 描述 |
|---|---|---|
| F1 | 🟠 High | `ClosingSigned` 两处接收对端 partial 直接存/聚合，无 `verify_partial` → 协作关闭 DoS（与 LOGIC-007 复合） |
| F2 | 🟠 High | `RevokeAndAck` partial 直接聚合 → 污染 revocation 链 → 反 cheat 防线（已记录在 CRYPTO-004.F2；本条强调 XMOD 维度） |
| F3 | 🟡 Medium | `AnnouncementSignatures` partial 直接聚合 + 仅 `warn!()` 不 ban → channel 公开化 DoS + gossip 污染入口 |
| F4 | 🟢 Low | 4720-4737 已有 TODO 注释明确知道该 bug 至今未修，工程债 |

## 5. 修复建议

**FOLLOWUP-A (🟠 High，3 处统一)**：以 `verify_and_complete_tx` (8339-8340) 为模板，在每处接收对端 partial 立即做 `verify_partial` 预校验：

```rust
// pseudocode pattern
let verify_ctx = self.get_<scope>_verify_context();
verify_ctx.verify(partial_signature, &message)?;  // ← 必加
// 之后才能 store / aggregate
```

涉及 3 处：`ClosingSigned` (792, 6591)、`RevokeAndAck` (7301)、`AnnouncementSignatures` (4720)。

**FOLLOWUP-B (🟠 High)**：`verify_partial` 失败时按 TODO 注释建议**主动 ban** 对端 peer（与 NET-001.F1 持久 ban list 协同；当前 NET-001.F1 也未实现 → 需先解一并补）。

**FOLLOWUP-C (🟡 Medium)**：把"verify_partial then aggregate"提炼成统一 helper `Channel::receive_remote_partial_or_ban<Scope>()`，使 5 个路径走同一代码路径，未来新增协议消息默认含校验。

## 6. 测试用例草案

1. **ClosingSigned bad-partial unit test**：双方完成 Shutdown 协商后，注入随机 64B partial，断言：
   - 状态机不离开 `ShuttingDown`
   - 我方主动 disconnect + ban remote peer
2. **RevokeAndAck bad-partial test**：第 N 次 commitment 提交坏 partial，断言下一次 revocation 不被污染，store 中 `RevocationData[N]` 仍保留前一轮正确值。
3. **AnnouncementSignatures bad-partial test**：构造坏 partial，断言 channel 不进入 gossip 池且对端被 ban。
4. **Cross-path regression**：5 处 partial 接收点的单测全部 require ban-on-bad-partial。

## 7. 引用与跟踪

- 与 AUDIT-CRYPTO-004.F2 (RevokeAndAck) 同源；本条独立提级为 XMOD 是因为 `AnnouncementSignatures` 横跨到 gossip 模块。
- 与 AUDIT-LOGIC-007 协作关闭 DoS 链复合 → 修复时同 PR 提交。
- 与 AUDIT-NET-001.F1 (持久 ban list) 必须协同：没有 ban list，verify_partial 失败也只能 disconnect，无法持久拒接，攻击者可重连。
- 4720-4737 TODO 注释是仓库内**已被开发者知晓**的 bug，但未提工单 — 本条 finding 同时作为正式跟踪条目。
