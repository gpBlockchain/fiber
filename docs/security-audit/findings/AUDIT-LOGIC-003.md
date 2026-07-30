# AUDIT-LOGIC-003 — Commitment 序号 & Revocation Key 管理

| 字段 | 值 |
|---|---|
| 维度 | DIM-LOGIC + DIM-FUNDS + DIM-DOS |
| 优先级 | 🔴 P0-Critical |
| 状态 | **[!] Medium × 2, Low × 2; 多项 Pass** |
| 审计会话 | S3 (2026-05-13) |
| 审计方法 | 序号语义跟踪 + 旧 commitment 攻击路径推演 + watchtower 流程审查 |

## 1. 范围

- `crates/fiber-types/src/channel.rs:308-346` — `CommitmentNumbers` 结构与 increment 接口
- `crates/fiber-lib/src/fiber/channel.rs:5524-5640` — `send_revoke_and_ack_message`
- `channel.rs:6841-6937` — `verify_commitment_signed_and_send_ack`
- `channel.rs:7270-7407` — `append_remote_commitment_point` + `handle_revoke_and_ack_peer_message`
- `channel.rs:7409-7587` — `handle_reestablish_channel_message`
- `crates/fiber-lib/src/watchtower/actor.rs:230-330, 395-490` — 链上 commitment 监控 + revocation tx 构造

## 2. 协议背景

Fiber 复用 LN 风格 commitment 协议：双方各自维护自己的 commitment tx 链（local / remote）。每轮：
1. A 发送 `CommitmentSigned`（包含对 B 的 commitment 签名 + 下一轮 nonce）；
2. B 验证并发送 `RevokeAndAck`（包含对自己上一轮 commitment 的 revocation 部分签名 + 下一个 per-commitment-point + 下一个 revocation-nonce）；
3. revocation 签名一旦释放，B 的旧 commitment 就被"撤销"——若 B 试图把旧 commitment 上链，A 可用 revocation 签名抢走全部资金。

**Watchtower 职责**：监控链上是否出现已被撤销的 commitment tx，若发现立即广播 revocation tx。

## 3. Commitment Number 管理

### 3.1 状态

`CommitmentNumbers { local: u64, remote: u64 }` (types/channel.rs:311-315)

- `local`：本方的 commitment 号（被对端签名以保护本方）；
- `remote`：对端的 commitment 号（被本方签名以保护对端）；
- 初始为 0；`increment_*` 仅 +1，无溢出检查。

### 3.2 增长点（grep 全仓库）

```
channel.rs:594   handle_peer_message::TxComplete (collaboration done)        → local++
channel.rs:3037  enter_awaiting_external_funding                              → local++
channel.rs:5613  send_revoke_and_ack_message (outgoing RevokeAndAck)         → remote++
channel.rs:6834  handle_tx_collaboration_msg::TxComplete (peer side)        → remote++
channel.rs:7108  on_new_channel_ready                                        → local++ remote++
channel.rs:7367  handle_revoke_and_ack_peer_message (incoming RevokeAndAck) → local++
```

### 3.3 Pass — 序号一致性

通过逐路径分析：
- 通道激活时 `on_new_channel_ready` 同步两侧到 1；
- 之后每轮一进一出严格对称：本方发 RevokeAndAck → remote++；收到 RevokeAndAck → local++；
- `handle_reestablish_channel_message:7466` 校验 `abs_diff(peer_local_cn, my_remote_cn) <= 1 && abs_diff(peer_remote_cn, my_local_cn) <= 1`，拒绝乱序 reestablish。

### 3.4 F1 (🟡 Medium) — `u64` 序号无显式上限/溢出检查

**位置**：`types/channel.rs:339-345`
```rust
pub fn increment_local(&mut self) { self.local += 1; }
pub fn increment_remote(&mut self) { self.remote += 1; }
```

- u64 溢出在 release 模式下 wrap → 序号从 u64::MAX 回到 0；
- 实际触达需 ≈ 10^19 次 commitment 轮，**实际不可达**；
- **但** revocation_data 通过 `to_be_bytes()` 嵌入 commitment lock args（参见 channel.rs:7343），后续 watchtower 比较 `revocation_data.commitment_number >= commitment_number`（actor.rs:286-289）—— 若曾发生过 wrap，比较失效，旧 commitment 不会被惩罚。

**严重级别**：Medium（理论性）。
**建议**：在 `increment_*` 中加 `checked_add(1)`，溢出时返回错误并立即强制 close 通道（cooperative 优先）。代价极小，消除潜在但难以触达的风险。

### 3.5 F2 (🟢 Low) — `get_remote_commitment_number() - 1` 下溢风险（理论性）

**位置**：`channel.rs:5590` 与 `7339`

```rust
let commitment_number = self.get_remote_commitment_number() - 1;     // line 5590
let commitment_number = self.get_local_commitment_number() - 1;      // line 7339
```

- `send_revoke_and_ack_message(false)` 仅在 `ChannelReady` / `PendingShutdown` 状态被调用（`verify_commitment_signed_and_send_ack:6930-6931`）；
- 进入 `ChannelReady` 前 `on_new_channel_ready` 已把两侧都增至 1，所以 `0 - 1` 不会发生；
- **但** 攻击者控制远端可在 `AwaitingTxSignatures` 状态下做奇怪事？审计该路径未发现可达 `send_revoke_and_ack_message` 且 remote==0 的入口；
- `handle_revoke_and_ack_peer_message:7339` 同样依赖前置 increment。

**严重级别**：Low（当前路径分析下不可达，但缺少防御性 `checked_sub`）。
**建议**：用 `checked_sub(1).ok_or(InvalidState(...))?` 替换裸 `-1`。

## 4. Revocation Data 与 Watchtower

### 4.1 RevocationData 构造（`handle_revoke_and_ack_peer_message:7312-7363`）

```rust
let commitment_number = self.get_local_commitment_number() - 1;    // 本方刚被签的"旧" commitment 号
let commitment_lock_script_args = [
    &blake2b_256(x_only_aggregated_pubkey)[0..20],
    self.get_delay_epoch_as_lock_args_bytes().as_slice(),
    commitment_number.to_be_bytes().as_slice(),
].concat();
let message = blake2b_256([output.as_slice(), output_data.as_slice(),
                            commitment_lock_script_args.as_slice()].concat());
let aggregated_signature = sign_ctx.sign_and_aggregate(message.as_slice(), revocation_partial_signature)?;
RevocationData { commitment_number, aggregated_signature, output, output_data }
```

- `commitment_number` 嵌入 args 是惩罚签名的"密码学绑定"；
- `aggregated_signature` 是 MuSig2 部分签名聚合的结果（由本节点 + peer 发来的 `revocation_partial_signature` 组合）。

### 4.2 Pass — Notify 流转

```rust
self.network().send_message(NetworkActorMessage::new_notification(
    NetworkServiceEvent::RevokeAndAckReceived(... revocation_data, settlement_data),
))
```
→ `event_handler.rs:75-81` → watchtower `UpdateRevocation` → `watchtower::store::update_revocation`

**Pass**：通知是 actor 消息（非 RPC），可靠性由 ractor 保证；watchtower store 是持久化的（RocksDB）。

### 4.3 F3 (🟡 Medium) — Watchtower 解析 commitment lock args 缺少长度检查 → panic-DoS

**位置**：`watchtower/actor.rs:267-275`

```rust
let lock_args = commitment_lock.args().raw_data();
let pub_key_hash: [u8; 20] = lock_args[0..20]
    .try_into()
    .expect("checked length");                       // ← 注释 "checked length" 不真实
let commitment_number = u64::from_be_bytes(
    lock_args[28..36]
        .try_into()
        .expect("u64 from slice"),
);
```

**前置检查**仅有 `tx.raw().outputs().len() == 1`（line 258），**没有任何 `lock_args.len() >= 36` 校验**。

**攻击路径**：
- 协作关闭 (`Shutdown` + `ClosingSigned`) 也是消耗 funding 输出的 1-output 交易；其输出的 lock 是双方协商的 `close_script`，可以是**任意 lock 脚本**（用户自定义关闭地址）；
- 如果 peer 在协作关闭谈判中给出一个 `close_script.args.len() < 36` 的脚本（例如 20 字节地址，CKB 中常见）→ 协作关闭 tx 上链后；
- Watchtower 定期扫描（`watchtower/actor.rs:230` 的循环）发现这笔 tx；
- 进入 `lock_args[28..36]` 越界 → **`.expect("u64 from slice")` panic** → watchtower actor 死亡 → 该节点全部通道失去链上保护（任何后续旧 commitment 攻击不会被处理）。

**严重级别**：🟡 Medium-High
- 触达成本极低（peer 在自己控制的关闭脚本上做手脚即可）；
- 一次 panic 危及节点所有通道的安全；
- panic 路径明确，无需复杂条件。

**注释明显误导**：`expect("checked length")` 暗示已经 checked，但实际未 check。

**建议**：
```rust
if lock_args.len() < 36 {
    debug!("Skipping non-commitment-lock tx (lock_args too short): {:?}", lock_args.len());
    continue;
}
```
或者：在解析前先用 `channel_data_funding_lock_args_layout` 校验脚本与已知 commitment-lock template 匹配。

**关联**：与 AUDIT-LOGIC-001.F5（`ClosingSigned` 不校验状态）联动 —— 攻击者甚至可不经合法 close 流程，只要能构造一笔满足 funding multisig 的 spending tx 即可。但 funding multisig 需要双方签名，所以仅在协作关闭路径可达；非协作关闭仍然是 commitment-lock 格式。

### 4.4 F4 (🟢 Low) — Watchtower 仅查询最近 1 笔交易（`limit=1u32`）

**位置**：`watchtower/actor.rs:246`

```rust
match ckb_client.get_transactions(search_key, Order::Desc, 1u32.into(), None) {
```

只取最新 1 笔。理论上每个 funding output 只能被一笔交易消耗（CKB UTXO 模型），因此 `limit=1` 是充分的。

**但**：
- 若 CKB indexer 因重组、暂时不一致而返回**错误的最新结果**（例如重组期间的 stale view），watchtower 可能错过短窗口内的实际消耗 tx；
- 没有 retry / 等待 confirmation 逻辑（仅检查 `tx_status.status == Committed`）；
- 没有跨多次轮询的"我之前看到过哪些 commitment tx"持久化记忆。

**严重级别**：🟢 Low（实际由 CKB 共识层 + indexer 保证，触达概率低）。
**建议**：增加 confirmation 阈值（如 6 块）后再处理；保留近期看到的 tx hash 集合用于去重。

### 4.5 Pass — Commitment Number 对比逻辑

```rust
// actor.rs:286-289
Some(revocation_data)
    if revocation_data.commitment_number >= commitment_number
```

- `revocation_data.commitment_number` = 本方刚撤销的本方分配 commitment 号；
- `commitment_number` = 从链上 commitment tx 的 lock args 解出的同一序号空间值（嵌入 args 的标号，对应 `send_revoke_and_ack_message:5590` 处 `get_remote_commitment_number() - 1`）。

二者引用同一序号空间，`>=` 比较语义正确。**Pass**。

### 4.6 F5 (🟢 Low) — Watchtower 中 `channel_data.revocation_data` 仅一份，无历史

**位置**：`watchtower/store.rs:32`，`watchtower/actor.rs:285`，`store_impl/mod.rs:1207-1209`

```rust
pub fn update_revocation(... revocation_data: RevocationData ...) {
    channel_data.revocation_data = Some(revocation_data);      // 覆盖
}
```

`update_revocation` 直接**覆盖**：同一时刻 watchtower 只持有"最新一轮"的 revocation data。F6 详细描述了由此引发的更严重问题。



**位置**：`watchtower/store.rs:30-50`，`watchtower/actor.rs:285-330`

**机制**：
- `update_revocation`（store_impl/mod.rs:1207-1209）以**覆盖**方式写入：`channel_data.revocation_data = Some(revocation_data)`；
- 同一通道在 store 中始终只保留一份 revocation_data（最新一轮）；
- Watchtower 扫描到链上 commitment 时，用 `>=` 判定是否启动惩罚（actor.rs:286-289），随后将持有的 revocation_data 传给 `build_revocation_tx`。

**问题**：每一轮 revocation 的 MuSig2 聚合签名只对该轮的 `commitment_lock_script_args`（含该轮 `commitment_number`）有效（参见构造签名的 message 拼接：channel.rs:7347-7354）。如果 peer 上链的是**更早**的旧 commitment（号 = N-K, K>1），本方的最新 revocation_data 对应的是号 N-1，签名 message 不匹配 → 链上 commitment lock 脚本验证 revocation tx 时会拒绝。

**为何 peer 能上链更早的旧 commitment**：
- peer 历史上的每一轮都收到过本方对那一轮 commitment 的有效 funding multisig 签名（CommitmentSigned 消息内）；
- 这些 commitment txs 都"链下合法签名完毕"，peer 可以挑选任何一轮在自己最有利时上链。

**结论**：**watchtower 仅能可靠惩罚 peer 上链"上一轮被撤销"的 commitment；peer 选择性上链更早的某一轮，watchtower 没有对应轮的 revocation 签名，惩罚 tx 无法构造。**

这与 BOLT-03/05 的 LN 设计不同：LN 用 per-commitment-secret 哈希链，从最新 secret 反推所有更早 secret，watchtower 只需存最新 secret。Fiber 用 MuSig2 部分签名，**每轮独立，无哈希链**。

**待动态验证**：
1. 链上 commitment lock 合约（项目方的 [commitment-lock](https://github.com/nervosnetwork/fiber-scripts) 合约源码）是否对 lock_args 中 commitment_number 与 witness 中 commitment_number 做绑定比对？
2. 若链上脚本不绑定 commitment_number（仅检查 aggregated_signature 对当前 cell 数据有效），则任意一轮的 revocation_data 都能打任意旧 commitment——但那样 message 拼接里嵌入 commitment_number 又有何意义？
3. 若链上脚本绑定，则本节点必须为每一轮 commitment 存储独立的 revocation_data。

**严重级别**：🟡 Medium（资金损失 + 需要进一步链下合约验证）。

**建议**：
- 在 watchtower store 中将 revocation_data 改为 `BTreeMap<commitment_number, RevocationData>` 或 `Vec<RevocationData>`；
- `update_revocation` 改为 `push` 语义；
- 扫描时按链上 commitment_number 精确查找对应轮的 revocation_data；
- 找不到则 warn 并尝试 fallback。

记入新增项 **AUDIT-LOGIC-003-FOLLOWUP-A**：动态验证 commitment-lock 合约的 commitment_number 绑定语义；如果确认是漏洞，按上述建议修复。

## 5. Reestablish 路径下的旧 commitment / nonce 处理

### 5.1 Pass — `abs_diff <= 1` 边界

`handle_reestablish_channel_message:7466-7472`：拒绝 |peer.cn - my.cn| > 1 的 reestablish 请求。**Pass**。

### 5.2 Pass — last_revoke_ack_msg 缓存重发

`send_revoke_and_ack_message:5529-5549`：reestablish 时使用缓存的 RevokeAndAck（而非重新签名），避免 nonce 复用风险。**Pass**。

### 5.3 Pass — nonce 双轨

`remote_revocation_nonce_for_send` / `_for_verify` 双轨切换（channel.rs:7386-7393, 5622-5628）：避免 reestablish 时新旧 nonce 混淆。**Pass**（不过设计较复杂，建议有图示注释）。

## 6. 修复建议总结

| # | 严重级别 | 建议 |
|---|---|---|
| F3 | 🟡 Medium | watchtower `lock_args[28..36]` 增加显式长度守卫；修正误导注释 `"checked length"` |
| F6 | 🟡 Medium | watchtower revocation_data 改为 BTreeMap，按 commitment_number 索引；**先动态验证链上合约绑定** |
| F1 | 🟡 Medium | `increment_local/remote` 使用 `checked_add`，溢出时强制 close 通道 |
| F2 | 🟢 Low | `get_*_commitment_number() - 1` 用 `checked_sub` |
| F4 | 🟢 Low | watchtower 增加 confirmation 阈值与历史 tx 去重缓存 |

## 7. 结论

通道协议层的 commitment 序号管理逻辑**整体正确**：序号增长对称、reestablish 边界严格、缓存 RevokeAndAck 避免 nonce 复用。

**主要风险在 watchtower 层**：
- **F3** 是直接可达的 panic-DoS（peer 通过自定义 close_script 触发），等级 Medium。
- **F6** 是潜在的资金损失风险，需要先动态验证链上 commitment-lock 合约是否绑定 commitment_number；如绑定则该缺陷成立，应改造 watchtower 存储多轮 revocation_data。

F1 (u64 溢出) 与 F2 (- 1 下溢) 为防御性编程改进；F4 (limit=1 查询) 为运行环境鲁棒性提升。

Follow-ups：
- **AUDIT-LOGIC-003-FOLLOWUP-A** — 动态验证链上 commitment-lock 合约 commitment_number 绑定行为
- **AUDIT-LOGIC-003-FOLLOWUP-B** — 编写 PoC：peer 关闭脚本提供 < 36 字节 lock_args，观测 watchtower 是否 panic
