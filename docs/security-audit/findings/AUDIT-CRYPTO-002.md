# AUDIT-CRYPTO-002 — Sphinx 洋葱包解封与回放保护

| 字段 | 值 |
|---|---|
| 维度 | DIM-CRYPTO + DIM-ERRINFO |
| 优先级 | 🔴 P0-Critical |
| 状态 | **[!] Medium × 1, Low × 1, Info × 1; Pass × 4** |
| 审计会话 | S2 (2026-05-13) |
| 审计方法 | 正向源码逻辑审查 + 逆向 oracle / replay 推演 + 现有 fuzz 覆盖度评估 |

## 1. 范围

- `crates/fiber-types/src/onion.rs` — 洋葱包封装、`PaymentOnionPacket`、`TlcErrPacket` 错误包
- `crates/fiber-lib/src/fiber/channel.rs` — TLC 添加路径上的 `peel`（外层 + trampoline 内层）、`apply_add_tlc_operation`
- `crates/fiber-lib/src/fiber/network.rs:2960+` — `handle_send_onion_packet_command` 转发路径、`forward_trampoline_packet`
- 上游依赖 `fiber-sphinx 2.3`（项目方自维护）

## 2. 分析

### 2.1 主路径调用图

```
peer P2P (AddTlc)
  → handle_add_tlc_peer_message            (channel.rs:1575)  仅记录 TLC，不 peel
  → ... CommitmentSigned ack ...
  → apply_add_tlc_operation                (channel.rs:1279)
      onion_packet.peel(privkey, Some(payment_hash), SECP256K1)  ←— 关键
      → apply_add_tlc_operation_with_peeled_onion_packet
          [is_trampoline] TrampolineOnionPacket::new(...).peel(...)
          [else last]      try_to_settle_down_tlc
          [forward]        ProcessTlcCommand::ForwardTlc → handle_send_onion_packet_command
```

### 2.2 关键观察 (Pass)

#### ✅ assoc_data 绑定 payment_hash
所有 `.peel(...)` 调用点 (channel.rs:1294, 1367; network.rs:3068) 使用：
```rust
.peel(state.private_key(), Some(payment_hash.as_ref()), SECP256K1)
```
fiber-sphinx 将 `assoc_data` 混入 HMAC 验证 → 攻击者无法将一个洋葱包用于不同 payment_hash。**等价于 BOLT-04 §"associated_data" 要求**。

#### ✅ Peel 错误统一映射 (channel.rs:830-836)
```rust
ProcessingChannelError::PeelingOnionPacketError(_) => TlcErrorCode::InvalidOnionPayload,
```
所有底层失败子类型（`InvalidHopData` / `UnknownVersion` / `Sphinx(HMAC fail)` / `Sphinx(version)`）压缩到单一 TlcErrorCode → **上游 peer 无法通过错误码区分失败原因**，不构成 oracle 泄露。`PeelingOnionPacketError(String)` 字段仅用于本地日志。

#### ✅ Trampoline 内层 peel 失败映射 (network.rs:3068-3071)
```rust
.map_err(|_| TlcErr::new_node_fail(TlcErrorCode::TemporaryNodeFailure, ...))?
```
丢弃具体错误信息，统一返回 `TemporaryNodeFailure`，与 Lightning trampoline 草案一致。

#### ✅ 错误包反向传播 (`TlcErrPacket::backward`)
中间节点用本跳 `shared_secret` 对 `OnionErrorPacket` 进行 xor 流加密反向传递（onion.rs:60-70）。`is_plaintext()` 检查头 32 字节是否全零 → 已加密时执行 xor，未加密时透传。逻辑符合 BOLT-04 §"Returning Errors"。

### 2.3 Findings

#### F1 (🟡 Medium) — 缺少应用层 shared-secret / 临时公钥 replay 缓存

BOLT-04 §"Receiving onions" 和 fiber 自身的 `docs/specs/payment-invoice.md` 隐含要求：节点应该跟踪近期见过的 (临时公钥 / shared_secret) 集合，并拒绝重复 onion，以避免下面的攻击：

> 攻击者在同一节点的两个不同入站通道上重放完全相同的 AddTlc。本节点会分别 peel、分别尝试 forward；攻击者获得"是否能成功 forward"的二元 oracle，间接推断本节点路由策略 / 流动性 / preimage 状态。

**当前防护**：
- 同通道内 `check_insert_tlc` (channel.rs:5784) 严格按 `next_tlc_id` 序列号顺序接收 → 同通道内**完全相同字节序列**的 AddTlc 不会被两次接受。
- 但 **跨通道**（攻击者控制两个 peer，与本节点各开一条通道）下未见应用层去重；同一 `payment_hash` 在两条入站通道上各到达一次会被分别处理，shared_secret 相同（因为 onion 的临时公钥相同）。
- assoc_data 绑定 payment_hash 阻止"洋葱+不同 payment_hash"组合，但不能阻止"洋葱+相同 payment_hash 重放"。

**关联代码**：
- `apply_add_tlc_operation_with_peeled_onion_packet` (channel.rs:1333) — 无去重检查
- `forward_trampoline_packet` (network.rs:3042) — 无去重检查

**建议**：
- 增加 `seen_onion_ephemeral_keys: LruCache<PublicKey, Instant>`（按 onion 临时公钥去重），TTL = 最大 TLC 到期窗口。
- 或 `(payment_hash, shared_secret) → deadline` 持久化集合。
- 命中重复时返回 `TlcErrorCode::InvalidOnionPayload`（不要透露"已见过"），等价于普通解封失败。

**严重级别说明**：归 Medium 因为：
- 实际利用需攻击者已与本节点建立多条通道（成本高）；
- 但其 oracle 价值大（可探测路由 / preimage / payment 路径）；
- 同时违反 BOLT-04 推荐。建议在 dynamic-validation 中确认是否可被实际触达。

记入新增项 **AUDIT-CRYPTO-002-FOLLOWUP-A**。

#### F2 (🟢 Low) — `TlcErrPacket::decode` 时间侧信道在 success / fail 路径不对称

`crates/fiber-types/src/onion.rs:136-145`：

```rust
OnionErrorPacket::from_bytes(self.onion_packet.clone())
    .parse(hops_public_keys, session_key, TlcErr::deserialize)
    .map(|(error, hop_index)| {
        for _ in hop_index..ERROR_DECODING_PASSES {        // 仅在 Some 分支执行
            OnionErrorPacket::from_bytes(self.onion_packet.clone())
                .xor_cipher_stream(&NO_SHARED_SECRET);
        }
        error
    })
```

注释声明意图："Always decrypting 27 times so the erring node cannot learn its relative position in the route by performing a timing analysis."

**问题**：
1. **失败分支无填充**：`.parse(...) → None` 时（无任何 hop 的 HMAC 匹配）函数直接返回 `None`，跳过填充循环 → 失败与成功的总时间差异显著。
2. **零密钥填充**：填充循环使用 `&NO_SHARED_SECRET`（全零密钥）xor。若 fiber-sphinx 内部对零密钥有 fast-path（例如 LLVM 把零字节 xor 优化掉），实际工作量 ≠ 真实 hop 的 xor 工作量 → 填充失效。
3. **填充范围错误方向**：`for _ in hop_index..ERROR_DECODING_PASSES` —— 若 `hop_index >= 27`（理论上不应发生但路径长度未硬上限），范围为空。

**威胁模型局限**：注释提到的 "if the sender were to retry the same route multiple times" 是相对弱的旁路（攻击者必须是路径上某中间节点，能观察到 sender 重试间隔），所以实际严重级别 Low；但既然代码已经尝试做填充，应该做对。

**建议**：
1. 把填充移到 `parse` 之后，无论 Some/None 都执行；填充次数 = `ERROR_DECODING_PASSES - parse_passes_done`。
2. 用真实非零密钥（哪怕是 `[1u8; 32]` 或随机 / `subtle::ConstantTimeEq`-级别构造）执行 xor。
3. 用 `subtle` crate 显式标注关键比较为恒定时间。
4. 加 `path_hops <= ERROR_DECODING_PASSES` 静态断言或运行时校验。

#### F3 (ℹ️ Info) — 依赖 `fiber-sphinx 2.3` 内部 HMAC 恒定时间 / 临时公钥构造

本审计未对 `fiber-sphinx 2.3` 源码（项目自维护 crate）进行字节级审查，关键属性需上游确认：

- `OnionPacket::peel` 中的 HMAC tag 比较是否恒定时间（应使用 `subtle::ConstantTimeEq`）
- `shared_secret(seckey, ephemeral_pubkey)` 派生是否抗侧信道（secp256k1 ECDH）
- `OnionErrorPacket::parse` 是否对每条 hop 执行恒定数量工作

记入 **AUDIT-CRYPTO-002-FOLLOWUP-B**：单独立项 `fiber-sphinx` 源码审计；或，至少：编写微基准测试，统计 success @ hop_k 与 fail 的时间分布，置信区间 < CPU 噪声方差。

### 2.4 Pass / 不构成 finding

- `pack_len_prefixed` / `unpack_len_prefixed_payload` / `molecule_table_data_len` (`onion.rs:471-515`)：使用 `checked_add`、`usize::try_from(u64)`、`< NUMBER_SIZE` 下界检查；不可触发越界 panic。
- `is_plaintext` (`onion.rs:54`) 使用 `>= 32` 长度检查后再切片，安全。
- `ProcessingChannelErrorWithSharedSecret` 模式（channel.rs:4351）确保 peel 失败前的"未知 shared_secret"分支用 `NO_SHARED_SECRET` 包装错误，与上游不同（明文回传），符合 spec。

## 3. 现有测试覆盖

- `crates/fiber-lib/fuzz/fuzz_targets/fuzz_sphinx_packet.rs` — fuzz `PaymentOnionPacket::into_sphinx_onion_packet`（前置解析）✓
- `fuzz_onion_packet.rs` — fuzz `PaymentHopData::deserialize` / `TrampolineHopPayload::deserialize` + roundtrip ✓
- `tests/payment.rs`、`tests/mpp.rs`、`tests/trampoline.rs` — 多跳 happy-path、部分失败路径 ✓

**缺口**：
- 无对抗性测试：cross-channel onion 重放（F1）。
- 无 timing 测试：`TlcErrPacket::decode` 在不同 hop_index 下的时间分布（F2）。
- 无 fuzz：`TlcErrPacket::decode`（输入 `onion_packet` 字节 + 任意 `hops_public_keys`）。

记入 **AUDIT-CRYPTO-002-FOLLOWUP-C**：fuzz 目标补全。

## 4. 关键代码引用

```rust
// crates/fiber-lib/src/fiber/channel.rs:1290-1301
let peeled = onion_packet
    .peel(
        state.private_key(),
        Some(add_tlc.payment_hash.as_ref()),  // assoc_data 绑定 payment_hash ✓
        SECP256K1,
    )
    .map_err(|err| ProcessingChannelError::PeelingOnionPacketError(err.to_string()))
    .map_err(ProcessingChannelError::without_shared_secret)?;
let shared_secret = peeled.shared_secret;
self.apply_add_tlc_operation_with_peeled_onion_packet(state, add_tlc, peeled)
    .map_err(move |err| err.with_shared_secret(shared_secret))?
```

```rust
// crates/fiber-lib/src/fiber/channel.rs:835-836
ProcessingChannelError::PeelingOnionPacketError(_) => TlcErrorCode::InvalidOnionPayload,
```

## 5. 修复建议总结

| # | 严重级别 | 建议 |
|---|---|---|
| F1 | 🟡 Medium | 在 `apply_add_tlc_operation` 或网络层加入 `seen_onion_ephemeral_keys` LRU 缓存；命中时返回 `InvalidOnionPayload` |
| F2 | 🟢 Low | 重写 `TlcErrPacket::decode` 填充逻辑：填充对 Some/None 对称；用非零密钥；使用 `subtle` 显式恒定时间原语 |
| F3 | ℹ️ Info | 单独审计 `fiber-sphinx 2.3` 源码 (AUDIT-CRYPTO-002-FOLLOWUP-B)；编写微基准统计时间分布 |

## 6. 结论

整体设计上风险**可控**：assoc_data 绑定、统一错误码、安全切片处理均符合预期。最值得跟进的是 F1（cross-channel onion 重放）的 dynamic validation 与 F3（fiber-sphinx 上游审计）。F2 是已知（注释承认）但实现不完美的 mitigation，建议尽快修补。
