# AUDIT-CRYPTO-001 — MuSig2 协同签名实现与 nonce 管理

| 字段 | 值 |
|---|---|
| 维度 | DIM-CRYPTO |
| 优先级 | 🔴 P0-Critical |
| 状态 | **[?] 疑似 High / Critical — 需动态验证** |
| 审计会话 | S1 (2026-05-13) |
| 审计方法 | 正向源码逻辑审查 (SKILL §三.A) + 逆向攻击思维 (§三.B) + 上下文关联 (§三.C) |

## 1. 范围

MuSig2 协同签名用于本仓库中三类场景：

1. **Funding 交易花费（commitment tx 共同签名）** — 决定通道资金的真正归属。
2. **Revocation 交易共同签名** — 旧 commitment 的废止。
3. **Channel announcement** — 公开通道的真实性证明（节点 1 + 节点 2 + 聚合签名）。

入口：

- `crates/fiber-types/src/channel.rs:1240` — `musig2_base_nonce = key_derive(tlc_base_key, b"musig nocne")` (the literal `"nocne"` is a pre-existing typo in source code, quoted verbatim here for accuracy — changing it would break key-derivation backwards-compatibility)
- `crates/fiber-types/src/channel.rs:1279` — `InMemorySigner::derive_musig2_nonce(commitment_number, context)`
- `crates/fiber-lib/src/fiber/channel.rs:6019` — `get_channel_announcement_musig2_secnonce()`
- `crates/fiber-lib/src/fiber/channel.rs:7952-7986` — `get_funding_sign_context()`, `get_revoke_sign_context()`

## 2. 分析过程

### 2.1 Nonce 派生路径

```rust
// crates/fiber-types/src/channel.rs:1279-1286
pub fn derive_musig2_nonce(&self, commitment_number: u64, context: Musig2Context) -> SecNonce {
    let commitment_point = self.get_commitment_point(commitment_number);
    let seckey = derive_private_key(&self.musig2_base_nonce, &commitment_point);

    SecNonceBuilder::new(seckey.as_ref())
        .with_extra_input(&context.to_string())   // 仅静态字符串 "COMMITMENT" / "REVOKE"
        .build()
}
```

```rust
// crates/fiber-lib/src/fiber/channel.rs:6019-6025
pub fn get_channel_announcement_musig2_secnonce(&self) -> SecNonce {
    let seckey = blake2b_hash_with_salt(
        self.signer.musig2_base_nonce.as_ref(),
        b"channel_announcement".as_slice(),
    );
    SecNonce::build(seckey).build()                // 完全确定性，连 context 字符串都没有
}
```

**关键观察**：

1. 两条派生路径都是**完全确定性**的，输入只有 `(musig2_base_nonce, commitment_point / 静态盐)`。
2. `SecNonceBuilder` 在 `musig2 0.2.4` 中支持以下混合输入（用于 BIP-327 推荐的 deterministic nonce 派生）：
   - `with_seckey(...)` — 签名密钥本身
   - `with_message(...)` — 即将签名的 message
   - `with_aggregated_pubkey(...)` — 聚合公钥
   - `with_extra_input(...)` — 附加随机熵
   都未被使用（仅 commitment 路径混入静态 context 字符串）。
3. 没有任何随机源（CSPRNG）参与。
4. 没有任何持久化"已用 nonce / 已签 message"反重放表。

### 2.2 不变量需求

只有当下列**全部**成立时，确定性 nonce 才是安全的：

- **I1**：对于每个 `(commitment_number, context)`，本节点至多用同一个 secnonce 签名**一个** message。
- **I2**：本节点的 secnonce 不会与对端的 secnonce 在任何聚合上下文中"等价"（MuSig2 BIP-327 已通过聚合 nonce 处理）。

违反 I1 ⇒ Schnorr-MuSig2 nonce-reuse ⇒ **funding 私钥可被被动 / 主动攻击者从两条 partial signature 中恢复**。后果：资金被盗。

### 2.3 攻击/异常路径推演（逆向）

#### 路径 A：通道重连 / 重传后改 message

`get_funding_sign_context()` (`channel.rs:7956`) 在每次需要签 commitment 时调用：

```rust
let secnonce = self.signer.derive_musig2_nonce(
    self.get_local_commitment_number(),
    Musig2Context::Commitment,
);
```

`local_commitment_number` 在成功 ack 后才 ++。
攻击者控制的 peer 在 reestablish 流程下，可能：
- 让本地在同一 `local_commitment_number` 上先签 message A，然后（在 ack 丢失/状态回滚时）再次构造 message A'（例如更改 TLC 集合）让本地再签。
- 若 message A ≠ message A'，且 secnonce 完全相同 → **funding key 被恢复**。

`crates/fiber-lib/src/fiber/channel.rs:4638` `restore_missing_revocation_send_nonce` 等"重建丢失 nonce"的逻辑暗示了已有重传/丢失场景的工程现实。

> 是否实际可达需要：(a) 仔细检查 `local_commitment_number` 推进点是否严格"先持久化、再发布、再 ++"；(b) 构造对抗 peer 的端到端测试。

记录为新 TODO 项 **AUDIT-CRYPTO-001-FOLLOWUP-A**。

#### 路径 B：Channel announcement 重签

`get_channel_announcement_musig2_secnonce` **不带 commitment_number**——纯静态。
若 `message_to_sign`（即 `ChannelAnnouncement` 头部字段）发生过任何变动（capacity 重算、`channel_outpoint` 矫正、UDT 类型脚本变更等）并触发"重签 announcement"，且本地缓存（`local_channel_announcement_signature`，`channel.rs:5395`）被某条路径无效化，则同一 secnonce 会被复用到不同 message 上 → **funding key 泄露**。

幸运的是，第 5390-5396 行的缓存"先看是否已有"返回机制提供了一层防护。但缓存的不变量在以下情况下可能被破坏：
- 反序列化恢复时若 `local_channel_announcement_signature` 字段为 `None` 但 announcement 已对外发送
- 任何 `public_channel_state_mut()` 路径意外地 clear 该字段

记录为 **AUDIT-CRYPTO-001-FOLLOWUP-B**。

#### 路径 C：Partial signature 验证

未观察到聚合前对**远端** partial signature 调用 `verify_partial(...)` 的代码——`aggregate_partial_signatures(...)` 在 `musig2 0.2.4` 内部会做基本校验，但攻击者提交无效 partial sig 仅会导致聚合失败（DoS），不会泄露 key。**此项较低风险**。

### 2.4 现有测试覆盖

- `crates/fiber-lib/src/fiber/tests/channel.rs` 大量 happy-path 测试。
- `channel_restart_stress.rs` / `peer_reconnect_stress.rs` 验证基础重连，但**未覆盖对抗性场景**：同 commitment_number 下故意推送两条不同消息。
- 无关于 announcement nonce 复用的单测。

## 3. 发现

| # | 描述 | 严重级别 | 影响 |
|---|---|---|---|
| F1 | MuSig2 nonce 完全确定性派生（无 message / 聚合公钥 / 随机熵） | 🔴 设计性高风险 | 一旦上层路径在同 (nonce_seed, msg) 不成立，funding 私钥泄露 → 资金被盗 |
| F2 | Channel announcement secnonce 连 commitment_number 都不含 — 唯一区分是 `b"channel_announcement"` 静态盐 | 🟠 H | 缓存若被绕过，重签即泄露 funding key |
| F3 | 缺少"已签 message 摘要 → 已用 nonce"的持久化反重放表 | 🟡 M | 防御深度欠缺 |
| F4 | 缺少对抗性测试（同 commitment_number 多 message 签名） | 🟡 M | 测试盲区 |

## 4. 关键代码引用

```rust
// crates/fiber-types/src/channel.rs:1279
pub fn derive_musig2_nonce(&self, commitment_number: u64, context: Musig2Context) -> SecNonce {
    let commitment_point = self.get_commitment_point(commitment_number);
    let seckey = derive_private_key(&self.musig2_base_nonce, &commitment_point);
    SecNonceBuilder::new(seckey.as_ref())
        .with_extra_input(&context.to_string())
        .build()
}
```

```rust
// crates/fiber-lib/src/fiber/channel.rs:6019
pub fn get_channel_announcement_musig2_secnonce(&self) -> SecNonce {
    let seckey = blake2b_hash_with_salt(
        self.signer.musig2_base_nonce.as_ref(),
        b"channel_announcement".as_slice(),
    );
    SecNonce::build(seckey).build()
}
```

## 5. 修复建议

**短期 (高优先级)**：

1. 在所有 `SecNonceBuilder::new(...)` 调用处补全：
   ```rust
   SecNonceBuilder::new(seckey.as_ref())
       .with_seckey(&funding_seckey)
       .with_message(&message_to_sign)            // 即将签名的 32B 摘要
       .with_aggregated_pubkey(&agg_pubkey)
       .with_extra_input(&{
           let mut r = [0u8; 32];
           rand::thread_rng().fill_bytes(&mut r); // CSPRNG 抗确定性故障
           r
       })
       .build()
   ```
2. 对 announcement nonce 同样将 `message_to_sign` 与 `agg_pubkey` 混入，并在签名后清除/标记缓存为"已绑定该 message 摘要"。

**中期 (深度防御)**：

3. 在通道状态持久化中加入 `BTreeMap<(commitment_number, Context), Blake2bHash>`，记录每次签名的 message 摘要；同一 (number, context) 收到不同 message 时**强制拒绝并 force-close** 通道。
4. 增加单测：用 `Musig2Context::Commitment` + 固定 commitment_number + 两条不同的 message 调用签名 API，确保上层逻辑拒绝。
5. 启用 musig2 库的 `verify_partial` 在聚合前对对端 partial 做强校验，降低 DoS。

**长期**：

6. 与 fiber-scripts (链上脚本) 协同审视：链上能否检测同 funding outpoint 出现两条互不矛盾的 commitment？若能则 watchtower 可作为最后一道防线。

## 6. 新增审计项

- **AUDIT-CRYPTO-001-FOLLOWUP-A**：动态验证 — 构造对抗 peer，在 reestablish 路径上让本地在同 `local_commitment_number` 下签两条不同 commitment message，观察是否能恢复 funding key。
- **AUDIT-CRYPTO-001-FOLLOWUP-B**：审查 `local_channel_announcement_signature` 缓存的 invalidation 不变量；若任何路径会 clear 该字段，则 announcement nonce 复用可达。

## 7. 结论

**疑似 High / Critical 设计性风险**。鉴于资金敏感性，建议优先修复（即使尚未找到端到端可利用攻击路径，BIP-327 §"Deterministic Signing Considerations" 明确要求在确定性 nonce 派生中混入 message 与聚合公钥，本实现不满足该要求）。
