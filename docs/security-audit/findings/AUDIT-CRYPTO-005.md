# AUDIT-CRYPTO-005 — PTLC / 曲线点·标量代数操作

**审计目标**: 检查 fiber 在 secp256k1 椭圆曲线上的点加 / 标量加 / 标量乘运算是否处理 identity 元 (点 O / 标量 0)、曲线阶 n 边界，以及 scalar tweak 是否做域分离。重点关注**两个输入同时受攻击者控制**的代数路径。

**Session**: S21  
**审计日期**: 2026-05-14  
**审计员**: Copilot  
**整体严重性**: 🟠 **High** — 1 个可远程触发的 channel-bricking panic (F1) + 数个 defense-in-depth 改进

---

## 概览

| Severity | Count |
|---|---|
| 🔴 Critical | 0 |
| 🟠 High | 1 (F1) |
| 🟡 Medium | 0 |
| 🔵 Low | 2 (F2, F3) |
| ℹ️ Info | 1 (F4) |
| ✅ Pass | 2 (F5, F6) |

**关键发现 (F1)**: `OpenChannel` / `AcceptChannel` 中的 `tlc_basepoint` 与 `first_per_commitment_point` **由 peer 在同一条消息中同时提供**，无任何代数关系校验。这两个值都直接喂给 `derive_tlc_pubkey` → `Pubkey::tweak`：

```
result = T + blake2b(Q.serialize()) · G        // T = tlc_basepoint, Q = commitment_point
```

`Pubkey::tweak` 末尾 `.not_inf().expect("valid public key")` 在 `result == O`（无穷远点）时直接 **panic**。攻击者可在握手阶段自由地共同选择 (T, Q)：

1. 选任意有效 Q = q·G；
2. 计算 `h = blake2b(Q.serialize()) mod n`；
3. 令 `T_priv = (n − h) mod n`，发送 `tlc_basepoint = T_priv · G`、`first_per_commitment_point = Q`。

受害节点在后续任何首次 `get_tlc_pubkeys` 调用 (AddTlc / 提交本地承诺 / 结算) 中触发 `T + h·G = O` → panic。该构造被**持久化到 ChannelActorState**，重启后立即重放，**永久 brick 整条通道**，受害方除链上 force-close 外无救济手段。

---

## F1 — 🟠 High · `Pubkey::tweak` 在点-加-至-无穷处 panic，且双输入均 attacker-controlled

**位置**:
- `crates/fiber-types/src/primitives.rs:511-519` (`Pubkey::tweak`)
- `crates/fiber-types/src/channel.rs:1166-1179` (`derive_private_key` / `derive_public_key` / `derive_tlc_pubkey`)
- `crates/fiber-lib/src/fiber/channel.rs:6097-6126` (`get_tlc_pubkeys` / `get_tlc_keys`)
- `crates/fiber-lib/src/fiber/channel.rs:8748-8762` (`From<&OpenChannel>` / `From<&AcceptChannel>` for `ChannelBasePublicKeys`)
- `crates/fiber-types/src/schema/fiber.mol:41-42, 58-59` (OpenChannel / AcceptChannel molecule schema)

### 现状（带行号摘录）

```rust
// crates/fiber-types/src/primitives.rs:511-519
pub fn tweak<I: Into<[u8; 32]>>(&self, scalar: I) -> Self {
    let scalar = scalar.into();
    let scalar = Scalar::from_slice(&scalar)
        .expect(format!("Value {:?} must be within secp256k1 scalar range. \
            If you generated this value from hash function, then your hash function is busted.",
            &scalar).as_str());
    // Convert to Point, perform operation, then serialize back
    let result = Point::from(self) + scalar.base_point_mul();
    let point = result.not_inf().expect("valid public key");   // ⬅ PANIC
    PublicKey::from(point).into()
}
```

```rust
// crates/fiber-types/src/channel.rs:1158-1174
pub fn get_tweak_by_commitment_point(commitment_point: &Pubkey) -> [u8; 32] {
    let mut hasher = ckb_hash::new_blake2b();
    hasher.update(&commitment_point.serialize());
    let mut result = [0u8; 32];
    hasher.finalize(&mut result);
    result
}
pub fn derive_public_key(base_key: &Pubkey, commitment_point: &Pubkey) -> Pubkey {
    base_key.tweak(get_tweak_by_commitment_point(commitment_point))
}
```

```rust
// crates/fiber-lib/src/fiber/channel.rs:8748-8762
impl From<&OpenChannel> for ChannelBasePublicKeys {
    fn from(value: &OpenChannel) -> Self {
        ChannelBasePublicKeys {
            funding_pubkey: value.funding_pubkey,
            tlc_base_key:   value.tlc_basepoint,        // ⬅ peer-supplied, no relation check
        }
    }
}
// AcceptChannel: identical pattern.
```

Schema 证明两个值在**同一条 P2P 消息**中由 peer 提供：
```
// crates/fiber-types/src/schema/fiber.mol:41-42  (OpenChannel)
tlc_basepoint:               Pubkey,
first_per_commitment_point:  Pubkey,
```

### 攻击场景

| 步骤 | 行为 | 复杂度 |
|---|---|---|
| 1 | 攻击者打开到 victim 的 channel：发任意 `OpenChannel` 但精心选取 (T, Q) 使 `T + blake2b(Q.serialize()) · G = O` | O(1) 算术，无哈希爆破 |
| 2 | Victim 把 `tlc_basepoint = T` 与 `remote_commitment_points[0] = Q` 持久化到 `ChannelActorState` | 攻击者无需在线 |
| 3 | 攻击者发任意 `AddTlc`（或 victim 自己想发 outgoing TLC）触发 `get_tlc_pubkeys` 计算 `derive_tlc_pubkey(T, Q)` | 一次 RPC |
| 4 | `Point::from(T) + h·G` = 无穷远 → `.not_inf().expect(...)` → **process abort 或 actor crash** | — |
| 5 | 重启后 channel state 仍含 (T, Q)，依然 panic；只有链上 force-close 能脱离 | — |

### 影响

- **直接资金损失**: 取决于通道余额 — force-close 阶段攻击者无法窃取，但受害方需付 CKB 交易费 + 等待 commit-tx 成熟 + 通道额度临时锁仓。
- **可用性**: 单个对端能廉价 brick 节点所有由它发起的通道。多对端协同可关闭节点全部公开通道。
- **持久性**: 状态被持久化 — 节点重启不能自愈，唯一出路是 force-close + 手工删除 channel row。
- **检测难度**: 受害方在 `get_tlc_pubkeys` 抛出之前看不出 (T, Q) 有任何异常 — 二者都是格式合法的 33 字节压缩公钥。

### 推荐修复

**最小修复**: 在 `AcceptChannelCommand` / `OpenChannelCommand` 处理路径接收到 (`tlc_basepoint`, `first_per_commitment_point`) 后立刻试算一次 `derive_tlc_pubkey`，失败则在握手阶段就拒绝通道，永远不持久化恶意状态：

```rust
// 在 OpenChannel/AcceptChannel handler 早期
if Point::from(&value.tlc_basepoint).checked_add(
    Scalar::from_slice(&get_tweak_by_commitment_point(&value.first_per_commitment_point))?
        .base_point_mul()
).is_none() {
    return Err(ProcessingChannelError::InvalidParameter(
        "tlc_basepoint and first_per_commitment_point sum to infinity".into()
    ));
}
```

**长期修复**: 把 `Pubkey::tweak` / `Privkey::tweak` 的 `.expect(...)` 全部改为返回 `Result<Self, _>`，并让所有调用方（包括 `derive_tlc_pubkey` 与 `signer.derive_tlc_key`）传播错误而非 panic — 见 F2/F3。

### 与本仓 stored memory `musig2 partial signature verification` 的关系

不同根因：CRYPTO-004 是 **签名聚合预校验缺失**（无 panic、仅卡通道）；本 F1 是 **曲线代数 panic**（直接 abort actor，强迫 force-close）。两者均利用 fiber 在握手阶段对 peer 输入做"原样存储 + 信任算法不会触发边界"的设计。

---

## F2 — 🔵 Low · `Privkey::tweak` 的 `.not_zero().expect(...)` 不可远程触发但 API 设计脆弱

**位置**: `crates/fiber-types/src/primitives.rs:403-412`

```rust
pub fn tweak<I: Into<[u8; 32]>>(&self, scalar: I) -> Self {
    let scalar = Scalar::from_slice(&scalar.into()).expect(...);
    let sk = Scalar::from(self);
    (scalar + sk).not_zero().expect("valid secp256k1 scalar addition").into()
}
```

唯一调用方是 `derive_private_key(secret, commitment_point)`（channel.rs:1167-1169），其中 `secret` 是本地 signer 私钥（如 `tlc_base_key`），**不**受攻击者控制；`commitment_point` 攻击者可控。要让 `sk + blake2b(Q) ≡ 0 mod n` 成立，攻击者必须找到 `Q` 使 `blake2b(Q.serialize()) ≡ −sk mod n` — 对 blake2b 的 256-bit 第二原像攻击 → 计算上不可行。

**风险等级**: Low — 当前不可远程触发，但若日后有新调用方把 attacker-controlled scalar 直接传入 `Privkey::tweak`，则会立即升级为 High。

**建议**: 把 `.not_zero().expect(...)` 改为返回 `Result<Self, CryptoError>`，强制调用方处理（与 F1 的修复同步进行）。

---

## F3 — 🔵 Low · `Scalar::from_slice(...).expect(...)` 在 attacker-controlled 输入下的 API 警告

**位置**: `crates/fiber-types/src/primitives.rs:405-406, 513-514`

```rust
let scalar = Scalar::from_slice(&scalar)
    .expect(format!("Value {:?} must be within secp256k1 scalar range. \
        If you generated this value from hash function, then your hash function is busted.",
        &scalar).as_str());
```

当前所有调用点先经过 `get_tweak_by_commitment_point` 的 blake2b（`crates/fiber-types/src/channel.rs:1158-1164`），blake2b 输出在 `[0, 2^256)` 上近似均匀；`Scalar::from_slice` 在输入 `≥ n` 时返回 `None`（概率 ≈ 2^-128 per call）。

**风险**: 概率上不可达，**但 API 形态危险**：

1. 注释明确说"假定上游已 hash"。如果未来有人把 `Pubkey::tweak(raw_attacker_32_bytes)` 这样调用，攻击者可在 ~2^128 步内构造一个落在 `[n, 2^256)` 区间的标量值 → panic（注：实际上为 2^256 − n ≈ 2^128，远低于 birthday 攻击下界，但仍非"可远程一次构造"）。
2. 错误消息把 `scalar` 整字段 hex 打到 panic message，攻击者若能远程触发会得到 attacker-known bytes 的回显，无信息泄漏，但 panic message 进 stderr 可能干扰运维日志聚类。

**建议**: 改为 `Result<Self, OutOfRangeScalar>`。即使保留 expect，也至少改成 `expect("scalar derived from blake2b cannot exceed secp256k1 group order")` 这种不回显输入的固定串。

---

## F4 — ℹ️ Info · scalar tweak 缺乏域分离 (domain separation) tag

**位置**: `crates/fiber-types/src/channel.rs:1158-1164`

```rust
pub fn get_tweak_by_commitment_point(commitment_point: &Pubkey) -> [u8; 32] {
    let mut hasher = ckb_hash::new_blake2b();
    hasher.update(&commitment_point.serialize());      // ⬅ 无 personalization / tag
    let mut result = [0u8; 32];
    hasher.finalize(&mut result);
    result
}
```

`ckb_hash::new_blake2b` 默认带 CKB 个性化串 (`"ckb-default-hash"`)，所以 fiber 协议外的字符串不会撞库；但 **fiber 协议内部**的多种 hash 用途（channel-id 派生、tlc-tweak、commitment-secret chain、gossip message-to-sign…）共享同一个 personalization，留下未来同议程冲突的隐患（参见 stored memory `gossip message_to_sign 无域分离 tag`，CRYPTO-004.F6 已记录）。

**风险等级**: Info — 当前无可触发的 cross-protocol attack 实例，纯 future-proofing。

**建议**: 在 hash 输入前 prefix 短常量 tag (e.g. `b"fiber/tlc-tweak/v1"`)，与 CRYPTO-004.F6 的 gossip 域分离一起在 BREAKING 版本中统一实施。

---

## F5 — ✅ Pass · `Pubkey::from_slice` 正确返回 `Result`，是同文件的"正确范本"

`crates/fiber-types/src/primitives.rs:503-508`：
```rust
pub fn from_slice(slice: &[u8]) -> Result<Self, secp256k1::Error> {
    let _ = PublicKey::from_slice(slice)?;          // ✓ 通过 libsecp256k1 验证压缩点
    let mut bytes = [0u8; PUBKEY_SIZE];
    bytes.copy_from_slice(slice);
    Ok(Pubkey(bytes))
}
```

良好的防御性 API — `tweak` 系列应当照此重构 (见 F1/F2/F3)。

---

## F6 — ✅ Pass · musig2 0.2.x 提供 `not_inf` / `not_zero` Option API

```toml
# crates/fiber-types/Cargo.toml
musig2 = { version = "0.2", ... }
```

库本身在曲线代数层暴露的是 `Option<NonInfPoint>` / `Option<NonZeroScalar>` 风格，**安全责任已下放给调用方**。当前 fiber 选择 `.expect(...)`；改用 `.ok_or(...)` 即可在不引入新依赖的情况下消除 F1/F2/F3。

---

## 整改优先级

| Finding | 优先级 | 触发难度 | 修复成本 | 备注 |
|---|---|---|---|---|
| F1 | **P0** | 单次 OpenChannel | 1 个 if + 1 个错误码 | 必须在握手期间拦截 |
| F2 | P2 | 不可远程触发（理论） | 同 F1 联动 | API 重构 |
| F3 | P2 | 不可远程触发（理论） | 同 F1 联动 | API 重构 + 错误消息脱敏 |
| F4 | P3 | 无 | BREAKING 升级 | 与 CRYPTO-004.F6 一起做 |

## 后续动作 (Follow-ups)

- **CR-A (P0)**: 实现 F1 的握手期算术校验，并加 P2P-level 回归测试：构造一对 (T, Q) 使 `T + blake2b(Q)·G = O`，确认 victim 在 OpenChannel 处理早期就 `InvalidParameter` 拒绝，状态机不进入 `NEGOTIATING_FUNDING`。
- **CR-B (P2)**: 重构 `Privkey::tweak` / `Pubkey::tweak` / `Scalar::from_slice` 调用链为 `Result`，把所有 `.expect(...)` 转为 `?` 传播；调整 `derive_tlc_pubkey` / `signer.derive_tlc_key` / `get_commitment_point` 等 7 个调用方。
- **CR-C (P3)**: 与 CRYPTO-004.F6 合并实施 fiber 协议内部哈希的域分离 tag schema。
