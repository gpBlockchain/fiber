# AUDIT-INPUT-002 — Invoice 解析（bech32m / molecule / CkbInvoice）

- **维度**: DIM-INPUT / DIM-SERDE
- **严重级别**: 🟠 **High**（High × 1 + Medium × 2 + Low × 2 + Info × 1 + Pass × 2）
- **审计 Session**: S12 (2026-05-14)
- **关联代码**:
  - `crates/fiber-types/src/invoice.rs:865-907` (`CkbInvoice::from_str`)
  - `crates/fiber-types/src/invoice.rs:887` (`ar_decompress(...).expect(...)` ⚠️)
  - `crates/fiber-types/src/invoice.rs:1018-1064` (`From<InvoiceAttr> for Attribute` — 多处 `.expect()`)
  - `crates/fiber-types/src/invoice.rs:1024,1042` (Description / FallbackAddr `String::from_utf8(value).expect(...)` ⚠️)
  - `crates/fiber-types/src/invoice.rs:1052` (PayeePublicKey `PublicKey::from_slice(...).expect(...)` ⚠️)
  - `crates/fiber-types/src/invoice.rs:1085,1088` (`u5::try_from_u8(x).expect(...)` / `from_base32_checked.expect(...)`)
  - `crates/fiber-types/src/invoice.rs:610` (`panic!("no other error may occur, got {:?}", e)`)
  - `crates/fiber-lib/src/rpc/invoice.rs:289-300` (`parse_invoice` RPC — 公开入口)
  - `crates/fiber-lib/src/cch/actor.rs:628` (`CkbInvoice::from_str(&receive_btc.fiber_pay_req)?` — CCH 入口)
  - `crates/fiber-lib/src/cch/actions/send_outgoing_payment.rs:254` (CCH outgoing 检查)
  - `crates/fiber-lib/src/cch/cch_fiber_agent.rs:115` (CCH agent 反序列化对端 RPC 响应)
  - `crates/fiber-lib/src/fiber/payment.rs:359` (`build_send_payment_data` 解析 send_payment RPC 中的 invoice 字段)
  - `crates/fiber-lib/fuzz/fuzz_targets/fuzz_invoice.rs:8-14` (现有 fuzz 目标)

## 1. 审计目标

CkbInvoice 字符串是 Fiber 的核心用户输入面：

1. **公开 RPC** `parse_invoice` 接受任意字符串 → `CkbInvoice::from_str`；
2. **公开 RPC** `send_payment` 的 `invoice` 字段同样进入 `from_str`；
3. **CCH** 在 `receive_btc(fiber_pay_req)` 中信任用户提供的 invoice 字符串；
4. **CCH agent** 把对端 fiber 节点的 HTTP RPC 响应字段直接 `from_str`；
5. **Invoice 存储** 反序列化路径（store → `RawCkbInvoice` → `CkbInvoice`）。

任意一个 panic 路径都构成**远程 DoS**（崩溃整个 fiber 节点进程，包括所有通道、payment 状态机、CCH 状态机）。Fiber 节点是 always-on 的支付节点，崩溃既影响所有用户支付，也可能在某些情况下被对手用作"诱发 force-close 风暴"的辅助手段（peer 觉察 fiber 进程崩溃，趁机刷 commitment 旧版本）。

本审计扫描：
1. `CkbInvoice::from_str` 调用链中的所有 `.expect()` / `.unwrap()` / `panic!`；
2. 攻击者是否能构造合法 bech32m 外壳 + 任意 molecule 内层 → 触发 panic；
3. 现有 `fuzz_invoice.rs` 是否覆盖；
4. 校验语义（duplicate attrs / empty signature path / Bech32 vs Bech32m）。

## 2. 系统性梳理

### 2.1 Invoice 字符串解析流水线

```
String
  ├─ bech32::decode  ── (hrp, data, variant) ── 错误 → InvoiceError::Bech32Error  ✅
  │
  ├─ variant == Bech32           → InvoiceError::InvalidChecksum                  ✅
  ├─ data.len() < 104            → InvoiceError::TooShortDataPart                 ✅
  ├─ parse_hrp(hrp)              → 错误 → MalformedHRP / UnknownCurrency          ✅
  │
  ├─ Vec::<u8>::from_base32(...) → 错误 → InvoiceError::Bech32Error               ✅
  │
  ├─ ar_decompress(&data_part).expect("decompress invoice data")                  ❌ PANIC
  │
  ├─ RawInvoiceData::from_slice(...)  → 错误 → InvoiceError::MoleculeError        ✅
  │
  ├─ invoice_data.try_into() = InvoiceData::try_from(RawInvoiceData)
  │   └─ for each attr: Attribute::from(InvoiceAttr)
  │       ├─ Description: String::from_utf8(value).expect(...)                    ❌ PANIC
  │       ├─ FallbackAddr: String::from_utf8(value).expect(...)                   ❌ PANIC
  │       └─ PayeePublicKey: PublicKey::from_slice(&value).expect(...)            ❌ PANIC
  │
  └─ check_signature() → recover_payee_pub_key()
      └─ panic!("no other error may occur, got {:?}", e)                          ⚠️ FRAGILE
```

### 2.2 Molecule 表层校验 vs 业务层校验缺口

`gen_invoice` 中：

- `Description.value : Bytes` — molecule **不强制 UTF-8**，只检查 `Bytes` 表头（4 字节长度 + 内容）；
- `FallbackAddr.value : Bytes` — 同上；
- `PayeePublicKey.value : Bytes` — molecule **不强制长度**，但 `PublicKey::from_slice` 要求恰好 33 字节（compressed）或 65 字节（uncompressed）。

`RawInvoiceData::from_slice` 通过表层结构校验，但 `From<InvoiceAttr> for Attribute` 在转换时**用 `.expect()` 假设 invariant 成立**。结果：molecule 校验通过 + 业务转换 panic = **完整解析路径不是 panic-free**。

### 2.3 Bech32m 外壳合法性与 ar_decompress 错误

`ar_decompress` (invoice.rs:150-164) 内部使用 `arcode::ArithmeticDecoder::new(48).decode(...)`，循环直至 `decoder.finished()`。`decode` 是 `IoResult<u32>`，可能返回 `io::Error`（例如 `BitReader` 在未到达 EOF 但流终止时）。

```rust
let data_part = ar_decompress(&data_part).expect("decompress invoice data");
```

⚠️ **任何使 `decode` 返回 `Err` 的输入都直接 panic**。攻击者构造合法 bech32m 包装 + 任意字节作为压缩负载，arithmetic decoder 在某些位模式下会返回 `Err(io::Error)`（例如位流读到末尾仍未输出 EOF 符号），从而触发 panic。

### 2.4 现有 fuzz 覆盖度评估

`fuzz_invoice.rs` 直接喂 `&[u8]` → `from_str`。问题：

1. `bech32::decode` 检查 checksum，绝大多数随机输入直接被拒；
2. 即便偶然产生合法 bech32m，要正好压成合法 ar 编码 + 合法 molecule 表 ≈ 0；
3. **fuzzer 永远到不了 `ar_decompress` 的 panic 路径，更不用说 `From<InvoiceAttr>`**。

实际有效的 corpus 应当：(a) 用合法 bech32m 外壳；(b) 注入畸形 `data_part`；(c) 注入合法 molecule 但 attrs 非 UTF-8 / 非法 pubkey。这是经典的"分层 fuzz"问题。

## 3. 发现

### 3.1 F1 (🟠 High) — `From<InvoiceAttr> for Attribute` 中三处 `.expect()` 远程 DoS

**位置**：`crates/fiber-types/src/invoice.rs:1024, 1042, 1052`

```rust
InvoiceAttrUnion::Description(x) => {
    let value: Vec<u8> = x.value().unpack();
    Attribute::Description(
        String::from_utf8(value).expect("decode utf8 string from bytes"),  // ← PANIC
    )
}
InvoiceAttrUnion::FallbackAddr(x) => {
    let value: Vec<u8> = x.value().unpack();
    Attribute::FallbackAddr(
        String::from_utf8(value).expect("decode utf8 string from bytes"),  // ← PANIC
    )
}
InvoiceAttrUnion::PayeePublicKey(x) => {
    let value: Vec<u8> = x.value().unpack();
    Attribute::PayeePublicKey(
        PublicKey::from_slice(&value).expect("Public key from slice"),     // ← PANIC
    )
}
```

#### 攻击 PoC（高层步骤）

1. 用 `InvoiceBuilder` 在本地生成一份合法 invoice（合法 bech32m 外壳、合法 molecule 数据）；
2. **绕过 `InvoiceBuilder`**，直接构造 `RawInvoiceData` molecule 原始字节，`Description.value = b"\xff\xff"`（非 UTF-8）；
3. 通过 `ar_encompress` 压缩 + bech32m 编码，得到一个合法格式的 invoice 字符串 `S`；
4. 调 `parse_invoice({invoice: S})` 或 `send_payment({invoice: S})` → 节点 panic → 进程退出。

由于 fiber 节点通常运行在单进程模型（actor framework），panic 会通过 `ractor` actor supervision 传播：

- 顶层 root actor panic → 整个进程崩溃 → 所有 channels / payments / CCH 中断；
- 或 RPC handler 中的 panic 通过 `tokio` `JoinError` 传播 → 至少该 RPC 调用失败，可能影响 worker 线程池。

无论哪种行为，**攻击者通过单次未授权的 HTTP RPC 调用即可造成 DoS**（`parse_invoice` 不需要 biscuit 授权 —— 见 `rpc/biscuit.rs` 的默认 permissions 中 invoice 相关的 capability 集）。即便 RPC 有授权，CCH `receive_btc` 接受 fiber_pay_req 字符串则将攻击面扩大到任何能与 CCH 交互的用户。

#### 严重性

- **远程触发**：只需一个 RPC 调用或一个 CCH 跨链订单创建；
- **零成本**：不需要任何资金；
- **零授权**（`parse_invoice` 是只读类）；
- **影响**：节点崩溃 → 通道无人监视 → AUDIT-LOGIC-008 类的 CCH preimage 处理无人响应 → AUDIT-LOGIC-007 类的 cooperative-close 状态丢失 → 重启 + 链上恢复成本。

**严重级别：🟠 High**。

#### 修复

把所有 `.expect()` 替换为返回 `InvoiceError::Malformed*`：

```rust
InvoiceAttrUnion::Description(x) => {
    let value: Vec<u8> = x.value().unpack();
    Attribute::Description(
        String::from_utf8(value)
            .map_err(|_| InvoiceError::MalformedAttribute("Description must be UTF-8".into()))?,
    )
}
```

这要求把 `From<InvoiceAttr>` 改为 `TryFrom<InvoiceAttr>`，并把调用点（invoice.rs:962）改为 `try_into().collect::<Result<Vec<_>, _>>()`，再把 `TryFrom<RawInvoiceData> for InvoiceData` 的错误传播给 `from_str`（line 902）—— 后者目前用 `.expect("pack invoice data")`，也需相应改为 `?`。

### 3.2 F2 (🟡 Medium) — `ar_decompress(...).expect()` 远程 DoS

**位置**：`crates/fiber-types/src/invoice.rs:887`

```rust
let data_part = ar_decompress(&data_part).expect("decompress invoice data");
```

`ar_decompress` 返回 `IoResult<Vec<u8>>`。`arcode::ArithmeticDecoder::decode` 在位流耗尽前未读到 EOF 符号、或某些格式错误情况下返回 `Err(io::Error)`，**直接 panic**。

#### 攻击 PoC

构造合法 bech32m 外壳，但 `data_part`（base32 解码后）不是合法的 ar 压缩流：

```python
# 伪代码
hrp = "fibd"
data = b"\x00" * 50  # 非合法的算术编码流
encoded = bech32m_encode(hrp, base32_encode(data))
# 调用 parse_invoice(encoded) → ar_decompress 返回 Err → panic
```

#### 严重性

- 与 F1 同样的远程触发面；
- 触发输入更容易构造（不需要构造合法 molecule）；
- 仍属于 panic 类 DoS。

**严重级别：🟡 Medium**（攻击向量与 F1 同源；只是单独 fix F1 不能消除此路径）。

#### 修复

```rust
let data_part = ar_decompress(&data_part)
    .map_err(|e| InvoiceError::DecompressionError(e.to_string()))?;
```

新增 `InvoiceError::DecompressionError(String)` 变体。

### 3.3 F3 (🟡 Medium) — `from_str` 中 `invoice_data.try_into().expect("pack invoice data")` 在重构后会变成第二个 panic 点

**位置**：`crates/fiber-types/src/invoice.rs:902`

```rust
data: invoice_data.try_into().expect("pack invoice data"),
```

当前 `TryFrom<RawInvoiceData> for InvoiceData`（line 952-966）的实现体只是 `Ok(...)`，**永远不返回 Err**，所以 `.expect()` 在当前代码下不会 panic。但它依赖一个**间接不变式**：`InvoiceData::try_from` 内部不调用任何可能失败的 `.into()`。如果 F1 的修复把 `From<InvoiceAttr>` 改为 `TryFrom<InvoiceAttr>`，那么 `InvoiceData::try_from` 也会需要传播错误，此时 line 902 的 `.expect()` 会变成真实可触发的 panic 点。

**严重级别：🟡 Medium**（与 F1 修复联动；单独看不可触发）。

#### 修复

把 line 902 改为 `?` 并相应在 `TryFrom<RawInvoiceData> for InvoiceData` 的 `Error` 类型中包含 `InvoiceError`（或新增 union error）。

### 3.4 F4 (🟢 Low) — `panic!("no other error may occur, got {:?}", e)` in `check_signature`

**位置**：`crates/fiber-types/src/invoice.rs:610`

```rust
match self.recover_payee_pub_key() {
    Err(secp256k1::Error::InvalidRecoveryId) => return Err(InvoiceError::InvalidRecoveryId),
    Err(secp256k1::Error::InvalidSignature) => return Err(InvoiceError::InvalidSignature),
    Err(e) => panic!("no other error may occur, got {:?}", e),  // ← FRAGILE
    Ok(_) => {}
}
```

`secp256k1::SECP256K1.recover_ecdsa` 可以返回的错误包括 `InvalidPublicKey`、`InvalidMessage`、`InvalidSecretKey` 等。当前输入下：

- `Message::from_digest_slice(&hash)` 用 32 字节 hash 创建 → 不会返回 InvalidMessage；
- 签名是 `RecoverableSignature` 结构体，不会再失败。

**理论上**当前代码不可达，但**未来 secp256k1 升级**或**新增错误变体**会让这条 panic 突然可触发。同时这是一个"用 panic 表达不变式"的反模式，合理写法是 `unreachable!` + 详细注释，或更好用 `Err(InvoiceError::InvalidSignature)` 兜底。

**严重级别：🟢 Low**（不当前可触发，但是脆弱）。

#### 修复

```rust
Err(_) => return Err(InvoiceError::InvalidSignature),
```

### 3.5 F5 (🟢 Low) — Duplicate attribute 不被拒绝；只取第一个

**位置**：`crates/fiber-types/src/invoice.rs:679-783` (各 attr accessor `.next()`)

所有 attribute 访问器都是 `.iter().filter_map(...).next()`，对相同 discriminant 的多次出现**只读第一个**。但 `hash()` 函数把所有 attrs 序列化进 preimage，因此签名覆盖了完整 attrs 列表。

这意味着同一个 invoice 可以包含两个 `Description`、两个 `ExpiryTime`、两个 `PayeePublicKey`：

- 校验逻辑（`is_expired`、`payee_pub_key`、`expiry_time`）都只看第一个；
- 但签名是对**所有** attrs 的 hash 验证 —— 不一致；
- 攻击者可发布两份 attribute（一份合法可见，一份隐藏的恶意意图）—— 但因签名要求是 payee 自己签发，对**自签**场景威胁有限；对**第三方分发场景**或**未签名 invoice**场景则可能产生预期外行为（一份用户看到的内容、一份系统认知的内容不一致）。

`InvoiceError::DuplicatedAttributeKey` 错误类型已经定义（line 92），但**没有被任何代码使用**（grep 0 命中）—— 设计意图存在但未实施。

**严重级别：🟢 Low**（自签场景影响小；未签名场景需要业务方决定语义）。

#### 修复

在 `InvoiceData::try_from` 完成后，对 `attrs` 做 discriminant 去重检查：

```rust
let mut seen = HashSet::new();
for attr in &result.attrs {
    let kind = std::mem::discriminant(attr);
    if !seen.insert(kind) {
        return Err(InvoiceError::DuplicatedAttributeKey(format!("{:?}", attr)));
    }
}
```

### 3.6 F6 (ℹ️ Info) — `fuzz_invoice` 几乎无法到达 panic 点（覆盖率结构性盲区）

**位置**：`crates/fiber-lib/fuzz/fuzz_targets/fuzz_invoice.rs`

当前 fuzz 直接喂随机字节给 `CkbInvoice::from_str`：

1. 99.99% 输入被 bech32 checksum 拒绝（4 字符 checksum = 30 比特熵）；
2. 极少数能通过 bech32 的会因 ar_decompress 在第一字节就报错或 panic，但 panic 是新发现，旧版本 fuzz 没人持续跑；
3. **彻底无法**到达 `From<InvoiceAttr>` 的 panic（需要合法 molecule + 非法 attr value）。

#### 改进

1. 新增 fuzz target `fuzz_invoice_inner`：直接对 `RawInvoiceData::from_slice` 的输入做 fuzz，绕过 bech32m + ar_decompress；
2. 新增 fuzz target `fuzz_invoice_attr`：对 `InvoiceAttr::from_slice` 的输入做 fuzz；
3. 在 `fuzz_invoice` 中提供有效 corpus（保留 `tests/invoice/tests/invoice_impl.rs` 中已有的合法 invoice 字符串作为种子）。

### 3.7 F7 (✅ Pass) — bech32 vs bech32m 强制（防 LN BOLT11 invoice 被误用）

**位置**：`crates/fiber-types/src/invoice.rs:871-873`

```rust
if var == bech32::Variant::Bech32 {
    return Err(InvoiceError::Bech32Error(bech32::Error::InvalidChecksum));
}
```

明确拒绝 bech32（非 m）变体。BOLT11 LN invoice 用 bech32（非 m），CKB invoice 用 bech32m，强制区分避免歧义。✅

### 3.8 F8 (✅ Pass) — 签名校验路径正确

`check_signature` (line 601-619) + `validate_signature` (621-650) 在签名存在时强制校验，恢复的 pubkey 与显式 `payee_pub_key` 一致检查（through hash 包含全部 attrs）。✅

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — `From<InvoiceAttr>` 三处 `.expect()` 远程 DoS（`parse_invoice` / `send_payment` / `cch.receive_btc`） | 🟠 **High** | ❌ 未修复 |
| F2 — `ar_decompress(...).expect(...)` 远程 DoS | 🟡 Medium | ❌ 未修复 |
| F3 — `invoice_data.try_into().expect(...)` 在 F1 修复后会变成可触发 panic | 🟡 Medium | ❌ 未修复（待 F1 联动） |
| F4 — `check_signature` 中 `panic!("no other error...")` 反模式 | 🟢 Low | ❌ 未修复 |
| F5 — Duplicate attribute 不拒绝；`InvoiceError::DuplicatedAttributeKey` 定义但未使用 | 🟢 Low | ❌ 未修复 |
| F6 — `fuzz_invoice` 结构性盲区（无法穿透 bech32m/ar_decompress 到 attr 转换层） | ℹ️ Info | ⚠️ 覆盖不足 |
| F7 — bech32m 强制拒绝 bech32 变体 | ✅ Pass | — |
| F8 — 签名校验路径正确 | ✅ Pass | — |
| 整体 | 🟠 **High** | ❌ |

### 总体评价

CkbInvoice 解析器在**信号层面**做得到位（bech32m 强制、签名校验、长度边界、HRP 解析、错误类型完整），但**异常处理层面**充满 `.expect()`/`unwrap()`/`panic!`，且这些 panic 全部在**用户可达的 RPC / CCH 入口**上：

| 入口 | 是否需要授权 | 受影响 |
|---|---|---|
| `rpc.parse_invoice` | 通常无 | F1, F2 |
| `rpc.send_payment(invoice=...)` | 通常需 | F1, F2 |
| `cch.receive_btc(fiber_pay_req=...)` | 视部署 | F1, F2 |
| `cch.send_outgoing_payment` 解析 outgoing_pay_req | 内部 | F1, F2（订单创建后路径） |
| `cch_fiber_agent` 解析对端 RPC 响应 | 内部，但信任对端 | F1, F2 |
| Invoice 存储反序列化（`RawCkbInvoice → CkbInvoice`） | 内部 | line 1085, 1088 panic |

**单次合法格式的 RPC 请求 → 节点崩溃**。这是本审计中除 LOGIC-008 之外最严重的 DoS 类发现，且**修复成本极低**（把 `.expect` 改为 `?`，把 `From` 改为 `TryFrom`）。

与 AUDIT-INPUT-001（P2P molecule 解析）相比：INPUT-001 中的 P2P 帧已被 tentacle 长度上限 + molecule 表层校验保护，但 INPUT-002 揭示**另一条相同攻击面的入口**（用户可达的 invoice 字符串）**未受同等保护**。

## 5. Follow-ups

- **AUDIT-INPUT-002-FOLLOWUP-A (🟠 High, 必修)**: F1 — 把 `From<InvoiceAttr> for Attribute` 改为 `TryFrom<InvoiceAttr> for Attribute`；新增 `InvoiceError::MalformedAttribute(String)` 变体；联动修复 F3 (line 902 `.expect → ?`) 与 line 1085 `u5::try_from_u8(x).expect` / 1088 `from_base32_checked.expect`。
- **AUDIT-INPUT-002-FOLLOWUP-B (🟡 Medium, 必修)**: F2 — `ar_decompress(...).expect()` 改 `?`；新增 `InvoiceError::DecompressionError(String)` 变体。
- **AUDIT-INPUT-002-FOLLOWUP-C (🟢 Low)**: F4 — `panic!("no other error...")` 改为 `Err(InvoiceError::InvalidSignature)` 兜底。
- **AUDIT-INPUT-002-FOLLOWUP-D (🟢 Low)**: F5 — `InvoiceData::try_from` 中加 attribute discriminant 去重，使用现有 `InvoiceError::DuplicatedAttributeKey` 变体。
- **AUDIT-INPUT-002-FOLLOWUP-E (ℹ️ Info, 测试)**: F6 — 新增 `fuzz_invoice_data`（直接 fuzz `RawInvoiceData::from_slice`）和 `fuzz_invoice_attr`（直接 fuzz `InvoiceAttr::from_slice` + `Attribute::from`）以穿透 bech32m / ar_decompress 层。提供 `tests/invoice/tests/invoice_impl.rs` 中的合法 invoice 作为 corpus 种子。
- **AUDIT-INPUT-002-FOLLOWUP-F (🟢 Low, 防御)**: 在 RPC 层和 actor 层包裹 `catch_unwind` 或建立 panic-hook，确保单次 RPC 解析 panic 不会击垮整个 fiber 进程；这是临时措施，长期仍需修复源 panic 点。

**关联**：
- 与 AUDIT-INPUT-001 同源 — 都依赖 molecule 表层校验，但本审计揭示业务转换层的 `.expect()` 是另一个独立的 attack surface；
- 与 AUDIT-LOGIC-008 协同 — Invoice DoS 击垮 CCH 进程后，已 IncomingAccepted 但 outgoing 未派发的订单进入"无人值守"状态，加剧 LOGIC-008 的资金损失风险。
