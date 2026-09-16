# AUDIT-SPEC-002 — Invoice 协议规范 (`docs/specs/payment-invoice.md`) 与实现 (`crates/fiber-types/src/schema/invoice.mol` + `invoice.rs` + `fiber-lib/src/invoice/`) 一致性

- **Session**: S25
- **Date**: 2026-05-14
- **Auditor**: Phase 1 iterative audit
- **Dim**: DIM-SPEC (规范一致性)
- **Status**: ⚠️ Spec-implementation drift（与 SPEC-001 同源问题家族；与 INPUT-002 invoice DoS 形成同链）
- **Severity**: 整体 🟡 Medium / 🟡 Medium × 6 + 🟢 Low × 4 + ℹ️ Info × 1 + ✅ Pass × 6

## 范围

对照 `docs/specs/payment-invoice.md`（71 行，最末更新于 v0.6 前；仅口语化描述）与权威实现：

- `crates/fiber-types/src/schema/invoice.mol`（Molecule schema，79 行）
- `crates/fiber-types/src/invoice.rs`（解析/签名/序列化，1200 行）
- `crates/fiber-lib/src/invoice/invoice_impl.rs`（`InvoiceBuilder` 构造侧，229 行）
- 远程入口：`crates/fiber-lib/src/rpc/invoice.rs:289 parse_invoice`、`crates/fiber-lib/src/cch/actor.rs:628 CkbInvoice::from_str(receive_btc.fiber_pay_req)`

审计目标：识别**规范-实现漂移**作为攻击面 — 任何独立实现 fiber invoice 协议的第三方钱包/中转节点若严格按 `payment-invoice.md` 编码：

1. 线缆级不兼容（字段宽度 / 字段类型 / 字段集合错位） → 发送方生成的发票被收款节点拒收；
2. **规范未提及的实现行为引入安全敏感解析路径**（`expect()`/`panic!` 与压缩反序列化）→ 已在 AUDIT-INPUT-002 中记录的 invoice DoS 在此被规范缺失放大；
3. 规范缺失关键字段（`payment_secret` / 签名"未签收发票"语义）→ 引入 MPP/probing 与 invoice 真实性脱节。

## 漂移清单

实现取自 `crates/fiber-types/src/schema/invoice.mol` 与 `crates/fiber-types/src/invoice.rs`，规范取自 `docs/specs/payment-invoice.md`。

### F1 🟡 Medium — `message_hash` preimage 域歧义（spec 措辞 vs 实现 base32 padding）

- **Spec** (`payment-invoice.md:37-38`):
  > `message_hash = SHA256-hash (((human-readable part) → bytes) + (data bytes))`
- **Impl** (`invoice.rs:166-187 construct_invoice_preimage`, `:652-657 hash()`):
  ```
  preimage = hrp_bytes ‖ Vec::<u8>::from_base32(data_part_u5 ‖ pad(0..2 × u5(0)))
  hash    = SHA256(preimage)
  ```
  即"data bytes"实际是**对 ar_encompressed 字节做 base32 编码再 padding-0、再 base32 反解**得到的 byte vector。当 `data_part.len() * 5 % 8 != 0` 时附加 1 或 2 个 `u5(0)` 进行字节对齐 (`invoice.rs:171-180`)，再 `from_base32` 还原。
- **影响**:
  - 三方实现严格按 spec → `hash(hrp ‖ raw_ar_compressed_bytes)`，与本节点签名不一致 → 签名校验恒失败 → invoice 无法被本节点 `check_signature` 通过。
  - 该漂移**无资金路径**（互联失败即拒收），但 wallet/CCH 集成者需通过反复试错才能定位差异。
  - 已是 BOLT-11 同款 padding 问题（lightning-invoice 也有同款 `construct_invoice_preimage`），但 BOLT-11 spec 明确写出 padding 规则；fiber spec 没有。
- **建议**: 规范明确"`data bytes`"定义为"ar_compress(raw molecule bytes) 经 base32 编码并 zero-pad 到字节边界后再 `from_base32` 还原所得字节"。

### F2 🟡 Medium — `expiry` 宽度 32 bit (spec) vs Uint64 (impl)

- **Spec** (`payment-invoice.md:52-54`): `expiry: [optional] 32 bits`
- **Impl** (`invoice.mol:18-20`): `struct ExpiryTime { value: Uint64 }`，Rust 侧 `Attribute::ExpiryTime(Duration)` 通过 `as_secs() → u64` 编码 (`invoice.rs:971-975, 1027-1030`)。
- **影响**:
  - 三方按 32-bit 实现，写发票时 `Uint64` 字段后 4 字节 0 → molecule 兼容（unpack 仍正常）；
  - 三方按 32-bit 实现读发票，遇到 ≥ 2^32 秒（136 年）的 expiry → 32-bit truncation 静默回绕；
  - 现实风险低（rationally no 136-year invoice），但**编码/解码长期失同步**埋下安全债。
- **建议**: 规范改写为 `expiry: [optional] 64 bits (Uint64)`，单位秒明确不变。

### F3 🟡 Medium — `final htlc timeout` (spec 字段 5) 已 v0.6.0 deprecated 且未文档化替代字段 `FinalHtlcMinimumExpiryDelta`

- **Spec** (`payment-invoice.md:57-59`): 列举为 mandatory data part 第 5 项，32 bit。
- **Impl** (`invoice.rs:521-523, invoice_impl.rs:216-225`):
  - `Attribute::FinalHtlcTimeout` 标注 `#[doc = "deprecated since v0.6.0"]`；
  - `InvoiceBuilder::build` 显式 `return Err(InvoiceError::DeprecatedAttribute("FinalHtlcTimeout"))`，**任何构造尝试均被拒绝**；
  - 替代字段 `Attribute::FinalHtlcMinimumExpiryDelta`（毫秒 u64）已实装且影响 final-hop expiry 校验 (`invoice.rs:818-829 is_tlc_expire_too_soon`)。
- **影响**:
  - 三方按 spec 实现：(a) 必填 `FinalHtlcTimeout` → 接入 fiber 节点的发票一律 `DeprecatedAttribute` 拒收；(b) 不会实装 `FinalHtlcMinimumExpiryDelta` → 中转/最终跳的 expiry 边界判断退化为 `unwrap_or_default() = 0ms`，付款时 `is_tlc_expire_too_soon` 始终 false → **应早预警的过短 expiry 不再预警** → 资金锁定窗口风险。
  - 与 AUDIT-LOGIC-002（TLC / PTLC lifecycle & timelocks）和 AUDIT-LOGIC-007（cooperative close）相互关联：第三方钱包若不实装 final expiry delta 校验，会接收非常短的 TLC，被中转 hop 抢跑结算。
- **建议**: 规范第 5 项重写为 `final_htlc_minimum_expiry_delta: [optional] 64 bits, milliseconds; replaces the deprecated final_htlc_timeout (Uint32) field since v0.6.0`，并在 v0.6+ schema 表中标注 deprecated 字段。

### F4 🟡 Medium — `feature` 宽度 32 bit (spec) vs 变长 Bytes (impl) — `FeatureVector` 位语义无文档

- **Spec** (`payment-invoice.md:62-63`): `feature: [optional] 32 bits — Feature flag to specify features supported by the payment`
- **Impl** (`invoice.mol:30-32`): `table Feature { value: Bytes }`，`FeatureVector` 内部 `Vec<u8>` 任意长度；用于 `basic_mpp` / `trampoline_routing` 位 (`invoice.rs:786-799`)。
- **影响**:
  - 三方按 32-bit fixed 实现：feature bytes 截断 → 永远无法表达 `basic_mpp_optional` / `trampoline_routing_optional` 标志位（其实际位偏移见 `crates/fiber-types/src/protocol.rs` FeatureVector 实装），feature gating 失效。
  - 同时 spec 未列举任何 feature bit 含义 — F4 与 SPEC-001 F7 (Init message + features negotiation) 同源，整套 feature negotiation 在公共文档中**完全空白**。
- **建议**: 规范第 7 项改为变长 bytes 并新增 "Feature flags" 节，与 SPEC-001 FOLLOWUP-F (Init features) 共享 bit 定义表。

### F5 🟡 Medium — `payment_secret` (256-bit, MPP 必需) 在 spec 中**完全缺失**

- **Spec**: data part 字段 1–10 中**未列出**。
- **Impl** (`invoice.mol:48-50, invoice.rs:543, invoice_impl.rs:100`):
  ```
  struct PaymentSecret { value: Byte32 }
  ```
  - `InvoiceBuilder::check_attrs_valid` (`invoice_impl.rs:189-199`) 强制 `allow_mpp=true ⇒ payment_secret.is_some()`；
  - 触发 `InvoiceError::PaymentSecretRequiredForMpp`。
- **影响**:
  - 三方未实装 `PaymentSecret` → 永远无法生成 MPP-enabled invoice，无 MPP 路由能力（属于规范-implementation 漂移导致**生态级 MPP 功能缺失**）；
  - 更隐蔽：`payment_secret` 是 BOLT-11 / fiber 防 final-hop "probing" 的关键随机数（最终跳必须重放 secret 才能 settle，否则 attacker 中转 hop 不能用部分付款探测发票存在）—— **规范缺失意味着没有任何要求规定 payment_secret 必须随机/不可猜**。三方实现可能用 `payment_hash` 复用、可预测 nonce 等。
  - 与 AUDIT-LOGIC-005（MPP / Trampoline split consistency）协同 — 第三方实现易导致 fiber 网络上 MPP probing oracle 复活。
- **建议**: 规范新增字段 11 `payment_secret: [optional, MANDATORY when basic_mpp feature is set] 256 bits — A random secret to bind multi-part HTLC sets. Must be uniformly random (CSPRNG)`。

### F6 🟡 Medium — `payee_public_key` 解析 panic（spec 33 bytes vs impl 变长 Bytes + `expect`）

- **Spec** (`payment-invoice.md:64-65`): `payee_public_key: [optional] 33 bytes — The public key of the payee`
- **Impl** (`invoice.mol:38-40`): `table PayeePublicKey { value: Bytes }`（任意长度）；
  `invoice.rs:1049-1054`:
  ```rust
  InvoiceAttrUnion::PayeePublicKey(x) => {
      let value: Vec<u8> = x.value().unpack();
      Attribute::PayeePublicKey(
          PublicKey::from_slice(&value).expect("Public key from slice"),
      )
  }
  ```
- **影响**:
  - **资金侧无影响**，但远程入口 `rpc::invoice::parse_invoice` 与 `cch::actor::CkbInvoice::from_str(receive_btc.fiber_pay_req)` 任一调用方传入 `PayeePublicKey` 长度 ≠ 33 或非曲线点的恶意 invoice 字符串 → **fiber 节点进程 panic**；
  - 该缺陷已在 AUDIT-INPUT-002 (memory: "invoice parsing DoS") 中标识为远程 DoS，此处从规范角度重述：spec 写 "33 bytes" 但 Molecule schema 容忍任意长度 → 实现侧承担长度校验责任，却使用 `.expect()` panic。
- **建议**:
  - 短期 (impl): `expect` 改为 `Result` 与 `InvoiceError::InvalidPayeePublicKey`，配合 SPEC 中的 33-byte 长度声明；
  - 长期 (schema): `PayeePublicKey` 字段类型改为 `array Byte33 [byte; 33]`（参考 `fiber.mol:Pubkey` 同名定义），让 Molecule schema 在反序列化期自然强制长度，与 spec 对齐。

### F7 🟡 Medium — `fallback` 字段 spec 称 "CKB address" 实际**无任何验证 + UTF-8 panic**

- **Spec** (`payment-invoice.md:60-61`): `fallback: [optional] variable length — A CKB address used for fallback in case the invoice payment fails`
- **Impl** (`invoice.mol:26-28, invoice.rs:1039-1044`):
  ```rust
  InvoiceAttrUnion::FallbackAddr(x) => {
      let value: Vec<u8> = x.value().unpack();
      Attribute::FallbackAddr(
          String::from_utf8(value).expect("decode utf8 string from bytes"),
      )
  }
  ```
  - **任何非 UTF-8 字节序列触发进程 panic**（同 F6 的远程 DoS 模式）；
  - 解析后亦**不校验 bech32 CKB 地址格式 / 网络 prefix（mainnet vs testnet）** — `CkbInvoice` 本体可携带任意字符串 fallback。
- **影响**:
  - **DoS**: 同 F6，远程恶意 invoice 触发节点 panic；
  - **逻辑性**: 三方按 spec 实现 fallback redemption（链上付款失败后转 fallback 地址），可能把 testnet 地址当 mainnet 地址解析，资金错网 → 不可恢复损失。
- **建议**:
  - schema 改为 `table FallbackAddr { value: Script }` 或者 `Bytes` + 实现侧强制 `String::from_utf8` 返回 `Result`，并对 fallback 字符串做 `ckb_sdk::Address::from_str` 校验、`network()` 必须匹配 invoice `currency` (`Fibb=Mainnet, Fibt=Testnet`)；
  - spec 明确 "must be a bech32m CKB address of the network matching the invoice prefix"。

### F8 🟡 Medium — 签名"可选"语义模糊：spec 描述"可用于确认完整性"但 impl `check_signature` 对未签名 invoice 直接返回 `Ok(())`

- **Spec** (`payment-invoice.md:33-39`): "The secp256k1 signature of the entire invoice, can be used to verify the integrity and correctness of the invoice, may also be used to imply the generator node of this invoice. By default, this field is none."
- **Impl** (`invoice.rs:601-619`):
  ```rust
  pub fn check_signature(&self) -> Result<(), InvoiceError> {
      if self.signature.is_none() {
          return Ok(());
      }
      ...
  }
  ```
- **影响**:
  - CCH 跨链 `receive_btc` 流程 (`cch/actor.rs:628`) 解析 `fiber_pay_req`、`rpc::invoice::parse_invoice` 等下游消费者**调用 `check_signature` 后即视 invoice 为 "已验证"** —— 然而 unsigned invoice 一律 pass，"已验证" 一词具误导性；
  - 与 AUDIT-CRYPTO-004 F5 同源记录："`CkbInvoice::check_signature` silently returns Ok for unsigned invoices; CCH `ReceiveBTC` path lacks `is_signed()` guard"；
  - spec 没有声明任何路径**应**强制要求 signature（如 CCH receive_btc 必须 signed-invoice 才允许跨链结算，否则 hub 无法绑定 invoice generator）。
- **建议**:
  - spec 在 §"Signature" 段末新增 "Implementations consuming an invoice from an untrusted source (e.g., cross-chain hub, public RPC) MUST reject invoices with `signature == None`."；
  - impl 配合：CCH `ReceiveBTC` / payment.rs `send_payment` 都加 `if !invoice.is_signed() { return Err(...) }` 守卫（属 CRYPTO-004.F5 follow-up，本处 cross-reference）。

### F9 🟢 Low — `description` 长度上限 639 字节 spec 未记载

- **Spec**: `description: [optional] variable length`，无上限。
- **Impl** (`invoice.rs:128-129`): `MAX_DESCRIPTION_LENGTH = 639`；超长 → `InvoiceError::DescriptionTooLong(len)`。
- **影响**: 三方按 spec 生成 > 639 字节 description → 本节点拒收。无安全影响。
- **建议**: spec 第 4 项注 "Maximum length: 639 bytes (UTF-8)" — 与 BOLT-11 对齐。

### F10 🟢 Low — `amount` 单位 UDT 情形未规定 / 大小 (u128) 未规定

- **Spec** (`payment-invoice.md:19-21`): "A standalone number, means the amount of CKB or UDT, for CKB it will be in unit of `shannon`"。
- **Impl** (`invoice.mol:7, invoice.rs:571`): `amount: AmountOpt(Uint128)`，u128 容量。
- **缺失**:
  - UDT 单位未规定（实际由 `udt_script` 字段决定，但 spec 不交代）；
  - amount 上限 (u128 vs 32-bit/64-bit) 未规定 — 三方实现可能误判为 u64 → 大额 UDT 发票溢出。
- **建议**: spec 明确 "amount is a Uint128 quantity in the smallest unit of the asset (shannon for CKB; 1 unit of the UDT script's natural decimals otherwise)"。

### F11 🟢 Low — 重复 attribute 在解析侧不被拒绝（builder 侧拒绝）

- **Impl** (`invoice_impl.rs:201-207`): `check_attrs_valid` 在 `InvoiceBuilder::build` 中 `O(n²)` 检测重复 attribute discriminant → builder 侧严格。
- **缺失**: `CkbInvoice::from_str` (`invoice.rs:868-906`) → `TryFrom<RawInvoiceData>` → `Attribute` 序列化路径**不**执行 `check_attrs_valid`；恶意 invoice 字节流可包含同 union variant 多次出现，`payee_pub_key()` 等 getter 只 `.next()` 取第一个 → 静默忽略后续。
- **影响**:
  - 三方实现按 spec 容忍重复 attrs → 与 fiber "第一个胜出" 不一致 → 字段歧义；
  - 安全侧：低（fiber 一致地"第一个胜出"，但 spec 应明文）。
- **建议**: spec 新增 "Each optional attribute MUST appear at most once. Duplicate attributes MUST be rejected."，impl 在 `TryFrom<RawInvoiceData>` 入口复用 `check_attrs_valid`。

### F12 🟢 Low — HODL invoice `payment_hash = blake2b_256(preimage)` (spec) 与 `HashAlgorithm` (impl 0=blake2b/1=sha256) 描述脱节

- **Spec** (`payment-invoice.md:50`): "If creating a `HODL` invoice, a `preimage` parameter must be provided, and the `payment_hash` is generated using `blake2b_256(preimage)` when the invoice is created."
- **Spec** (`payment-invoice.md:68-71`): `hash_algorithm: 0: ckb hash / 1: sha256`。
- **Impl** (`invoice_impl.rs:146-156`): `HODL` 路径使用 `hash_algorithm.hash(preimage)`，即**用户选的 HashAlgorithm**，不是固定 blake2b_256。
- **影响**: 三方按 spec 实现 HODL 固定 blake2b_256，生成发票后无法被实装 `Sha256` 的对端节点结算（payment_hash 不匹配）。
- **建议**: spec §HODL 段改 "the `payment_hash` is generated using the algorithm specified by `hash_algorithm`（default `ckb hash`/blake2b_256）".

### F13 ℹ️ Info — 规范无版本号 / 无 "data byte length 上限" 规定

- spec 文档头无 `version:` 与日期；与 SPEC-001 同类（FOLLOWUP-I）。
- 无 invoice 总长度上限规定，远程 `parse_invoice` 接受任意大字符串 → 配合 `ar_decompress` (`invoice.rs:887` `.expect("decompress invoice data")`) 与 AUDIT-INPUT-002.F1 形成已知 DoS；本审计仅交叉引用，不重复评分。
- **建议**: spec 新增 "The encoded invoice MUST NOT exceed 7090 bech32 characters (matching BOLT-11 limit) to prevent unbounded decompression DoS"，并指向 INPUT-002 follow-up。

## ✅ Pass / 一致项

- **HRP prefix mapping** (`payment-invoice.md:15-18` vs `invoice.rs:270-281`): `fibb`/`fibt`/`fibd` 三 currency 一致 ✓
- **Timestamp** (`spec:46` vs `invoice.mol:69, invoice.rs:551-552`): 128 bits milliseconds since 1970 ✓
- **Payment hash** (`spec:49` vs `invoice.mol:3, invoice.rs:554`): 256-bit `Byte32` ✓
- **Encoding scheme** (`spec:25-29` vs `invoice.rs:846-862, 868-906`): `bech32m` (variant) + `arcode` 压缩，明确拒绝 `Variant::Bech32` (legacy) — 优于 BOLT-11 仅 bech32 的设计 ✓
- **Signature size** (`spec:33`: 65 bytes vs `invoice.mol:4, invoice.rs:126`): 65 bytes compact + 104 u5 base32, OK ✓
- **HashAlgorithm enum mapping** (`spec:68-71` vs `invoice.rs:296-323`): 0=ckb_hash(blake2b_256)/1=sha256 byte 值一致 ✓

## 协同攻击链 / 资金影响

- **L1 (spec-following peer 拒收)** F2/F3/F4 任意一处 wire 失同步 → 三方按 spec 生成的发票被 fiber 节点拒收（DescriptionTooLong, DeprecatedAttribute, Bech32Error, etc.）。**第三方自伤**，fiber 本身免疫。Severity Low。
- **L2 (远程进程崩溃)** F6 (`PayeePublicKey::from_slice.expect`) + F7 (`String::from_utf8.expect` on FallbackAddr) + F13 (`ar_decompress.expect`) 三处任一可被恶意 invoice 字符串通过 RPC `parse_invoice` / `CCH receive_btc` 触发 → fiber 节点进程崩溃 → **资金通道 force-close（commitment 失同步），watchtower 离线，gossip 网络断流**。已在 AUDIT-INPUT-002 中评 High；本处 spec 角度强调 "schema 已声明长度（33 bytes）但反序列化不强制" 的修复责任分摊问题。Severity High（跨章节继承）。
- **L3 (MPP probing 复活)** F5 `payment_secret` spec 缺失 + F8 unsigned invoice silently passed → 三方实现的发票生成器可能用可猜 payment_secret 或省略 payment_secret，配合 fiber `InvoiceExpired` / `InvoiceCancelled` final-hop 错误码（AUDIT-LOGIC-006 / memory: "payment error codes"）形成网络性 probing oracle，泄露发票存在 / 状态。Severity Medium（隐私损失，不直接资金损失）。
- **L4 (跨网络 fallback 资金错放)** F7 fallback 字段无 network 校验 → 三方在 mainnet 发票里塞 testnet fallback address，付款失败时落 fallback → testnet 地址无人持有 → 资金永久锁定。Severity Medium（罕见但可能）。

## 修复建议（按优先级）

| ID | 优先级 | 描述 | 工作量 |
|---|---|---|---|
| FOLLOWUP-A | 🟡 Medium | 重写 `payment-invoice.md` data part 章节，对齐 `invoice.mol`：删除 `final_htlc_timeout`、引入 `final_htlc_minimum_expiry_delta: Uint64 ms`、`payment_secret: Byte32`、把 `expiry` 改 Uint64、把 `feature` 改变长 Bytes（与 SPEC-001 FOLLOWUP-F 共享 feature bit 表）。涵盖 F2/F3/F4/F5。 | 1-2 小时文档 |
| FOLLOWUP-B | 🟠 High | impl 把 `invoice.rs:1023, 1042, 1052, 887` 四处 `.expect()` 改为 `Result`-返回，建立 `InvoiceError::InvalidPayeePublicKey / InvalidFallbackAddr / InvalidUtf8 / DecompressionFailed`，并修改 `From<InvoiceAttr>` 为 `TryFrom`。涵盖 F6/F7/F13 + INPUT-002 follow-up。 | 1 天工程 + tests |
| FOLLOWUP-C | 🟡 Medium | Molecule schema 收紧：`PayeePublicKey { value: Bytes }` → `array PayeePublicKey [byte; 33]`；`FallbackAddr { value: Bytes }` 保留 Bytes 但配合 impl `Address::from_str` + `currency.network()` 校验。涵盖 F6/F7。**注**: schema 改动 = wire-breaking → 走 migration archive 路线，与 STORE-001/INPUT-002 协调。 | 半天工程 + 迁移 |
| FOLLOWUP-D | 🟡 Medium | impl `TryFrom<RawInvoiceData>` 入口复用 `check_attrs_valid`，拒绝重复 attr；spec §Data Part 加 "Each attribute MUST appear at most once"。涵盖 F11。 | 2 小时 |
| FOLLOWUP-E | 🟡 Medium | spec §Signature 增 "Implementations consuming invoices from untrusted sources MUST reject `signature == None`"；CCH `ReceiveBTC` / `send_payment` 增 `is_signed()` 守卫。涵盖 F8（亦是 CRYPTO-004.F5 收敛）。 | 半天 |
| FOLLOWUP-F | 🟡 Medium | spec §HRP 修正 amount 单位 / u128 容量；§HODL 修正 hash 来源为 `hash_algorithm`；§"Encoding and Decoding" 明确"data bytes"是 base32-padded-then-from_base32 字节。涵盖 F1/F10/F12。 | 1 小时文档 |
| FOLLOWUP-G | 🟢 Low | spec §description 加 "Maximum length: 639 bytes UTF-8" + §"Invoice total size" 加 7090-char 总上限。涵盖 F9/F13。 | 半小时 |
| FOLLOWUP-H | ℹ️ Info | spec 文档头加 `version:` + `last-updated:` 字段；CI 增加 `tools/check-spec-impl-drift.sh` invoice 子目录变体（与 SPEC-001 FOLLOWUP-I 复用同一脚本） | 1 小时工程 |

## 整体评价

`docs/specs/payment-invoice.md` 现状是 **v0.5 设计快照**（71 行，简短到接近"草案"水平），相对当前 `invoice.mol` + `invoice.rs` 已出现 **6 处中等漂移**（F1/F2/F3/F4/F5/F6/F7/F8 部分含安全语义）和 **4 处低危漂移**（F9/F10/F11/F12，主要为字段约束与边界条件未规定）。

**正面**:

- 实现侧的 HRP / 时间戳 / payment_hash / bech32m / arcode 压缩 / 签名核心算法 6 项一致；
- `InvoiceBuilder::check_attrs_valid` 与 `MAX_DESCRIPTION_LENGTH` 等安全守卫已在 builder 侧建立 — 仅缺解析侧对称（FOLLOWUP-D）；
- 弃用字段（`FinalHtlcTimeout`）以 explicit `DeprecatedAttribute` error 拒绝构造，比 silent-ignore 更稳。

**负面**:

- 公共规范文档严重落后于实现，签名 preimage 域、`payment_secret`、`final_htlc_minimum_expiry_delta` 等关键字段公共文档**完全缺失**；
- 多个 `.expect()` panic 在 spec 容忍的字段宽度（33B / 变长 / 压缩流）边界处发生 → spec-implementation 责任分摊不清是 INPUT-002 invoice DoS 长期未修的根因；
- CCH 跨链 hub 与 RPC `parse_invoice` 是最远的远程入口，spec 不规定"untrusted-source 必须签名"令上游集成者难以正确实施信任决策。

无直接 fiber 节点资金损失（仅 force-close 风险经由 L2 panic 链产生），但**集成者侧资金损失风险高**（L4 跨网络 fallback）。

主要 deliverable：8 项 FOLLOWUP（A-H），其中 FOLLOWUP-B (impl `.expect` 移除) 优先级最高，与 INPUT-002 / CRYPTO-004 follow-ups 形成同条修复链。
