# AUDIT-ERR-002 — 日志/tracing 中的敏感信息

- **维度**: DIM-ERR (observability / log hygiene)
- **严重级别**: 🟡 **Medium**（Medium × 1 + Low × 3 + Info × 2 + Pass × 3）
- **审计 Session**: S16 (2026-05-14)
- **关联代码**:
  - 初始化:
    - `crates/fiber-bin/src/main.rs:38,84-89` — `tracing_subscriber::fmt() + EnvFilter::from_default_env()` (默认 `ERROR` level，无独立 sink，未启用 `JsonLayer`/redaction layer)
  - 敏感类型 Debug/Display:
    - `crates/fiber-types/src/primitives.rs:215-217` — `Privkey(pub SecretKey)` `#[derive(Debug)]` 使用 secp256k1 0.30 内置 `#REDACTED#` Debug 实现 ✓
    - `crates/fiber-types/src/primitives.rs:263-369` — `Hash256` Debug/Display **完整 hex** 输出 (`Hash256(0x{hex})`)，被广泛用作 `payment_hash` / `channel_id` / `commitment_tx_hash`
  - 已识别的可疑日志点:
    - `crates/fiber-lib/src/rpc/biscuit.rs:234-235` — `tracing::debug!("revoked token: {token}")` + `anyhow!("Token is in revocation list: {token}")` (与 AUDIT-AUTH-001.F4 同条记录)
    - `crates/fiber-lib/src/rpc/biscuit.rs:260` — `tracing::warn!("fetch {id:?} {node_id:?}");` **leftover 调试代码** (`extract_node_id`)
    - `crates/fiber-lib/src/watchtower/actor.rs:181` — `tracing::error!("CreatePreimage with wrong preimage, payment_hash: {payment_hash:?} preimage: {preimage:?}");`
    - `crates/fiber-lib/src/watchtower/actor.rs:740` — `warn!("Found a preimage for payment hash: {:?}, but not match the tlc, ..." payment_hash, tx.calc_tx_hash())`
    - `crates/fiber-lib/src/fiber/network.rs:5413` — `error!("Payment success but no preimage found for {payment_hash}")` (仅 payment_hash 无 preimage — 可)
  - 用户已记录的同质 fact:
    - AUDIT-AUTH-001.F4 (biscuit.rs:234) - token 全量入 debug log + anyhow Error chain
    - AUDIT-INPUT-002.F1/F2/F3 - panic 信息流可能携带 invoice 字段

## 1. 审计目标

Lightning / 支付节点的日志安全模型：

1. **绝对禁止泄露**：私钥、preimage（未 settled 前）、密码、撤销密钥、commitment_seed、token、API key。
2. **最小化泄露**：payment_hash / channel_id / pubkey — 这些虽然在协议中明文传输，但本地 log 文件比磁盘 store 更易被泄露（log aggregator / 错配权限 / unintended export）。
3. **完整记录**：错误根因、状态变迁、可观测性指标。

具体审计项：

- a. 默认 tracing filter 与 `RUST_LOG` 默认行为；
- b. `Privkey` / `SecretKey` / `Preimage` / `Hash256` / `Pubkey` 等敏感类型 `Debug`/`Display` 实现是否安全；
- c. 各模块的 `info!`/`warn!`/`error!` 是否在生产可能开启级别上携带敏感数据；
- d. 错误链（`anyhow::Error` / `thiserror`）是否把敏感字段冒泡到调用方日志；
- e. RPC 服务在错误响应中是否回显敏感数据（与 INPUT-003 接续）。

## 2. 系统性梳理

### 2.1 默认 logging 配置

`crates/fiber-bin/src/main.rs:84-89`:

```rust
fmt()
    .with_env_filter(EnvFilter::from_default_env())
    .pretty()
    .fmt_fields(node_formatter)
    .try_init()
```

`EnvFilter::from_default_env()` 在 `RUST_LOG` 未设置时取**全局默认级别 ERROR**。这意味着：

- `tracing::debug!("revoked token: {token}")` 在生产默认配置下**不输出**；
- 但运维若设置 `RUST_LOG=info` / `RUST_LOG=debug` / `RUST_LOG=fnn=debug` 调试，debug! 立即激活；
- 默认 `pretty()` formatter 输出多行人类可读格式，不是 JSON — 不便机器化二次过滤。

**风险定位**：log redaction 必须发生在**`tracing::*!` 调用点**，不能依赖运维"不开 debug"作为最后防线。

### 2.2 敏感类型的 Debug/Display 实现

| 类型 | Debug 实现 | Display | 安全性 |
|---|---|---|---|
| `Privkey(SecretKey)` | `#[derive(Debug)]` → 委托 secp256k1 0.30 `SecretKey::Debug` → `"#REDACTED#"` | 无 | ✅ Pass — secp256k1 ≥0.27 自带 redaction |
| `Hash256([u8; 32])` | 手动 impl, 完整 hex `Hash256(0x{hex})` | 同上 | ⚠️ 完整泄露 — 但用于 payment_hash / channel_id 等协议公开值 |
| `Pubkey` | 来自 `tentacle_secio::PublicKey` 或 secp256k1 — 输出公钥 hex | - | ⚠️ 公开值 |
| `Preimage` | 通过 `Hash256` 表示 (`payment_preimage: Hash256`) — Debug 完整 hex | - | ❌ **如果 Preimage 用 Hash256 类型 → `{:?}` 直接泄露** |
| `NodeId` | 来自 `parse::<NodeId>` 字符串 — Debug 字符串内容 | - | ⚠️ |
| `Privkey::from_slice` 等 | 不携带原值 | - | OK |

**关键发现**：`Preimage` 在 fiber 中没有独立类型，与 `payment_hash` 共用 `Hash256`（见 `fiber-lib/src/store/store_impl/mod.rs:799,837` 与 watchtower 类型 `RemoteSettlementData::payment_preimage: Hash256`）。这意味着任何 `preimage: Hash256` 上的 `{:?}` 都会**完整十六进制泄露**。

### 2.3 已识别的有问题日志点

#### A. `rpc/biscuit.rs:260` — leftover 调试 `warn!`

```rust
pub fn extract_node_id(token: &Biscuit) -> Result<NodeId> {
    const QUERY: &str = "data($id) <- node($id)";
    let (id,): (String,) = token.authorizer()?.query_exactly_one(QUERY)?;
    let node_id = NodeId::from_str(id.as_str())?;
    tracing::warn!("fetch {id:?} {node_id:?}");  // ← 留下的调试代码
    Ok(node_id)
}
```

- 每次启用 biscuit auth 的 RPC 请求成功通过 `require_rpc_context` rule 时（watchtower 全部方法）都会 `warn!`；
- WARN 级别**默认就输出** (`EnvFilter::from_default_env()` 也会让 WARN 通过任何级别 ≥ ERROR 的设置，且很多运维设置 `RUST_LOG=info` 时会输出 INFO+WARN+ERROR)；
- 内容是 `node_id` 字符串 — 等价于 `Pubkey` hex；
- 单看每次输出无害（pubkey 公开），但**每次** RPC 请求生成一条 WARN 行 → log 噪声 + 攻击者通过日志容易枚举 watchtower 接入的客户端节点身份。

应改为 `tracing::trace!` 或直接删除。

#### B. `watchtower/actor.rs:181` — `error!` 输出 preimage 全文

```rust
WatchtowerMessage::CreatePreimage(payment_hash, preimage) => {
    if HashAlgorithm::supported_algorithms()
        .iter()
        .any(|algorithm| payment_hash == algorithm.hash(preimage).into())
    {
        self.store.insert_watch_preimage(NodeId::local(), payment_hash, preimage);
    } else {
        tracing::error!(
            "CreatePreimage with wrong preimage, \
             payment_hash: {payment_hash:?} preimage: {preimage:?}"
        );
    }
}
```

ERROR 级别在任何 RUST_LOG 设置下都会输出。该分支的进入条件是"preimage 与 payment_hash **不匹配**"，因此泄露的 preimage 实际上**不能**解锁该 payment_hash 的 TLC（与 `payment_hash` 算法签匹配的 preimage 在合并 if 中被接受了）。但：

1. **多算法误用**：fiber 支持 `HashAlgorithm::supported_algorithms()`（CkbHash + Sha256）。攻击者若以 `payment_hash = sha256(P)` 注册 invoice 但通过 watchtower API 提交 `(payment_hash, P)` 时，路径都是匹配的；只有当 caller 提交完全错误的 preimage 时才进 else 分支。该 preimage 对**目标支付**无效，但对**其它**未来的支付仍可能是合法值（攻击者可批量提交"测试" preimage 触发 log）。
2. **配合 log aggregator**：日志若被 ship 到 third-party (Datadog/Loki)，preimage 进入第三方系统。即使 preimage 此刻无效，未来若同一字节流被重新用作另一支付的 preimage，attacker 已经在 log 里有它。
3. **配合 STORE-001.F1 (DB 文件权限默认 0644)**：本地用户读 store + 读 log → 完整 preimage / payment_hash 配对集。

修复：仅打印 payment_hash，preimage 部分用 `<redacted, len={preimage.len()}>` 或完全省略。

#### C. `watchtower/actor.rs:740` — `warn!("Found a preimage for payment hash: {:?}, but not match the tlc ...")`

```rust
warn!(
    "Found a preimage for payment hash: {:?}, but not match the tlc, tx hash: {:?}",
    payment_hash,
    tx.calc_tx_hash()
);
```

这里 `payment_hash` 是 `Byte32` 类型（链上 witness 解析出的）— Debug 完整 hex。preimage 本身不在 log 里 ✓。**但**该日志由 watchtower 在扫链时触发，"找到 preimage 但 hash 不匹配"通常意味着 watchtower 当前的 TLC 列表 stale：链上 commitment tx 的 hash 是真实的，watchtower 本地 tlc 列表过时。WARN 级别默认输出 → 攻击者可通过观察该 log 推断 watchtower 同步状态延迟（与 force-close 攻击窗口相关）。

属信息泄露 (Info)，但本质是 watchtower 内部协议事件 — 保留 payment_hash 用于调试是合理的。

#### D. `rpc/biscuit.rs:234-235` — 已记录 in AUDIT-AUTH-001.F4

```rust
tracing::debug!("revoked token: {token}");
return Err(anyhow::anyhow!("Token is in revocation list: {token}"));
```

- debug! 默认不输出 ✓；
- 但 `anyhow!("... {token}")` 把 token 拼入 Error.Display → 后续 `middleware.rs:88 tracing::debug!("Failed check_permission #{err:?}");` 在 debug 级别下泄露；
- 更严重：rpc/utils.rs 的 `rpc_error_no_data` 把 anyhow Error 转 JSON-RPC error → 攻击者**远程** RPC 调用得到 `"Token is in revocation list: <full-token>"` 错误响应。

修复：error message 不应包含 token 字面值；token 自身 hash/前 8 字节即可定位。

#### E. `rpc/middleware.rs:88` — 错误 `{err:?}` 链式泄露

```rust
Err(err) => {
    tracing::debug!("Failed check_permission #{err:?}");
    return false;
}
```

`err` 是从 `check_permission_with_time` 冒泡的 `anyhow::Error`。错误链包含 D 中的 token 文本（若是 revoked token 路径）或 biscuit 库错误（这些通常不含敏感数据）。debug! 级别 → 默认不出，开启 debug 时泄露。

### 2.4 安全的部分

#### Pass-1. `Privkey` Debug 来自 `secp256k1 0.30`

`Cargo.lock` 中 `secp256k1 0.30.0`. 该版本 `SecretKey` Debug impl:

```rust
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SecretKey").finish_non_exhaustive()
    }
}
```

输出 `SecretKey { .. }` — 不含 key 内容。fiber 的 `Privkey(pub SecretKey)` `#[derive(Debug)]` 委托此实现 → `"Privkey(SecretKey { .. })"` ✓ 安全。

#### Pass-2. `commitment_seed` 不在任何 `*!` 调用中

grep 全局：`commitment_seed` 仅在 `channel.rs` ChannelActorState 字段 + `derive_*` 派生路径中出现，**没有任何 logging 调用引用它**。✓

#### Pass-3. wallet 解密路径

`utils/encrypt_decrypt_file.rs:13-53` 中 `password: &[u8]` 与 `key: Key<Aes256Gcm>` 均不进入任何 `tracing::*!`。`.expect("checked output key length")` panic 消息不含 password。✓

### 2.5 攻击者视角对照

| 攻击者目标 | 路径 | 是否成立 |
|---|---|---|
| 通过日志获取 Privkey | secp256k1 Debug redacts | ❌ 不成立 ✓ |
| 通过日志获取 commitment_seed | 无 logging 引用 | ❌ 不成立 ✓ |
| 通过日志获取 password / API key | 无 logging 引用 | ❌ 不成立 ✓ |
| 通过 RPC 错误响应获取 biscuit token | `anyhow!("... {token}")` 透传到 JSON-RPC error data | ⚠️ 部分成立 (debug! 默认关; anyhow error 走 RPC error 路径) — AUTH-001.F4 |
| 通过 log 获取无效 preimage | watchtower/actor.rs:181 `error!` ERROR 级别 | ✅ 成立 — **F1** |
| 通过 log 枚举 watchtower 接入的 node_id | biscuit.rs:260 `warn!` WARN 级别 | ✅ 成立 — **F2** |
| 通过 RPC error data 获取 invoice 内部 panic 字符串 | INPUT-002 主路径（panic 后 jsonrpsee 截获） | ⚠️ jsonrpsee 把 panic 转为通用 -32603 — 不直接泄露 panic message ✓ |

## 3. 发现

### 3.1 F1 (🟡 Medium) — `watchtower/actor.rs:181` 用 ERROR 级别日志输出 preimage 全文

**位置**：`crates/fiber-lib/src/watchtower/actor.rs:181`

#### 问题

```rust
tracing::error!("CreatePreimage with wrong preimage, payment_hash: {payment_hash:?} preimage: {preimage:?}");
```

- ERROR 级别默认输出（任何 `RUST_LOG` 设置）；
- `preimage:?` 用 `Hash256` 的 Debug 实现，输出完整 32 字节 hex；
- 该分支仅在 caller-provided preimage 与 payment_hash 不匹配时进入；
- **但**：
  1. preimage 字节本身可能在未来用作其它支付的 preimage（preimage 是 caller 任意选择的随机字节）；
  2. log aggregator/Datadog/Loki 集中存储 → 第三方持有 preimage 字节集合；
  3. 与 STORE-001.F1 (DB 0644) / 同主机多租户 (INPUT-003.F5) 协同 → 本地用户拼接 log + store 即可枚举 preimage/payment_hash 对；
  4. 该日志由可远程调用的 watchtower RPC `create_preimage` 路径触发（rpc/watchtower.rs:246-266 + 经 actor 路径）— **攻击者可主动诱导**。

#### 修复

```rust
tracing::error!(
    "CreatePreimage with wrong preimage, payment_hash: {payment_hash:?} preimage_len: {}",
    preimage.as_ref().len()
);
```

或彻底删除 preimage 字段。

**评级**：🟡 **Medium** — 默认 ERROR 级别输出 + 远程可诱导 + 字节字面值，符合"敏感数据泄露"标准。

### 3.2 F2 (🟢 Low) — `rpc/biscuit.rs:260` leftover 调试 `warn!("fetch {id:?} {node_id:?}")`

**位置**：`crates/fiber-lib/src/rpc/biscuit.rs:260`

#### 问题

```rust
pub fn extract_node_id(token: &Biscuit) -> Result<NodeId> {
    ...
    let node_id = NodeId::from_str(id.as_str())?;
    tracing::warn!("fetch {id:?} {node_id:?}");  // 留下的调试
    Ok(node_id)
}
```

- WARN 级别默认输出；
- 每次 `require_rpc_context` rule 命中的 RPC 请求都生成一条；
- 内容是 pubkey hex（公开值），但**生成噪声**+**便利日志侧攻击者枚举接入客户端**；
- 显然是开发期遗留 — 应改 `trace!` 或删除。

#### 修复

```rust
tracing::trace!("extract_node_id: {id:?}");
```

或删除整行。

**评级**：🟢 **Low** — 非秘密数据；噪声 + 弱信息泄露。

### 3.3 F3 (🟢 Low) — `rpc/biscuit.rs:234-235` token 进入 anyhow Error 链 → 远程错误响应回显

**位置**：`crates/fiber-lib/src/rpc/biscuit.rs:234-235`

（与 AUDIT-AUTH-001.F4 部分重复，从 log/error-message 维度补强）

#### 问题

```rust
tracing::debug!("revoked token: {token}");
return Err(anyhow::anyhow!("Token is in revocation list: {token}"));
```

- debug! 默认关 ✓；
- 但 `anyhow!("... {token}")` 是 **Error Display 内容**，会沿 `check_permission → middleware.auth_call → MethodResponse::error → JSON-RPC error.message` 路径被远程客户端看见（取决于 jsonrpsee error mapping）。
- token 是 base64-encoded biscuit — 持有该 token 的攻击者**已经**用它了一次（被拒），但 log/error response 把它转储到任何能看见错误的中间组件（reverse proxy log、CDN、客户端浏览器 console）。

#### 修复

```rust
let token_hint = &token.get(..8.min(token.len())).unwrap_or("");
return Err(anyhow!("Token is in revocation list (prefix: {token_hint}...)"));
```

并把 debug! 改为 `trace!`。

**评级**：🟢 **Low** — token 本来就在 attacker 手中；但跨系统传播扩大了泄露面，违反"最小化敏感数据流通"原则。

### 3.4 F4 (🟢 Low) — `Hash256` 默认 Debug 输出完整 hex 导致 `preimage: Hash256` 误用风险

**位置**：`crates/fiber-types/src/primitives.rs:358-362` + 多处 `payment_preimage: Hash256`

#### 问题

`Preimage` 在 fiber 中没有独立类型，与 `payment_hash` / `channel_id` / `tx_hash` 等公开值共用 `Hash256`。`Hash256::Debug` 输出完整 hex：

```rust
impl ::core::fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Hash256({:#x})", self)
    }
}
```

任何 `tracing::*!("...{preimage:?}", preimage)` 自动输出完整 32 字节 — **F1 就是这个模式的具体实例**。未来开发者很容易再写出类似 log，类型系统**没有**任何防护。

LN 主网实现（rust-lightning）定义独立 `PaymentPreimage` newtype 且 `Debug` impl redact 中段或全部。

#### 修复（防御性，长期）

```rust
// 新增 fiber-types/src/primitives.rs:
pub struct PaymentPreimage(Hash256);
impl fmt::Debug for PaymentPreimage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // 仅显示前 4 字节用于调试关联
        let bytes: &[u8] = self.0.as_ref();
        write!(f, "PaymentPreimage({:02x}{:02x}{:02x}{:02x}…)", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}
```

然后逐步迁移 `payment_preimage: Hash256` → `PaymentPreimage`。短期内代价高，建议至少在 ERROR-002-FOLLOWUP 中列出，配 lint。

**评级**：🟢 **Low** — 设计层防护缺失；F1 是已知实例。

### 3.5 F5 (ℹ️ Info) — 默认 logging filter `EnvFilter::from_default_env()` 在 `RUST_LOG` 未设时是 ERROR-only

**位置**：`crates/fiber-bin/src/main.rs:85`

`from_default_env()` 在 `RUST_LOG` 缺省时返回 `EnvFilter::new("error")` — 即仅输出 ERROR 级别。这一个：

- 优点：debug!/trace! 默认安静，含敏感数据的 debug! 不外泄；
- 缺点：生产事故时缺乏可观测性，运维易设置 `RUST_LOG=info` 或 `RUST_LOG=debug` → 上面 F2/F3 全部激活；
- 缺乏明显的"默认 info"文档/提示。

#### 建议

将默认改为 `info`（参考 ckb-node），并：
- 显式拒绝在 `info` 默认下输出含敏感字段的 debug 信息；
- 文档说明 `RUST_LOG=debug` 会输出哪些字段。

**评级**：ℹ️ Info — 默认安全但 UX 差，是个权衡问题。

### 3.6 F6 (ℹ️ Info) — 缺少 redaction layer / Json formatter / structured fields

**位置**：`crates/fiber-bin/src/main.rs:84-89`

当前 formatter：

- `pretty()`：多行人类可读，不便机器化二次过滤；
- 没有 `tracing_subscriber::filter::Filter` 或自定义 `Layer` 做敏感字段重写；
- 没有 JSON 输出选项（log aggregator 友好）；
- 没有 `tracing::field::display` / `Empty` 用于在 high-level 字段内置 redaction。

LN 类节点通常会用结构化 + 字段级 redaction（rust-lightning 内部使用 `LogRecord` 带 `level` 与 `module`、不直接 `Display` 敏感字段；c-lightning 使用 `log-level-overrides`）。

#### 建议

- 加 `--log-format json` 选项（feature `tracing-subscriber/json`）；
- 加 redaction layer：扫描 `format_args!` 输出，若匹配 `Hash256(0x...)` 模式且字段名为 `preimage`/`*_secret` 则替换为 `<redacted>`。

**评级**：ℹ️ Info — 工程提升，不是漏洞。

### 3.7 F7 (✅ Pass) — `Privkey` Debug 委托 secp256k1 0.30 redaction

`secp256k1 0.30.0` `SecretKey::Debug` 输出 `"SecretKey { .. }"`（finish_non_exhaustive）。fiber `Privkey(pub SecretKey) #[derive(Debug)]` → `"Privkey(SecretKey { .. })"`。✓

### 3.8 F8 (✅ Pass) — `commitment_seed` / wallet password 不进入任何 logging 调用

grep 全局：

- `commitment_seed` 仅在 `ChannelActorState` 字段与 `derive_*` 派生中出现，**0 处 `tracing::*!` 引用**；
- `password` 仅在 `utils/encrypt_decrypt_file.rs` 参数和 scrypt 调用中，**0 处 logging**；
- `FIBER_SECRET_KEY_PASSWORD` env 变量读取后立即 zeroize 路径。

### 3.9 F9 (✅ Pass) — `tracing::error!`/`panic!` 不携带额外栈变量内容

Rust panic backtrace 不会自动展开 local 变量；fiber 的 `expect("...")` 字符串均为静态文本或仅含类型边界值（如 line numbers / lengths），不携带 secret 数据。✓

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — `watchtower/actor.rs:181` ERROR 级别输出 preimage 全文 | 🟡 Medium | ❌ 未修复 |
| F2 — `rpc/biscuit.rs:260` leftover `warn!("fetch {id:?} {node_id:?}")` | 🟢 Low | ❌ 未修复 |
| F3 — `rpc/biscuit.rs:234-235` token 进入 anyhow Error 链 → 远程错误响应回显 | 🟢 Low | ❌ 未修复（与 AUTH-001.F4 同条） |
| F4 — `Hash256` Debug 完整 hex + `Preimage` 与公开 hash 共用类型 → 未来 log 泄露隐患 | 🟢 Low | ❌ 未修复 |
| F5 — `EnvFilter::from_default_env()` 默认 ERROR-only — UX/可观测性差 | ℹ️ Info | — |
| F6 — 缺少 redaction layer / JSON formatter / 字段级过滤 | ℹ️ Info | — |
| F7 — `Privkey` Debug 来自 secp256k1 0.30 redaction | ✅ Pass | — |
| F8 — `commitment_seed`/password 不在任何 `*!` 调用 | ✅ Pass | — |
| F9 — panic backtrace 不展开 local 变量；`expect("...")` 字符串静态 | ✅ Pass | — |
| 整体 | 🟡 **Medium** | ❌ |

### 总体评价

fiber 的日志层在"机密性维度"基础保护良好：

- 核心密钥类型 (`Privkey` / `commitment_seed` / password) 均未流入日志；
- secp256k1 0.30 + 编写者纪律配合得当；
- 默认 filter ERROR-only 限制了 debug! 路径泄露面。

**主要缺口集中在三处**：

1. **F1**：watchtower 一个 ERROR 级别 `tracing::error!` 直接打印 preimage 字面值，是当前唯一明确的"敏感字节进入默认输出"路径；
2. **F2**：biscuit.rs 一个 leftover `warn!` 在每次 watchtower 鉴权 RPC 都生成 node_id；
3. **F3**：token 通过 `anyhow!` 进入 Error Display，被远程 RPC 错误响应回显（AUTH-001.F4 镜像）。

**结构性缺口**（F4/F6）：缺少独立 `PaymentPreimage` 类型 + 缺 redaction layer，意味着未来的开发者很容易再写出"Hash256 当 preimage 直接 `{:?}` log"的代码。

修复成本：F1/F2/F3 各 1-3 行；F4 需要类型重构（中期）；F5/F6 是 UX/工程改进。

## 5. Follow-ups

- **AUDIT-ERR-002-FOLLOWUP-A (🟡 Medium, 必修)**: F1 — `watchtower/actor.rs:181` `error!` 移除 `preimage:?` 字段，只保留 payment_hash + preimage_len。
- **AUDIT-ERR-002-FOLLOWUP-B (🟢 Low)**: F2 — `rpc/biscuit.rs:260` `warn!` 改 `trace!` 或删除。
- **AUDIT-ERR-002-FOLLOWUP-C (🟢 Low)**: F3 / 与 AUTH-001-FOLLOWUP-D 合并 — `anyhow!("Token is in revocation list: {token}")` 改为只含前 8 字符 hash/前缀；`debug!("revoked token: {token}")` 改为 `trace!` 或仅 prefix。
- **AUDIT-ERR-002-FOLLOWUP-D (🟢 Low, 中期)**: F4 — 引入 `PaymentPreimage` newtype 包裹 `Hash256`，自定义 `Debug` redact 中段；逐步迁移 `payment_preimage: Hash256` 字段。配 clippy lint 禁用 `payment_preimage:?` 模式（custom lint）。
- **AUDIT-ERR-002-FOLLOWUP-E (ℹ️ Info)**: F5 — 默认 filter 升 `info`；文档说明 `RUST_LOG=debug` 会激活哪些字段。
- **AUDIT-ERR-002-FOLLOWUP-F (ℹ️ Info)**: F6 — 加 `--log-format json` 选项；加 redaction tracing layer（扫描 `Hash256(0x...)` × 字段名为 preimage/secret → 替换 `<redacted>`）。

**关联**：
- F1 与 **AUDIT-STORE-001.F1**（DB 文件 0644）和 **AUDIT-INPUT-003.F5**（同主机多租户）协同：本地 user 同时读 log + store → 完整 preimage 数据集；
- F3 是 **AUDIT-AUTH-001.F4** 在 ERR 维度的镜像（同一 line of code，不同评估视角）；
- F4 与 **AUDIT-AUTH-002**（peer identity）联动：未来若引入 onion preimage、blinding factor 等，类型保护需提前到位；
- F6 与 **AUDIT-DEP-001** 的 tracing-subscriber 升级跟踪挂钩。
