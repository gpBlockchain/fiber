# AUDIT-INPUT-004 — 存储反序列化 (bincode) 与迁移

- **维度**: DIM-INPUT (storage deserialization) ∩ DIM-LOGIC (migration framework)
- **严重级别**: 🟡 **Medium**（Medium × 2 + Low × 3 + Info × 2 + Pass × 2）
- **审计 Session**: S18 (2026-05-14)
- **关联代码**:
  - `crates/fiber-store/Cargo.toml:25` — `bincode = "1.3.3"`
  - `crates/fiber-lib/src/store/store_impl/mod.rs:121-132` — `serialize_to_vec`/`deserialize_from` panic-on-error wrappers
  - `crates/fiber-lib/src/store/store_impl/mod.rs:167-320` — `check_validate` 全局校验入口
  - `crates/fiber-store/src/migration.rs:41-312` — Migration framework
  - `crates/fiber-store/src/migrations/mig_20260511_channel_connectivity_state.rs:1-99` — 已存在的字段新增型迁移
  - `crates/fiber-store/build.rs:1-90` — 自动 register migrations
  - `crates/fiber-store/Cargo.toml:19,22` — `fiber-types-090` (NEW) + `fiber-types-081` (OLD) snapshot deps
  - 用户已记录 fact: STORE-001 (DB 0644 perms / no SQLite advisory lock / `panic!`-on-deserialize / migration non-atomic)

## 1. 审计目标

bincode 序列化 + 升级迁移构成 fiber 持久化层的语义边界。审计项：

- a. bincode 1.3.3 默认配置语义（fixint / 长度上限 / trailing bytes / variant alloc）；
- b. 类型层 schema-evolution 风险（字段顺序、enum 变体编号、option/None、Vec 长度）；
- c. 迁移框架的 happy-path、错误传播、原子性；
- d. 迁移版本号被外部修改 (rewind / forward) 的回弹路径；
- e. `check_validate` 覆盖完备性；
- f. snapshot 依赖 (`fiber-types-081` / `-090`) 的版本钉死与可重现性；
- g. WASM/IndexedDB 路径的对称性（已委托 WASM-001/002）。

## 2. 系统性梳理

### 2.1 bincode 1.3.3 默认语义（实测验证）

```
$ cargo run /tmp/bctest
A bytes: [1, 0, 0, 0, 2, 0, 0, 0] len 8
B from full A buf: Ok(B { x: 1 })          // ← struct prefix 静默接受
A from buf+2 trailing: Ok(A { x: 1, y: 2 }) // ← trailing bytes 静默接受
```

**实测结论**（用 `bincode 1.3.3` + serde 1.0 验证）：

1. **`bincode::deserialize::<T>` 默认接受 trailing bytes** — 不调用 `bincode::Options::with_limit().reject_trailing_bytes()`；
2. **结构 "prefix overlap" 静默成功** — 类型 `B { x: u32 }` 从 `A { x, y }` 编码反序列化成功，多出来的 4 字节被忽略；
3. **fixint encoding** — `u32` 占 8 字节（little-endian fixed），`Vec<u8>` 长度前缀是 `u64`；
4. **enum 变体编号是 `u32` little-endian** — 重排变体 = 数据破坏（无字段名校验）；
5. **`Option<T>` 用 `u8` discriminant** — `None=0`, `Some=1`；
6. **没有"struct-name"或"version" 写入** — 任意类型可"假装"是任意类型，只要字节布局兼容。

### 2.2 `serialize_to_vec` / `deserialize_from`

```rust
// store_impl/mod.rs:121-132
pub(crate) fn serialize_to_vec<T: ?Sized + Serialize>(value: &T, field_name: &str) -> Vec<u8> {
    bincode::serialize(value)
        .unwrap_or_else(|e| panic!("serialization of {} failed: {}", field_name, e))
}

pub(crate) fn deserialize_from<'a, T>(slice: &'a [u8], field_name: &str) -> T
where T: serde::Deserialize<'a>,
{
    bincode::deserialize(slice)
        .unwrap_or_else(|e| panic!("deserialization of {} failed: {}", field_name, e))
}
```

- `panic!`-on-error（与 STORE-001.F3 一致）。
- `field_name` 仅出现在 panic message，不参与 schema 校验（无类型前缀）。
- 调用点遍历整个 store 层（70+ 处），每个读路径都是 panic 边界。

### 2.3 现有迁移 `mig_20260511_channel_connectivity_state.rs`

```rust
// 行 36-86
let entries = store.collect_prefix(CHANNEL_ACTOR_STATE_PREFIX);
for (key, value) in entries {
    if let Ok(_new) = bincode::deserialize::<NewChannelActorData>(&value) {
        skipped += 1;
        continue;                                    // ← 关键判定
    }
    let old: OldChannelActorData = bincode::deserialize(&value).map_err(...)?;
    let mut json_value = serde_json::to_value(&old)?;
    json_value.as_object_mut()?
        .insert("connectivity_state".to_string(), serde_json::json!("Offline"));
    let new: NewChannelActorData = serde_json::from_value(json_value)?;
    let new_bytes = bincode::serialize(&new)?;
    store.put(&key, &new_bytes);                     // ← 单条 put，无 batch/tx
}
```

- "已迁移" 检测依赖 `bincode::deserialize::<NewChannelActorData>` 成功 — **这受 prefix-overlap 静默成功影响**。
- 通过 `serde_json` 中转执行 schema 演化（避免手写 v0/v1 转换）— 设计干净。
- 但：`json_value.as_object_mut().ok_or("Expected JSON object")?` 假设根是 object。如果 old type 是 enum / tuple-struct，这条直接失败。
- `store.put(&key, &new_bytes)` 一次 put 一条 — 无 batch/tx — 与 STORE-001.F4 一致。

### 2.4 Migration 框架版本号路径

```rust
// migration.rs:213-311 auto_migrate
let db_version = match self.get_db_version(store) {
    None => { self.init_db_version(store); return Ok(()); }   // 新库
    Some(v) => v,
};
if db_version == latest { return Ok(()); }
if db_version > latest { return Err(DatabaseTooNew {...}); }
if db_version < INIT_DB_VERSION { return Err(DatabaseTooOld {...}); }

let pending = self.pending_migrations(&db_version);
if pending.is_empty() {
    self.init_db_version(store);                              // ← 危险路径
    return Ok(());
}
// ... run migrations, after each: store.put(MIGRATION_VERSION_KEY, m.version()) ...
```

观察：

1. **`MIGRATION_VERSION_KEY = b"db-version"` 无完整性签名** — 任何人能写 store 都能改版本号。STORE-001.F1 (DB 0644) 让"任意"等于"同主机所有用户"。
2. **空 pending 但版本不等于 latest → 直接 stamp latest** — 危险：
   - 设 `LATEST_DB_VERSION = "20260511120000"`（当前唯一 migration 的版本），且某攻击者把 db-version 改为 `"20260511120001"`（介于 latest 和未来 migration 之间）。
   - `pending_migrations(db_version)` 返回 `(db_version, ∞)` 区间内的 migrations — 空。
   - `init_db_version` 把版本盖回 `LATEST_DB_VERSION = "20260511120000"`。
   - **结果**：版本号被静默重置；后续若添加新 migration（版本 `"20260512..."`），它会重新被 detect 为 pending。该路径本身不丢数据，但在更复杂场景（攻击者把版本号改为某个介于两个 migration 之间的版本）会导致中间 migration 被跳过。
3. **`migrate()` 循环内单条 put + 循环外 stamp** — crash-recovery 时：
   - 部分记录已转换为 NEW 格式，剩余仍是 OLD；
   - 由于 `MIGRATION_VERSION_KEY` 还未更新（在循环外），重启时迁移**重新执行**；
   - 重跑依赖 `if let Ok(_new) = bincode::deserialize::<NewChannelActorData>(&value) { skipped }` — 受 §2.5 false-positive 影响。
4. **`add_migration` 无版本冲突检测**：`BTreeMap::insert(version, migration)` 静默覆盖。两个 migration 同版本号 → 后注册的胜出，前者永不执行。
5. **版本字符串格式无校验**：`"foo"` 与 `"20260511120000"` 都是合法 BTree key；string compare 排序，`"foo"` 比所有数字版本大 → 被错误认为最新。

### 2.5 bincode "已迁移" 判定的 false-positive 风险

迁移内的检查：

```rust
if let Ok(_new) = bincode::deserialize::<NewChannelActorData>(&value) { skipped += 1; continue; }
```

风险矩阵：

| Old vs New 结构关系 | bincode::deserialize::<New>(old_bytes) 行为 | 影响 |
|---|---|---|
| **NEW = OLD + 新增字段在末尾** | 大概率 EOF 错误（NEW 期望更多字节）→ ✓ 正确 fall through | 当前 mig 属于此类，相对安全 |
| **NEW = OLD - 删除字段** | NEW 比 OLD 短 → 老数据被静默接受为 New（多余字节忽略），**skipped++** | ❌ 老记录永不迁移 |
| **NEW = OLD 重命名字段** | 字节布局相同 → New 静默成功 | ❌ 完全相同的字节被解释为不同语义 |
| **NEW = OLD 重排字段** | 字节布局变化 → 大概率失败 | ✓ |
| **NEW = OLD 改类型 (u32→u64)** | 长度变化 → 大概率失败 | ✓ |
| **NEW enum 增加变体（追加在末尾）** | discriminant `u32` 仍合法 → 成功 | ⚠️ |
| **NEW enum 重排变体** | 变体编号变化 → 数据被错误解释 | ❌ 静默语义破坏 |
| **NEW Vec/HashMap 字段类型变更** | 长度前缀 + 元素重新解析 → 大概率失败 | ✓ |

**当前 `connectivity_state` 迁移**走 "末尾追加字段" 路径，相对安全。但如果未来迁移走"删字段"或"改类型"路径，无新增 schema-version 防护。

### 2.6 `check_validate` 覆盖

`store_impl/mod.rs:185-269`：

- 14 个已知 prefix 中：
  - **覆盖 (10)**: `CHANNEL_ACTOR_STATE`, `PUBLIC_KEY_NETWORK_ACTOR_STATE`, `CKB_INVOICE`, `PREIMAGE`, `CKB_INVOICE_STATUS`, `CHANNEL_OUTPOINT_CHANNEL_ID`, `BROADCAST_MESSAGE`, `PAYMENT_SESSION`, `PAYMENT_HISTORY_TIMED_RESULT`, `PAYMENT_CUSTOM_RECORD`, `CCH_ORDER`, `WATCHTOWER_CHANNEL`；
  - **空 case (2)**: `PUBKEY_CHANNEL_ID_PREFIX => {}` (line 219)、`BROADCAST_MESSAGE_TIMESTAMP_PREFIX => {}` (line 234) — 注释明确这两个 prefix 的 value 仅是占位/timestamp，但**注释缺失**会让维护者误以为遗漏；
  - **catch-all (1)**: `_ => {}` (line 268) — **未知 prefix 被静默忽略**。如果 binary 旧、DB 由更新的 binary 写入了新 prefix，`check_validate` 不会报错；运行时 `prefix_iterator + deserialize_from` 才会 panic。
- `Hash256` 在多个 prefix 用作 value，全部走相同 `check_deserialization::<Hash256>` — Hash256 是定长 32 字节，任何 32 字节都合法，校验**等于零**（不能 detect `commitment_seed`/`preimage` 误置）。
- WASM (`#[cfg(not(target_arch = "wasm32"))]`) 跳过 `CCH_ORDER`，但 watchtower 只在 `feature="watchtower"` 时校验。

### 2.7 Snapshot 依赖钉死

```toml
# Cargo.toml
fiber-types-090 = { package = "fiber-types", version = "0.9.0-rc1" }
fiber-types-081 = { package = "fiber-types", version = "0.8.1" }
```

- 用 cargo `package = "fiber-types"` rename trick 引入两个版本 ✓；
- 但版本是 `version = "0.9.0-rc1"` — **caret 隐含**（cargo 默认 `^0.9.0-rc1`），未来 `0.9.0-rc2` 发布后 `cargo update` 会拉取新版本，**migration 引用的"OLD"和"NEW"语义可能漂移**；
- 应改为 `version = "=0.9.0-rc1"`（精确匹配），或对所有 migration 用的 schema snapshot 都用 `=` 锁定。
- `fiber-types-081 = "0.8.1"` 同样是 caret，但 0.8.x line 已经 frozen，风险低；如果 0.8.2 修了某个 bug 改了字段，会破坏 OLD 语义。

### 2.8 SQLite 后端 vs RocksDB 后端的 atomic-write 对称性

- SQLite 单条 `INSERT OR REPLACE` 是事务化的，但 `store.put` 调用循环没有外层 `BEGIN/COMMIT`；
- RocksDB 的 `WriteBatch` 未在 migration 里使用（直接 `db.put`）；
- 跨后端 migration 都依赖**单条原子性**，不依赖**集合原子性**；
- crash 在循环中段 → 部分迁移 + 版本号未更新 → 重启重跑 → 依赖 §2.5 false-positive-resistant 判定 = 脆弱。

## 3. 发现

### 3.1 F1 (🟡 Medium) — Migration "已迁移" 判定依赖 bincode prefix-overlap 静默成功，未来"删字段"/"重命名"型迁移会静默失败导致数据丢失或运行时 panic

**位置**：`crates/fiber-store/src/migrations/mig_20260511_channel_connectivity_state.rs:42` + 通用模式

#### 问题

```rust
if let Ok(_new) = bincode::deserialize::<NewChannelActorData>(&value) {
    skipped += 1;
    continue;
}
```

实测确认（§2.1）：bincode 1.3.3 `deserialize` 静默接受 trailing bytes 且接受 struct-prefix 重解释。当前 migration 走 "末尾追加字段" 路径（NEW 比 OLD 长一字段），所以 OLD bytes deserialize as NEW 大概率因 EOF 失败 — 当前安全。

但模式是危险范本。如果未来某 migration 走：

- **删字段** (NEW = OLD - field)：OLD 编码比 NEW 长 → `deserialize::<NEW>(old)` **静默成功**，trailing bytes 忽略 → `skipped++` → **OLD 记录永不被迁移**，但下次 binary 用 NEW 类型 `deserialize_from` 读这条记录时仍然能成功（只是数据有"过期残留"语义）。最危险的场景是删除的字段是某个 invariant（比如 channel 创建时间戳）— 业务逻辑会读到错误的默认值。
- **重命名字段** (NEW = OLD with field renamed)：字节布局完全相同 → `deserialize::<NEW>(old)` 成功 → `skipped` → 新代码读到错误命名的字段值。
- **enum 变体重排** (NEW reorders variants)：`u32` discriminant 不变 → 静默成功，但语义反转。

#### 修复

migration 应当用**显式 marker**判定记录格式，而非"能不能 deserialize 成 NEW"。常用模式：

1. **Schema version byte prefix**：每条 value 编码时加一字节 schema_version，迁移按 prefix 分流。
2. **Type tag in value**：`(SchemaTag, T)` 元组序列化，反序列化时先读 SchemaTag。
3. **改用 strict bincode**：`bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes().deserialize(...)`，让 prefix-overlap fail-fast；至少在 migration 的"是否已迁移"判定路径上启用。
4. **Migration 内显式记录已处理 keys**：用一个 staging key (e.g. `b"mig:20260511:done"`) 列出已处理 channel_id 集合，crash recovery 时跳过这些；不依赖反序列化结果。

最小修复（适用当前框架）：

```rust
fn try_strict_deserialize<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, _> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(b)
}
if let Ok(_new) = try_strict_deserialize::<NewChannelActorData>(value) { skipped += 1; continue; }
```

至少消除 trailing-bytes 静默接受。但 prefix-overlap-without-trailing 情况（NEW 与 OLD 同长度）仍需要 schema marker。

**评级**：🟡 **Medium** — 当前迁移类型不触发，但**模式**是 footgun，未来添加删字段/重命名 migration 时数据丢失或 panic 是高概率事件。修复成本极低（5 行代码）。

### 3.2 F2 (🟡 Medium) — `MIGRATION_VERSION_KEY` 无完整性签名 + "空 pending → stamp latest" 路径让外部修改版本号导致 migration 跳过

**位置**：`crates/fiber-store/src/migration.rs:255-262, 41`

#### 问题

```rust
pub const MIGRATION_VERSION_KEY: &[u8] = b"db-version";
// ...
let pending = self.pending_migrations(&db_version);
if pending.is_empty() {
    self.init_db_version(store);  // ← 直接 stamp latest，不检查"为什么空"
    return Ok(());
}
```

攻击场景（结合 STORE-001.F1 DB 0644 + STORE-001.F2 SQLite 无独占锁）：

1. 攻击者（同主机用户）写 `db-version = "20260511120001"`（介于唯一 migration `20260511120000` 和未来 migration 之间，或介于两个未来 migrations 之间）；
2. 受害者运行升级后 binary，假设新 binary 版本到 `LATEST_DB_VERSION = "20260512000000"`；
3. `pending_migrations("20260511120001")` 返回 `(20260511120001, ∞)` 区间 migrations。如果攻击者选的版本号刚好介于已注册和 LATEST 之间且区间里无 migration → 空；或攻击者把 `db-version` 改为 `"99999999999999"`（也 < latest 时则不空，>= latest 时触发 `DatabaseTooNew`）。
4. 更现实的版本：攻击者把 `db-version` 直接改为 `LATEST_DB_VERSION` 的字面值 → `db_version == latest` → **完全跳过 migration**。后续 deserialize 到 OLD 字节时 panic。

#### 不易触发但更隐蔽的变体

- 攻击者把版本号设为某个**已存在 migration 的版本**：`pending` 只包含**之后的** migration → 当前 migration 被跳过。具体地：把版本设为 `"20260511120000"`（当前 唯一 migration 的版本）→ pending 为空 → stamp latest 不做事；后续添加一个 `"20260512000000"` migration 时，老库的 OLD 数据没被处理，但 `db-version` 已是 `20260511120000`，pending = `[20260512]`，新 migration 跑但只期望 NEW 输入 → panic。

#### 加固

1. **版本号附 HMAC** 或与 binary signing key 校验（重)；
2. **校验所有已注册 migration 的版本号都 <= db-version 时**，至少做一次"sample read" 验证：随机抽 N 条 `CHANNEL_ACTOR_STATE` 等关键 prefix 的 value 用 LATEST schema 反序列化 — 任意失败则报错引导用户运行 `check_validate`；
3. **`pending.is_empty()` 时不 stamp latest**：保留当前 db-version，记 warning（"DB 比 binary 旧但无可执行 migration"），让运营者排查；不要"自愈式"前进；
4. STORE-001-FOLLOWUP-A (0700/0600 perms) 与 STORE-001-FOLLOWUP-B (SQLite advisory lock) 可降低 prerequisite。

**评级**：🟡 **Medium** — 需要本地写权限，但 STORE-001.F1 让多租户场景成立；后果是静默数据损坏 / 启动后随机 panic。

### 3.3 F3 (🟢 Low) — `serialize_to_vec`/`deserialize_from` 全局 `panic!` (重申 STORE-001.F3)

**位置**：`crates/fiber-lib/src/store/store_impl/mod.rs:121-132`

#### 问题

70+ 调用点的任一读路径，遇到一条损坏 value 直接进程 panic。`StorageBackend` trait 已经返回 `Option<Vec<u8>>`（`Result` even better），但反序列化层把 IO/parse 错误都升级为 fatal。已记录于 STORE-001.F3，本次审计**确认**问题仍存在；不再独立计算严重级。

#### 修复

参考 STORE-001-FOLLOWUP-C：把 `deserialize_from` 改为返回 `Result<T, StoreError>`，调用点决定是否 fatal（启动期 fatal、运行期 skip-and-warn）。

**评级**：🟢 Low（重复发现）。

### 3.4 F4 (🟢 Low) — `check_validate` catch-all `_ => {}` 静默忽略未知 prefix

**位置**：`crates/fiber-lib/src/store/store_impl/mod.rs:268`

#### 问题

```rust
match key[0] {
    CHANNEL_ACTOR_STATE_PREFIX => {...},
    // ... 12 known prefixes ...
    _ => {}  // ← 未知 prefix 全部跳过
}
```

升级路径：DB v(N+1) 引入新 prefix，binary v(N) 运行 `check_validate`（运营者升级前的健康检查）→ 新 prefix 被静默忽略 → 报告 "All keys and values valid" → 实际未知数据从未校验。下次 `prefix_iterator` 命中时 panic。

#### 修复

```rust
_ => {
    errors.insert(format!(
        "Unknown key prefix 0x{:02x} (key len={}); maybe newer DB schema",
        key[0], key.len()
    ));
}
```

或维护 `KNOWN_PREFIXES: &[u8]` allowlist 在 `schema.rs`，`_` 报错。

**评级**：🟢 Low — 影响运营者 health-check 可信度，不是直接 RCE/DoS。

### 3.5 F5 (🟢 Low) — `fiber-types-090` / `fiber-types-081` 未用 `=` 精确锁版本，cargo update 可能漂移 migration 语义

**位置**：`crates/fiber-store/Cargo.toml:19,22`

```toml
fiber-types-090 = { package = "fiber-types", version = "0.9.0-rc1" }   # 隐含 ^
fiber-types-081 = { package = "fiber-types", version = "0.8.1" }       # 隐含 ^
```

#### 问题

cargo 默认 caret (`^0.9.0-rc1` ≈ `>= 0.9.0-rc1, < 0.10.0`)。如果 `fiber-types` 0.9.0-rc2 / 0.9.0 发布且包含 schema 微调（甚至只是字段顺序、`#[serde(rename)]`），`cargo update` 后 migration 引用的"OLD"或"NEW"会**漂移**：

- `OldChannelActorData` 应当严格冻结 = 历史 0.8.1 序列化产物；任何漂移都让"读旧 DB 的能力"失效；
- `NewChannelActorData` 应当 = 当前 binary 的类型 — 但已经独立通过 `fiber-types` 主依赖引用，这里再独立 pin 是为了**显式**表明"migration 写出的 NEW 格式" — 应跟主 `fiber-types` 同步。

#### 修复

```toml
fiber-types-090 = { package = "fiber-types", version = "=0.9.0-rc1" }
fiber-types-081 = { package = "fiber-types", version = "=0.8.1" }
```

或更进一步：把 OLD snapshot 复制到本仓内 `crates/fiber-store/src/migrations/snapshots/v081.rs`（自包含、不依赖外部 crate registry），消除 supply-chain 漂移面。

**评级**：🟢 Low — 需要 `cargo update` + 上游 yank/republish，但 supply-chain 角度是真实风险。

### 3.6 F6 (ℹ️ Info) — `add_migration` 同版本 silent overwrite + 无版本号格式校验

**位置**：`crates/fiber-store/src/migration.rs:152-156`

```rust
pub fn add_migration(&mut self, migration: Arc<dyn Migration>) {
    self.migrations.insert(migration.version().to_string(), migration);
}
```

- 两个 migration 同版本号 → `BTreeMap::insert` 静默覆盖；后注册者胜。
- `version()` 返回 `&str`，无 `YYYYMMDDHHMMSS` 格式校验。`"foo"` 会按 string 比较排在所有数字版本之后，被错误认为 latest。
- `build.rs` 自动注册时按 `MIGRATION_DB_VERSION` 字符串比较 max — 同样无格式校验。

#### 修复

`add_migration` 改为 `Result<()>`，重复版本号返回 `Err`；版本号用 regex `^\d{14}$` 校验。

**评级**：ℹ️ Info — 内部 invariant，不是远程攻击面。

### 3.7 F7 (ℹ️ Info) — Migration 框架 `MigrationFailed { error: String }` 类型擦除

**位置**：`crates/fiber-store/src/migration.rs:74-78`

`error: String` 让上层无法区分 IO 错误（可重试）/ 解析错误（数据损坏，需手动）/ schema 错误（binary bug，需回滚）。当前所有 callers 把它当 fatal 处理，但未来 GUI/CLI 想给出更细的错误恢复指导时被卡。

#### 修复

`enum MigrationStepError { Io, Decode { tag: &'static str, source: ... }, SchemaInvariant { ... } }`，`String` Display 兜底。

**评级**：ℹ️ Info。

### 3.8 F8 (✅ Pass) — `DatabaseTooNew` / `DatabaseTooOld` 边界检查

`auto_migrate` (line 240-254) 正确处理：

- `db_version > latest` → `DatabaseTooNew` 拒绝启动 ✓；
- `db_version < INIT_DB_VERSION` → `DatabaseTooOld` + 引导用户 fnn-migrate v0.8.x ✓；
- 这两条防止"binary 比 DB 旧"和"DB 太老到无法递增升级"。

### 3.9 F9 (✅ Pass) — `serde_json` 中转执行字段新增 schema 演化

`mig_20260511` 把 OLD bincode → JSON → 加字段 → JSON → NEW bincode 是优雅的 schema-evolution 模式，避免手写 v0/v1 转换 trait。`fiber-types-081` / `-090` 用 `package =` rename trick 引入两版本同名类型 ✓。该模式应作为团队标准记录到 `migrations/mod.rs` 顶部注释（已部分文档化）。

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — bincode prefix-overlap + trailing-bytes 静默接受让 migration "已迁移" 判定脆弱（实测验证） | 🟡 Medium | ❌ 未修复 |
| F2 — `MIGRATION_VERSION_KEY` 无完整性签名 + "空 pending → stamp latest" 让外部改版本号跳过 migration | 🟡 Medium | ❌ 未修复 |
| F3 — `serialize_to_vec`/`deserialize_from` 全局 `panic!`（重申 STORE-001.F3） | 🟢 Low | ❌ 重复 |
| F4 — `check_validate` catch-all `_ => {}` 静默忽略未知 prefix | 🟢 Low | ❌ 未修复 |
| F5 — snapshot deps 未 `=` pin，cargo update 可能漂移 OLD/NEW 语义 | 🟢 Low | ❌ 未修复 |
| F6 — `add_migration` 同版本 silent overwrite + 无版本号格式校验 | ℹ️ Info | — |
| F7 — `MigrationFailed { error: String }` 类型擦除 | ℹ️ Info | — |
| F8 — `DatabaseTooNew` / `DatabaseTooOld` 边界 | ✅ Pass | — |
| F9 — `serde_json` 中转 schema 演化模式优雅 | ✅ Pass | — |
| 整体 | 🟡 **Medium** | ❌ |

### 总体评价

存储反序列化 + migration 框架的**外形**专业（snapshot deps trick、`DatabaseTooNew/Old` 边界、`check_validate` 实现），但**内核**有两类系统性脆弱：

1. **bincode 1.3.x 默认配置过于宽松** — 实测验证 trailing-bytes 与 struct-prefix 都静默成功；当前唯一 migration 走"末尾加字段"路径未触发，但模式是 footgun，无 schema-version 防护；
2. **migration 版本号缺乏完整性保护** — 配合 STORE-001.F1 (DB 0644)，同主机攻击者可静默跳过 migration 让后续读路径 panic 或读到错误数据；空 pending 路径直接 stamp latest 进一步放大。

修复成本均低（每条 < 30 行），但需要项目层引入"strict bincode" + "schema-version-byte" 约定。

**关联**：
- F1/F3 与 STORE-001.F3/F4 同源，应统一修复（strict bincode 选项 + checked deserialize）；
- F2 与 STORE-001.F1/F2 协同：单修 perms 不够，需补 version 完整性；
- F4 与 INPUT-003 / ERR-002 是"健康检查信号可信度"主题。

## 5. Follow-ups

- **AUDIT-INPUT-004-FOLLOWUP-A (🟡 Medium, 必修)**: F1 — 把 migration 内的 "已迁移" 判定换成 `bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes().deserialize::<NewT>(value)`；建议团队级约定：所有持久化 value 加 1 字节 `schema_version` prefix，迁移按 prefix 分流。
- **AUDIT-INPUT-004-FOLLOWUP-B (🟡 Medium, 必修)**: F2 — `pending.is_empty() && db_version != latest` 时不 stamp latest，记 error 退出；让运营者显式介入；同时把 `MIGRATION_VERSION_KEY` 的完整性写入 `(version, hmac(version, derived_from_seed))` 元组。
- **AUDIT-INPUT-004-FOLLOWUP-C (🟢 Low)**: F3 — 与 STORE-001-FOLLOWUP-C 合并：`deserialize_from` 改返回 `Result<T, StoreError>`。
- **AUDIT-INPUT-004-FOLLOWUP-D (🟢 Low)**: F4 — `check_validate` 把 `_ => {}` 改为 `errors.insert("Unknown key prefix 0x{:02x}")`；维护 `KNOWN_PREFIXES` allowlist。
- **AUDIT-INPUT-004-FOLLOWUP-E (🟢 Low)**: F5 — `fiber-types-090` / `fiber-types-081` Cargo.toml 加 `version = "=…"`。或迁移到 vendored snapshots (`crates/fiber-store/src/migrations/snapshots/`)。
- **AUDIT-INPUT-004-FOLLOWUP-F (ℹ️ Info)**: F6 — `add_migration` 改 `Result<()>`，重复版本号或非数字版本号返回 `Err`。
- **AUDIT-INPUT-004-FOLLOWUP-G (ℹ️ Info)**: F7 — `MigrationStepError` enum 替换 `String`，让 GUI 给出针对性恢复指引。

**实测脚本**（PoC for F1）：
```bash
$ cd /tmp/bctest && cargo run --release
A bytes: [1, 0, 0, 0, 2, 0, 0, 0] len 8
B from full A buf: Ok(B { x: 1 })            # ← prefix-overlap 静默成功
A from buf+2 trailing: Ok(A { x: 1, y: 2 })  # ← trailing bytes 静默接受
```
