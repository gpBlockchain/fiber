# AUDIT-STORE-001 — 持久层与迁移安全

- **维度**: DIM-STORE (Persistence & migration)
- **严重级别**: 🟡 **Medium**（Medium × 2 + Low × 4 + Info × 1 + Pass × 2）
- **审计 Session**: S14 (2026-05-14)
- **关联代码**:
  - 后端实现:
    - `crates/fiber-store/src/native.rs:17-23` (RocksDB `Store::open_db`)
    - `crates/fiber-store/src/native.rs:29-105` (RocksDB get/put/delete/Batch — 全部 `.expect`)
    - `crates/fiber-store/src/sqlite.rs:20-51` (SQLite `Store::open_db`)
    - `crates/fiber-store/src/sqlite.rs:57-181` (SQLite get/put/delete/Batch — 全部 `panic!`/`.expect`)
    - `crates/fiber-store/src/browser.rs:84-198` (WASM browser store IPC)
  - 序列化包装:
    - `crates/fiber-lib/src/store/store_impl/mod.rs:121-132` (`serialize_to_vec` + `deserialize_from`，两者均 `panic!`)
    - `crates/fiber-lib/src/store/store_impl/mod.rs:166-320` (`check_validate` — 启动可选校验)
  - 迁移框架:
    - `crates/fiber-store/src/migration.rs:41-43` (`MIGRATION_VERSION_KEY = b"db-version"`、`INIT_DB_VERSION = "20260302100001"`)
    - `crates/fiber-store/src/migration.rs:213-312` (`Migrations::auto_migrate` — 非原子写入)
    - `crates/fiber-store/src/migrations/mig_20260511_channel_connectivity_state.rs:30-93` (典型迁移 — 逐条 put，无 batch)
    - `crates/fiber-store/Cargo.toml:19-22` (双版本 `fiber-types-090`/`fiber-types-081` 旧数据反序列化路径)
  - 用户入口:
    - `crates/fiber-bin/src/main.rs:101-119` (`check_validate` CLI)
    - `crates/fiber-bin/src/main.rs:121-129` (`open_store_with_migration` 自动迁移)

## 1. 审计目标

fiber 节点持久化的资产是高敏感的：

- **私钥与撤销密钥种子**：`ChannelActorState` 中含 `commitment_seed` / `local_revocation_secret` 派生材料；watchtower `ChannelData` 中含 `Privkey`；丢失/损坏 → 无法 force-close、无法反 cheat。
- **TLC preimage**：`PREIMAGE_PREFIX` / 受让 preimage 是直接的链上资金。
- **PaymentSession + Attempt** 历史：路径选择依赖。
- **gossip 缓存**：channel announcement / update + node announcement。
- **CCH 订单状态**：跨链 swap 的中介状态。
- **数据库版本号**：单点—损坏即拒绝启动。

本审计聚焦：

1. **Crash/Recovery 一致性**：异常关机、torn write、并发开 DB、磁盘错误的反应；
2. **反序列化 panic 面**：读到任何"非预期"字节是否会让节点进入永久 boot-loop；
3. **迁移原子性**：多步迁移若中途崩溃，状态是否可恢复或前后一致；
4. **文件权限/锁**：DB 目录权限、独占锁、备份/还原一致性；
5. **后端差异**：RocksDB / SQLite / WASM browser 三套后端的语义一致性与失败处理；
6. **远程触发**：是否任何攻击者可控的字节可经合法路径进入 store 触发解码崩溃。

## 2. 系统性梳理

### 2.1 后端架构

`fiber_store::Store` 有三种实现，由 `Cargo.toml` features 选择：

| 后端 | 编译开关 | 数据库技术 | 进程锁 | 备份策略 |
|---|---|---|---|---|
| RocksDB (native) | `feature = "rocksdb"` (默认 + 非 wasm) | LSM-tree + LZ4 compression | RocksDB 内部 LOCK file (强独占) | 文件目录拷贝（cold） |
| SQLite | `feature = "sqlite"` (非 wasm 可选) | B-tree + WAL | **无独占锁** | `.backup()` 在线（未使用） |
| Browser | `target_arch = "wasm32"` | IndexedDB / SAB IPC | 浏览器单页 | 浏览器存储配额 |

所有后端实现统一 `StorageBackend` trait（get/put/delete/batch/collect_iterator）。

### 2.2 序列化策略

`serialize_to_vec` (store_impl/mod.rs:121-124) + `deserialize_from` (mod.rs:126-132) 是**全局**的 bincode 包装：

```rust
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

**特征**：bincode 1.x，不是自描述、严格按顺序解码；当字节流不匹配类型布局时返回 `Err`。所有调用点（mod.rs:550, 565, 642, 660, 729, 743, 750, 769, 825, 851, 859, 867, 875, 884, 895, 919, 950, 981, 996, 1027, 1127, 1140, 1206, 1231, 1255, 1301, 1309, 1348, 1379, 1391, 1629）一律走 `deserialize_from` → 任何字节级损坏即 panic。

**没有 fallback、没有跳过、没有回滚**。

### 2.3 后端 panic 表面

#### RocksDB (`crates/fiber-store/src/native.rs`)

```rust
fn get<K>(&self, key: K) -> Option<Vec<u8>> {
    self.db.get(key.as_ref())
        .map(|v| v.map(|vi| vi.to_vec()))
        .expect("get should be OK")                  // ⚠️ 磁盘错误 → panic
}
fn put<K, V>(&self, key: K, value: V) {
    self.db.put(key, value).expect("put should be ok");  // ⚠️ 同上
}
fn delete<K>(&self, key: K) {
    self.db.delete(key).expect("Unexpected error from delete");
}
// Batch::put/delete/commit 同样 .expect
```

#### SQLite (`crates/fiber-store/src/sqlite.rs`)

```rust
fn get<K>(&self, key: K) -> Option<Vec<u8>> {
    let conn = self.conn.lock().expect("lock poisoned");
    match conn.query_row(...) {
        Ok(value) => Some(value),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => panic!("get failed: {e}"),         // ⚠️ I/O 错 → panic
    }
}
fn put<K, V>(&self, key: K, value: V) {
    let conn = self.conn.lock().expect("lock poisoned");  // ⚠️ poisoning
    conn.execute(...).expect("put should be ok");          // ⚠️
}
// 同样：collect_iterator 内 5 处 .expect
```

#### Browser (`crates/fiber-store/src/browser.rs`)

```rust
fn get<K>(&self, key: K) -> Option<Vec<u8>> {
    return match self.chan.dispatch_database_command(...).unwrap() {  // ⚠️
        DbCommandResponse::Read { mut values } => values.remove(0),
        _ => unreachable!(),
    };
}
// 同样：put/delete/iterator 全部 .unwrap()
```

### 2.4 启动流程

```
main.rs:128  open_store_with_migration(store_path, cli_confirm, cli_progress)
  → store_impl/mod.rs:142 open_store_with_migration
    → fiber_store::Store::open_db(path)        ← 创建/打开数据库
    → run_auto_migrate                         ← 检查 + 迁移
      → DbMigrate::new + register_all_migrations
      → migrations.auto_migrate                 ← 见下
    → Ok(Store { inner, watcher: None })
```

`Migrations::auto_migrate` (migration.rs:213-312)：

1. 读 `b"db-version"`；为空 → init_db_version (新库) → return Ok
2. db_version == latest → return Ok
3. db_version > latest → `DatabaseTooNew` 错误
4. db_version < INIT_DB_VERSION → `DatabaseTooOld`（需先用 fnn-migrate v0.8）
5. 收集 pending；空 → 直接 update version 为 latest（**疑点**：未跑任何迁移就升版本号！）
6. 构造 `MigrationPlan` 调 `confirm_fn`；CLI 是 `cli_confirm`；用户拒绝 → `UserCancelled`
7. 逐个 pending：调 `m.migrate(store)`，成功后 **`store.put(MIGRATION_VERSION_KEY, m.version())`**

### 2.5 单条 migration 的写入模式

mig_20260511_channel_connectivity_state.rs:30-93 是当前 active 的迁移：

```rust
let entries = store.collect_prefix(CHANNEL_ACTOR_STATE_PREFIX);
for (key, value) in entries {
    if let Ok(_new) = bincode::deserialize::<NewChannelActorData>(&value) {
        skipped += 1; continue;
    }
    let old: OldChannelActorData = bincode::deserialize(&value).map_err(...)?;
    // ... new = old + connectivity_state = Offline
    store.put(&key, &new_bytes);                      // ⚠️ 逐条 put，未在 batch 内
    migrated += 1;
}
```

**没有 transaction / batch**。每个 `store.put` 是独立写。如果在第 N 条上崩溃：

- 前 N-1 条已是新格式（可被 `bincode::deserialize::<NewChannelActorData>` 解出）；
- 第 N 条之后仍是旧格式；
- `MIGRATION_VERSION_KEY` 没被更新（仅在迁移完成后才写）；
- 下次启动重新跑此迁移 → `if let Ok(_new) = bincode::deserialize::<NewChannelActorData>(&value)` 跳过已转换的 → 继续处理剩余条目 ✓

这是**幂等**的设计 — 但**前提**是 `bincode::deserialize::<NewChannelActorData>` 不会对旧字节也 Ok。bincode 不是 self-describing，仅按"字段顺序按 size 消耗"。如果新结构是 `{old_fields..., connectivity_state: enum}` 而 enum 占 1 字节：旧字节流末尾若恰好有 1 个合法 enum 变体字节（0/1/2/3），会误判为新格式。该单条字节流末尾可能是任意值（例如 `Vec<...>` 的下个 entry 的 length prefix）→ 完全可能误判。

**实际影响**：误判会导致一条记录**永久跳过迁移**，下次读取时 `deserialize_from::<NewChannelActorData>` 失败 → 启动 panic。受影响仅限旧 DB 中恰好"末尾字节 = 合法 enum 变体且其后无更多 bytes"的 ChannelActorData 条目，**概率较低**但不为零。

### 2.6 SQLite 并发开 DB

`crates/fiber-store/src/sqlite.rs:20-25`:

```rust
pub fn open_db(path: &Path) -> Result<Self, String> {
    std::fs::create_dir_all(path)...?;
    let db_file = path.join("data.sqlite");
    let conn = Connection::open(&db_file).map_err(|e| e.to_string())?;
    // ...
    "PRAGMA journal_mode = WAL;"
}
```

`Connection::open` 不获取独占文件锁。WAL 模式默认允许**多 reader + 单 writer**。如果两个 fiber 实例同时启动指向同一 store_path：

- 两者各自调用 `migrations.auto_migrate`；
- 两者各自调用 `store.put(MIGRATION_VERSION_KEY, m.version())` — 末次写胜利；
- 两者各自迁移可能产生互覆盖；
- 即使没有迁移，两者各自的 `ChannelActor` 都认为对端是离线（peer 连接由各自的 secio session 维护），但 settle/revocation 状态可能两边并发更新 → **revocation key 错误 → 反 cheat 失败**。

RocksDB 用 LOCK 文件强制独占，**RocksDB 不受此影响**。SQLite 受影响。

### 2.7 文件权限

DB 目录在 `parsed_fiber_config.store_path()`，由 `create_dir_all` 创建。**未显式设置权限**。系统 umask 决定（典型 022 → 目录 0755、文件 0644）。

`ChannelActorState`（含 `commitment_seed` 等长期密钥派生材料）、watchtower `ChannelData`（含 `Privkey`）、preimage 全部以 0644 写入。同主机其他用户可读 → 长期密钥泄漏 → 远程资金风险（cheat 后受害者无法反 revoke）。

对比：onion service 私钥（onion_service.rs:475）正确写为 0600；wallet 私钥（fiber-bin）也强制 0600。**只有 store 路径不设权限**，构成对称性缺口。

## 3. 发现

### 3.1 F1 (🟡 Medium) — DB 目录文件权限未强制 0700/0600，敏感密钥材料世界可读

**位置**：`crates/fiber-store/src/native.rs:17-23` (`open_db`)、`crates/fiber-store/src/sqlite.rs:20-25` (`open_db`)、`crates/fiber-bin/src/main.rs:121-129`

#### 问题

`std::fs::create_dir_all(path)` 用进程 umask 创建目录；`rocksdb::DB::open` / `rusqlite::Connection::open` 创建文件不指定 mode。典型部署下 store 目录是 0755、数据文件 0644。

存储中包含：
- `CHANNEL_ACTOR_STATE_PREFIX` 下的 `ChannelActorState`，含 `commitment_seed`（HKDF 派生 per-commitment secrets 的种子）— 拿到种子即可重建所有历史 revocation secret，等价于**完全失去反 cheat 能力**；
- `WATCHTOWER_CHANNEL_PREFIX` 下的 `ChannelData`，含 watchtower 用于签反惩罚交易的 `Privkey`；
- `PREIMAGE_PREFIX` 下的 preimage — 直接资金。

任何与节点同主机的非 root 用户均可读取（共享托管、多租户容器等场景）。

#### 修复

参考 `onion_service.rs:485-491` 的 `set_permissions(Permissions::from_mode(0o600))` 模式：在 `open_db` 后调用一次 `fs::set_permissions(path, 0o700)` 设置目录权限，并在 DB 文件创建后调 0o600。或在节点启动前由 deployment 脚本预创建。

**评级**：🟡 **Medium** — 取决于部署环境，但与 onion key / wallet key 已经 enforce 0o600 的对称性差距明显。

### 3.2 F2 (🟡 Medium) — SQLite 后端无独占文件锁，并发启动两个进程指向同一 store 可静默并发改写

**位置**：`crates/fiber-store/src/sqlite.rs:20-51` (`open_db`)

#### 问题

`Connection::open(&db_file)` + `journal_mode = WAL` 允许多个进程同时打开同一文件。RocksDB 用 `LOCK` 文件强制独占（同时打开返回 IO 错），SQLite 没有等价机制。

#### 攻击/事故场景

- systemd 重启竞态：旧实例 graceful shutdown 尚未完成新实例已起；
- 运维误操作：在两个 shell 误启同一 config；
- Docker 容器配额满后 OOM-killer 杀掉一实例后自动重启；
- 用户在 `check_validate` 期间同时启动正常实例。

后果：

- `MIGRATION_VERSION_KEY` 双写竞态；
- 同一 channel 状态被两个 `ChannelActor` 各自更新 → revocation secret 历史不一致 → force-close 时 cheat-detection 误报或漏报；
- 同一 PaymentSession attempt 被双重处理。

#### 修复

显式 `O_EXCL` 风格的 advisory lock：开 `data.sqlite` 后用 `fs2::FileExt::try_lock_exclusive` 锁文件，open_db 返回 error if locked。或在 `Store::open_db` 后检查 `PRAGMA application_id` 加进程 PID 写入，启动时若已存在且对端 PID alive → bail。

**评级**：🟡 **Medium** — 运维侧事故概率不低，状态损坏可直接影响资金安全（错误 revocation）。

### 3.3 F3 (🟢 Low) — `deserialize_from` 全局 `panic!` 让单条损坏记录永久阻断启动

**位置**：`crates/fiber-lib/src/store/store_impl/mod.rs:121-132`、以及 30+ 调用点

#### 问题

`serialize_to_vec`/`deserialize_from` 用 `unwrap_or_else(|e| panic!(...))` 处理 bincode 错。任何**一条**记录的字节级损坏（torn write、磁盘 bit-rot、ext4 metadata corruption、上一次迁移半途崩溃残留）→ 节点启动时迭代到该条目 → panic → 永久 boot-loop。

`check_validate` (mod.rs:166-320) 提供启动**前**的一次性扫描，但：

1. 默认不调用（需 `config.check_validate = true`）；
2. 即使报错也只 `eprintln + exit(1)`，不提供修复路径；
3. `_ => {}` 默认分支跳过未识别前缀，对未来新增前缀漏报。

更糟的是：**watchtower 工作进程**也调用同一序列化函数。攻击者若能 cheat 之前先让受害 watchtower DB 中某条记录损坏（例如通过 stop-restart 时机制造 torn write）→ watchtower 永久启动失败 → cheat 成功。

#### 修复

- 把 `deserialize_from` 改为返回 `Result<T, StoreError>`，调用方决定 panic / skip / log；
- 至少为读路径加 `tracing::error!` + `continue` 跳过损坏记录，让节点能加载其余状态；
- `check_validate` 在 `open_store_with_migration` 中自动跑 read-only 校验一次，损坏记录 quarantine 到 `<prefix>:quarantine:<key>`。

**评级**：🟢 **Low** — 当前已知无远程触发路径（所有写入字节都源自我们自己），但 boot-loop 是单点失效设计。

### 3.4 F4 (🟢 Low) — Migration 写入非原子，半途崩溃依赖"幂等"假设而该假设依赖 bincode 非自描述边界

**位置**：`crates/fiber-store/src/migration.rs:289-307`、`crates/fiber-store/src/migrations/mig_20260511_*.rs:41-86`

#### 问题

`Migrations::auto_migrate` 对每个 migration：

```rust
m.migrate(store)?;                                   // 单步迁移：可能跑 N 条 store.put
store.put(MIGRATION_VERSION_KEY, m.version());       // 全部 N 条之后才更新版本
```

`m.migrate` 自身内部循环逐条 `store.put(&key, &new_bytes)` — **无 batch、无 transaction**。如果在第 K 条上 panic（OOM、信号、power loss）：

- 前 K-1 条已是新格式；
- 第 K..N 条仍是旧格式；
- `MIGRATION_VERSION_KEY` 未更新。

重启再跑 → 当前 mig_20260511 的"幂等"分支：

```rust
if let Ok(_new) = bincode::deserialize::<NewChannelActorData>(&value) {
    skipped += 1; continue;
}
```

这要求 **bincode 解码新结构对旧字节流必须失败**。但 bincode 1.x 是非自描述、按"消耗 N 字节"工作。如果新结构 = 旧结构 + `enum ConnectivityState{Offline, ...}` (1 byte)：

- 旧字节流末尾若**多出至少 1 字节**且该字节恰好是一个合法 enum 变体（`0..=variants-1`）→ 误判为新格式 → 跳过这条记录的实际迁移；
- 重启后这条记录永久保留为"伪新格式"+ 末尾尾巴；
- 后续读取 `deserialize_from::<NewChannelActorData>(...)` 可能成功但末尾尾巴被忽略；可能失败（如果 bincode 严格校验 input 长度）→ panic。

bincode 默认 `Bounded` config 在解码后**会**校验"剩余字节为 0"吗？看 mig 中的判定：

```rust
if let Ok(_new) = bincode::deserialize::<NewChannelActorData>(&value) { ... }
```

`bincode::deserialize` 使用 `DefaultOptions`，**默认对额外尾随字节不报错**（fixint encoding 不要求完全消耗）。这意味着旧字节流只要前缀符合新结构 + 末尾 enum 字节即可被误判。

#### 修复

- **优先**：把单步 migration 包成 `store.batch()` + `batch.commit()`，使该 migration 全部 put 在一个 RocksDB WriteBatch / SQLite tx 中原子提交；
- 在 `m.migrate(store)?` 成功 + `store.put(MIGRATION_VERSION_KEY, ...)` 之间使用 batch，让 "数据更新 + 版本号更新" 也原子；
- 添加 strict-bincode 配置（`bincode::config().reject_trailing_bytes()`，bincode 2.x 自带 `Configuration::trailing_bytes`）让"误判幂等"消失；
- 单元测试：用一条旧 ChannelActorData 序列化字节 + 任意 0x00 尾字节，断言 `bincode::deserialize::<NewChannelActorData>` 失败。

**评级**：🟢 **Low** — 触发需要 mid-migration crash + bincode 边界恰好（概率 ≤ 1/N_variants per record），但一旦发生即静默数据丢失。

### 3.5 F5 (🟢 Low) — `auto_migrate` 在"无 pending migrations 但版本不等"时无条件升版本号

**位置**：`crates/fiber-store/src/migration.rs:256-262`

```rust
let pending = self.pending_migrations(&db_version);
if pending.is_empty() {
    // Between INIT and LATEST but no migrations to run
    self.init_db_version(store);            // ← 直接写 LATEST_DB_VERSION
    return Ok(());
}
```

#### 问题

如果二进制声明的 `LATEST_DB_VERSION = "20260601000000"` 但代码中并没有任何 ≥ db_version 的 migration（例如 dev 分支误编了 `latest_db_version.rs` 却忘了 commit 对应迁移），节点会**静默**把 db version 升到 LATEST，掩盖配置错误。下次正确二进制启动时按版本认为 DB 已新 → 跳过实际需要的迁移 → 读字段 panic。

#### 修复

`init_db_version` 在这条路径上不应升到 `LATEST`，应保持原 `db_version`，或至少 `tracing::warn!("no migrations registered for {db_version} → {LATEST}, leaving as-is")`。

或者校验：如果 `db_version < LATEST` 且 `pending.is_empty()` → 报错 `MissingMigration`。

**评级**：🟢 **Low** — 上游构建错误问题，不是攻击面，但能导致后续启动隐蔽 panic。

### 3.6 F6 (🟢 Low) — `cli_confirm` 默认互动模式下的迁移决策无法在非交互环境（systemd、k8s init container）自动化

**位置**：`crates/fiber-bin/src/main.rs:128`

`cli_confirm` 在 stdin 不是 TTY 时行为如何？需检查实现。如果 `cli_confirm` 总是 wait stdin，则 systemd unit / docker run 在升级时会 hang 直至超时被 kill → 升级被静默回滚。

#### 修复

提供 `--auto-confirm-migration` flag 或 `FNN_AUTO_MIGRATE=1` 环境变量；在非 TTY 时默认 false 并清晰报错 "migration required, run with --auto-confirm-migration"。

**评级**：🟢 **Low** — UX/运维问题，不是安全问题。

### 3.7 F7 (🟢 Low) — 后端 `.expect("get/put should be OK")` 模式将磁盘 I/O 错抬升为 panic，无 graceful shutdown

**位置**：`crates/fiber-store/src/native.rs:33-105`、`crates/fiber-store/src/sqlite.rs:66-100,124-129,170-175`

磁盘满、I/O error、文件被外部删除 → 任意 `db.get` / `db.put` panic 整个进程。Watchtower / ChannelActor 在 commit pending state 时崩溃 → channel state 与 peer 视图不一致 → 重启后可能强制 `force_close`（保守 fallback）但 commitment_number 还没递增 → 对端拒绝 close 提案 → channel stuck 14 天后才能 timelock 取回。

#### 修复

后端 trait 改为 `Result<...>` 返回类型；调用方决定 retry / graceful flush / 报 RPC error。这是较大重构，但当前 panic-on-I/O 在生产部署中是单点失效设计。

**评级**：🟢 **Low** — 当前部署模式（用户重启）下可恢复；但与"无 graceful shutdown" 协同时 channel state 一致性受损。

### 3.8 F8 (ℹ️ Info) — `_ => {}` 默认分支让 `check_validate` 对未来前缀盲检

**位置**：`crates/fiber-lib/src/store/store_impl/mod.rs:268`

新增 prefix 时若忘记在 `check_validate` 加分支，会被静默跳过。建议改为 `unknown => errors.insert(format!("unknown key prefix 0x{unknown:02x}, count: ..."))`，至少 warn 一次。

**评级**：ℹ️ Info — 维护性建议。

### 3.9 F9 (✅ Pass) — `INIT_DB_VERSION` + `DatabaseTooOld` 阻断越过 epoch 的隐式迁移

`migration.rs:248-254` 正确拒绝早于 `INIT_DB_VERSION = "20260302100001"` 的 DB，避免老格式自动跑入新代码。这是好的 defense-in-depth。

### 3.10 F10 (✅ Pass) — Gossip BroadcastMessage 入 DB 前已验签

`messages_to_be_saved` 的 prune 路径在 `verify_messages` 后才 `insert_message` 到 store（见 MEM-001 F1 分析）。换言之，**store 中 BROADCAST_MESSAGE_PREFIX 下不会有 attacker-controlled 字节**。bincode 反序列化失败的实际触发只能来自：

- 程序 bug 写入错误格式；
- 磁盘 corruption；
- 跨版本破坏性变更未走迁移。

这显著降低了 F3 的远程可利用性。

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — DB 文件权限未强制 0600/0700 → 同主机用户读取密钥种子/preimage/watchtower Privkey | 🟡 Medium | ❌ 未修复 |
| F2 — SQLite 后端无独占锁，多实例并发改写 → revocation 状态损坏 | 🟡 Medium | ❌ 未修复 |
| F3 — `deserialize_from` 全局 `panic!` → 单条损坏永久 boot-loop | 🟢 Low | ❌ 未修复 |
| F4 — Migration 非原子写 + bincode 非严格尾字节校验 → mid-crash 后静默误判幂等 | 🟢 Low | ❌ 未修复 |
| F5 — `pending.is_empty()` 路径无条件升版本号，掩盖缺失迁移 | 🟢 Low | ❌ 未修复 |
| F6 — `cli_confirm` 非交互环境下挂起 | 🟢 Low | ❌ 未修复 |
| F7 — 后端 `.expect` 把 I/O 错抬升为 panic，无 graceful shutdown | 🟢 Low | ❌ 未修复 |
| F8 — `check_validate` 默认 `_ => {}` 不报未识别前缀 | ℹ️ Info | ❌ 未修复 |
| F9 — `INIT_DB_VERSION` + `DatabaseTooOld` 拒绝跨 epoch | ✅ Pass | — |
| F10 — Gossip 验签后入 DB（来自 MEM-001 F1 分析） | ✅ Pass | — |
| 整体 | 🟡 **Medium** | ❌ |

### 总体评价

持久层整体设计是**保守可用**的：bincode 不自描述但 schema 由代码控制；RocksDB 有独占锁；INIT_DB_VERSION 拒绝跨 epoch；gossip 已验签后入 DB（F10）。

但有两类问题需关注：

1. **机密性维度** (F1)：与 onion key (0600) / wallet (0600) 已经 enforce 的对称性差距 — store 目录中含 commitment_seed / watchtower Privkey / preimage 三类高敏数据，0644 默认权限是显著遗漏。修复成本极低（5 行）。
2. **一致性维度** (F2 + F4 + F7)：SQLite 无独占锁、migration 非原子、I/O 错 panic 三者构成"重启时机制造状态不一致 → revocation 失效 → cheat 成功"的链条。SQLite 锁与 migration batch 修复较小；I/O 错全面改 Result 是较大重构。

F3 (deserialize panic) 当前是低可利用性（F10 限制了远程注入路径），但与 F4 协同时构成 boot-loop 风险，建议至少在读路径加 quarantine 而非直接 panic。

## 5. Follow-ups

- **AUDIT-STORE-001-FOLLOWUP-A (🟡 Medium, 必修)**: F1 — 在 `open_db` 后调用 `fs::set_permissions(path, 0o700)` 设目录权限；对 RocksDB/SQLite/WASM 三套后端分别处理。参考 `onion_service.rs:485-491`。
- **AUDIT-STORE-001-FOLLOWUP-B (🟡 Medium, 必修)**: F2 — SQLite 后端添加 `fs2`/`fd_lock` 风格的独占 advisory lock（或写 PID file 后检查 alive）。RocksDB 已有 LOCK，但单元测试要补 multi-open 拒绝路径。
- **AUDIT-STORE-001-FOLLOWUP-C (🟢 Low)**: F4 — 把单步 migration 改用 `store.batch()` + `commit()` 原子化；同时在 `auto_migrate` 中将 "migration 完成 + version key 更新" 包装为单个 batch；bincode 配置增加 `reject_trailing_bytes`。
- **AUDIT-STORE-001-FOLLOWUP-D (🟢 Low)**: F3 — 把 `deserialize_from` panic 改为返回 `Result`；至少在 store 读路径加 `tracing::error!` + skip，让节点能跳过损坏记录并把它们 quarantine 到 `:quarantine:` 前缀。
- **AUDIT-STORE-001-FOLLOWUP-E (🟢 Low)**: F5 — `auto_migrate` 在 "db_version < latest 但无 pending" 时报 `MissingMigration` 错而不是隐式升版本。
- **AUDIT-STORE-001-FOLLOWUP-F (🟢 Low)**: F6 — 添加 `--auto-confirm-migration` flag，并在 stdin 非 TTY 时改默认拒绝 + 清晰报错。
- **AUDIT-STORE-001-FOLLOWUP-G (🟢 Low, 大重构)**: F7 — 后端 trait 改 `Result<...>`，提供 graceful flush 钩子。可拆为单独 RFC。
- **AUDIT-STORE-001-FOLLOWUP-H (ℹ️ Info)**: F8 — `check_validate` 末尾分支报告 unknown prefix counts。

**关联**：
- F1 与 AUDIT-AUTH-002.F3 (onion key 权限) 同质 — 文件权限对称性问题；
- F2 + F4 与 AUDIT-LOGIC-007 (force-close DoS) 协同：状态不一致可触发 channel-stuck；
- F3 与 AUDIT-MEM-001.F1 镜像：MEM-001 是 attacker-controlled 字节直接入内存；STORE-001 F3 是 attacker-controlled 字节入 DB（被 F10 拦截），但磁盘 corruption 路径仍存在；
- F4 (bincode 非严格尾字节) 在未来 schema 增字段时是反复出现的隐式假设，建议在 bincode 配置层面解决。
