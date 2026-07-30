# AUDIT-WASM-002 — WASM 持久化 / IndexedDB 读写一致性

| 字段 | 值 |
|---|---|
| 维度 | DIM-WASM / DIM-STORE |
| 严重度 | 🟡 Medium (Medium × 2 + Low × 3 + Info × 1 + Pass × 2) |
| 状态 | [!] 发现弱设计 |
| 关联代码 | `crates/fiber-store/src/browser.rs:46-198`, `crates/fiber-wasm-db-worker/src/db.rs:1-50+`, `crates/fiber-wasm-db-common/src/lib.rs`, `crates/fiber-store/src/migration.rs` (共享路径) |

## 1. 背景

fiber wasm 端用 IndexedDB 作为持久化层（idb crate 封装）。db-worker 把所有数据塞进单一 object store；前端 `Store::put/get/batch` 通过 SharedArrayBuffer IPC 同步等待 db-worker 完成 IndexedDB 操作后返回。

## 2. 发现

### F1 🟡 Medium — `Batch::commit` 拆成两个独立 IPC 请求，非原子

```rust
// browser.rs:190-197
fn commit(self) {
    self.chan.dispatch_database_command(DbCommandRequestWithTakeWhile::Delete { keys: self.delete })
        .expect("Failed to delete batch");
    self.chan.dispatch_database_command(DbCommandRequestWithTakeWhile::Put { kvs: self.puts })
        .expect("Failed to put batch");
}
```

- Native (RocksDB/SQLite) 端的 `batch.commit()` 是 atomic write batch；wasm 端拆成两次独立 IPC 调用，**两个 IndexedDB transaction**。
- 中间任一步出错（worker 异常、SharedArrayBuffer 失败、tab 关闭）→ delete 已生效但 put 未生效 → 数据丢失。
- 影响：与 `migration.rs` 配合使用时，迁移半途崩溃会留下损坏状态（与 AUDIT-INPUT-004 / STORE-001.F4 同质，但 wasm 端更严重：浏览器 OOM/tab 切换是常态）。
- ChannelActorState 持久化用 batch（actor handler 内单条 channel 更新 = 1 个 batch.commit）→ delete-then-put 中间断电 → state 丢失 → channel reload 失败 → 强制关闭，资金被 CSV delay 锁定。

### F2 🟡 Medium — IndexedDB 跨 origin / 多 tab 不互斥

- IndexedDB 浏览器规范：同 origin 多 tab 可同时打开同一 database；事务 isolation 是 IDB 内置的（serializable），**但 fiber 自身 store 层抽象不感知**。
- 用户在 tab A 跑 fiber web 节点 + tab B 同样开 fiber web 节点（同 origin） → 两个 db-worker 同时操作同一 IndexedDB → 内部 IDB 事务串行化，但 fiber 业务层（如 commitment_number 单调增长）**无版本检查** → state 互相覆盖 → 类似 AUDIT-STORE-001.F2 (SQLite 无 advisory lock) 的双开实例问题，但 wasm 端无任何护栏。

### F3 🟢 Low — `db.rs:35,40` `serde_wasm_bindgen::to_value(...).unwrap()` panic

- KeyRange 序列化用 unwrap()，浏览器内存压力/JS 引擎异常时会让 db-worker 整体崩溃。
- 与 AUDIT-INPUT-005 / STORE-001.F3 同质模式：边界 IPC 全 panic。

### F4 🟢 Low — 无 IndexedDB quota 监控

- 浏览器对 IndexedDB 有 quota（通常 50% 可用磁盘），fiber 端无 `navigator.storage.estimate()` 监控 / 报警。
- 长期运行后 quota 满 → put 失败 → 通过 IPC 传回前端 → fiber-store `put.unwrap()` panic → ChannelActorState 写失败 → channel 状态机不一致。

### F5 🟢 Low — `Iterator` 命令通过 `RequestTakeWhile` 反向 IPC 循环（browser.rs:336-355）

- 每个 key 都要走一次 main-worker ↔ db-worker 同步 round-trip；大 prefix scan（如 gossip broadcast 表）会引入 N 次 `Atomics.wait` block，主 worker 阻塞期间 RPC 处理停滞。
- 与 AUDIT-INPUT-003.F2 / MEM-003 协同：在 wasm 端 `graph_nodes { limit: u64::MAX }` 会触发更糟糕的 hang（每条 key 一次 IPC 同步）。

### F6 ℹ️ Info — 无版本号 / schema migration framework wasm 路径未审计

- wasm 端共用 native 的 `crates/fiber-store/src/migration.rs`；IndexedDB schema upgrade（`onupgradeneeded`）与 fiber `MIGRATION_VERSION_KEY` 是两套独立机制。
- 当前 fiber 只把 IDB 当扁平 KV，不依赖 IDB 的版本机制。但 idb crate 的 `Factory::open(name, version)` 调用语义未审计（idb 0.x 上游有过 version > old_version 时数据丢失的 issue，已修复但需确认 fiber 锁的版本）。

### F7 ✅ Pass — 单 store 扁平 KV 设计简单稳健

- `db.rs` 只用一个 ObjectStore，避免了 IDB 多 store 跨事务问题；put/get/delete/iterator 都对应单一 IDB API。
- 设计上消除了大量并发坑（同 origin 跨 tab 问题仍存在 — F2）。

### F8 ✅ Pass — IDB 内置 transaction isolation

- IDB 规范保证 `readwrite` 事务串行化（IDB transaction model）；单 db-worker 顺序处理 IPC → 同一 worker 内 IDB 操作无 race。

## 3. 影响

- 默认部署（单 tab × 单 db-worker × 主 worker fiber 实例）：**实际安全**（F8 Pass 兜底）。
- 多 tab / 高负载 / 长期运行场景：**Medium 风险**：F1 非原子 batch + F2 多 tab 互不感知 = 数据丢失/状态分裂。

## 4. 修复建议

| 优先级 | 建议 | 估改动 |
|---|---|---|
| P1 | `Batch::commit` 在 db-worker 端合并成单 IDB transaction：新增 `DbCommandRequest::Batch { deletes, puts }` IPC 类型 | ~50 行（含 worker 端） |
| P2 | 启动期用 `BroadcastChannel` / `navigator.locks.request()` 实现跨 tab 互斥；同 origin 第二个实例 fail-fast | ~30 行 |
| P2 | `navigator.storage.estimate()` 定期监控；quota > 90% 通过 RPC 警告事件上报 | 30 行 |
| P3 | `db.rs` 的 `serde_wasm_bindgen::to_value().unwrap()` 路径改 `?` 传播 | ~10 行 |
| P3 | `Iterator` 命令在 db-worker 端做完整 prefix scan + 一次性返回（消除 N 次 RequestTakeWhile IPC），代价是大集合内存压力但消除 main-worker hang | ~40 行（设计权衡） |

## 5. 跟踪项

- AUDIT-WASM-002-FOLLOWUP-A：实现 atomic `DbCommandRequest::Batch` IPC
- AUDIT-WASM-002-FOLLOWUP-B：跨 tab 互斥（`navigator.locks` 或 BroadcastChannel）
- AUDIT-WASM-002-FOLLOWUP-C：与 AUDIT-INPUT-003.F2 联动 — wasm 端把 RPC `limit` 上界打更严
- AUDIT-WASM-002-FOLLOWUP-D：审计 idb crate 版本 + `Factory::open` 版本号传参；确认无 schema upgrade 数据丢失 issue
