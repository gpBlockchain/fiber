# AUDIT-WASM-001 — `fiber-store` 浏览器 `unsafe impl Send/Sync` 不变量

| 字段 | 值 |
|---|---|
| 维度 | DIM-WASM |
| 严重度 | 🟡 Medium (Medium × 1 + Low × 2 + Info × 1 + Pass × 2) |
| 状态 | [!] 发现弱设计 |
| 关联代码 | `crates/fiber-store/src/browser.rs:31-32, 200-369`, `crates/fiber-store/src/browser_test.rs:19-20`, `crates/fiber-wasm-db-worker/src/db.rs`, `crates/fiber-wasm-db-common/src/lib.rs` |

## 1. 背景

wasm32 目标下，`fiber-store::browser::Store` 用 `SharedArrayBuffer` + `Atomics.wait` 与 db-worker (运行在独立 Web Worker 中操作 IndexedDB) 通信。`Store` 持有的 `CommunicationChannel` 内部字段 `Int32Array` / `Uint8Array` 都是 `JsValue` wrapper，wasm-bindgen 给它们标 `!Send + !Sync`。fiber-store 通过两处 `unsafe impl Send/Sync` 强制 promote：

```rust
// browser.rs:31-32
unsafe impl Send for Store {}
unsafe impl Sync for Store {}
```

这是 fiber 整个 workspace 的两处主要 `unsafe`（外加 `browser_test.rs:19-20` 同模式 + `tests/test_utils.rs` 一处，AUDIT-MEM-003 已 cross-ref）。

## 2. 发现

### F1 🟡 Medium — `unsafe Send/Sync` 不变量隐性化

- `Send` 在浏览器单线程 wasm 上下文里**不可能违反**（无真实抢占式线程），但 fiber-lib 上层调用方（`ractor` actor system）以 `Send` 为类型契约。当未来某 wasm threads (`wasm32-unknown-unknown` + `+atomics,+bulk-memory,+mutable-globals`) 真实落地时：
  - `Int32Array` / `Uint8Array` 内部持有 JS-side 句柄表索引（wasm-bindgen `JsValue` IDX），多线程同时操作同一句柄表 → wasm-bindgen 运行时**未定义行为**（已知上游 issue：`wasm-bindgen/issues/2415`）。
  - `SharedArrayBuffer` 本身可跨 worker，但 `Int32Array`/`Uint8Array` view 不可。
- 当前代码注释 (browser.rs) 没有解释这两条 `unsafe` 的安全前置条件，违反 Rust 社区 "any unsafe block must have a SAFETY: comment" 约定（rustc 自身已 lint）。

### F2 🟢 Low — `DB_INITIALIZED` AtomicBool + thread_local 状态机理论上跨 worker 不一致

- `DB_INITIALIZED: AtomicBool` (browser.rs:204) 是 Rust 静态量，对每个 wasm 实例独立 (wasm 模块每 worker 一份实例)；`INPUT_BUFFER`/`OUTPUT_BUFFER` 是 `thread_local!` (browser.rs:200-203)。
- 当前架构每个 fiber 实例只在主 worker 实例化一次 `Store`，单实例假设成立；但**任何把 fiber 嵌入 nested worker / Service Worker 的二次封装**都会破坏这个不变量（不会立刻崩，但会导致两个 worker 各自走完整的 `open_database` 握手 → IndexedDB 层并发开同名 store → idb crate 报错 → store/get 路径 unwrap panic）。

### F3 🟢 Low — 大量 `.unwrap()` / `.expect()` 在 wasm IPC 路径上

- `browser.rs` 内 14 处 `.unwrap()`：`Atomics::wait().unwrap()`, `try_from().unwrap()`, `write_command_with_payload().unwrap()`, `dispatch_database_command().unwrap()` 等。
- 任何 SharedArrayBuffer 协议错配（如 db-worker 升级了 enum discriminant 没同步前端）→ wasm 整页 panic / abort。
- 这与 AUDIT-STORE-001.F3 (native `panic!`) 同质，但 wasm 端 panic 等于浏览器整个 fiber web 节点崩溃，无 supervisor 重启。

### F4 ℹ️ Info — `unsafe impl` 与上游 wasm-bindgen 演化

- wasm-bindgen 0.2.x 系列尚未对 `Int32Array`/`Uint8Array` 提供 conditional `Send` impl；fiber 这种"应用层 promote `Send`"模式是 wasm 生态长期妥协（也是 `web-sys::*` 大量使用的常规做法）。
- 真实 risk 是 wasm-bindgen 大版本升级（如 0.3.x）若把这些类型从 `!Send` 转 `Send`（在某些 feature 下），fiber 的 `unsafe impl` 会与上游 impl 冲突 (orphan rule + auto-trait conflict)。
- 当前 build matrix 未在 CI 锁住 wasm-bindgen 版本（`Cargo.lock` 隐式锁，但 `cargo update` 会更新）。

### F5 ✅ Pass — 单 worker 假设下的内存安全

- 当前部署架构（主 worker × 1 + db worker × 1）下，`Store::clone()` 通过 `chan: CommunicationChannel.clone()` 完成；clone 是按引用复制 JS 句柄，单 worker 内不存在数据竞争。
- `Atomics.wait` + busy-loop `RequestTakeWhile` 协议是经典的 producer-consumer 模型；语义上等价于 `crossbeam-channel` 在 wasm 上的替代。

### F6 ✅ Pass — IPC 协议有显式 enum discriminant 校验

- `OutputCommand::try_from(i32)` (`fiber-wasm-db-common/src/lib.rs`) 校验 wire-level enum；db-worker 与 main worker 用同一 crate 共享 enum，编译期保证一致。
- 这部分设计明显**反映了对单 worker 假设的尊重**：用 `try_from` + Result 而不是 `transmute` 是良好范本。

## 3. 影响

- 单 worker 部署下：**实际不会触发 UB**（浏览器无真实抢占式线程）；当前架构安全。
- 多 worker / wasm threads 部署下：**理论 UB**（wasm-bindgen 句柄表跨线程访问）。fiber 当前架构不支持，但缺少阻止开发者扩展到该场景的护栏。

## 4. 修复建议

| 优先级 | 建议 | 估改动 |
|---|---|---|
| P2 | `unsafe impl Send/Sync` 上加 `// SAFETY: ...` 注释解释单 worker 假设 + wasm threads 不兼容 | 2 块注释 |
| P2 | `browser.rs` 顶部加 `#![cfg(not(target_feature = "atomics"))]` 编译期阻止 wasm threads 构建 | 1 行 |
| P3 | IPC `.unwrap()` 路径改 `.context()? → propagate to caller` (与 STORE-001.F3 修复同链路) | ~20 行 |
| P3 | CI: 锁 `wasm-bindgen = "=X.Y.Z"` 精确 pin，避免大版本升级静默改变 Send-ness | Cargo.toml |
| P3 | 加 `tests/wasm_send_sync.rs` static_assertions::assert_impl_all!(Store: Send + Sync) 防回归 | 5 行 |

## 5. 跟踪项

- AUDIT-WASM-001-FOLLOWUP-A：写 `SAFETY:` 注释 + 编译期 cfg gate
- AUDIT-WASM-001-FOLLOWUP-B：同步 AUDIT-STORE-001.F3 修复路径，浏览器 wasm 端 unwrap → Result
- AUDIT-WASM-001-FOLLOWUP-C：评估 fiber 是否需要支持 wasm threads / Service Worker 嵌入；若否，文档化"single worker only"假设
