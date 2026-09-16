# AUDIT-XMOD-014 — fiber-wasm-db-* ↔ store ↔ channel 跨 tab 状态机损坏

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟠 **High**（浏览器多 tab 同 wallet → commitment 倒退 → 资金罚没） |
| 状态 | [!] 发现弱设计（静态可达，浏览器多 tab 场景下高概率） |
| 出处 | 本次跨模块审计补强；基于 WASM-001 / WASM-002 / STORE-001 + "store layer security" 记忆 |
| 关联代码 | `crates/fiber-store/src/browser*.rs`（IndexedDB 适配；2 处 `unsafe impl Send/Sync`）<br>`crates/fiber-store/src/migration.rs:213-312`（migration 逐条 put，无 IndexedDB transaction）<br>`crates/fiber-wasm-db-worker/`（单 worker 假设）<br>`crates/fiber-wasm-db-common/`（跨 worker 接口）<br>`crates/fiber-wasm/`（浏览器入口）<br>`crates/fiber-lib/src/fiber/channel.rs`（`ChannelActorState`：commitment_seed / commitment_number 核心持久化对象）<br>`crates/fiber-store/src/sqlite.rs:20-181`（SQLite 后端无独占 advisory lock — native 同源问题） |
| 关联 finding | AUDIT-WASM-001（单 worker 假设）、AUDIT-WASM-002（Batch 非原子）、AUDIT-STORE-001（SQLite advisory lock 缺位）、AUDIT-LOGIC-002（commitment lifecycle） |

## 1. 现象

浏览器场景下 fiber 没有"单进程独占 store"的实现保障：

1. **多 tab 同时打开同一 wallet**：每个 tab 实例化各自的 `ChannelActor` + 各自的 `WatchtowerActor`，但底层 IndexedDB **同源共享** → 两份 ChannelActor 各自基于"上次读到的" `ChannelActorState` 推进 commitment_number → 写回时 **最后写者赢**（IndexedDB Object Store `put` 默认覆盖）。
2. **migration 非原子**：`fiber-store/src/migration.rs:213-312` 逐条 put 无 transaction → tab A migration 进行到一半、tab B 刷新页面也开始 migration → 双 migration 并发 → DB 进入未定义状态（部分 mig 已跑、部分未跑、db-version 不一致）。
3. **SQLite 后端无 advisory lock**（STORE-001 已记）：native 也有此问题但通常单进程；浏览器场景"多 tab = 多进程实例"使触发概率显著上升。
4. **commitment_seed / commitment_number 损坏 = 永久 brick + 资金罚没**：tab A 推进到 N、tab B 仍在 N-1，tab B 重新签名旧 commitment → 对端视为 cheat → revocation tx 上链 → **本端资金被罚没**。

## 2. 跨模块攻击 / 误用链

不需要外部攻击者，**用户行为**即可触发：

```
[user] 同时开两个浏览器 tab，加载同一钱包
  → tab A: send_payment(...)  推进 commitment_number = N
  → tab B (页面刷新前看到 N-1) → send_payment(...) 仍按 N-1 签名 → 写回 IndexedDB → 覆盖 tab A 写的 N
  → tab A 发出去的新 commitment 与对端协商成功；tab B 也广播同 commitment_number 的另一签名
  → 对端持有两个不同有效 commitment → 取旧那个上链 → revocation 见效 → 本端资金被罚没
```

或：

```
[user] tab A 在做 fiber-wasm-db-* migration（如升级版本）
  → migration 跑到一半（部分 put 完成）
  → user 在 tab B 刷新或新开页面 → 触发同一 migration
  → 两份 migration 并发 put，IndexedDB ObjectStore.put 无 transaction 隔离
  → 最终状态：部分 mig 完成、db-version stamp 错位 → 数据 schema 错位
```

## 3. 与已有发现的区别

- WASM-001 只看"单 worker 假设"内部一致性；
- WASM-002 只看"Batch 操作非原子"；
- STORE-001 只看 native DB 权限；
- 本条强调 **多 tab × 多 worker × 共享 IndexedDB × 无锁** 四元组形成的"用户级误用即罚没"风险。
- 浏览器 wallet 是 fiber **最贴近终端用户**的形态，威胁模型与服务器节点完全不同。

## 4. 影响评估

- **资金罚没**（不是 brick / DoS）；
- 无须攻击者：用户日常误操作即可触发；
- 影响 fiber-wasm 全部用户；
- 检测困难：罚没在链上发生，浏览器侧只看到"signature mismatch"等次级错误。

## 5. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | P0 | `fiber-wasm` 启动时调 `navigator.locks.request('fiber-wallet-' + wallet_id, { mode: 'exclusive' }, async () => {...})` 申请独占锁；**第二个 tab 进入只读 / 观察模式**，禁用签名/发送 RPC，UI 显示"已在另一标签页打开"。 |
| F2 | P0 | `fiber-store/src/browser*.rs` 把 migration + 所有 channel state 写入包装到 IndexedDB **transaction** (`readwrite` mode)；跨 ObjectStore 用 `transaction([...], 'readwrite')`，失败回滚。 |
| F3 | P1 | ChannelActor 启动时检测 `commitment_number` 单调性：如果新读到值 < 内存中"我以为最后一次写入"的值，主动 force-close + 报警，**不继续推进**。 |
| F4 | P1 | SQLite 后端补 `PRAGMA locking_mode = EXCLUSIVE` 或文件 `flock` advisory lock（与 STORE-001 / XMOD-003.F5 共享修复路径）。 |
| F5 | P2 | 在 db-version key 周围增加 "migration-in-progress" 标志位；并发 migration 启动直接 bail。 |

## 6. 验证测试

- **Playwright 集成测试**：双 tab 同时打开同一 wallet + 同时 `send_payment`，断言：
  - 其中一方进入只读模式（UI 指示）；
  - IndexedDB 中只有一份连续 commitment_number 序列，无回退。
- `fiber-store::tests::test_migration_transactional`：在 IndexedDB mock 上模拟"migration 中途崩溃" → 重启后断言要么完全回滚、要么完全应用，无中间状态。
- `channel::tests::test_commitment_number_monotonic_guard`：手动 store 写入回退值，重启 ChannelActor 断言进入 `bricked` + 触发 force-close emit。

## 7. 状态

- F1+F2 为浏览器场景必要项；F3+F4 深度防御；F5 后置。
- 关联 PR：暂无。
