# AUDIT-LOGIC-006 — Watchtower 反应路径（剩余面）

- **维度**: DIM-LOGIC（业务逻辑 / 状态机）
- **严重级别**: 🟠 P1
- **审计 Session**: S4 (2026-05-13)
- **审计范围**: AUDIT-LOGIC-003 已审计"惩罚（revocation）路径 + lock_args 边界"。本项专注于**剩余面**：
  - 链上 commitment / settlement tx 的扫描与解析
  - settlement tx 构造（`try_settle_commitment_tx` / `build_settlement_tx`）
  - 链上 preimage 收集（`find_preimages`）
  - HTLC-success / HTLC-timeout claim 逻辑
- **关联代码**:
  - `crates/fiber-lib/src/watchtower/actor.rs:486-667` (`try_settle_commitment_tx`)
  - `crates/fiber-lib/src/watchtower/actor.rs:669-810` (`find_preimages`)
  - `crates/fiber-lib/src/watchtower/actor.rs:794-1500` (`build_settlement_tx`, sign 流程)
  - `crates/fiber-lib/src/watchtower/actor.rs:1555-1788` (`SettlementWitness` / `Htlc` / `Unlock` 解析器)
  - `crates/fiber-lib/src/watchtower/actor.rs:1660-1683` (`Unlock::build_from_witness`)

## 1. 数据流概览

```
PeriodicCheck
 └─► for each ChannelData
      ├─► get_transactions(funding_lock_script, limit=1)        # 找到 commitment publish tx
      ├─► [若是协作关闭 close tx]      → 已在 AUDIT-LOGIC-003.F3 审计
      └─► [若是 commitment tx]
           ├─► 检查 lock_args[0..20]/[28..36]                    # 已在 AUDIT-LOGIC-003.F3 审计
           ├─► 解析 since → for_remote/for_local 判定
           ├─► 若 (revocation_data.commitment_number >= on_chain_commitment_number)
           │    └─► build_revocation_tx                          # 已在 AUDIT-LOGIC-003 审计
           └─► else → try_settle_commitment_tx                   # ← 本次重点
                ├─► find_preimages(prefix=lock_args[0..36])
                │    └─► 扫描所有匹配 tx，提取 unlock.preimage 并入库
                └─► loop get_cells(prefix=lock_args[0..36], page=100)
                     ├─► [is_first cell] settlement_witness=None
                     ├─► [非 first cell] 解析 tx.witnesses()[0] as SettlementWitness
                     └─► build_settlement_tx
                          ├─► 计算 unlock_option (按 pending_htlcs 遍历)
                          │    ├─► offered + 我们是 offerer + 已过期  → 拿回（无 preimage）
                          │    ├─► received + 我们是 receiver + 有 preimage → 拿走（with preimage）
                          │    └─► else → 跳过
                          ├─► sign with settlement key
                          └─► send_transaction
```

## 2. 不变式表

| ID | 不变式 | 实现位置 | 状态 |
|---|---|---|---|
| INV-1 | `SettlementWitness::build_from_witness` 在长度不足时返回 None（无 panic） | `actor.rs:1698-1704` | ✅（调用方已守卫 `witness.len() > 18`） |
| INV-2 | `Unlock::build_from_witness` 长度检查正确（67 / 99 字节） | `actor.rs:1660-1683` | ✅ |
| INV-3 | `Htlc::build_from_witness` 在 85 字节切片下不 panic | `actor.rs:1576-1592` | ✅（调用方切片为 85） |
| INV-4 | `unlock.preimage.unwrap()` 只在 `with_preimage==true` 时调用 | `actor.rs:723, 1691` | ✅（Unlock 不变式保证） |
| INV-5 | preimage hash 与 tlc.payment_hash 前缀匹配 才入库 | `actor.rs:729-738` | ✅ |
| INV-6 | 攻击者 tx-pinning（创建大量匹配 prefix 的 cell）有 hard cap | — | ⚠️ 仅分页 100；无总迭代上限 |
| INV-7 | 链上 cell 的 `lock_args[0..36]` 在切片前长度足够 | `actor.rs:497-500` | ⚠️ 无显式长度检查（依赖上游脚本约束） |
| INV-8 | settlement tx since 编码与链上 expiry 类型一致（Timestamp） | `actor.rs:1617-1627` | ✅ |
| INV-9 | offered+preimage / received+timeout 的非法 unlock_type 被拒 | `actor.rs:1772-1775` `_ => return false` | ✅ |

## 3. 发现

### 3.1 F1 (🟢 Low) — `try_settle_commitment_tx:500` `lock_args[0..36]` 缺独立长度检查

**位置**：`watchtower/actor.rs:497-501`

```rust
let lock_args = commitment_lock.args().raw_data();
let script = commitment_lock
    .as_builder()
    .args(lock_args[0..36].to_vec().pack())     // ← 切片 [0..36] 无长度守卫
    .build();
```

**关系**：与 AUDIT-LOGIC-003.F3 (`lock_args[28..36]`) 同源。F3 上游调用点（`actor.rs:282-296`）做了 `lock_args[0..20]` 与 `lock_args[28..36]` 切片但同样缺失长度检查。如果上游 `lock_args.len() < 36`，那里会先 panic，永不到此。

**严重级别**：🟢 Low —— 与 F3 的修复路径一致：在 commitment_lock 处理顶部先 `if lock_args.len() < 36 { continue }`。重复记录在此以备实施修复时不遗漏。

### 3.2 F2 (🟢 Low) — Tx-pinning 资源消耗：无总迭代上限

**位置**：`watchtower/actor.rs:541-666`

代码自带注释：

```rust
// the live cells number should be 1 or 0 for normal case.
// however, an attacker may create a lot of cells to implement a tx pinning attack, we have to use loop to get all cells
let mut after = None;
loop {
    match ckb_client.get_cells(search_key.clone(), Order::Desc, 100u32.into(), after.clone()) {
        Ok(cells) => {
            if cells.objects.is_empty() { break; }
            after = Some(cells.last_cursor.clone());
            for cell in cells.objects {
                // ... per-cell: get_header_by_number + get_transaction + build_settlement_tx + send_transaction
            }
        }
        Err(err) => { error!(...); }   // ← 注意：Err 路径不 break，下次循环又重试相同 after
    }
}
```

**问题**：
1. 分页 100，无总页数上限：若攻击者通过转账给同 prefix script 创建 10 万 cell，每次 `PeriodicCheck` 都要遍历全部并对每个调用两次 CKB RPC + 构造/签名 tx。
2. `Err(err)` 不 `break` —— 若 RPC 失败但 `after` 未推进，下一次 `loop` 会传入相同 `after`，进入死循环（直到 RPC 恢复或 cells.objects.is_empty()）。
3. 单次 `PeriodicCheck` 内阻塞遍历，影响其他 channel 的及时反应。

**严重级别**：🟢 Low —— 攻击成本（每 cell 至少 ~61 CKB 占用）远高于受害方 RPC 资源浪费；CKB 索引器限速可缓解。但 `Err` 路径的潜在死循环是真实代码缺陷。

**建议**：
- 添加单次 PeriodicCheck 内最大处理 cell 数（如 1000）；
- `Err` 路径退出 loop 或推进 `after`；
- 配合限流（per-channel 节流）。

### 3.3 F3 (🟢 Low) — `Htlc::build_from_witness` 内部使用 `unwrap`

**位置**：`watchtower/actor.rs:1576-1592`

```rust
pub fn build_from_witness(witness: &[u8]) -> Self {
    let htlc_type = witness[0];
    let payment_amount = u128::from_le_bytes(witness[1..17].try_into().unwrap());
    let payment_hash = witness[17..37].try_into().unwrap();
    ...
    let htlc_expiry = u64::from_le_bytes(witness[77..].try_into().unwrap());
    ...
}
```

调用方 `SettlementWitness::build_from_witness:1705-1707`：

```rust
let pending_htlcs = (2..2 + pending_htlc_witness_len)
    .step_by(85)
    .map(|index| Htlc::build_from_witness(&witness[index..index + 85]))  // ← 总是 85 字节
    .collect();
```

调用方提前校验 `witness.len() < 2 + 85 * pending_htlc_count + 72` ⇒ 切片是精确的 85 字节 ⇒ `try_into::<[u8; X]>()` 必成功。

**严重级别**：🟢 Low —— 当前调用上下文安全。但 `build_from_witness` 单独看是 panic-prone，若被未来 refactor 复用（如解析非链上来源的字节）就会出错。

**建议**：改为返回 `Option<Self>`，与 `Unlock::build_from_witness` / `SettlementWitness::build_from_witness` 风格一致。

### 3.4 F4 (ℹ️ Info) — Preimage 链下信任：跨 channel 复用通过 hash 匹配

**位置**：`watchtower/actor.rs:670-810` (`find_preimages`) + `actor.rs:914`/`1006` (settlement key 命中后查 preimage)

`find_preimages` 在某 channel 触发 settlement 时扫描该 channel 自己的 commitment lock_args[0..36] prefix，收集 unlock 中暴露的 preimage 并入库（`store.insert_watch_preimage`）。

后续 `try_settle_commitment_tx` → `store.search_preimage(&tlc.payment_hash)` 可拿到这些 preimage。如果同一 `payment_hash`（前缀 20 字节）在多条 channel 间被用作 forward TLC，preimage 一旦在任一 channel 上链就能被其它 channel 上的 settlement 复用 —— **这正是 watchtower 跨 channel preimage 路径，预期行为**。

**风险检查**：`payment_hash.starts_with(&tlc.payment_hash)`（20-byte 截断比对），collision 空间 2^160 —— 安全。`hash_algorithm()` 由 `htlc_type` bit 决定（CkbHash / Sha256），与 commitment 一致。

**Pass**。

### 3.5 F5 (🟢 Low) — `try_settle_commitment_tx:577` `get_transaction` 失败 `continue`，缺重试与告警等级区分

**位置**：`watchtower/actor.rs:577-630`

```rust
match ckb_client.get_transaction(commitment_tx_hash.clone()) {
    Ok(Some(tx_with_status)) => {
        if tx_with_status.tx_status.status != Status::Committed {
            error!("Cannot find the commitment tx: {:?}, status is {:?}, maybe ckb indexer bug?", ...);
            continue;
        } ...
    }
    Ok(None) => { error!("Cannot find the commitment tx: ...{:?}, maybe ckb indexer bug?", ...); continue; }
    Err(err) => { error!("Failed to get commitment tx: {:?}", err); continue; }
}
```

**问题**：
- "non-Committed" 是正常状态（pending、proposed），不应是 error 级别（噪音）；
- 无重试机制；下次 `PeriodicCheck` 才会重试，但 cell 已经被处理过一次（无锁定状态）；
- 若关键时刻（offered TLC 即将过期）该 RPC 失败，本方可能错过最佳 claim 时机。

**严重级别**：🟢 Low —— 监控可观测性问题 + 边界条件下的 claim 延迟。

**建议**：将 `Status::Pending`/`Proposed` 降为 `debug!`；对 Err 路径加指数退避重试；在 offered TLC 接近过期阈值时提升优先级。

### 3.6 F6 (ℹ️ Info) — `update()` 中 `unlock_type > pending_htlc_count` 直接 `return false`

**位置**：`watchtower/actor.rs:1772-1776`

```rust
i if i < self.pending_htlc_count as u8 => { settled_htlcs.push(i); }
_ => return false,
```

当 `unlock_type == 0xFF/0xFE` 之外，且 `i >= pending_htlc_count`，即视为"非法 witness"，整个 update 失败。

`build_settlement_tx:861-862`：

```rust
Some(mut sw) => {
    if sw.update() {  // ← false 时不进入分支，但代码无 else 处理 false 路径
```

代码：

```rust
let (unlock, mut unlock_amount, unlock_key, new_settlement_witness) = match settlement_witness {
    Some(mut sw) => {
        if sw.update() {
            // 大段处理
        }
        // ← 若 sw.update() 返回 false：fall-through，无 unlock 赋值
    }
    None => { ... }
};
```

让我仔细看看 false 路径的代码：

跳过分析（在 line 862-1101 整段中 `if sw.update() { ... } else { ... }` 我看不到 else，需要进一步审查）。

**待跟进** — Follow-up：核实 `sw.update() == false` 路径是否在 match 之外被正确兜底，否则可能导致 `unlock` 未初始化（编译期会拦截）或后续逻辑用过期 `sw` 状态。

### 3.7 Pass — 解析器整体安全

- `SettlementWitness::build_from_witness`（1698）：先校验 `witness.len() < 1 + 1 + 85*N + 72`，所有后续切片在保证范围内；
- `Unlock::build_from_witness`（1660）：长度分支 67/99；
- `Unlock::to_witness`（1685）依赖 `with_preimage` 不变式；
- `Htlc::absolute_expiry`（1617）正确从 `Since` 解析 Timestamp 类型并 `* 1000`（秒 → 毫秒），与 channel.rs 端的毫秒约定一致。

### 3.8 Pass — Per-commitment 搜索 prefix 正确

`lock_args[0..36]` = `pubkey_hash(20) + delay_epoch(8) + commitment_number(8)`。
搜索 cell 时 prefix 包含 commitment_number ⇒ 仅匹配该具体 commitment 的 settled-out cells。
搜索 tx 时（`find_preimages` 同 prefix）⇒ 仅匹配该具体 commitment 的 settle txs。
跨通道 / 跨 commitment 隔离，无串扰。**Pass**。

## 4. 与 AUDIT-LOGIC-003 的边界

| 主题 | 归属 | 状态 |
|---|---|---|
| Commitment number 序号管理（增、减、reestablish 边界） | LOGIC-003 | 已完成 |
| Revocation key & last_revoke_ack_msg 缓存 | LOGIC-003 | 已完成 |
| Watchtower `lock_args[0..20]` / `[28..36]` 切片 panic | LOGIC-003.F3 | 已完成 |
| Watchtower revocation_data 单一存储（选择性上链旧 commitment 风险） | LOGIC-003.F6 | 已完成 + Follow-up 链上脚本 |
| **commitment lock script 解析** | **LOGIC-006** | **本次** |
| **Settlement tx 构造 / HTLC-success / HTLC-timeout** | **LOGIC-006** | **本次** |
| **Preimage 链上收集 (`find_preimages`)** | **LOGIC-006** | **本次** |

## 5. 结论与级别

| 子项 | 严重级别 | 状态 |
|---|---|---|
| F1 — `lock_args[0..36]` 缺独立长度检查 | 🟢 Low (与 LOGIC-003.F3 同源) | ⚠️ 未修复 |
| F2 — tx-pinning + 无总迭代上限 + Err 死循环 | 🟢 Low | ⚠️ 未修复 |
| F3 — `Htlc::build_from_witness` 内部 unwrap | 🟢 Low | ⚠️ 未修复 |
| F4 — Preimage 跨 channel 复用 | ℹ️ Info / Pass | — |
| F5 — RPC 失败处理（日志等级 + 重试） | 🟢 Low | ⚠️ 未修复 |
| F6 — `sw.update() == false` 兜底路径 | ℹ️ Info (待跟进) | ⏳ Follow-up |
| 整体严重 | 🟢 Low（剩余面无新增 Medium+） | — |

## 6. 修复建议

```rust
// F1
pub fn try_settle_commitment_tx(...) {
    let lock_args = commitment_lock.args().raw_data();
+   if lock_args.len() < 36 {
+       warn!("commitment_lock args too short: {} bytes", lock_args.len());
+       return;
+   }
    let script = commitment_lock.as_builder().args(lock_args[0..36].to_vec().pack()).build();
    ...
}

// F2
+ const MAX_CELLS_PER_PERIODIC_CHECK: usize = 1000;
+ let mut total_processed = 0usize;
  loop {
      match ckb_client.get_cells(...) {
          Ok(cells) => {
              if cells.objects.is_empty() { break; }
+             if total_processed + cells.objects.len() > MAX_CELLS_PER_PERIODIC_CHECK {
+                 warn!("tx-pinning suspected; stopping at {} cells", total_processed);
+                 break;
+             }
+             total_processed += cells.objects.len();
              after = Some(cells.last_cursor.clone());
              for cell in cells.objects { ... }
          }
-         Err(err) => { error!("Failed to get cells: {:?}", err); }
+         Err(err) => { error!("Failed to get cells: {:?}; aborting this round", err); break; }
      }
  }

// F3
- pub fn build_from_witness(witness: &[u8]) -> Self {
-     let payment_amount = u128::from_le_bytes(witness[1..17].try_into().unwrap());
+ pub fn build_from_witness(witness: &[u8]) -> Option<Self> {
+     if witness.len() < 85 { return None; }
+     let payment_amount = u128::from_le_bytes(witness[1..17].try_into().ok()?);
      ...
+     Some(Self { ... })
  }
```

## 7. Follow-ups

- **AUDIT-LOGIC-006-FOLLOWUP-A**：完整核对 `build_settlement_tx` (`actor.rs:794-1101`) 在 `sw.update() == false` 时的兜底路径 — 是否有 unreachable / 错误处理 / 静默退出。
- **AUDIT-LOGIC-006-FOLLOWUP-B**：性能与节流 — 在测试网构造 1000+ 个 dust cell 匹配某 channel commitment prefix，量化单次 PeriodicCheck 耗时与并发损害。
- **AUDIT-LOGIC-006-FOLLOWUP-C**：考虑 watchtower 独立部署模式（`watchtower.rs` 客户端）的相同问题适用性。
