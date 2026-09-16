# AUDIT-INPUT-005 — CKB Tx / Cell 数据校验

| 维度 | 内容 |
|---|---|
| 整体严重度 | 🟠 **High** |
| 分布 | High × 2 + Medium × 4 + Low × 2 + Info × 1 + Pass × 3 |
| Session | S19 (Phase 1) |
| 关联 trust boundary | ③ CKB 链数据 + ① P2P 网络 (funding/commitment tx 跨界) |
| 关联模块 | `crates/fiber-lib/src/ckb/{actor,client,contracts,signer,funding/funding_tx}.rs`, `crates/fiber-lib/src/watchtower/actor.rs`, `crates/fiber-lib/src/fiber/network.rs` |

## 摘要

CKB 链上数据（attacker 可放任意 cell / 任意 tx 上链）流入 fiber 的两条主路径——**watchtower 周期性扫描 funding cell 的消费 tx**（`run_periodic_check`）和 **funding tx 构造时的 UDT cell 收集**（`FundingTxBuilder`）——存在多处对 attacker-controlled 字节序列的 `panic!` / `unwrap` / `expect` / 直接 slice 索引，可被低成本远程触发让 watchtower 后台任务整体崩溃（保护责任链断裂），或在 funding 流程中让节点崩溃。同时 RPC 客户端用 `panic!("bytes response format not used")` 处理 ckb-node 返回的 bytes-format response，对运维误配置或 ckb 节点版本升级零容错。

最严重场景（**F1+F2 协同**）：cheating peer 把旧 commitment tx 上链时使用一个 `args.len() < 36` 或 `code_hash != commitment_lock` 的 lock script 作为输出锁——`run_periodic_check` 即会在 `lock_args[28..36]` slice 处 panic，watchtower 周期任务退出，**该 channel 的 cheat 不会被反应惩罚**，资金损失。

## 环境

- Rust 1.93.0 / `[profile.release] overflow-checks = true` ✓
- ckb-types/ckb-sdk 5, molecule 0.9
- watchtower `run_periodic_check` 在 `tokio::task::spawn_blocking` 内执行，panic 仅终止该次扫描（`PeriodicCheckGuard` Drop 清理 flag），**actor 本身存活但下一轮 panic 仍重现** → 等同于"该通道永远不被检查"

---

## 发现详情

### 🟠 F1 — High: `run_periodic_check` 对 attacker-controlled output lock_args 直接 slice，无 `code_hash` 校验

**位置**: `crates/fiber-lib/src/watchtower/actor.rs:266-275`

```rust
let commitment_lock = output.lock();
let lock_args = commitment_lock.args().raw_data();
let pub_key_hash: [u8; 20] = lock_args[0..20]      // ❌ 无 len 检查
    .try_into()
    .expect("checked length");                     // ❌ 注释撒谎，实际未检查
let commitment_number = u64::from_be_bytes(
    lock_args[28..36]                              // ❌ 无 len 检查
        .try_into()
        .expect("u64 from slice"),
);
```

**触发链**:
1. Watchtower 用 `funding_tx_lock` 作为 `SearchKey.script` 查询 ckb-indexer 返回**消费该 funding cell 的最新 tx**
2. 该 tx 的输出 lock 应该是 fiber 的 `commitment_lock`，但 indexer 返回任何能引用该 funding cell 作为 input 的 tx
3. 攻击者（cheating peer 持有旧 commitment_tx，或第三方构造解锁脚本不同的 settlement）只要让 ckb 共识接受该 tx 即可
4. 当 lock_args.len() < 36（比如 attacker 用 `args = [0u8; 20]`）时，`lock_args[28..36]` panic
5. `run_periodic_check` 函数返回，**当前轮所有后续 channel 的检查被跳过**；下一轮调度仍会重现 panic 因为同一 funding cell 仍然指向同一 attacker tx

**前置代码 251-257 也无 `commitment_lock.code_hash() == COMMITMENT_LOCK_CODE_HASH` 校验** → 任何匹配 funding_tx_lock-as-input 的 tx 都进入 slice 路径。

**影响**: 远程低成本 watchtower DoS。在 cheat 场景下 = 直接资金损失（受害者依赖 watchtower 检测旧 commitment 上链并广播 revocation tx；watchtower 一旦不能正常完成轮询，60h+ 后超时即放弃监督）。与 LOGIC-006（watchtower reaction paths）形成完整链。

**修复**: ① 校验 `commitment_lock.code_hash() == get_commitment_lock_code_hash() && hash_type == X`；② 校验 `lock_args.len() >= 36`；③ 用 `if let Some(slice) = lock_args.get(28..36) { ... } else { warn!; continue; }` 替代 panic。

---

### 🟠 F2 — High: `Htlc::build_from_witness` / `SettlementWitness::build_from_witness` `unwrap` 反模式

**位置**: `crates/fiber-lib/src/watchtower/actor.rs:1577-1592, 1697-1726`

```rust
impl Htlc {
    pub fn build_from_witness(witness: &[u8]) -> Self {  // ❌ 公共 API 不返回 Option/Result
        let htlc_type = witness[0];                       // panic if len < 1
        let payment_amount = u128::from_le_bytes(witness[1..17].try_into().unwrap());
        let payment_hash = witness[17..37].try_into().unwrap();
        let remote_htlc_pubkey_hash = witness[37..57].try_into().unwrap();
        let local_htlc_pubkey_hash = witness[57..77].try_into().unwrap();
        let htlc_expiry = u64::from_le_bytes(witness[77..].try_into().unwrap());
        ...
    }
}

impl SettlementWitness {
    pub fn build_from_witness(witness: &[u8]) -> Option<Self> {
        let pending_htlc_count = witness[1] as usize;     // ❌ panic if witness 空
        let pending_htlc_witness_len = 85 * pending_htlc_count;
        if witness.len() < 1 + 1 + pending_htlc_witness_len + 72 { return None; }
        ...
        let settlement_remote_pubkey_hash = witness[...].try_into().unwrap();  // OK 因前置长度校验
        ...
    }
}
```

**当前调用点局部安全**: `SettlementWitness::build_from_witness:1705-1707` 用 `step_by(85)` + 长度预检 1702 → 调 `Htlc::build_from_witness` 时 slice 恰为 85 字节 → `witness[77..]` 长度 8 → 当前不 panic。`witness[1]` 在 1699 行也有前置 `if witness.len() < 67` 跨越 by `Unlock` 路径（实际 `SettlementWitness::build_from_witness` 入口 1698 没有自己的 `witness.len() >= 2` 前置！）

**未来缺陷向**: ① `Htlc::build_from_witness` 公共 API、`SettlementWitness::build_from_witness` 入口未校验 `len >= 2` 即读 `witness[1]`，任何重构调用方易触发 panic；② 与 STORE-001.F3、INPUT-002.F4、INPUT-004.F3 同质 `.unwrap`/`panic!` 反模式；③ `Unlock::build_from_witness` (1660-1683) 用 `Option<Self>` 是正确范本但同文件未对称应用。

**触发链 (现行)**: 上链 settlement tx witness 作为 attacker-controlled 字节进入 watchtower 校验路径；目前 SettlementWitness 入口 `witness[1]` 无 len-1 校验 → witness 为空字节 panic。验证：`pub fn build_from_witness(witness: &[u8]) -> Option<Self> { let pending_htlc_count = witness[1] as usize;` — 是入口第一行，无任何 `witness.is_empty()` / `witness.len() < 2` 前置守卫。

**影响**: 远程触发 watchtower 后台任务 panic（同 F1 路径），同 channel 反应能力丢失。

**修复**: 全部转成 `Option<Self>` + 入口长度守卫 + `try_into().ok()?` 替代 `.unwrap()`。

---

### 🟡 F3 — Medium: `CkbRpcClient` 解码 panic — `panic!("bytes response format not used")`

**位置**: `crates/fiber-lib/src/ckb/client.rs:37-39, 70-72`

```rust
ckb_jsonrpc_types::Either::Right(_) => {
    panic!("bytes response format not used");
}
```

**触发链**: ① 运维错配置 ckb-rpc client 走 hex/bytes serialization；② ckb-node 升级后默认 response 格式变化；③ middlebox / proxy 改写 response。任何一种 → fiber 进程 panic。CkbChainActor 在 root supervisor 下，actor 重启策略默认 `Stop`（待验证）→ 进程退出。

**影响**: 中等可用性，非攻击者远程触发但是运维零容错地雷。注意客户端在 `crates/fiber-lib/src/watchtower/actor.rs:235-236` 同样用 `expect("create ckb rpc client should not fail")` — 如 ckb 节点连接失败，watchtower 也立即 panic。

**修复**: 改为 `Err(Error::UnexpectedRpcFormat)` 传播。

---

### 🟡 F4 — Medium: `FundingTxBuilder` UDT cell 数据 slice 无长度校验

**位置**: `crates/fiber-lib/src/ckb/funding/funding_tx.rs:404-407`

```rust
for cell in udt_cells.iter() {
    let mut amount_bytes = [0u8; 16];
    amount_bytes.copy_from_slice(&cell.output_data.as_ref()[0..16]);  // ❌ panic if data.len() < 16
    let cell_udt_amount = u128::from_le_bytes(amount_bytes);
    ...
}
```

**触发链**: cell_collector 按 type_script 过滤返回 UDT cells；attacker 在公链上以同 type_script 部署一个 cell 但 `output_data.len() < 16`（XUDT 标准要求 ≥ 16，但链共识不强制 type_script 校验为 udt-data-validator）→ 我方 funding builder 收集到该 cell → slice panic。

**影响**: funding 流程崩溃（一次 open_channel 失败 + 该地址未来所有 funding 同样失败，因为 cell_collector 仍会重新返回该 attacker cell）→ 持久化 funding DoS。

**修复**: `cell.output_data.as_ref().get(0..16).map(|s| amount_bytes.copy_from_slice(s)).unwrap_or_else(|| skip)` 或 `if cell.output_data.len() < 16 { warn!("malformed UDT cell"); continue; }`。

---

### 🟡 F5 — Medium: `get_chain_hash() = unwrap_or_default()` 静默退化为零哈希

**位置**: `crates/fiber-lib/src/fiber/network.rs:226-244`

```rust
static CHAIN_HASH_INSTANCE: OnceCell<Hash256> = OnceCell::new();

pub fn get_chain_hash() -> Hash256 {
    CHAIN_HASH_INSTANCE.get().cloned().unwrap_or_default()  // ❌ 全零 fallback
}

pub(crate) fn check_chain_hash(chain_hash: &Hash256) -> Result<(), Error> {
    if chain_hash == &get_chain_hash() { Ok(()) } else { Err(...) }
}
```

**触发链**: `init_chain_hash` 仅在 `crates/fiber-bin/src/main.rs` bootstrap 中调用一次。若该路径未执行（测试 fixture / 集成 / 库使用方）→ `get_chain_hash` 返回 `Hash256::default()` = 全零；此时若对端在 `Init` 消息也发全零 chain_hash（恶意构造）→ 跨链/不同 chain instance 通道建立成功，资金可能在错误链上锁定。

**影响**: 跨链 replay 风险；与 AUDIT-AUTH-002.F8 (peer identity binding) 互补的 chain identity binding 漏洞。

**修复**: ① `get_chain_hash` 改 `expect("CHAIN_HASH must be initialized")`；② `check_chain_hash` 直接读 `CHAIN_HASH_INSTANCE.get().expect()` 不走 fallback。

---

### 🟡 F6 — Medium: `ScriptCellDep::From<config::ScriptCellDep>` 配置 panic

**位置**: `crates/fiber-lib/src/ckb/contracts.rs:34-47`

```rust
_ => panic!("Invalid ScriptCellDep"),
```

`From` trait 不能返回 Result，导致配置 toml 写错（同时给 `cell_dep` 与 `type_id` 或都不给）→ 节点启动 panic 而非友好报错。**与 INPUT-002.F1 `From → TryFrom` 同质问题在 ckb-config 路径上的实例**。

**修复**: 改为 `impl TryFrom` + 在调用点把 `ContractsInfo::new()` 改为返回 `Result<Self>`。

---

### 🟢 F7 — Low: `funding_tx.rs:494` `outputs_data` 出现 silent `unwrap_or_default`

**位置**: `crates/fiber-lib/src/ckb/funding/funding_tx.rs:494`

```rust
for (i, output) in tx.outputs().into_iter().enumerate().skip(1) {
    outputs.push(output.clone());
    outputs_data.push(tx.outputs_data().get(i).unwrap_or_default().clone());
}
```

**问题**: peer 提供的 tx 若 `outputs.len() != outputs_data.len()`（CKB 共识允许的异常状态），FNN 默默用空 Bytes 填充 → 后续 funding tx 哈希与 peer 期望不一致 → 静默失败延后到广播阶段而不是早期拒绝。

**修复**: 校验 `tx.outputs().len() == tx.outputs_data().len()` 后再处理。

---

### 🟢 F8 — Low: `expect("create ckb rpc client should not fail")` 反模式扩散

**位置**: `crates/fiber-lib/src/watchtower/actor.rs:235-236`, 类似多处 `expect`

watchtower 周期任务每个 channel 都重建 ckb rpc client，构造失败即 panic 整个 spawn_blocking 任务。RPC client 构造失败是真实运维场景（DNS 抖动、URL 配置改变热加载等）。修复成本低（log + continue）。

---

### ℹ️ F9 — Info: `tx_tracing_actor` 对 ckb 节点 reorg / inconsistent status 无主动校验

`tx_tracing_actor.rs` 依赖 ckb-node 返回的 `TxStatus.status` 推进 channel state。若 ckb-node 受攻击（攻击者控制其连接的 ckb-node）返回 inconsistent / oscillating status（Pending → Committed → Pending），fiber 状态机响应未审计。**建议下个 session 单独审计 reorg 容错**。

---

### ✅ F10 — Pass: `FundingTxBuilder` checked-arithmetic 模式

**位置**: `crates/fiber-lib/src/ckb/funding/funding_tx.rs:269-282, 295-310`

```rust
udt_amount = udt_amount
    .checked_add(self.request.remote_amount)
    .ok_or_else(|| { error!(...); FundingError::OverflowError })?;
ckb_amount = ckb_amount
    .checked_add(self.request.remote_reserved_ckb_amount)
    .ok_or_else(|| { ... FundingError::OverflowError })?;
```

UDT/CKB amount 累加全部 `checked_add` + 显式错误路径，是 fiber 中算术处理的范本（与 MEM-002.F4 评价一致）。

### ✅ F11 — Pass: `Unlock::build_from_witness` 长度预检模板

`watchtower/actor.rs:1660-1683` 是同文件中唯一正确的"长度守卫 + Option 返回"模板，应作为 F2 修复参考。

### ✅ F12 — Pass: Funding tx integrity 多维校验

`funding_tx.rs:799-865` 对 peer 提供的 tx 同时校验 version / cell_deps / inputs / outputs / witnesses，结构完备（来自 LOGIC-001 已审）。

---

## 整体评价

CKB 链数据校验在**正路径**（FundingTxBuilder 数值算术、PeerTx 完整性）做得相当稳健（F10/F12 ✓），但在**异常路径**（attacker 把任意 tx 上链 → watchtower 强行解析其 args/witness）有系统性 panic 漏洞 (F1/F2)。这是项目层级范式差异：funding 路径默认 attacker-friendly + 防御 vs watchtower 路径默认 trust-on-chain-shape。**watchtower 是反 cheat 防线本身，不允许 panic**，应优先按 F1/F2 修复。

修复成本：F1 ≈ 8 行（加 code_hash 校验 + `if let Some(slice) = lock_args.get(0..20)`）；F2 ≈ 30 行（`Htlc::build_from_witness → Option<Self>` + 入口长度守卫）；F3/F6 ≈ 10 行（panic → Err）；F4/F5 ≈ 5 行；F7/F8 ≈ 3 行。

## Follow-ups

- **A (highest, must-fix)**: F1 加 commitment_lock code_hash 校验 + 长度守卫。
- **B (high)**: F2 `Htlc/SettlementWitness::build_from_witness` 全部转 `Option<Self>` + 入口长度守卫。
- **C (medium)**: F3/F6 `panic!`→`Err` (与 INPUT-002-A `From → TryFrom` 风格一致)。
- **D (medium)**: F4 UDT cell data slice 长度守卫。
- **E (medium)**: F5 `get_chain_hash` 移除 `unwrap_or_default` 并 audit 所有调用方。
- **F (low)**: F7 outputs_data 长度对齐校验。
- **G (low)**: F8 watchtower per-channel rpc-client 构造失败 → log + continue。
- **H (info, 下个 session)**: F9 ckb-node reorg / inconsistent status 容错单独审计 (与 LOGIC-006 互补)。

## 关联其它 finding

- **AUDIT-LOGIC-006** (Watchtower reaction paths) — F1/F2 是 LOGIC-006 已知"watchtower 关键路径 panic 反模式"在 INPUT 维度的具体实例化。
- **AUDIT-INPUT-002** (`From → TryFrom`) — F6 同质问题。
- **AUDIT-AUTH-002.F8** (Peer identity binding) — F5 是同问题在 chain identity 维度的实例。
- **AUDIT-MEM-002.F4 Pass** (apply_remove_tlc checked\_*) — F10 与之并列范本。
- **AUDIT-STORE-001.F3 / INPUT-002.F4 / INPUT-004.F3** — F2/F3/F8 同质 `.unwrap`/`panic!` 反模式。
