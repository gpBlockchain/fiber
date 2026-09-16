# AUDIT-XMOD-006 — Watchtower ↔ CKB ↔ Channel ↔ Gossip 反 cheat 三模块协同断裂

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟠 **High**（远程 cheat 链 → 资金直损） |
| 状态 | [!] 发现弱设计（部分组件已有 PoC：cheat tx 上链路径） |
| 出处 | 本次跨模块审计补强；对应 REPORT.md §4 链 A |
| 关联代码 | `crates/fiber-lib/src/watchtower/actor.rs:266-275, 1577-1592, 1660-1683, 1697-1726`（`run_periodic_check` slice 无守卫；Htlc::build_from_witness 全 unwrap；SettlementWitness::build_from_witness witness[1] 无长度守卫）<br>`crates/fiber-lib/src/ckb/client.rs:37-39, 70-72`（CKB RPC client 入站结构无 sanity）<br>`crates/fiber-lib/src/ckb/funding/funding_tx.rs:404-407, 494`<br>`crates/fiber-lib/src/fiber/network.rs:226-244`（peer eviction）<br>`crates/fiber-lib/src/fiber/channel.rs:7301-7356`（`RevokeAndAck` 无 `verify_partial`）<br>`crates/fiber-lib/src/fiber/gossip.rs`（gossip 池 + Sybil 推挤） |
| 关联 finding | AUDIT-INPUT-005（witness 解析）、AUDIT-LOGIC-003.F6（revocation_data 覆盖式存储）、AUDIT-CRYPTO-004.F2（RevokeAndAck `verify_partial`）、AUDIT-AUTH-002.F1（Sybil eviction）、AUDIT-NET-001.F1（持久 ban list 缺位） |

## 1. 现象

防 cheat 的成功依赖 4 个独立的不变量同时成立：

1. **Sybil 不会把合法 peer 推出**（NET-001.F1 / AUTH-002.F1）：当前无持久 ban list，`enforce_inbound_peer_budget` 仅 `on_peer_connected` 触发，secio/pre-Init 会话逃过 admission；攻击者可大量 Sybil 推挤 victim 把"对手 peer"踢出可见 peer 集 → watchtower / channel 失去对手在线状态视图。
2. **watchtower 解析 cheat tx 不会 panic**（INPUT-005）：`run_periodic_check` 直接对 attacker-controlled `lock_args[0..20]` / `lock_args[28..36]` slice，`commitment_lock.code_hash()` 不校验，`witness[1]` 无 len 守卫，`Htlc::build_from_witness` 全 unwrap → 单条对手 cheat tx 可 panic 整个 watchtower actor。
3. **revocation_data 不会被覆盖**（LOGIC-003.F6）：channel 当前以"最新一份"覆盖式存储 revocation 信息；若对手快速发多次 RevokeAndAck 把存储位置覆盖到错误状态，watchtower 后续看不到正确的 revocation script。
4. **RevokeAndAck 不会被坏 partial 阻塞**（CRYPTO-004.F2 / XMOD-008）：channel.rs:7301-7356 不 `verify_partial`，对端发坏 partial → aggregate 失败/通过都 → revocation chain 错位。

**任一不变量失效 → 反 cheat 防线完全崩塌**：watchtower 要么"看不到"（防线 1），要么"看到但 panic"（防线 2），要么"看到但用错 script"（防线 3），要么"上游 channel 已经存错 revocation"（防线 4）。

## 2. 跨模块攻击链

完整四步：
```
T0: 攻击者 Sybil 推挤 victim, evict victim's honest peer view (NET-001.F1)
T1: 攻击者用旧 commitment + 错位 revocation_data 触发 channel 进入坏状态 (LOGIC-003.F6 + CRYPTO-004.F2)
T2: 攻击者把 cheat commitment tx 上链
T3: victim watchtower run_periodic_check 解析 attacker-crafted commitment lock_args / witness → panic (INPUT-005)
T4: watchtower restart 后再次 panic（同一笔 tx 仍在链上）→ 攻击者从容拿走时间锁后的资金
```

## 3. 与已有发现的区别

- 4 个单独 finding 各自评为 Medium / High；
- 本条强调"它们是一条链上互锁的环"：修复任一项**单独**不解决 cheat → 必须按链顺序协同修复，否则攻击者绕到剩余薄弱环。
- 与 XMOD-008 共享 "ban list" 依赖（持久 ban 列表在 NET-001.F1 + XMOD-006/008 都需要）。

## 4. 影响评估

- **资金直损**：完整 channel balance；
- **远程可达**：攻击者只需作为 fiber 网络任一节点 + 能驱动 victim 接受其作为 peer；
- **现有 finding 已部分 PoC**：cheat tx 上链路径在 INPUT-005 中有最小化 witness 输入即可触发 watchtower panic。

## 5. 修复建议（FOLLOWUP）

按修复优先链顺序：

| 编号 | 优先级 | 修复要点 | 依赖 |
|---|---|---|---|
| F1 | P0 | NET-001.F1 持久 ban list + `enforce_inbound_peer_budget` 覆盖 secio/pre-Init 会话；同时 AUTH-002.F1 反序驱逐改"老 + 不活跃优先"。 | — |
| F2 | P0 | INPUT-005.F1/F2 `lock_args` 长度守卫 + `commitment_lock.code_hash()` 校验；`witness[1]` 长度守卫；`Htlc::build_from_witness` / `SettlementWitness::build_from_witness` 返回 `Option`。 | F1（让 watchtower 看到正确 tx） |
| F3 | P0 | LOGIC-003.F6 `revocation_data` 改 append-only by `commitment_number`，禁止覆盖；watchtower 取最大 commitment_number 那条。 | F2 |
| F4 | P0 | CRYPTO-004.F2 / XMOD-008 `RevokeAndAck` 路径 `verify_partial` 预校验；失败 ban peer（F1 提供 ban list 设施）。 | F1 |
| F5 | P1 | watchtower 启动加 supervisor + retry budget；单 channel periodic_check panic 不影响其它 channel。 | F2 |

## 6. 验证测试

- `tests/security/cheat_chain.rs`：完整四步集成测试，断言 victim 资金保留。
- `watchtower::tests::test_periodic_check_isolation`：构造 panic-trigger tx，断言 watchtower actor 不退出，单 channel 标 `failed_monitoring`。
- `channel::tests::test_revocation_data_no_overwrite`：写 N=1..10 commitment number revocation，断言 watchtower 取 10。
- `network::tests::test_sybil_does_not_evict_honest`：100 Sybil 入站，断言 honest peer 仍在 peer view。

## 7. 状态

- 5 项 FOLLOWUP **必须协同合入**才算消项；分次合入会留下"暂时无防"窗口。
- 关联 PR：暂无。
