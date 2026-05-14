# AUDIT-XMOD-002 — CCH ↔ Watchtower ↔ Channel 跨链订单 / preimage 时序错配 24h 窗口

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟠 **High**（CCH 单边资金损失，跨链结算路径）|
| 状态 | [!] 发现弱设计（静态可达，无 PoC） |
| 出处 | 本次跨模块审计补强；基于 AUDIT-LOGIC-008 + "cch scheduler 时序" 记忆扩展 |
| 关联代码 | `crates/fiber-lib/src/cch/config.rs:6-12`（`DEFAULT_ORDER_EXPIRY_DELTA_SECONDS=36h` vs BTC/CKB final TLC `60h`）<br>`crates/fiber-lib/src/cch/scheduler.rs:262-301`（`expire_order`，已 `is_final()` 跳过 final 订单但未排除 InFlight）<br>`crates/fiber-lib/src/cch/actor.rs:450-457`（订单状态机入口）<br>`crates/fiber-lib/src/watchtower/actor.rs:173-183`（preimage 落地点） |
| 关联 finding | AUDIT-LOGIC-008（CCH 状态机一致性）、AUDIT-INPUT-005（watchtower 解析）、AUDIT-LOGIC-002（commitment lifecycle） |

## 1. 现象

CCH 默认 `order_expiry = 36h`，但其在 fiber 侧挂出的 TLC `final_expiry`（`DEFAULT_CKB_FINAL_TLC_EXPIRY_DELTA_SECONDS = 60h`）与挂在 LND 侧的 BTC HTLC `cltv = 360 blocks ≈ 60h`，留下 **24 小时** "订单已 Failed 但 HTLC/TLC 仍 InFlight 且 preimage 可被对手在链上揭示" 的窗口。

`expire_order` 现在虽已检查 `is_final()`（line 273 跳过 Settled/Refunded/Failed），但**未排除 InFlight 订单**：

1. T=0：CCH 接受跨链请求，挂出 fiber TLC + LND HTLC，订单 status=`InFlight`。
2. T=36h：CCH scheduler 触发 `expire_order` → status=`Failed`、释放 in-memory 状态。
3. T=36h..60h：链上仍存在未结算的 BTC HTLC / fiber TLC。对手在该窗口内：
   - 在 BTC 侧用 preimage 取走 BTC（CCH 还以为订单 Failed，不去 LND 端 settle）。
   - 在 fiber 侧 CCH 应当用同一 preimage 去 settle TLC 回收资金；但 CCH 已视订单不存在，对应入站 preimage 事件被 `get_active_order_or_none` 返回 None 丢弃。
4. 净结果：**CCH 在 BTC 侧失去 BTC，但在 fiber 侧没回收 CKB**（或反向，取决于方向）→ 单边损失。

## 2. 与已有发现的区别

- AUDIT-LOGIC-008 已记 CCH 状态机不变量缺失，但仅在 cch 模块视角；
- 本条强调 **cch / watchtower / channel** 三模块的"时序不变量"：watchtower 已落地 preimage 但 CCH 不再 ACK，channel 已经被推到 commitment 阶段也不能回滚。
- 任何单模块修复（如只改 cch 状态机）都不解决：必须由"order_expiry vs final_tlc_expiry"全局不变量保证。

## 3. 攻击场景

### 3.1 主动型对手（CCH 上游 LND peer）
1. 攻击者向 CCH `receive_btc` 创建跨链请求 (BTC→CKB)。
2. CCH 挂 fiber TLC，准备好接 BTC HTLC。
3. T=36h 之前，攻击者**故意不揭示 preimage**，让两侧都等到 expiry 边缘。
4. T=36h CCH 把 order 改 Failed → 释放内部哈希到 preimage 映射。
5. T=36h..60h 攻击者在 BTC 侧 settle 拿走 BTC（preimage 公开上链）。
6. fiber 侧 TLC 仍可被 CCH 用同一 preimage 回收 — 但 CCH 已不知道这条订单，watchtower 落地的 preimage 没有路径回到 CCH actor。
7. T=60h fiber TLC 超时退款给攻击者；BTC 已被攻击者拿走 — 净损 CCH = BTC 总额。

### 3.2 被动型（对端 fiber 节点慢响应/丢包诱导超时）
对端持续延迟 settle，CCH 在 36h 自然 expire；之后任何"补 settle"窗口内的 preimage 都被丢弃，仍走 3.1 路径。

## 4. 影响评估

- **直损**：CCH 单笔交易最大金额（受 `cch.max_btc_per_request` 控制；缺省较高）。
- **可重复**：每天一个请求即可累积。
- **检测难度高**：单边账本各自看上去都"正常超时"，只有交叉账本对账才看到偏差。
- **远程可达**：跨链订单本身是远程入口（LND lightning network 或 fiber 网络任一边）。

## 5. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | P0 | `cch/config.rs` 启动校验：`order_expiry > max(BTC_final_tlc_seconds, CKB_final_tlc_seconds) + safety_margin (≥30min)`，不满足直接 `bail!`。 |
| F2 | P0 | `expire_order` 仅对 `status=Pending`（未实际挂 HTLC/TLC）生效；`InFlight` 必须等链上 settle/timeout 才能转 Failed。 |
| F3 | P0 | watchtower 检测到 preimage 时**始终**持久化事件并向 CCH 重放（即便 CCH 当时认为订单 Failed），CCH 收到回填 preimage 应主动尝试 settle 回收。 |
| F4 | P1 | 增加 cross-ledger reconciliation：每 N 分钟扫所有 InFlight + 最近 24h Failed 的订单，比对两侧链上状态。 |
| F5 | P1 | 在 cch RPC `receive_btc` 返回里显式带 `expected_expire_at`，让客户端可观察一致性。 |

## 6. 验证测试

- 单元测试：`cch::scheduler::tests::test_expire_inflight_blocked` — 构造 status=InFlight 的订单，调 `expire_order`，断言订单仍 InFlight，仅 status=Pending 的会变 Failed。
- 集成测试：模拟 36h 内 expire + watchtower preimage 事件，断言 cch 完成补 settle。
- 配置测试：`order_expiry=10s` + `btc_final=60h` 启动直接 panic / bail。

## 7. 状态

- 修复链：F1+F2+F3 必须同时合入才算消项；F4/F5 为深度防御。
- 关联 PR：暂无。
