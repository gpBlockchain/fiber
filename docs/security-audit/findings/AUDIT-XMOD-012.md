# AUDIT-XMOD-012 — Invoice ↔ Channel ↔ Payment final-hop 错误码 probing oracle

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟡 Medium（协议级 oracle 泄露 invoice 状态 / 存在性 / 金额；与 BOLT-04 不一致） |
| 状态 | [!] 发现弱设计（协议层面已偏离 LN 主网现行做法） |
| 出处 | 本次跨模块审计新发现；记忆 "payment error codes" |
| 关联代码 | `crates/fiber-types/src/payment.rs:808-834`（`TlcErrorCode`：fiber 独有 `InvoiceExpired = PERM\|16`、`InvoiceCancelled = PERM\|17`，并保留 `FinalIncorrectTlcAmount` / `FinalIncorrectExpiryDelta`）<br>`crates/fiber-lib/src/fiber/channel.rs:840-844, 1156-1170`（`process_add_tlc_peeled_onion_packet` final-hop 校验路径，错误原因 → 错误码映射）<br>对比 BOLT-04：主网 LN 已把 4 类折叠为 `IncorrectOrUnknownPaymentDetails (PERM\|15)` |
| 关联 finding | AUDIT-ERR-001（错误信息泄露通用）、AUDIT-SPEC-002（payment 协议规范）、AUDIT-INPUT-002（与 invoice 解析协同） |

## 1. 现象

fiber 在 final hop 区分以下 4 种失败情形，并返回不同 TlcErrorCode：

| 触发条件 | fiber 返回 | BOLT-04 主网做法 |
|---|---|---|
| payment_hash 未知 | `IncorrectOrUnknownPaymentDetails (PERM\|15)` | 同 |
| payment_hash 已存在但 invoice expired | **`InvoiceExpired (PERM\|16)` (fiber 独有)** | 折叠为 PERM\|15 |
| payment_hash 已存在但 invoice cancelled | **`InvoiceCancelled (PERM\|17)` (fiber 独有)** | 折叠为 PERM\|15 |
| payment_hash 已存在 + amount/cltv 不符 | `FinalIncorrectTlcAmount` / `FinalIncorrectExpiryDelta` | 折叠为 PERM\|15 |

任意攻击者能路由到 final hop（fiber 网络任一节点）即可：

- 用 1 satoshi / 任意 payment_hash 试探：
  - 返回 PERM|15 → payment_hash 未知；
  - 返回 PERM|16 → payment_hash 存在 + invoice expired（pre-state oracle）；
  - 返回 PERM|17 → payment_hash 存在 + invoice 主动取消（行为 oracle）；
  - 返回 FinalIncorrect* → payment_hash 存在 + invoice 仍有效 → 泄露 invoice **存在性**；
- 进一步：用不同 `amt_to_forward` 做差分回归 → 推 invoice **真实金额**（FinalIncorrectTlcAmount 在金额不符时返回）。

## 2. 与已有发现的区别

- ERR-001 关注本地图 slander（XMOD-001 已升级）；
- ERR-002 关注一般错误信息泄露；
- 本条专门覆盖**协议级错误码的 oracle 语义**：与 BOLT-04 偏离的设计选择是问题根源，不是单点 bug。

## 3. 攻击场景

### 3.1 Invoice 存在性 + 状态 probing
1. 攻击者从某泄露源（如博客 / 二维码截图）拿到 fiber 用户 npub / node_id；
2. 枚举可能的 invoice payment_hash（如生成 1000 个候选）；
3. 对每个 hash 发 1 sat payment → 收集错误码；
4. 区分目标节点：有 invoice / 已 expired / 已 cancel / 仍有效。

### 3.2 金额泄露（差分）
1. 在 hash 已知存在的情形（返回 FinalIncorrect*）；
2. 二分搜索 amt：从 amt=1 sat 提到 amt=1B sat，看错误码从 FinalIncorrectTlcAmount 切到成功；
3. 推得 invoice 金额（fiber 当前未做 fixed-budget 延迟，可能伴随时序差异加速搜索）。

### 3.3 跨链 oracle（与 CCH 协同）
fiber 节点用于 CCH 跨链 hop 时，attack final-hop 错误码可推 CCH 内部订单状态。

## 4. 影响评估

- 隐私泄露（invoice 存在性、状态、金额）；
- 不直接资金损失，但破坏 LN/fiber 模型的隐私不变量；
- 与 BOLT-04 规范偏离 → 跨实现兼容性问题。

## 5. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | P2 | **`process_add_tlc_peeled_onion_packet` final-hop 路径统一返回 `IncorrectOrUnknownPaymentDetails (PERM\|15)`**，不论实际原因（InvoiceExpired / InvoiceCancelled / FinalIncorrect*）— 与 BOLT-04 对齐。 |
| F2 | P2 | `InvoiceExpired = PERM\|16` / `InvoiceCancelled = PERM\|17` 仅保留为**本地事件类型** 用于 RPC subscription / 本端日志，**不在 P2P 报文 / `TlcErr.error_code` 中暴露**。 |
| F3 | P2 | 差分时序攻击防御：final-hop 任何失败响应延迟到固定 budget（如 50ms）以避免侧信道。 |
| F4 | P3 | SPEC-002 文档明确写出"final-hop 错误码与 BOLT-04 对齐"的规范约束；新错误码 review 需明示是否对外可见。 |
| F5 | P3 | 单元 / 集成测试覆盖 4 类 probing 路径返回**对外**错误码均为 PERM\|15。 |

## 6. 验证测试

- `channel::tests::test_final_hop_returns_unified_perm15`：4 种失败情形（unknown / expired / cancelled / amount mismatch）都断言**对外返回**`IncorrectOrUnknownPaymentDetails`。
- `channel::tests::test_final_hop_response_timing_fixed_budget`：响应时间方差 < 5ms（统计 100 次）。
- `payment::tests::test_payment_error_subscription_still_sees_local_reason`：本端 RPC `subscribe_payment_failed` 仍能看到详细原因，不影响对外。

## 7. 状态

- F1+F2+F3 协同；F4/F5 后置。
- 关联 PR：暂无。
