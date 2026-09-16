# AUDIT-LOGIC-008 — CCH 跨链 HTLC 依赖与到期 (Cross-Chain HTLC Dependency & Expiry)

- **维度**: DIM-LOGIC（跨链 HTLC 状态机 + 到期协调）
- **严重级别**: 🟠 **High**（High × 1 + Low × 1 + Info × 1 + Pass × 3）
- **审计 Session**: S11 (2026-05-13)
- **关联代码**:
  - `crates/fiber-lib/src/cch/scheduler.rs:262-301` (`expire_order` 不区分 status)
  - `crates/fiber-lib/src/cch/actor.rs:459-473` (`schedule_job_for_non_final_order`)
  - `crates/fiber-lib/src/cch/actor.rs:450-457` (`get_active_order_or_none` 过滤 final 订单)
  - `crates/fiber-lib/src/cch/order/state_machine.rs:68-84` (`allow_transition`，`_ → Failed` 在非 Success 状态总是允许)
  - `crates/fiber-lib/src/cch/actions/settle_incoming_invoice.rs:124-126` (`should_dispatch` 要求 `OutgoingSuccess`)
  - `crates/fiber-lib/src/cch/actor.rs:560` (`min_final_cltv_expiry_delta() * 600` 未 checked_mul)
  - `crates/fiber-lib/src/cch/actions/send_outgoing_payment.rs:249` 同上
  - `crates/fiber-lib/src/cch/actions/send_outgoing_payment.rs:205` (`saturating_mul` ✅ — 一致性瑕疵)
  - `crates/fiber-lib/src/cch/actions/send_outgoing_payment.rs:180-212` (`compute_max_outgoing_expiry_seconds` half-budget ✅)
  - `crates/fiber-lib/src/cch/actions/send_outgoing_payment.rs:218-281` (`check_expiry_or_fail` ✅)
  - `crates/fiber-lib/src/cch/order/state_machine.rs:44-65` (preimage hash 验证 ✅)
  - `crates/fiber-lib/src/cch/actor.rs:557-564` (SendBTC 静态 half check ✅)
  - `crates/fiber-lib/src/cch/actor.rs:655-674` (ReceiveBTC 静态 half check ✅，含 `checked_mul`)
  - `docs/specs/cch-expiry-dependency.md` (设计说明)

## 1. 审计目标

CCH（Cross-Chain Hub）是 Fiber 与 BTC Lightning 之间的原子互换中继。其安全核心是 **HTLC 时序依赖**：任何在 CCH 上发生的成功支付都必须保证 incoming HTLC 的剩余时间 ≥ outgoing HTLC 的最大可能路由时间 + CCH 本地结算时间，否则会产生 *free option* 攻击窗口 —— 用户可单边攫取 outgoing 资金而让 CCH 来不及 settle incoming。

本次审计专注于：

1. **静态 half-budget 检查**（订单创建期）—— 是否在生成 incoming 发票/接受 outgoing pay_req 时正确验证两侧 final expiry 比例；
2. **动态 half-budget 检查**（outgoing 调度期）—— 是否在调度 outgoing 支付时再次校验剩余 incoming 时间；
3. **状态机** —— 是否存在 InvalidTransition / 状态丢失导致 preimage 被丢弃的路径；
4. **订单到期与 TLC/HTLC 到期协调** —— 调度器到期是否会与 outgoing 流程产生竞态；
5. **整型边界** —— BTC blocks→seconds 转换 (`* 600`) 等是否有溢出风险；
6. **preimage 完整性** —— 是否对 outgoing 返回的 preimage 做 hash 校验。

## 2. 系统性梳理

### 2.1 CCH 订单状态机

`fiber-types/src/cch.rs` 定义状态：
```
Pending → IncomingAccepted → OutgoingInFlight → OutgoingSuccess → Success
                          ↘                                       ↗
                            ───────────── (immediate) ─────────────
```
+ `(_, Failed) if from != Success → true`（任意非 Success 状态可转 Failed）。

**关键观察**：
- `is_final()` 只返回 `Success | Failed`，**不包含** `IncomingAccepted / OutgoingInFlight / OutgoingSuccess`。
- `OutgoingSuccess` 已携带 preimage，但仍可被 `_ → Failed` 转走。
- `get_active_order_or_none`（actor.rs:450）对 is_final 订单**直接返回 None**，丢弃所有后续 tracking event。

### 2.2 双重 expiry 检查（设计层面正确）

- **静态**（订单创建）：
  - SendBTC: `actor.rs:560-564` `btc_final_cltv_seconds = invoice.min_final_cltv_expiry_delta() * 600` 必须 `< ckb_final_tlc_expiry_delta_seconds / 2`；
  - ReceiveBTC: `actor.rs:658-674` `ckb_final_tlc_millis < btc_final_tlc_expiry_delta_blocks * BTC_BLOCK_TIME_MILLIS / 2`（`checked_mul` 防溢出 ✅）。
- **动态**（outgoing 调度）：`send_outgoing_payment.rs:180-212 compute_max_outgoing_expiry_seconds` 计算 `(incoming_remaining - elapsed) / 2`，下放到 `tlc_expiry_limit` / `cltv_limit`，再用 `check_expiry_or_fail` 与 outgoing invoice 的 final expiry 对比。

### 2.3 preimage 校验（设计层面正确）

`state_machine.rs:49-54`：当 OutgoingPaymentChanged 携带 preimage 时计算 SHA256 并与 `order.payment_hash` 对比，不一致时返回 `CchError::PreimageHashMismatch`。这是 CCH 防御伪造 preimage 的关键校验，已正确实施。

### 2.4 调度器与到期

`scheduler.rs`:
- `ScheduleExpiry` 在 `schedule_job_for_non_final_order` 中**仅在订单创建时**入队一次（actor.rs:309, 323；以及重启恢复 actor.rs:280）；
- 到期时间 = `created_at + order_expiry_delta_seconds`（默认 **36 小时**）；
- TLC/HTLC final expiry 默认 **60 小时**（ckb_final_tlc_expiry_delta_seconds = 60 \* 60 \* 60；btc_final_tlc_expiry_delta_blocks = 360 ≈ 60h）；
- `expire_order` (scheduler.rs:262)：**不调用状态机**，直接 `order.status = CchOrderStatus::Failed`。

## 3. 发现

### 3.1 F1 (🟠 High) — `expire_order` 与 outgoing 流程的致命竞态：preimage 被丢弃 → CCH 直接资金损失

**位置**：`crates/fiber-lib/src/cch/scheduler.rs:262-301`

```rust
fn expire_order(&self, mailbox: ActorRef<SchedulerMessage>, payment_hash: Hash256)
    -> Result<(), CchError>
{
    let mut order = match self.store.get_cch_order(&payment_hash) {
        Ok(order) => order,
        Err(_) => return Ok(()),
    };
    // Skip if order is already final
    if order.is_final() { return Ok(()); }       // ← 只跳过 Success/Failed

    // ⚠️ 不论 Pending / IncomingAccepted / OutgoingInFlight / OutgoingSuccess
    //    全部强制 Failed，不调用状态机，不取消 outgoing，不取消 hold-invoice
    order.status = CchOrderStatus::Failed;
    order.failure_reason = Some("Order expired".to_string());
    self.store.update_cch_order(order);
    ...
}
```

#### 数值前提

| 配置项 | 默认值 | 含义 |
|---|---|---|
| `order_expiry_delta_seconds` | **36 h** | 调度器在订单创建后多久强制 Failed |
| `ckb_final_tlc_expiry_delta_seconds` | **60 h** | CCH 创建 Fiber incoming invoice 时填入的 final TLC expiry |
| `btc_final_tlc_expiry_delta_blocks` | **360 (≈60 h)** | CCH 创建 LND hold invoice 时填入的 cltv_expiry |

**结论：order_expiry (36 h) < TLC/HTLC expiry (60 h)，留下 24 小时的"调度器先于 TLC 失效"窗口。**

#### 攻击路径（SendBTC：Fiber → Lightning）

1. **T = 0**：恶意用户调用 RPC `send_btc(btc_pay_req)`。CCH 创建 Fiber incoming invoice，设 `payment_hash = H`，并通过 `schedule_job_for_non_final_order` 入队 ExpireOrder@T+36h。
2. **T ≤ 36h − ε**：用户**故意延迟**直到 ε 很小（例：5 分钟）时再支付 Fiber invoice。CCH 收到 TLC，订单 → `IncomingAccepted`。`compute_max_outgoing_expiry_seconds` 计算 `remaining = 60h − (T) ≥ 24h + ε`，`max_outgoing = remaining / 2 ≥ 12h + ε/2`，通过 `check_expiry_or_fail`。
3. **T = 36h − ε + δ**：CCH 通过 `SendLightningOutgoingPaymentExecutor` 向 LND 发起 `SendPayment(cltv_limit = max_outgoing / 600)`。LND 广播 BTC HTLC。
4. **T = 36h**：调度器 `ProcessJobs` 弹出 ExpireOrder@T+36h。`expire_order` 读取订单（status 为 `IncomingAccepted` 或 `OutgoingInFlight` 或 `OutgoingSuccess`），`is_final() == false`，**强制写入 Failed**，并 schedule prune@T+57d。**未取消 LND `SendPayment`，未取消 Fiber incoming TLC**。
5. **T = 36h + Δ (Δ 秒级)**：用户在收款端 BTC LN 节点用 preimage `P` claim BTC。LND 报告 `PaymentStatus::Success`，事件抵达 `CchActor::handle_tracking_event`。
6. `get_active_order_or_none` 检查订单，`is_final() == true`（Failed），**返回 None → 整个事件被静默丢弃**（actor.rs:344 调用链中 `handle_tracking_event` 走 `match state.handle_tracking_event(event).await { Ok(actions) => ... Err(err) => tracing::error! }`，结果为空 actions）。
7. **结果**：
   - 用户收到了 BTC（real BTC on Lightning）；
   - CCH 知道 outgoing 成功但 preimage **从未写入 order**（因为 state-machine apply 被 get_active_order_or_none 提前阻止）；
   - Fiber incoming TLC 仍 pending，无人 settle；
   - **T = 60h**：Fiber incoming TLC 链上 timeout → Fiber 付款方（= 攻击者本人 / 同伙）**取回**他原先支付的 wrapped BTC。
   - **净结果：用户同时获得 (a) 真实 BTC 和 (b) 退回的 wrapped BTC；CCH 损失 (a) 的全部金额。**

#### ReceiveBTC（Lightning → Fiber）反向版本

同理可推：
1. 攻击者用 LND 节点支付 CCH 的 hold-invoice ≈ 36h − ε 时刻；
2. CCH 派发 Fiber 出账，攻击者收方 settle Fiber TLC 获 wrapped BTC，揭示 preimage；
3. 调度器 fail 订单，preimage 事件被丢弃；
4. LND hold-invoice 始终 "ACCEPTED"，永不 settle；
5. 到达 BTC HTLC cltv_expiry（~60h），LND 自动 cancel hold-invoice，攻击者付款方的 BTC HTLC 也 timeout，BTC 退回；
6. **净结果：攻击者同时获得 (a) wrapped BTC（Fiber 上）和 (b) 退回的 real BTC；CCH 损失 (a) 的等值。**

#### 进一步的两个子情境

**(b)** 即使在调度器 fire 之前，outgoing 已经 `OutgoingSuccess` 并把 preimage 存入 order（state_machine.rs:60-62），**`SettleIncomingInvoiceDispatcher::should_dispatch` 要求 status==`OutgoingSuccess`**（settle_incoming_invoice.rs:124-126）。一旦调度器把状态改成 Failed，下次 retry 时 `get_active_order_or_none` 返回 None → settle 行动永不被派发。preimage 仍在 DB 中，但**没有任何代码路径会把它送给 LND/Fiber 去 settle incoming**。

**(c)** `expire_order` **绕过状态机**直接写库（注意：`allow_transition` 的 `(_, Failed) if from != Success` 即便走状态机也会通过，所以这里不是状态机 bug 本身，而是"调度器不应当在 outgoing 流程中触发 Fail"的语义 bug）。

#### 触发难度

- 不需要任何协议层漏洞；
- 不需要任何加密学攻击；
- 仅利用 CCH 默认配置 `order_expiry (36h) < TLC_expiry (60h)`；
- 攻击者完全控制何时支付 incoming → 完全控制竞态窗口；
- 24 小时的窗口意味着即使部分时钟漂移或 outgoing 网络延迟，攻击都极易复现。

**实战难度：低。资金损失：每次订单的全额（最多到 incoming_amount + fee）。**

#### 缓解（现有代码）

- 无主动缓解。CCH 操作员需要监控错误日志并手动 SettleInvoice（提取 DB 中的 payment_preimage）。
- `failure_reason = "Order expired"` 字段可用于事后审计，但已经损失发生后无法恢复。

#### 修复建议（优先级从高到低）

1. **关键修复**：`expire_order` 增加状态条件，**仅在 status == `Pending` 时**强制 Failed：
   ```rust
   if order.status != CchOrderStatus::Pending {
       // 已进入 outgoing 流程，不再强制 fail；改为延后重试或直接放弃过期判定
       tracing::warn!("Order {:x} in {:?} reached order_expiry but skipping fail",
                      payment_hash, order.status);
       return Ok(());
   }
   ```
   配合：对非 Pending 订单，应基于 **TLC/HTLC 剩余时间**而非 wall-clock order_expiry 来决定何时放弃。
2. **结构修复**：把 "order wall-clock expiry" 与 "HTLC/TLC settlement deadline" 拆分为两个独立调度作业。前者只对 Pending 生效；后者基于 incoming TLC 实际剩余时间 + CCH 本地结算预留时间动态计算。
3. **对称取消**：当 `expire_order` 决定 fail 一个已 IncomingAccepted 订单时，必须：(a) 调用 LND `CancelInvoice` 关闭 hold-invoice（ReceiveBTC）/ 取消 outgoing SendPayment（如可能）；(b) 对 Fiber 侧调用 invoice cancel API。当前代码 **完全没有** cancel 路径（grep 结果：`grep cancel_invoice|CancelInvoice|cancel_payment` 在 `crates/fiber-lib/src/cch` 下 0 命中）。
4. **防御性恢复**：`handle_tracking_event` 收到 `PaymentChanged{ payment_preimage: Some(_) }` 但订单已 Failed 时，**不应直接丢弃** —— 至少把 preimage 写入一个 "orphaned_preimages" 表或日志，便于离线恢复。
5. **配置层加固**：发现/拒绝 `order_expiry_delta_seconds < max(ckb_final_tlc_expiry_delta_seconds, btc_final_tlc_expiry_delta_blocks * 600)` 的危险组合；CchConfig 启动时应校验。

### 3.2 F2 (🟢 Low) — `min_final_cltv_expiry_delta() * 600` 未 checked_mul（两处与一处 saturating_mul 不一致）

**位置**：
- `actor.rs:560` (SendBTC 静态检查) — `let btc_final_cltv_seconds = invoice.min_final_cltv_expiry_delta() * 600;`
- `send_outgoing_payment.rs:249` (SendBTC 动态检查) — `.map(|inv| inv.min_final_cltv_expiry_delta() * 600)`
- 对比：`send_outgoing_payment.rs:205` (ReceiveBTC 动态检查) — `.saturating_mul(600)` ✅

`min_final_cltv_expiry_delta()` 返回 `u64`（来自 lightning-invoice）。bolt11 invoice 中 `c` (min_final_cltv_expiry_delta) tag 用变长整数编码，理论上可以达到 u64::MAX 附近。若攻击者构造 `min_final_cltv = u64::MAX / 599`：

- `* 600` wrap → 一个**很小的数**；
- `btc_final_cltv_seconds < ckb_final_tlc_seconds / 2` 检查**轻易通过**；
- CCH 接受订单 → 但实际 cltv_expiry 巨大 → 后续 `SendPayment` 在 LND 端被拒（或被 BTC 网络拒绝）→ 不会立即资金损失，但已写入 incoming Fiber invoice 给用户。

**实际后果**：DoS / 订单僵尸（incoming invoice 已发布但 outgoing 永远失败）。不直接资金损失，因为外层 LND/BOLT11 库会拒绝该 invoice 的实际支付。但 incoming Fiber invoice 已经发布给恶意用户，理论上恶意用户可以让 CCH 创建任意多个"卡死"的 invoice 消耗 LND/CCH 资源（与 AUDIT-MEM-001 趋同）。

**严重级别**：🟢 Low —— 实际利用受 bolt11/LND 上游限制约束，但是与同文件 line 205 的 `saturating_mul` 不一致，明显是疏漏。

**修复**：把两处统一为 `saturating_mul(600)` 或者 `checked_mul(600).ok_or(CchError::BTCInvoiceFinalTlcExpiryDeltaTooLarge)?`。

### 3.3 F3 (ℹ️ Info) — BTC block time 假设固定 600 秒

`compute_max_outgoing_expiry_seconds`（ReceiveBTC 路径，send_outgoing_payment.rs:205）和 static check（actor.rs:560，672）都把 BTC 区块固定为 **600 秒**。实际：

- BTC 主网平均 ~600s，但短期可能 300-900s（难度调整周期内）；
- 若实际块速**比 600s 慢**（例如 800s/块），CCH 的 cltv_limit 计算**低估**剩余时间 → 偏保守 → CCH 仍安全；
- 若实际块速**比 600s 快**（例如 400s/块），CCH **高估**剩余时间 → 偏激进 → 极端情况下可能让 outgoing route 用掉超过实际 HTLC 剩余的时间 → **理论上可能产生类 F1 的损失**。

**实际影响**：BTC 块速持续偏快超过 33% 的情况极少（要求 ckb_final_tlc 的一半被用完后剩余还能再被 outgoing 跑超）；通常被 half-budget 的安全因子吸收。仍属于**模型假设记录**，不是当前可利用 bug。

**建议**：在文档与 config doc 中注明该 600s 假设，并允许部署方按链 fork/调整周期下调 `btc_final_tlc_expiry_delta_blocks` 的安全系数。

### 3.4 F4 (✅ Pass) — preimage hash 校验

`state_machine.rs:49-54` 对 outgoing 返回的 preimage 做 SHA256 验证：

```rust
if let Some(ref preimage) = payment_preimage {
    let hash_algorithm = HashAlgorithm::Sha256;
    let computed_hash = hash_algorithm.hash(*preimage);
    if computed_hash.as_slice() != order.payment_hash.as_ref() {
        return Err(CchError::PreimageHashMismatch);
    }
}
```

防御了 outgoing 后端伪造 preimage 试图骗 CCH settle incoming 的攻击。SHA256 是 LN/Fiber 标准。✅

### 3.5 F5 (✅ Pass) — 静态 half-budget 检查

- SendBTC（actor.rs:557-564）：`btc_final_cltv_seconds >= ckb_final_tlc_seconds / 2` 时拒绝。
- ReceiveBTC（actor.rs:655-674）：`ckb_final_tlc_millis >= btc_final_cltv_millis / 2` 时拒绝，且 `checked_mul` 防溢出。

设计正确，符合 `docs/specs/cch-expiry-dependency.md`。

### 3.6 F6 (✅ Pass) — 动态 half-budget + max-outgoing 检查

`compute_max_outgoing_expiry_seconds` + `check_expiry_or_fail`（send_outgoing_payment.rs:180-281）正确实现 spec §2-§4：

- 使用 `elapsed = now − order.created_at`（保守下界，TLC 接受时间 ≥ created_at）；
- `remaining / 2` 切分；
- 与 outgoing invoice 的 `min_final_cltv` / `final_tlc_minimum_expiry_delta` 对比；
- 失败时通过 `PaymentChanged { status: Failed }` 走正常状态机路径，保留 incoming hold 资金的恢复机会（——不过仍依赖 F1 的取消缺口）。

`tlc_expiry_limit = max_outgoing_seconds.saturating_mul(1000).min(MAX_PAYMENT_TLC_EXPIRY_LIMIT)` 与 `cltv_limit = (max_outgoing_seconds / 600) as i32` 计算被正确传递给 Fiber/LND 后端。

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — `expire_order` 在非 Pending 订单上强制 Failed → preimage 丢弃 → 直接资金损失（24h 攻击窗口） | 🟠 **High** | ❌ 未修复 |
| F2 — `min_final_cltv_expiry_delta() * 600` 两处未 checked/saturating（与同文件 line 205 不一致） | 🟢 Low | ⚠️ 未修复 |
| F3 — BTC 600 s/block 固定假设（极端块速可能压缩 half-budget 安全余量） | ℹ️ Info | — |
| F4 — preimage SHA256 hash 校验防伪造 | ✅ Pass | — |
| F5 — 静态 half-budget 检查（含 `checked_mul` for BTC blocks→millis） | ✅ Pass | — |
| F6 — 动态 half-budget + max_outgoing 限制 + 状态机 fail-path | ✅ Pass | — |
| 整体 | 🟠 **High** | ❌ |

**总体评价**：CCH 的**协议层设计**严格遵循 LN 跨链 HTLC 标准 —— preimage hash 验证、双重 half-budget 检查、单调状态机、保守的 elapsed 计算都做得到位。但 **运营层调度**与 **协议层状态机** 之间存在严重的**接口失配**：

1. **F1**：`expire_order` 把 wall-clock 订单过期与 HTLC 时序过期混为一谈。把 36h 的"订单 wall-clock 过期"无条件用作"放弃 HTLC 流程"的触发器，会在 outgoing 已提交、preimage 即将揭晓的窗口期强制 fail 订单，使 CCH 丢失 preimage → 直接资金损失。这是 LN 节点常见的"settled-htlc race"漏洞类别（参见 LN-bolt#03 §3.3 expiry 部分），CCH 默认配置使其**默认开启**。
2. **F2**：与 line 205 `saturating_mul` 风格不一致的两处 `* 600`，暴露代码评审的覆盖盲区。
3. **F3**：600s 块速假设需要文档化。

F1 是本审计**最严重的 LOGIC 类发现** —— 优先级高于 AUDIT-LOGIC-007（cooperative close DoS）。建议作为下一个修复焦点。

## 5. Follow-ups

- **AUDIT-LOGIC-008-FOLLOWUP-A (High, 必修)**: F1 — `expire_order` 仅当 `status == Pending` 时才强制 Failed；为已进入 outgoing 流程的订单设计基于 TLC/HTLC 实际剩余时间的独立调度作业。
- **AUDIT-LOGIC-008-FOLLOWUP-B (High, 必修)**: F1 续 — 实现 LND `CancelInvoice` 与 Fiber invoice cancel 的反向路径；当 CCH 决定放弃订单时主动取消两侧的 in-flight HTLC/TLC，避免资金被对手单边占用。
- **AUDIT-LOGIC-008-FOLLOWUP-C (Medium, 防御性恢复)**: F1 续 — `handle_tracking_event` 若收到 `PaymentChanged { payment_preimage: Some(_) }` 且订单已 Failed，将 preimage 旁路写入 "orphaned_preimages" 表或显著日志，并尝试一次 best-effort settle。
- **AUDIT-LOGIC-008-FOLLOWUP-D (Low)**: F2 — 把 `min_final_cltv_expiry_delta() * 600` 两处统一为 `saturating_mul(600)` 或 `checked_mul(600).ok_or(...)?`。
- **AUDIT-LOGIC-008-FOLLOWUP-E (Info, 文档)**: F3 — 在 `docs/specs/cch-expiry-dependency.md` 中明确 600 s/block 假设以及在 BTC 块速持续偏快情况下应调整 `btc_final_tlc_expiry_delta_blocks` 的指导。
- **AUDIT-LOGIC-008-FOLLOWUP-F (Low, 配置校验)**: 启动时拒绝 `order_expiry_delta_seconds <= ckb_final_tlc_expiry_delta_seconds` 或 `<= btc_final_tlc_expiry_delta_blocks * 600` 的危险配置组合，强制 `order_expiry < min(both_TLC) - safety_margin`。

**关联**：
- 与 AUDIT-MEM-001 类似 — 不验证状态前置条件的"自动 fire"机制是攻击放大器；
- 与 AUDIT-AUTH-001（standalone watchtower NodeId 冲突）协同 — 若 CCH 与 standalone watchtower 共用 nodeId 命名空间，则 F1 fail 后的"善后"链上恢复更复杂。
