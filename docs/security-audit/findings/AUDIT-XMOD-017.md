# AUDIT-XMOD-017 — rpc/pubsub ↔ store/StoreChange ↔ cch/watchtower 维度 preimage / payment-session 越权泄露 + 顺序广播 DoS

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟠 **High**（任一持有 `read("cch")` 的 RPC 客户端可实时获取所有结算 preimage → 可被用于 invoice 劫持 / 跨链 preimage 窃取；loopback 默认 `enable_auth=false` 时同主机任意进程零门槛触发） |
| 状态 | [!] 发现弱设计 + 资金敏感数据越权暴露（静态可达，启用 `pubsub` 模块即触发） |
| 出处 | 本次跨模块审计新发现；XMOD-005（RPC 鉴权）、XMOD-009（mailbox DoS）、XMOD-011（preimage 日志）单独都不覆盖 pubsub 通道这条独立泄露面 |
| 关联代码 | `crates/fiber-lib/src/rpc/pubsub.rs:55-65`（`Publish` 处理器把 `StoreChange` 序列化为 raw JSON 后**顺序 await** 每个 sink；`expect("serialize to JSON")` panic）<br>`crates/fiber-lib/src/rpc/pubsub.rs:74-95`（`register_subscription` 把订阅添加到 actor，且 actor 用默认 `OutputPort` + 无界 mailbox）<br>`crates/fiber-lib/src/rpc/biscuit.rs:82`（`b.rule("subscribe_store_changes", r#"allow if read("cch");"#);` — 与 `receive_btc` / `get_cch_order` 共用 facet）<br>`crates/fiber-lib/src/store/store_impl/mod.rs:380-393`（`StoreChange::PutPreimage { payment_hash, payment_preimage }` / `PutPaymentSession { ..PaymentSession }` / `PutCkbInvoiceStatus`）<br>`crates/fiber-lib/src/store/store_impl/mod.rs:792-835`（preimage 落地路径主动调 `self.notify(StoreChange::PutPreimage { .. })`）<br>`crates/fiber-lib/src/cch/actor.rs:208-215, 874-911`（standalone CCH 用 `token` 调 `subscribe_store_changes` WebSocket）<br>`crates/fiber-lib/src/rpc/middleware.rs:62, 92-113`（`enable_auth=false` 即跳过 token 校验直接放行；`is_public_addr` 仅看监听地址，不阻止 loopback 多租户）|
| 关联 finding | AUDIT-AUTH-001（standalone watchtower / 默认鉴权关闭）、AUDIT-XMOD-005（RPC 鉴权穿透）、AUDIT-XMOD-009（actor mailbox 无界）、AUDIT-XMOD-011（preimage 日志卫生）、AUDIT-XMOD-002（CCH 时序与 preimage 跨链耦合）、AUDIT-STORE-001（preimage 持久化）|

## 1. 现象

`fiber-lib` 引入了 `pubsub` RPC 模块用于把 *Fiber 节点持久化层的变更事件*（`StoreChange`）通过 JSON-RPC over WebSocket 广播给订阅者，主要服务 *standalone CCH* 用例。该机制存在 **3 个独立但耦合的问题**：

### 1.1 严重：preimage / payment session 在普通 `read("cch")` 权限即可订阅

- `biscuit.rs:82` 规则 `subscribe_store_changes` = `allow if read("cch")` 与 `receive_btc` / `get_cch_order` 共用 facet；
- 但 `StoreChange` 实际承载（`store_impl/mod.rs:380-393`）：
  - `PutPreimage { payment_hash, payment_preimage: Hash256 }` — **每笔已结算 invoice 的明文 preimage**；
  - `PutPaymentSession { payment_hash, payment_session: PaymentSession }` — 全量路由 / 金额 / 节点序列；
  - `PutCkbInvoiceStatus { payment_hash, invoice_status }` — 结算时序 oracle；
- 业务上 `read("cch")` 是给 CCH dashboard / 跨链监控的"读权限"，操作员合理预期它只能 `get_cch_order` 查看跨链订单状态；却隐式获得了全节点 preimage stream。**权限范围严重越权**（least privilege 违反）；
- 当 `enable_auth=false`（loopback / 非 `is_public_addr` 默认；见 `rpc/middleware.rs:62, 92-113`）时**完全无鉴权** — 同主机任何进程都能订阅。

### 1.2 顺序 await 的广播循环让单个慢订阅者阻塞所有人

```rust
// rpc/pubsub.rs:55-65 (简化)
PubSubServerMessage::Publish(event) => {
    let subscription_message = serde_json::value::to_raw_value(&event)
        .expect("serialize to JSON");                // (a) panic on serialize 失败
    let sinks = std::mem::take(&mut state.sinks);
    for sink in sinks {                              // (b) 顺序循环
        if sink.send(subscription_message.clone())   // (c) await 每个 sink 写入
            .await.is_ok() {
            state.sinks.push(sink);
        }
    }
}
```

- (b)+(c)：恶意 / 缓慢订阅者只要不读自己的 WebSocket buffer，`sink.send().await` 就阻塞，导致**整个 `PubSubServerActor` `handle` 协程挂起**，所有后续 `Publish` 消息排队进 actor mailbox；
- mailbox 是 ractor 0.15 默认无界 MPSC（参见 XMOD-009）→ 内存增长无上限 →进程 OOM；同时 **合法 CCH 订阅者收不到 `PutPreimage` 事件** → 跨链订单状态机停滞 → 与 XMOD-002 时序窗口叠加 → preimage 落地 watchtower 但 CCH 不知道 → 跨链入金/赎回失窃。

### 1.3 `serde_json::to_raw_value(&event).expect(...)` 在 actor 内部 panic

当前 `StoreChange` 变体都是简单类型，序列化失败概率极低；但作为长期演进风险，未来给 `PaymentSession` 加入含 `f64::NAN` / 自定义 Serialize 的字段时会直接 panic 该 actor，触发"反 cheat 报警通道关停"的失败模式（与 XMOD-006 / XMOD-002 间接耦合）。

## 2. 跨模块攻击路径

```
攻击者 / 误配的客户端（持 read("cch") 或 同主机 enable_auth=false）
        │
        ▼ rpc/middleware.rs:62, 92-113
   auth_call 放行 subscribe_store_changes
        │
        ▼ rpc/pubsub.rs:82-93
   register_subscription → AddSink → PubSubServerState.sinks 持续累积
        │
        ▼ store_impl/mod.rs:792-835
   收单 / 反 cheat 路径每次 PutPreimage 都 self.notify(StoreChange::PutPreimage { .. })
        │
        ▼ rpc/pubsub.rs:55-65
   订阅者实时收到 JSON: {"payment_hash":"...","payment_preimage":"..."}
        │
        ▼ 攻击者把 preimage 直接用于:
   (1) 在另一条出站路径 / 跨链 LND 上 settle 同 payment_hash 抢走对端资金（XMOD-002 同步路径）；
   (2) 在 invoice 仍可结算窗口内"代为 settle"以套利；
   (3) 与 XMOD-011 日志泄露互补，构成第二条 preimage 出口。
```

并行 DoS 路径：

```
单一慢订阅者持续 hold sink.send().await
        │
        ▼ rpc/pubsub.rs:58-63 顺序循环阻塞
   PubSubServerActor.handle 挂起
        │
        ▼ store 写入路径仍持续触发 watcher → 调 send_message
        │
        ▼ ractor unbounded mailbox 持续累积 Publish 消息
        │
        ▼ 进程 RSS 无界增长 + 合法 CCH 订阅停滞 → XMOD-002 时序窗口叠加
```

## 3. 跨模块边映射

对照 [`MODULES.md`](../MODULES.md) §3：

- **新增入站边 E11**：JSON-RPC WebSocket subscriber → `rpc/pubsub` → `PubSubServerActor`（控制度 🟥 远程 / 🟨 本地非特权 / 取决于 `enable_auth`）。
- **新增模块间边 I13**：`store/store_impl::notify` → `rpc/pubsub::PubSubServerActor::Publish`（数据来源：`channel`/`payment` 模块的 preimage 落地 → I6 的姊妹路径）。
- **新增出站边 O6**：`rpc/pubsub` → 远程 WebSocket subscriber，承载 `StoreChange` JSON — **明文 preimage 出网**。

链上跨：`channel`（结算触发 preimage 落地）→ `store`（持久化 + notify）→ `rpc/pubsub`（actor 广播）→ 远程 subscriber → `cch`（合法消费者）/ 攻击者。

## 4. 与已有 XMOD 的区别

| 已有 XMOD | 与本条的关系 |
|---|---|
| **XMOD-005** | 关注 *RPC 鉴权 gate*（CORS / Host / standalone watchtower），未涉及 *单 facet 内权限粒度过粗* 的应用层授权问题；本条强调"鉴权通过后授权仍越权" |
| **XMOD-009** | RPC actor 调用全 `call!` 无 timeout + ractor 默认无界 mailbox 是通用模式问题；本条具体落到 *pubsub broadcast actor* 的顺序 await + 持久 sink 列表导致 *单慢订阅者*-级别的阻塞 |
| **XMOD-011** | preimage 通过 `tracing::error!` 进**日志文件**；本条 preimage 通过 **JSON-RPC WebSocket 通道**实时出网；两路并存 |
| **XMOD-002** | CCH 与 watchtower 时序错配；本条提供 *第二条* preimage 失窃路径（即便修复了 XMOD-002 时序，仍可被订阅劫持） |
| **STORE-001** | 关注磁盘 0o644 离线泄露；本条关注**在线运行时**通过 RPC 出口主动推送 |

## 5. 影响评估

- **资金敏感**：preimage 是 invoice 结算证明，等价于"已收款凭据"；攻击者获得后可在同 `payment_hash` 另一未结算 hop 上抢先 settle 套利（典型 Lightning Network preimage race）。
- **触发成本**：
  - 已部署 standalone CCH 的节点必然启用 `pubsub` 模块 + 颁发 `read("cch")` token；任何获得该 token 的客户端（CCH dashboard / 监控 / API 集成）= 实时 preimage 听众；
  - loopback 默认 `enable_auth=false` 时同主机非特权进程零门槛订阅 → 容器多租户 / shared VM 场景立即触发。
- **可观测性弱**：`AddSink` 路径无日志、无连接 audit；管理员无法发现是否有"隐形监听者"。
- **不可逆**：preimage 一旦发送给订阅者即视为泄露，无召回；CCH cross-chain 模型下意味着对端可直接取走 BTC / CKB 锁仓。

## 6. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| **F1** | **P0** | 把 `subscribe_store_changes` 的 biscuit rule 改为独立高权 facet（建议 `write("store_changes")` 或新引入 `subscribe("preimage")`），与 `receive_btc` / `get_cch_order` 解耦；现有 standalone CCH 部署文档同步升级（`docs/biscuit-auth.md` + `docs/cch.md`）。**配套**：发布说明明确"重启后 `read("cch")` 旧 token 不再能订阅"。 |
| **F2** | **P0** | 在 `rpc/pubsub.rs` 引入"事件过滤白名单"：`StoreChange::PutPreimage` 默认**不**进 raw JSON；改为只推 `{payment_hash, type:"preimage_ready"}`，preimage 本身留在本地 store 由订阅者通过另一个**显式高权**RPC `fetch_preimage(payment_hash, biscuit_token_with_specific_payment_hash_attenuation)` 拉取；该 RPC 用 biscuit *attenuation* 机制把 token 范围限制到具体 `payment_hash` 上。 |
| **F3** | **P0** | `enable_auth=false` 时**显式拒绝** `subscribe_store_changes`（即便是 loopback），并在 `auth_call` 加白名单维护一组"敏感订阅方法即便 loopback 也必须 token"。 |
| **F4** | **P1** | `PubSubServerActor` 的广播循环改为**并发**或为每个 sink 设置 send timeout（推荐 5s）：`tokio::time::timeout(Duration::from_secs(5), sink.send(msg))`；超时即视为断开并丢弃 sink，避免单订阅者拖死全局。 |
| **F5** | **P1** | `PubSubServerActor` 显式使用 bounded mailbox（与 XMOD-009.FOLLOWUP-2 同 PR）；溢出时丢最旧 `Publish` 并 warn — 因为合法 CCH 应该实时跟进，落后即视为故障。 |
| **F6** | **P1** | 替换 `.expect("serialize to JSON")` 为 `match`：失败 `tracing::error!` 并跳过该事件，避免单条 malformed 事件 panic 整个广播 actor。 |
| **F7** | **P2** | `AddSink` 路径加 `tracing::info!` audit 日志（节点 ID + remote addr，注意脱敏与 XMOD-011 协同）；`PubSubServerState` 暴露 metrics（sinks 数 / 每秒推送数 / 慢消费者数）。 |
| **F8** | **P2** | 与 XMOD-011 一同推进：`Preimage` 引入独立 newtype，在 `StoreChange` 中只允许出现该 newtype 且其 `Serialize` 在 `pubsub` 路径触发"redacted by default"。 |

## 7. 验证测试

- `rpc::pubsub::tests::test_subscribe_requires_dedicated_facet`：F1 后 `read("cch")` token 调 `subscribe_store_changes` → 拒绝。
- `rpc::pubsub::tests::test_preimage_not_in_default_event_stream`：F2 后默认事件流不含明文 preimage。
- `rpc::pubsub::tests::test_loopback_subscription_requires_token`：F3 后即使 `enable_auth=false` 也拒绝。
- `rpc::pubsub::tests::test_slow_subscriber_does_not_block_others`：F4 — 一个 sink 阻塞 6 秒，断言其它 sink 在 ≤6s 内全部收到事件并被剔除慢者。
- `rpc::pubsub::tests::test_publish_actor_uses_bounded_mailbox`：F5 — 入参溢出时观察到 warn 日志而非 RSS 增长。
- Property test：随机注入 `StoreChange` 变体，断言 actor 不 panic（覆盖 F6）。
- Integration：`tests/it_cch_subscribe.rs` mock 一个有 `read("cch")` 但无新 facet 的 token，断言订阅被拒并保留 `receive_btc` 调用能力 — 防止 F1 误伤合法 CCH 路径。

## 8. 状态

- F1+F2+F3 协同：必须三者同步落地才能堵住 preimage 泄露面；任一缺失都留有出口。
- F4+F5 与 XMOD-009.FOLLOWUP-2 合并：以"敏感 actor 全面 bounded mailbox + timeout"为统一原则推进。
- 关联 PR：暂无。文档版本：MODULES.md v4 / REPORT.md v1.4 同步引用。
