# AUDIT-INPUT-003 — JSON-RPC 参数校验

- **维度**: DIM-INPUT (RPC API surface)
- **严重级别**: 🟡 **Medium**（Medium × 2 + Low × 4 + Info × 1 + Pass × 3）
- **审计 Session**: S15 (2026-05-14)
- **关联代码**:
  - 入口与服务器:
    - `crates/fiber-lib/src/rpc/mod.rs:124-246` (`start_server` — tower 服务构造)
    - `crates/fiber-lib/src/rpc/mod.rs:248-264` (`is_public_addr` 公网监听保护)
    - `crates/fiber-lib/src/rpc/mod.rs:283-408` (`start_rpc` — 模块注册 + CORS + biscuit auth)
    - `crates/fiber-lib/src/rpc/config.rs:1-38` (RpcConfig — 无 rate-limit / body-size 字段)
    - `crates/fiber-lib/src/rpc/middleware.rs:42-114` (BiscuitAuthMiddleware — 参数注入 + 认证)
  - 各 RPC 模块的参数处理:
    - `crates/fiber-lib/src/rpc/invoice.rs:289-300` (`parse_invoice` — 用户字符串 → `from_str` panic 路径)
    - `crates/fiber-lib/src/rpc/invoice.rs:302-326,328-369` (`get_invoice`/`cancel_invoice` 中 `.expect("no invoice status found")`)
    - `crates/fiber-lib/src/rpc/invoice.rs:207-210` (`expiry: u64 → Duration::from_secs` 无上界)
    - `crates/fiber-lib/src/rpc/payment.rs:169-233` (`send_payment` — invoice 字段直传)
    - `crates/fiber-lib/src/rpc/payment.rs:315-343` (`list_payments` — `limit: u64` 无上界)
    - `crates/fiber-lib/src/rpc/graph.rs:128-184` (`graph_nodes`/`graph_channels` — `limit: u64` 无上界)
    - `crates/fiber-lib/src/rpc/cch.rs:68-115` (`send_btc`/`receive_btc`/`get_cch_order` — pay_req 字符串直传)
    - `crates/fiber-lib/src/rpc/peer.rs:71-127` (`connect_peer`/`disconnect_peer`)
    - `crates/fiber-lib/src/rpc/watchtower.rs:147-277` (watchtower RPCs — 已由 AUTH-001 覆盖)
    - `crates/fiber-lib/src/rpc/dev.rs:38-82` (DevRpc — `#[cfg(debug_assertions)]` 仅 debug 启用 ✓)
  - 错误转换工具:
    - `crates/fiber-lib/src/rpc/utils.rs:1-84` (`rpc_error`/`rpc_error_no_data`/`RpcResultExt`)

## 1. 审计目标

JSON-RPC API 是 fiber 节点与外部世界的主要管理接口，对应以下风险面：

- 进程**可用性**：单个恶意请求是否能让节点崩溃（panic、OOM、CPU 耗尽、磁盘/socket 资源耗尽）。
- 状态**完整性**：未授权 / 越权调用能否破坏 channel state / payment session / store。
- 信息**机密性**：是否泄漏 invoice 状态、payment hash、preimage、私钥派生材料。
- 边界**正确性**：用户控制的数值/字符串/数组在解码、校验、转换层的每一步。

具体审计项：

1. 所有 RPC 方法的入参解析路径 — 是否走 `try_from`/`?` 还是 `.expect`/`.unwrap`/`panic!`；
2. 数值上界（`limit`、`amount`、`expiry`、`max_tlc_*`、`final_expiry_delta` 等）；
3. 字符串入参（pay_req、multiaddr、pubkey、hex）是否有长度上限与解析 panic；
4. 不需要授权时的攻击面（无 biscuit / loopback / `enable_auth=false`）；
5. JSON-RPC 服务器自身的 DoS 防护（max_body_size、max_connections、per-IP rate-limit、slowloris）；
6. CORS 配置下浏览器 XSS / cross-origin 暴露面；
7. 与已发现漏洞（INPUT-002 invoice DoS、AUTH-001 watchtower NodeId::local()、AUTH-002 CORS Any）的协同。

## 2. 系统性梳理

### 2.1 RPC 模块清单

`rpc/config.rs:3-6` 定义默认启用模块：

```rust
const DEFAULT_ENABLED_MODULES: &str = "cch,channel,graph,payment,info,invoice,peer";
// watchtower feature 时加 "watchtower"
```

| 模块 | 方法数 | 默认启用 | 备注 |
|---|---|---|---|
| `info` | 1 | ✓ | node_info — 暴露 node_id / chain_hash / 启动时间 |
| `peer` | 3 | ✓ | connect_peer / disconnect_peer / list_peers |
| `channel` | ~12 | ✓ | open_channel / accept_channel / shutdown_channel / list_channels / update_channel / ... |
| `payment` | 5 | ✓ | send_payment / get_payment / build_router / send_payment_with_router / list_payments |
| `invoice` | 5 | ✓ | new_invoice / parse_invoice / get_invoice / cancel_invoice / settle_invoice |
| `graph` | 2 | ✓ | graph_nodes / graph_channels |
| `cch` | 3 | ✓ | send_btc / receive_btc / get_cch_order |
| `watchtower` | 7 | feature 启用 | 由 AUTH-001 单独审计 |
| `dev` | 6 | `cfg(debug_assertions)` only | release 自动禁用 ✓ |
| `prof` | feature `pprof` | optional | pprof CPU profiler |
| `pubsub` | gossip event | optional | websocket events |

### 2.2 鉴权决策矩阵

`mod.rs:285-296` + `middleware.rs:60-114`:

- 公网监听（`is_public_addr == true`）→ **必须**配置 `biscuit_public_key`，否则启动失败 ✓
- 私网 / loopback → **可选**鉴权
  - 若 `biscuit_public_key = None` → `enable_auth = false` → middleware 直接放行 + 同时把 RpcContext 注入为 `NodeId::local()`（AUTH-001.F1 已覆盖）
- biscuit 启用时 → 每方法可有独立 rule；rule 未注册的方法走 `Err` 路径但 `enable_auth=false` 下 `.allow local rpc to proceed.`（middleware.rs:109-110，AUTH-001.F2）

**关键观察**：私网 / loopback 部署下默认无鉴权 — 同主机其他进程（多租户容器、共享 dev 机、CI runner 容器）即可调用所有 RPC。

### 2.3 字符串入参 — 远程触发的解析 panic

最危险的一族：**用户字符串 → 内部解析器**。

| 入口 RPC | 字符串字段 | 内部调用 | 已知 panic 路径 |
|---|---|---|---|
| `invoice.parse_invoice(params.invoice)` | invoice bech32m | `InternalCkbInvoice::from_str` → `ar_decompress.expect()` + `From<InvoiceAttr>` 三处 `.expect()` | ✗ INPUT-002.F1/F2/F3 — 单次合法格式 invoice → 崩进程 |
| `payment.send_payment(params.invoice: Option<String>)` | 同上 | 同上 | ✗ 同上 |
| `cch.receive_btc(params.fiber_pay_req)` | fiber invoice | 经 `CchMessage::ReceiveBTC` → 在 actor 内 parse | ✗ 同上 |
| `cch.send_btc(params.btc_pay_req)` | BTC LN invoice | 经 `CchMessage::SendBTC` → lightning-invoice parse | ⚠️ 取决于 `lightning-invoice` crate 健壮性，本审计未覆盖 |
| `peer.connect_peer(params.address)` | multiaddr | `Multiaddr::parse()` 返回 `Result` ✓ | ✓ pass |
| `peer.connect_peer(params.pubkey)` | hex pubkey | `Pubkey::try_from` 返回 `Result` ✓ | ✓ pass |
| `watchtower.update_revocation/...(ctx.node_id)` | NodeId hex | `parse::<NodeId>()` 返回 `Result` ✓ | ✓ pass |

`invoice.rs:289-300`:

```rust
pub async fn parse_invoice(&self, params: ParseInvoiceParams)
    -> Result<ParseInvoiceResult, ErrorObjectOwned>
{
    let result: Result<InternalCkbInvoice, _> = params.invoice.parse();
    //                                          ↑ 这里 .parse() 返回 Result，但
    //   InternalCkbInvoice::from_str 内部走 ar_decompress.expect()/UTF-8.expect()/...
    match result { ... }
}
```

`Result<_, _>` 的语义被破坏 — 调用方以为 fallible 的 `.parse()` 仅返回 Err，实际下层多处 `.expect()` 会 panic 整个 jsonrpsee runtime。INPUT-002 详细分析了该路径；本审计标注 **RPC 是远程触发的入口**。

### 2.4 数值入参 — 无上界 / 资源耗尽

#### F2 候选位置 1：`graph_nodes` / `graph_channels` (`rpc/graph.rs:128-184`)

```rust
let default_max_limit = 500;
let limit = params.limit.unwrap_or(default_max_limit) as usize;
let nodes = network_graph.get_nodes_with_params(limit, cursor);
```

`params.limit: Option<u64>`。**未对 `limit` 设上界**。攻击者发 `{ "limit": 18446744073709551615 }`:

- 64-bit 平台 `as usize` 无截断；
- `get_nodes_with_params(limit, cursor)` 内部 iterator 不会真分配 u64::MAX 个槽位（流式收集），但若网络图本身有 10 万节点 → 10 万次 NodeInfo clone + 序列化为 JSON。每个 NodeInfo 含若干 Vec<u8>。Worst case JSON 响应数 MB → CPU + memory + bandwidth 一次性爆发。
- 攻击成本：单次合法 RPC（已认证或无 auth 私网）。
- 默认 `graph` 模块在默认配置中**启用**。

#### F2 候选位置 2：`list_payments` (`rpc/payment.rs:315-343`)

```rust
let default_limit: u64 = 15;
let limit = params.limit.unwrap_or(default_limit) as usize;
let sessions = self.store.get_payment_sessions_with_limit(limit, after, status);
```

同样无上界。`get_payment_sessions_with_limit` 在 store 中遍历所有 payment session。中等节点可有 10^5+ session。攻击者发 `{ "limit": 18446744073709551615 }` → 拉取全部 session + JSON 序列化（含 SessionRoute、custom_records、错误码字符串）→ 数十 MB 响应。

#### 数值边界 — 其它已经正确处理的字段

| 字段 | 位置 | 上界处理 |
|---|---|---|
| `final_expiry_delta` | `invoice.rs:242-254` | ✓ `< MIN_TLC_EXPIRY_DELTA` / `> MAX_PAYMENT_TLC_EXPIRY_LIMIT` 双向检查 |
| `params.amount` | invoice/payment | 由 InvoiceBuilder/SendPaymentCommand 下游校验（MEM-002.F3 已覆盖 commitment_fee 等） |
| `funding_amount` | `channel.rs:224` | 由 OpenChannelCommand 下游 cap < u64::MAX |
| `commitment_delay_epoch.value()` | `channel.rs:229-230` | `EpochNumberWithFractionCore::from_full_value` 不做范围检查（与 ckb-types 一致；该值用于链上比较） |

`expiry: u64 → Duration::from_secs(expiry)` (`invoice.rs:207-210`) — `Duration` 支持完整 u64 秒，不会 panic，但 invoice 在 builder 中可能拒绝过大值（未细查）。属 Info。

### 2.5 `.expect` 在 RPC 层 — invoice 状态查询

`invoice.rs:309-313` 和 `336-339`:

```rust
let status = match self
    .store
    .get_invoice_status(&payment_hash)
    .expect("no invoice status found")    // ⚠️ panic if invoice 存在但 status 缺失
{ ... };
```

`get_invoice` 与 `cancel_invoice` 在以下序列下 panic：

1. 节点收到 `add_invoice` → store 写 `INVOICE` 记录但**未**完成 `INVOICE_STATUS` 二次写（短时间窗口或部分 IO 故障）；
2. 攻击者立即调用 `get_invoice { payment_hash }`；
3. `store.get_invoice(...).is_some()` 进入分支 + `store.get_invoice_status(...).expect(...)` → panic 整个 jsonrpsee 服务。

虽然该窗口很短，但 `InvoiceStore::insert_invoice` 中两次写是否原子？

<details>
<summary>查 InvoiceStore impl（关联 STORE-001.F3 同质风险）</summary>

`get_invoice_status` 的 None 也可以由迁移 mid-crash（STORE-001.F4）产生 — `INVOICE_STATUS_PREFIX` 字节被半改写后反序列化为 None（实际是字节级失败 → panic 在 deserialize_from 层），但仅 status missing 也足够触发该 RPC panic。
</details>

更稳健的写法是 `unwrap_or(CkbInvoiceStatus::Open)` 或 `.unwrap_or_else(|| return Err(rpc_error("status missing", params)))`。

### 2.6 服务器端 DoS 防护

`mod.rs:124-246` 的 `start_server`:

```rust
let per_conn = PerConnection {
    methods: methods.into(),
    stop_handle: stop_handle.clone(),
    svc_builder: jsonrpsee::server::Server::builder().to_service_builder(),
    //  ↑ 使用默认 builder — 无定制
};
```

`jsonrpsee::server::Server::builder()` 默认值（jsonrpsee 0.x）：

| 设置 | 默认 | 实际暴露 |
|---|---|---|
| `max_request_body_size` | 10 MB | ✓ 有限制（10 MB） |
| `max_response_body_size` | 10 MB | ✓ 有限制 |
| `max_connections` | 100 | ✓ 有限制（默认 100） |
| `max_subscriptions_per_connection` | 1024 | 无问题 |
| `enable_http` / `enable_ws` | 都启用 | OK |
| Per-IP rate limit | 无 | ✗ 无任何限制 |
| Slowloris timeout | hyper 默认 | hyper 默认 keep-alive 75s, no explicit recv timeout |

**问题**：

- 100 个连接全部由单个攻击者占用 → 合法用户被拒；
- 单连接内可发送任意多次合法 RPC，无 per-method / per-second 限速；
- 与 F1（parse_invoice panic）协同：1 条合法 invoice 字符串即让进程崩溃 + 重启；
- 与 F2（limit u64::MAX）协同：1 条合法 graph_nodes 即让进程 OOM；
- 与 MEM-001（gossip 50MB/s OOM）协同：内存预算被 RPC 拉满后 gossip OOM 加速。

`rpc/config.rs` 配置中**完全没有**暴露这些参数给运维 — 无法在生产收紧。

### 2.7 CORS — 浏览器 Cross-Origin 攻击面

`mod.rs:211-228`:

```rust
let cors_layer = if cors_allowed_origins.is_empty() {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
} else { /* allow list */ };
```

`cors_enabled: bool` 默认 `false`，但一旦运维启用且未指定 `cors_allowed_origins`（典型 dev/test 场景）→ `Any` 三件套（AUTH-001.F3 已覆盖）。

**新增观察**：CORS 是**最外层**（layer order 见 mod.rs:209 注释 "CORS must be the outermost layer to handle OPTIONS preflight requests **before** authentication"）。这意味着：

- OPTIONS preflight 不需要 biscuit token；
- POST 实体（包含 RPC body）通过 preflight 后由内层 biscuit middleware 校验；
- 攻击页面无法读取响应（同源策略由浏览器保留），但**可以**通过 `fetch(url, {mode: "no-cors", body: ...})` 单向触发 RPC 方法（fire-and-forget），副作用 RPC（cancel_invoice / disconnect_peer / shutdown_channel）会被执行。
- 即使 biscuit 启用，浏览器无法发 Authorization header（被 CORS allow-headers 控制；如果攻击者诱导用户在浏览器粘贴 token 到一个授信站点，再被 XSS / 反射到攻击页面发起请求，token 在 Header 中通过 CORS 可被使用 — AUTH-002 关联）。

### 2.8 `middleware.inject_rpc_context` 的 `.expect`

`middleware.rs:54-56`:

```rust
req.params = Some(Cow::Owned(
    serde_json::value::to_raw_value(&[serde_json::json!(ctx), params])
        .expect("serialize injected params"),
));
```

`to_raw_value` 失败仅在 `serde::Serialize` 自身报错时发生；`RpcContext` 与 `serde_json::Value` 都是 well-formed → 实际不会 panic。属 Info / 防御性建议。

### 2.9 已经做得正确的部分

- **Pubkey / Hash256 / Privkey / Multiaddr** 解析全部走 `try_from`/`parse` 并通过 `RpcResultExt::rpc_err` 转 `ErrorObjectOwned`（payment.rs:175, channel.rs:219, peer.rs:81/95/118, watchtower.rs 全部入参）。
- **`only_pending && include_closed`** 互斥检查（channel.rs:306-311）— 正面案例。
- **`is_public_addr` + `biscuit_public_key` 强制**（mod.rs:285-287）— 强制公网启用鉴权 ✓。
- **DevRpc 仅 `cfg(debug_assertions)`** — release build 自动禁用 ✓。
- **错误码** — `INVALID_PARAMS_CODE` / `CALL_EXECUTION_FAILED_CODE` 区分清晰，未泄漏内部 panic backtrace。

## 3. 发现

### 3.1 F1 (🟡 Medium) — `parse_invoice` / `cch.receive_btc` / `send_payment.invoice` 是 INPUT-002 invoice DoS 的远程入口

**位置**：`rpc/invoice.rs:289-300`、`rpc/cch.rs:84-99,68-82`、`rpc/payment.rs:215`、`rpc/payment.rs:302`

#### 问题

INPUT-002 已记录 `InternalCkbInvoice::from_str` 在多处使用 `.expect()` / `panic!`（ar_decompress、Description UTF-8、FallbackAddr UTF-8、PayeePublicKey::from_slice、`from_str` line 902 等）。本审计补充以下 **RPC 入口**作为远程触发面：

1. `invoice.parse_invoice` — **无需任何认证**（私网默认场景）即可 RPC + 1 条 payload 字符串 → 进程崩溃。
2. `cch.receive_btc(params.fiber_pay_req)` — 同样路径；CCH 公网网关风险尤甚。
3. `payment.send_payment(params.invoice: Option<String>)` — invoice 字段会被内部 actor `parse`（payment.rs:215 透传）。
4. `payment.send_payment_with_router(params.invoice)` — 同上。

middleware 的 `parse::<serde_json::Value>().unwrap_or_default()` 是好习惯（不让 JSON 错乱 panic），但**调用层**的 `.expect` 直接绕过了这一防御。

#### 修复路径

- 与 INPUT-002-FOLLOWUP-A/B 同步：把 `From<InvoiceAttr>` 改 `TryFrom`，`ar_decompress` 错误传播。
- 防御性补丁：在 `parse_invoice` 和 `payment.send_payment` 入口外包 `std::panic::catch_unwind`（参考 INPUT-002-FOLLOWUP-F）。

**评级**：🟡 **Medium** — INPUT-002 已记录的 panic 路径在 RPC 层是**最常见的远程触发面**。本条主要起入口标记作用，修复依赖于 INPUT-002 主修复。

### 3.2 F2 (🟡 Medium) — `graph_nodes`/`graph_channels`/`list_payments` 的 `limit` 无上界 → 资源耗尽 DoS

**位置**：`rpc/graph.rs:134,159`、`rpc/payment.rs:320`

#### 问题

三个 list-type RPC 的 `limit: Option<u64>`：

```rust
// graph.rs:128-184
let default_max_limit = 500;
let limit = params.limit.unwrap_or(default_max_limit) as usize;
let nodes = network_graph.get_nodes_with_params(limit, cursor);
```

`unwrap_or(默认值)` 仅对**缺省**有效；当用户**显式**传入 `{ "limit": 18446744073709551615 }` 时直接通过。`as usize` 在 64-bit 上无截断。

虽然 jsonrpsee 默认 max_response_body_size=10 MB，但生成 10 MB JSON 之前已经：

- 遍历整个 graph / payment session 集合；
- 每个元素 clone NodeInfo / SessionRoute / custom_records；
- 序列化失败前已消耗 ~10 MB 临时内存 + N 次 serde 调用 + 大量 store 读 I/O。

10 个并发请求即可让 1 节点占用 100+ MB + 大量 CPU。配合 jsonrpsee 默认 100 并发连接 → 单 IP 攻击者轻松占满。

`graph` 模块默认启用、`payment` 模块默认启用、私网无鉴权下无门槛。

#### 修复

在每个 list RPC 入口加显式上限：

```rust
const MAX_LIMIT: u64 = 1000;  // 与 default_max_limit 不同
let raw_limit = params.limit.unwrap_or(default_max_limit);
if raw_limit > MAX_LIMIT {
    return Err(rpc_error(format!("limit must be <= {MAX_LIMIT}"), params));
}
let limit = raw_limit as usize;
```

或在 store 层 `get_*_with_limit(limit.min(MAX_LIMIT), ...)` cap。

**评级**：🟡 **Medium** — 无鉴权场景下零成本远程 DoS；有鉴权场景下任意 token 持有者均可触发。

### 3.3 F3 (🟢 Low) — `get_invoice`/`cancel_invoice` 中 `.expect("no invoice status found")` 在状态分裂窗口可远程触发 panic

**位置**：`rpc/invoice.rs:312, 338`

#### 问题

```rust
let status = match self
    .store
    .get_invoice_status(&payment_hash)
    .expect("no invoice status found")
{ ... };
```

进入分支的前提是 `store.get_invoice(...)` 已经返回 `Some`，即 INVOICE 记录存在。`get_invoice_status` 应同步存在 — 但：

- 二者由 `insert_invoice` 串行 `put` 两条记录（参考 STORE-001.F4 中 migration 非原子写讨论）；非 batch；
- IO 故障 / 程序崩溃可让 INVOICE 写入成功但 STATUS 写入失败；
- STORE-001.F3 的 `deserialize_from` 全局 panic 实际在更早 panic（key 存在但解码失败），但若 status 字节缺失为 None，则触发本 `.expect`。

攻击者枚举 payment_hash 触发 panic — 实际概率低（需要状态分裂窗口），但仍是单点 panic。

#### 修复

```rust
let status = self
    .store
    .get_invoice_status(&payment_hash)
    .ok_or_else(|| rpc_error("invoice status missing for existing invoice", params.clone()))?;
```

**评级**：🟢 **Low** — 触发条件苛刻，但模式与 INPUT-002 / STORE-001.F3 同类（信任 `.expect` 在 RPC 层做边界），统一改造收益正向。

### 3.4 F4 (🟢 Low) — jsonrpsee server 用默认配置，缺少 per-IP/per-method 限速 + 无 RpcConfig 字段暴露给运维收紧

**位置**：`rpc/mod.rs:160` (`Server::builder().to_service_builder()`)、`rpc/config.rs:1-38`

#### 问题

`Server::builder()` 用默认值：

- `max_connections = 100`：单 IP 占满即拒绝其他客户端（明显的 DoS 放大）。
- `max_request_body_size = 10 MB`：合法但被 F1 单字符串 + F2 单 list_payments 已经超过有效门槛。
- 无 per-method / per-second 限速。
- 无 slowloris 防御（hyper 默认 keep_alive=75s，无 receive timeout）。

`RpcConfig` 仅暴露 `listening_addr` / `biscuit_public_key` / `enabled_modules` / `cors_*`。无任何 limit 字段。

#### 修复

- 在 `RpcConfig` 加 `max_connections / max_request_body_size / per_ip_qps`，传给 `Server::builder()`；
- 加 `tower::limit::RateLimitLayer` 或 `tower-governor` 做 per-IP/per-method 限速；
- 设置 hyper `keep_alive_timeout`。

**评级**：🟢 **Low** — 防御纵深问题；本身不直接导致漏洞，但放大 F1/F2/MEM-001 影响。

### 3.5 F5 (🟢 Low) — 私网/loopback 监听下默认无鉴权 = 同主机多租户用户可读所有 RPC

**位置**：`rpc/mod.rs:285-287` (`is_public_addr` 仅检查公网)、`rpc/middleware.rs:92-113` (本地无 token 直接放行)

#### 问题

`is_public_addr` 检测公网 → 强制 biscuit；私网（10/8、192.168/16、127/8、::1、fc00::/7、link-local）**不强制** biscuit。

部署场景：

- 多租户 dev 容器 / CI runner / k8s pod 内多个 sidecar；
- 共享 dev 机 / mainframe；
- 容器内 init container 与主进程共享 localhost；
- WSL 与 Windows 主机共享 loopback。

→ 同主机其他用户/进程无 token 即可调用 RPC，包括：

- `cancel_invoice` / `shutdown_channel` / `disconnect_peer` 等**状态破坏型**方法；
- `send_payment` 等**资金移动**方法；
- `list_payments` / `graph_nodes` 等**信息泄漏**。

#### 修复

`is_public_addr` 不区分公网/私网 — 当配置 enabled_modules 中含 `payment`/`channel`/`cch` 等敏感模块时一律强制 biscuit。或在 RpcConfig 增加 `force_auth: bool` 默认 true。

**评级**：🟢 **Low** — 多租户共享主机是少数生产场景，但与 onion key / wallet enforce 0600 / store 文件权限（STORE-001.F1）协同看，文件层和 RPC 层的"同主机隔离"应一致。

### 3.6 F6 (ℹ️ Info) — `inject_rpc_context` 用 `.expect("serialize injected params")`

**位置**：`rpc/middleware.rs:55`

`to_raw_value(&[RpcContext, Value])` 在 well-formed 输入下不会失败。属反模式 — 建议改 `Result` 传播，避免未来 `RpcContext` 结构修改时引入隐式 panic。

**评级**：ℹ️ Info — 防御性建议。

### 3.7 F7 (✅ Pass) — Pubkey/Hash256/Privkey/Multiaddr 解析全部走 fallible API

`Pubkey::try_from(params.pubkey).rpc_err(&params)?`、`address.parse::<Multiaddr>().rpc_err(...)?`、`NodeId::parse::<NodeId>().rpc_err_no_data()?` 等均返回 `Result` 并被 `?` 传播。无 `.expect` 在解码路径。

### 3.8 F8 (✅ Pass) — DevRpc `#[cfg(debug_assertions)]` 在 release build 中自动剔除

`mod.rs:7-8, 356-373` 与 `dev.rs:1` `#[cfg(debug_assertions)]` 保证 DevRpc 的 `add_tlc / remove_tlc / submit_commitment_transaction / sign_external_funding_tx` 等危险方法在 release 不存在。

### 3.9 F9 (✅ Pass) — `is_public_addr` + `biscuit_public_key` 强制公网鉴权

`mod.rs:285-287` 在公网监听+无 biscuit 配置时启动失败：

```rust
if config.biscuit_public_key.is_none() && is_public_addr(listening_addr)? {
    bail!("Cannot listen on a public address without a biscuit public key set...");
}
```

公网部署强 fail-fast。

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — `parse_invoice` / cch.receive_btc / send_payment.invoice 是 INPUT-002 远程入口 | 🟡 Medium | ❌ 未修复（依赖 INPUT-002 主修复） |
| F2 — `graph_nodes`/`graph_channels`/`list_payments` 的 `limit: u64` 无上界 → 资源耗尽 DoS | 🟡 Medium | ❌ 未修复 |
| F3 — `get_invoice`/`cancel_invoice` `.expect("no invoice status found")` 在状态分裂窗口可 panic | 🟢 Low | ❌ 未修复 |
| F4 — jsonrpsee server 默认配置，无 per-IP/per-method 限速，无 RpcConfig 字段暴露 | 🟢 Low | ❌ 未修复 |
| F5 — 私网/loopback 监听默认无鉴权 = 同主机多租户可读所有 RPC | 🟢 Low | ❌ 未修复 |
| F6 — `inject_rpc_context.expect("serialize injected params")` 反模式 | ℹ️ Info | ❌ 未修复 |
| F7 — Pubkey/Hash256/Multiaddr 解析全部走 try_from + ? | ✅ Pass | — |
| F8 — DevRpc `#[cfg(debug_assertions)]` release 剔除 | ✅ Pass | — |
| F9 — `is_public_addr` + `biscuit_public_key` 公网强制鉴权 | ✅ Pass | — |
| 整体 | 🟡 **Medium** | ❌ |

### 总体评价

RPC 层在**类型解析**层面整体严谨（Pubkey/Hash256 全部 `try_from`，公网监听强制鉴权，DevRpc 编译期剔除），但在**用户字符串透传到底层解析器**（F1）和**集合 size 边界**（F2）两个面上有重要缺口：

- F1 是 INPUT-002 的远程触发面 — RPC 是该 panic 链的"导火索"，单条合法 invoice 字符串即可远程零授权（cch.receive_btc 在跨链场景）让节点崩溃；
- F2 是低门槛资源耗尽 — 单条 RPC 即可让节点临时不可用，且无任何 rate-limit 阻挡重复触发；
- F3/F4/F5 是防御纵深问题 — 单独看影响有限，但与 STORE-001、MEM-001、AUTH-001 协同时构成可观的攻击面。

修复成本：F1 依赖 INPUT-002 主修复（已立项）；F2 / F3 各 < 10 行；F4 / F5 需要小幅 RpcConfig 扩展 + tower middleware 添加。

## 5. Follow-ups

- **AUDIT-INPUT-003-FOLLOWUP-A (🟡 Medium, 必修)**: F2 — `graph_nodes`/`graph_channels`/`list_payments` 加 `MAX_LIMIT` 显式上界，超限返回 `INVALID_PARAMS`；同时检查其它 list-type RPC（`list_channels`、`list_peers`）。
- **AUDIT-INPUT-003-FOLLOWUP-B (🟢 Low)**: F3 — `get_invoice`/`cancel_invoice` 中 `.expect("no invoice status found")` → `ok_or_else(|| rpc_error(...))`。统一审视所有 RPC handler 的 `.expect()`/`.unwrap()` 调用。
- **AUDIT-INPUT-003-FOLLOWUP-C (🟢 Low)**: F4 — `RpcConfig` 增加 `max_connections`/`max_request_body_size`/`per_ip_qps` 字段；引入 `tower-governor` 或 `tower::limit` 做 per-IP/per-method 限速；hyper `keep_alive_timeout` 设置。
- **AUDIT-INPUT-003-FOLLOWUP-D (🟢 Low)**: F5 — `is_public_addr` 不再作为唯一 gate；当启用敏感模块（`payment`/`channel`/`cch`/`watchtower`）时一律强制 biscuit，独立于监听地址私/公网。或新增 `force_auth: bool` 默认 true。
- **AUDIT-INPUT-003-FOLLOWUP-E (ℹ️ Info)**: F6 — `inject_rpc_context` 改 `Result` 传播，避免未来 `RpcContext` schema 调整引入隐式 panic。
- **AUDIT-INPUT-003-FOLLOWUP-F (🟢 Low)**: 在 `parse_invoice` 与 `payment.send_payment` 的 RPC 入口外包 `std::panic::catch_unwind` 作为 INPUT-002 主修复未完成前的临时防御（参考 INPUT-002-FOLLOWUP-F）。

**关联**：
- F1 是 **AUDIT-INPUT-002** 的远程入口；F1 修复依赖 INPUT-002 主修复完成；
- F2 与 **AUDIT-MEM-001**（gossip OOM）协同：两条 50MB 内存消耗叠加 → 加速 OOM；
- F3 与 **AUDIT-STORE-001.F3/F4**（deserialize panic + migration 非原子）同质：信任 `.expect()` 在边界层；
- F5 与 **AUDIT-AUTH-001/002**（biscuit fail-open + onion 明文 TCP）协同：本地访问绕过整套鉴权；
- F4 / F5 与 **AUDIT-ERR-002**（日志/tracing 敏感信息，下一会话）将一起决定生产部署的可观测性。
