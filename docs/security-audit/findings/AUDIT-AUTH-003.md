# AUDIT-AUTH-003 — RPC CORS / Tower-http 配置

- **维度**: DIM-AUTH (cross-origin policy / browser-side defence-in-depth)
- **严重级别**: 🟡 **Medium**（Medium × 1 + Low × 2 + Info × 2 + Pass × 3）
- **审计 Session**: S17 (2026-05-14)
- **关联代码**:
  - `crates/fiber-lib/src/rpc/config.rs:23-31` — `cors_enabled: bool` (default false), `cors_allowed_origins: Vec<String>` (default empty)
  - `crates/fiber-lib/src/rpc/mod.rs:76,128-129,206-235` — `CorsLayer::new()` 构造 (空 origins → `Any/Any/Any`)
  - `crates/fiber-lib/src/rpc/mod.rs:248-264,285-287` — `is_public_addr` + biscuit gate (与 INPUT-003.F5 联动)
  - `crates/fiber-lib/src/rpc/middleware.rs:30-40` — `auth_token` 仅读 `Authorization: Bearer ...` header（不读 Cookie）
  - `crates/fiber-lib/Cargo.toml:63,87-88` — `hyper 1.5`, `tower 0.5`, `tower-http 0.6 features=["cors"]`, `jsonrpsee 0.25.1`
  - 用户已记录的同质 fact:
    - INPUT-003.F5（同主机多租户 + 私网/loopback 默认 enable_auth=false）
    - AUTH-001.F3（CORS 与 biscuit 关系）

## 1. 审计目标

JSON-RPC 节点的浏览器侧攻击面主要是：

1. **跨源 RPC 调用**（CSRF / 跨站请求伪造）— 恶意网页 JS 让用户浏览器主动调用 fiber RPC（`send_payment`/`cancel_invoice`/`shutdown_channel`）。
2. **DNS rebinding** — 攻击者把 `evil.com` 解析到 `127.0.0.1`，浏览器视为 same-origin 绕过 CORS。
3. **Origin/header spoofing 与 credential 泄露**— 错配 `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` 会让任意源带 cookie 跨域请求。
4. **Preflight / Host header 缺失** — 没有 Host header allowlist 时即使 CORS 关闭，DNS rebinding 仍可绕过。

具体审计项：

- a. CORS 默认值与显式配置；
- b. `CorsLayer` 的 origin/method/header/credential 设置是否过宽；
- c. tower-http 版本是否有已知 CVE（已在 AUDIT-DEP-001 覆盖：tower-http 0.6 不在 CVE 列表）；
- d. 是否存在 Host header / vhost allowlist；
- e. biscuit 鉴权 token 来源（仅 header / 是否 cookie 可携带）；
- f. CORS layer 与鉴权 layer 的相对位置（preflight 是否绕过鉴权）。

## 2. 系统性梳理

### 2.1 CORS 配置默认值

```rust
// rpc/config.rs:23-31
#[default(false)]
pub cors_enabled: bool,

#[default(Vec::new())]
pub cors_allowed_origins: Vec<String>,
```

- `cors_enabled: false` 默认 — ✓ 安全默认；
- 启用后 `cors_allowed_origins: Vec::new()` 空数组的语义不是"拒绝全部"，而是 **fall-through 到 `Any` origin**（line 211-216）。

### 2.2 CorsLayer 构造

```rust
// rpc/mod.rs:207-228
let svc = if cors_enabled {
    let cors_layer = if cors_allowed_origins.is_empty() {
        // ⚠ 空数组 → 通配所有源
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        use tower_http::cors::AllowOrigin;
        let origins: Vec<_> = cors_allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())   // ⚠ 解析失败静默丢弃
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods(Any)
            .allow_headers(Any)
    };
    tower::ServiceBuilder::new()
        .layer(cors_layer)
        .service(svc)
        .boxed_clone()
}
```

观察：

1. **空 origins 等价于 `Any`** — 与运营者直觉相反；运营者可能预期"empty 列表 = 禁用所有 origin"。
2. **`allow_methods(Any)`** — 即使限定 origin，方法仍开放所有 HTTP verbs（PUT/DELETE/PATCH 在 JSON-RPC 中无意义但接受）。
3. **`allow_headers(Any)`** — 包含 `Authorization`，意味着跨域 JS 可携带 Bearer token（需要 user 先泄露 token 给 evil.com，但 origin 限定可能足够防御）。
4. **未设置 `allow_credentials(true)`** — tower-http 默认 false，浏览器不会跨域自动携带 Cookie/HTTP-Auth credentials ✓。
5. **`filter_map(parse().ok())`** — 解析失败的 origin 字符串（如带 trailing `/`、含 path、含 query）被静默丢弃，运营者无法发现 typo。

### 2.3 CORS layer 与鉴权 layer 的关系

```rust
// rpc/mod.rs:200-235
let mut svc = svc_builder
    .set_rpc_middleware(rpc_middleware)   // ← biscuit auth, jsonrpsee 内层
    .build(methods, stop_handle);
...
// CORS layer 在 jsonrpsee Server 外层 (tower 层)
let svc = tower::ServiceBuilder::new()
    .layer(cors_layer)
    .service(svc)
    .boxed_clone();
```

- **CORS 在外，biscuit 在内** — 符合 CORS 规范要求（preflight OPTIONS 不能要求鉴权）；
- OPTIONS 请求被 CorsLayer 直接响应，**不经 biscuit middleware**，因此端口探测可通过 OPTIONS preflight 完成（不带 Origin header 时 CorsLayer 行为依赖 tower-http 版本，通常是 pass-through）；
- 实际的 RPC 调用（POST application/json）经 CorsLayer 后到 biscuit middleware — auth 仍执行 ✓。

### 2.4 biscuit token 来源

```rust
// rpc/middleware.rs:30-40
fn auth_token(&self) -> Result<String> {
    let auth_str = self
        .headers
        .get(AUTHORIZATION)
        .ok_or_else(|| anyhow!("no authorization header"))?
        .to_str()?;
    let token = auth_str.strip_prefix(BEARER_PREFIX)?...
}
```

- **仅** `Authorization: Bearer <token>` header；
- **不**支持 Cookie / Query string / Custom header；
- → 浏览器**不会**为跨域请求**自动**附加 token；只有 JS 显式 `fetch(url, { headers: { Authorization: ... } })` 才能携带。这从根本上消除了"被诱导跨域提交"的 CSRF（用户没在 evil.com 输入 token 的话，evil.com 无法盗用）。

### 2.5 Host header / DNS rebinding 防御

grep 全局：

```
$ grep -rn "host_filter\|HostFilter\|allowed_hosts\|host_allowlist" crates/
(no matches)
```

- jsonrpsee 0.25 自身**没有** Host header 校验默认；
- fiber 未集成任何 host allowlist 中间件；
- DNS rebinding 攻击仍是开放路径：
  1. 攻击者控制 `evil.com`，TTL 设极短；
  2. 第一个 DNS 响应返回攻击者服务器，浏览器加载 JS；
  3. 第二个 DNS 响应返回 `127.0.0.1`（受害者 fiber 监听地址）；
  4. JS `fetch("/")` — 浏览器视作 same-origin（与 evil.com 同），不触发 CORS preflight；
  5. Host header 是 `evil.com`（攻击者 rebound 后的"域名"），但 fiber 不校验 Host header；
  6. → fiber 接受 RPC 请求。
- **关键**：这条路径在 `cors_enabled=false` 默认下仍然成立，因为 same-origin (DNS rebound) 跳过 CORS。
- **唯一缓解**：biscuit 鉴权 — 若运营者在 loopback 上也启用 `biscuit_public_key` 强制鉴权，DNS rebinding 拿不到 token，无法调用。但默认 loopback `enable_auth=false`（INPUT-003.F5）。

### 2.6 CORS 真正威胁向量梳理

| 场景 | cors_enabled | listening_addr | enable_auth (biscuit) | 可被恶意网站攻击 |
|---|---|---|---|---|
| 默认 prod（公网） | false | 0.0.0.0 | **forced true** (line 285) | ❌ 无 — biscuit 拦截 |
| 默认 dev（loopback） | false | 127.0.0.1 | false | ⚠️ DNS rebinding 仅 — F4 |
| 启用 CORS，空 origins | true | 任意 | 同上 | ⚠️ **F1** — Any origin |
| 启用 CORS + 严格 origins | true | 任意 | 同上 | 中（origin 校验 + Allow-Methods Any + Allow-Headers Any 防御过宽）— F2 |
| 启用 CORS，typo origin | true | 任意 | 同上 | 静默拒绝（运营者难诊断） — F3 |

### 2.7 与 wallet drainer 攻击模板对照

主网常见 RPC drainer pattern（Ethereum/Bitcoin Core/CKB-node）：

1. 用户运行节点在 `127.0.0.1:port`，无鉴权或带 RPC cookie；
2. 用户浏览器访问恶意页面；
3. 恶意 JS 直接 `fetch("http://127.0.0.1:port/", { method: "POST", body: ... })`；
4. **正常情况**：浏览器对 `application/json` POST 发起 preflight OPTIONS；
5. **CORS disabled** 节点：OPTIONS 无响应 / 不带 ACAO header → 浏览器拒绝；
6. **CORS enabled with `*`** 节点：OPTIONS 返回 `Access-Control-Allow-Origin: *` → 浏览器放行 → JS 执行后续 POST → 节点处理 RPC。

fiber 在 cors_enabled=true 且未配 origin 时正属于第 6 类。Bitcoin Core 0.15+ 引入 `-rpcallowip`/`-rpcbind` + cookie；Ethereum geth 默认 host allowlist；fiber 缺这些防御。

## 3. 发现

### 3.1 F1 (🟡 Medium) — CORS `cors_allowed_origins` 空数组 fall-through 到 `Any` origin + `Any` methods + `Any` headers，组合 INPUT-003.F5 loopback no-auth 形成 wallet drainer 路径

**位置**：`crates/fiber-lib/src/rpc/mod.rs:211-216` + `crates/fiber-lib/src/rpc/config.rs:29-31`

#### 问题

```rust
let cors_layer = if cors_allowed_origins.is_empty() {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
}
```

运营者配置 `cors_enabled=true` 且没填 `cors_allowed_origins`（典型 dev/CI 场景或运营者误以为"空 = 拒绝全部"），CorsLayer 通配所有源 / 方法 / header。配合：

- **INPUT-003.F5**：私网/loopback 监听时 `enable_auth=false`（默认）；
- 用户在同一台机器上运行 fiber + 浏览器；
- 用户访问 `evil.com`；
- 恶意 JS `fetch("http://127.0.0.1:<rpc_port>/", { method: "POST", body: JSON.stringify({ jsonrpc:"2.0", id:1, method:"send_payment", params:[...] }) })`；
- CorsLayer 响应 preflight OPTIONS 通配 → 浏览器放行；
- biscuit middleware `enable_auth=false` → `auth_call` 返回 true 不要求 token；
- → `send_payment`/`shutdown_channel`/`cancel_invoice` 任意调用。

这是 Bitcoin/Ethereum 节点早年（pre-2014）经历过的 classic RPC drainer pattern。

#### 攻击面对照

| 前置条件 | 是否需要 |
|---|---|
| 受害者运行 fiber 节点 | ✓ |
| 受害者浏览 attacker-controlled 页面 | ✓ |
| 受害者机器知道 fiber RPC 端口 | 否 — JS 可枚举常见端口 / 默认值固定 |
| 受害者节点开启 CORS | ✓（运营者配置） |
| 受害者节点 listening loopback | ✓ 或私网（INPUT-003.F5） |
| Bearer token | **否** — `enable_auth=false` |

#### 复现 PoC（概念）

```html
<!-- attacker.com -->
<script>
fetch("http://127.0.0.1:8227/", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "send_payment",
    params: [{ /* invoice + amount */ }]
  })
}).then(r => r.json()).then(console.log);
</script>
```

预期：fiber `cors_enabled=true && cors_allowed_origins=[]` 且 loopback 监听 → 调用成功。

#### 修复

```rust
let cors_layer = if cors_allowed_origins.is_empty() {
    // ❌ 改为返回错误 / panic 在 startup：CORS 启用但未指定 origin 是配置错误
    bail!("rpc.cors_enabled=true requires rpc.cors_allowed_origins to be non-empty");
} else {
    use tower_http::cors::AllowOrigin;
    let origins: Vec<HeaderValue> = cors_allowed_origins
        .iter()
        .map(|o| o.parse().map_err(|e| anyhow!("invalid origin '{o}': {e}")))
        .collect::<Result<_>>()?;
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION])
};
```

或显式新增一个 `cors_allow_any_origin: bool` 字段（默认 false），仅在 `cors_allow_any_origin=true` 时才走 `Any` 分支，避免"空数组 = Any"的反直觉语义。

**评级**：🟡 **Medium** — 默认 `cors_enabled=false` 让 P=低；但 vector 是 user-controlled config 错配 + same-machine + 用户浏览任意网页，符合"配错即失保"标准，且与 INPUT-003.F5 强联动。

### 3.2 F2 (🟢 Low) — `allow_methods(Any)` + `allow_headers(Any)` 即便 origin 受限仍过宽

**位置**：`crates/fiber-lib/src/rpc/mod.rs:215-216, 226-227`

#### 问题

即使运营者正确配置 `cors_allowed_origins=["https://app.example.com"]`，两处 `Any` 仍允许：

- 任意 HTTP method（PUT/DELETE/PATCH/CONNECT/TRACE） — JSON-RPC 仅需 POST + OPTIONS，多出的 verb 是不必要攻击面；
- 任意 request header — 攻击者可注入 `Authorization`、`Cookie`、`X-Forwarded-*` 等头。`allow_headers(Any)` 在 tower-http 中**不包含**带 hyphen 的特殊 header 与 `Authorization`（前者是兼容性 bug，后者按 CORS 规范需要显式列出），但仍是宽松配置。

#### 修复

```rust
.allow_methods([Method::POST, Method::OPTIONS])
.allow_headers([CONTENT_TYPE, AUTHORIZATION])
```

**评级**：🟢 **Low** — origin 已限定时实际可利用面有限；属深度防御。

### 3.3 F3 (🟢 Low) — `cors_allowed_origins` parsing 失败静默丢弃，运营者难诊断

**位置**：`crates/fiber-lib/src/rpc/mod.rs:220-223`

#### 问题

```rust
let origins: Vec<_> = cors_allowed_origins
    .iter()
    .filter_map(|o| o.parse().ok())
    .collect();
```

`HeaderValue::from_str` (或 `Origin` parser) 拒绝：

- 带 trailing slash 的 `https://example.com/`
- 带 path 的 `https://example.com/app`
- 含空格 `https://example.com ,https://other.com`（CSV split 后单元素含空格）
- 空字符串

全部静默丢弃。最坏情况：运营者填了 3 个 origin，2 个 typo，结果只允许 1 个 origin，其余请求被 CORS 拒绝 → 运营者看到"为什么 example.com 不能访问"反复试错。或全部 typo → `AllowOrigin::list(vec![])` 拒绝一切请求，运营者以为"CORS 没工作"。

#### 修复

```rust
let origins: Vec<HeaderValue> = cors_allowed_origins
    .iter()
    .map(|o| {
        o.parse::<HeaderValue>()
            .map_err(|e| anyhow!("invalid CORS origin '{o}': {e}"))
    })
    .collect::<Result<_>>()?;
```

在 startup 报错而非运行时静默丢弃。

**评级**：🟢 **Low** — UX/可运维性，但配置失误可能让运营者在生产开放更宽 fallback 配置。

### 3.4 F4 (ℹ️ Info) — 无 Host header allowlist / DNS rebinding 防御

**位置**：全局（无该机制）

#### 问题

jsonrpsee 0.25 / fiber 均未集成 Host header allowlist：

- Ethereum geth: `--http.vhosts localhost`（默认）
- Bitcoin Core: 无（依赖 cookie 认证）
- ckb-node: `RpcConfig.rpc_hosts` (虽然 fiber 不在 ckb-node 中)

DNS rebinding 攻击路径（即便 cors_enabled=false 也成立）：

1. 攻击者控制 evil.com，TTL=0；
2. evil.com IP 初次解析 → attacker server，返回 JS；
3. JS 主动 `fetch("/rpc")`，浏览器对**当前域名** evil.com 重新 DNS 解析；
4. 此时 DNS 返回 127.0.0.1（fiber loopback）；
5. 浏览器对 evil.com → 127.0.0.1 发起 same-origin 请求（**不触发** CORS preflight，因为浏览器视 evil.com 为 origin，cors_enabled=false 也允许 same-origin）；
6. Host header 是 evil.com（rebound 后的 hostname），fiber 不校验 → 接受请求。
7. 配合 INPUT-003.F5 loopback no-auth → 攻击成立。

CORS 不能防御 DNS rebinding（CORS 是 same-origin 例外机制；DNS rebinding 把跨域伪装为 same-origin）。Host header allowlist 是标准防御。

#### 修复（建议）

加 `rpc.allowed_hosts: Vec<String>`（默认 `["localhost", "127.0.0.1", "[::1]"]`），用 tower middleware 校验 Host header；不匹配返回 403：

```rust
ServiceBuilder::new()
    .layer(ValidateRequestHeaderLayer::custom(host_validator))
    .layer(cors_layer)
    .service(svc)
```

**评级**：ℹ️ Info — 与 INPUT-003.F5 联动，单独评级偏低；但属"生产部署缺少标准防御层"。

### 3.5 F5 (ℹ️ Info) — biscuit token 仅 Authorization Bearer header，不接受 Cookie / Query — 这是好的设计，应文档化

**位置**：`crates/fiber-lib/src/rpc/middleware.rs:30-40`

#### 现象

`auth_token` 只读 `Authorization` header。这意味着：

- 浏览器**不会**为跨域请求**自动**附加 token（cookie 才会被浏览器跨域自动附加，符合 SameSite 策略）；
- 攻击者跨域 JS 必须**显式**在 fetch 中设置 Authorization header，需要先在攻击者 origin 拿到 token；
- 这从根本上消除了"凭证被被动盗用"的 CSRF 向量；
- 即使 `Access-Control-Allow-Credentials: true` 也无效，因为我们不依赖 cookie。

应在 README / config 文档中明示这一设计选择，避免后续开发者引入 cookie 备份方案破坏该不变量。

**评级**：ℹ️ Info — 好的设计，需要文档化保护。

### 3.6 F6 (✅ Pass) — `cors_enabled: false` 默认

`rpc/config.rs:24 #[default(false)]` — 生产默认关 CORS。✓

### 3.7 F7 (✅ Pass) — `allow_credentials` 未显式设为 true，tower-http 0.6 默认 false

`CorsLayer::new()` 不调用 `.allow_credentials(true)` → 浏览器不会跨域自动携带 Cookie/HTTP-Auth credentials。结合 F5 的 Bearer-only 设计，凭证被动盗用面 = 0。✓

### 3.8 F8 (✅ Pass) — CORS layer 与 biscuit middleware 顺序正确

```
hyper request → CorsLayer (tower outer) → jsonrpsee.Server → BiscuitAuthMiddleware (jsonrpsee inner) → handler
```

- OPTIONS preflight 在 CorsLayer 直接返回，不经 biscuit（符合 CORS 规范）；
- 实际 POST RPC 经 biscuit 鉴权 ✓；
- 没有把 CorsLayer 放在 biscuit 内层导致 preflight 鉴权失败的反模式。

### 3.9 F9 (✅ Pass) — tower-http 0.6 无已知 CVE

参考 AUDIT-DEP-001：tower-http 0.6 在 GitHub Advisory DB 中无开放 CVE（截至 2026-05）。jsonrpsee 0.25.1 同样无开放 CVE。

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — 空 `cors_allowed_origins` fall-through 到 `Any` origin/methods/headers + INPUT-003.F5 loopback no-auth → drainer pattern | 🟡 Medium | ❌ 未修复 |
| F2 — `allow_methods(Any).allow_headers(Any)` 即便 origin 限定仍过宽 | 🟢 Low | ❌ 未修复 |
| F3 — `cors_allowed_origins` parsing 失败静默丢弃 | 🟢 Low | ❌ 未修复 |
| F4 — 无 Host header allowlist / DNS rebinding 防御 | ℹ️ Info | — |
| F5 — Bearer-only token（不读 Cookie）— 好的设计，需文档化 | ℹ️ Info | ✓ Design pass |
| F6 — `cors_enabled: false` 默认 | ✅ Pass | — |
| F7 — `allow_credentials` 未启用 + tower-http 默认 false | ✅ Pass | — |
| F8 — CORS layer 在 biscuit 外层，preflight 正确放行，实际 RPC 经鉴权 | ✅ Pass | — |
| F9 — tower-http 0.6 / jsonrpsee 0.25.1 无已知 CVE | ✅ Pass | — |
| 整体 | 🟡 **Medium** | ❌ |

### 总体评价

fiber 的 CORS / browser-side 攻击面整体保护良好：

- **默认安全**（cors_enabled=false）；
- **设计安全**（Bearer-only auth，不读 Cookie，浏览器无被动凭证传递）；
- **层级正确**（CorsLayer 在外，biscuit 在内）；
- **依赖安全**（tower-http 0.6 / jsonrpsee 0.25.1 无 CVE）。

**主要缺口**集中在两处：

1. **F1 (Medium)**：`cors_enabled=true && cors_allowed_origins=[]` 的"反直觉默认"组合 INPUT-003.F5 形成 wallet drainer 路径。这是 user-controlled config 错配场景，但 fiber 应在 startup 时拒绝该错配（fail-closed）。
2. **F4 (Info)**：缺少 Host header allowlist 让 DNS rebinding 绕过 CORS。这与 INPUT-003.F5（loopback default no-auth）联动是真正的同主机/远程攻击路径。

F2/F3 是工程化/可运维性改进，F5 是好设计但应文档化。

整体相比 AUTH-001/AUTH-002（实际中等漏洞）属于"配置可加固但默认OK"的中等级别。

## 5. Follow-ups

- **AUDIT-AUTH-003-FOLLOWUP-A (🟡 Medium, 必修)**: F1 — startup 时若 `cors_enabled=true && cors_allowed_origins.is_empty()` 直接 `bail!`；或新增显式 `cors_allow_any_origin: bool` flag。同时 `allow_methods` / `allow_headers` 改为白名单（POST/OPTIONS + Content-Type/Authorization）。
- **AUDIT-AUTH-003-FOLLOWUP-B (🟢 Low)**: F2 — `allow_methods(Any).allow_headers(Any)` 改为白名单 `[POST, OPTIONS]` / `[CONTENT_TYPE, AUTHORIZATION]`（与 A 合并）。
- **AUDIT-AUTH-003-FOLLOWUP-C (🟢 Low)**: F3 — `filter_map(parse().ok())` 改为 `Result` 传播；startup 时显式报告失败的 origin 字符串。
- **AUDIT-AUTH-003-FOLLOWUP-D (ℹ️ Info, 推荐)**: F4 — 新增 `rpc.allowed_hosts: Vec<String>`（默认 `["localhost", "127.0.0.1", "::1"]`），加 tower `ValidateRequestHeaderLayer` 校验 Host header；DNS rebinding 主防御。
- **AUDIT-AUTH-003-FOLLOWUP-E (ℹ️ Info)**: F5 — 在 `docs/rpc-auth.md` / `crates/fiber-lib/src/rpc/README.md` 明示"Bearer-only, no Cookie support"作为 SECURITY NOTE，防止后续开发者引入 Cookie 备份方案破坏该不变量。

**关联**：
- F1 是 **AUDIT-INPUT-003.F5** 的浏览器侧扩展：INPUT-003.F5 是"loopback 默认 no-auth"，F1 是"同时开 CORS=Any 让浏览器 JS 也能利用"。两者修复需协同（INPUT-003-FOLLOWUP-E force_auth + AUTH-003-FOLLOWUP-A fail-closed CORS）。
- F4 是 INPUT-003.F5 在 DNS rebinding 维度的对应漏洞 — 与 INPUT-003-FOLLOWUP-E force_auth 互为深度防御。
- F2/F3 与 AUTH-001-FOLLOWUP-D（token 不入 Error Display）共同形成"CORS 配置审计"主题。
