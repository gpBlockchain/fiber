# AUDIT-AUTH-001 — Biscuit RPC 鉴权

- **维度**: DIM-AUTH（认证与鉴权）
- **严重级别**: 🟠 High (1 × High + 2 × Medium + 4 × Low + 2 × Info)
- **审计 Session**: S7 (2026-05-13)
- **关联代码**:
  - `crates/fiber-lib/src/rpc/biscuit.rs:1-262` (BiscuitAuth & 规则定义)
  - `crates/fiber-lib/src/rpc/middleware.rs:1-205` (jsonrpsee 中间件)
  - `crates/fiber-lib/src/rpc/mod.rs:124-246` (start_server / CORS), `248-264` (is_public_addr), `283-296` (auth 装配)
  - `crates/fiber-types/src/primitives.rs:85-99` (NodeId::local)
  - `crates/fiber-lib/src/rpc/watchtower.rs:147-275` (require_rpc_context 方法调用 store.\*)
  - `crates/fiber-bin/src/main.rs:235-293` (standalone watchtower)
  - `crates/fiber-lib/src/rpc/config.rs:1-50`

## 1. 审计目标

验证 RPC 控制面对外暴露时的鉴权完整性：

- biscuit-token 校验链（签名→撤销→规则）的不可绕过性；
- 公网监听强制要求 biscuit 公钥；
- `enable_auth=false` 本地模式的访问范围；
- `require_rpc_context` 多租户隔离（来自 token 的 node_id 决定写入哪个 key 空间）；
- CORS 设置对凭据滥用的影响；
- 资源耗尽 / 暴力枚举防御。

## 2. 数据流与不变式

```
HTTP Request
  ↓
[CORS layer (optional)]                              ← mod.rs:207-235
  ↓
[BiscuitAuthMiddleware::call]                        ← middleware.rs:145-158
  ↓
auth_call(req)                                        ← middleware.rs:61-114
  ├─ enable_auth=true:
  │    ├─ auth_token() — Authorization: Bearer <b64>
  │    ├─ check_permission(method, token):
  │    │     ├─ Biscuit::from_base64(token, pubkey)  (ed25519 verify)
  │    │     ├─ revocation_list.contains(...)
  │    │     └─ rule(method).authorize(token, now)   (datalog)
  │    └─ if rule.require_rpc_context:
  │           inject_rpc_context(ctx { node_id: extract_node_id(token) })
  └─ enable_auth=false (local bypass):
       ├─ if get_rule(method).is_ok():
       │     if rule.require_rpc_context:
       │         inject_rpc_context(ctx { node_id: NodeId::local() })    ← empty
       │     return true
       └─ else:
             return true   ⚠️ unknown method silently passes
```

### 不变式

| ID | 不变式 | 实现 | 状态 |
|---|---|---|---|
| INV-1 | 公网监听必须配 biscuit 公钥 | `mod.rs:285-287` | ✅ |
| INV-2 | biscuit 签名经 ed25519 验证（不可伪造） | `biscuit-auth::Biscuit::from_base64` | ✅ (来自上游库) |
| INV-3 | 撤销列表中的 token 必拒 | `biscuit.rs:230-236` | ✅ |
| INV-4 | 每个 method 必须显式声明规则（fail-secure） | **❌ middleware.rs:107-111 (local bypass)** | ⚠️ F3 |
| INV-5 | `require_rpc_context` 的 node_id 来自经签名验证的 token | `middleware.rs:75-83` | ✅ (auth=on)；**❌ auth=off 时为空** F1 |
| INV-6 | Notifications 与 calls 鉴权策略一致 | `middleware.rs:117-127` 无 `enable_auth=false` 分支 | ⚠️ F6 |
| INV-7 | token 内容不进入日志 / 错误回包 | `biscuit.rs:234-235` 泄露完整 token | ⚠️ F5 |

## 3. 发现

### 3.1 F1 (🟠 High) — Standalone watchtower 在 `enable_auth=false` 下所有客户端共享同一 NodeId 命名空间

**位置**：
- `middleware.rs:94-106` (local bypass branch 注入 `NodeId::local()`)
- `fiber-types/src/primitives.rs:96-98` (`NodeId::local() = Self(Default::default())`，即空 `Vec<u8>`)
- `watchtower.rs:152, 188, 199, 219, 235, 253, 272` (`ctx.node_id.parse::<NodeId>()` → `store.update_revocation(node_id, ...)`)
- `bin/main.rs:235-267` (standalone watchtower client setup)

**问题**：

```rust
// middleware.rs:96-104  (enable_auth=false path)
if rule.require_rpc_context {
    let node_id = NodeId::local();   // = NodeId(vec![])  ←  empty bytes
    let ctx = RpcContext { node_id: node_id.to_string() };  // = "" (bs58 of empty)
    self.inject_rpc_context(req, ctx);
}
```

Watchtower store API 使用 `(node_id, channel_id)` 作为复合 key（参见 `watchtower.rs:171: WatchtowerStoreUpdate { node_id, channel_id, ... }`）。当 standalone watchtower 以 `enable_auth=false` 启动（场景：私网内可信节点 + 多 Fiber-node tenant 连同一个 watchtower），所有连接的 Fiber 节点都被映射到 **同一个空 NodeId**：

1. Fiber 节点 A 调用 `update_revocation(channel_X, revocation_A)` → 写入 store key `(NodeId{}, channel_X)`；
2. Fiber 节点 B 拥有不同 `channel_X'`（不同通道）但因 channel_id 是 32 字节 hash，碰撞概率忽略；**但**若 B 调用 `remove_watch_channel(channel_X)`（猜测/扫描）→ 删除 A 的监视项；
3. 更危险：B 可调用 `update_revocation(channel_X, attacker_revocation)` → **覆盖** A 的 revocation tx，使 watchtower 在 A 的 channel 被 cheat 时无法反制。

**触发前置**：
- standalone watchtower 启动时未配 `biscuit_public_key`，且监听私网/容器 bridge 网络；
- 攻击者可达 watchtower 监听端口（同 LAN / 同 docker network / 同主机其他容器）；
- 攻击者知道（或扫描得到）受害 channel_id（gossip 中公开）。

**后果**：
- watchtower 反惩罚机制被中和；peer 可放心广播旧 commitment 实施 cheat；
- 资金损失等于通道余额。

**INV-1 (`mod.rs:285-287`) 不够强**：

```rust
if config.biscuit_public_key.is_none() && is_public_addr(listening_addr)? {
    bail!("Cannot listen on a public address without a biscuit public key set...");
}
```

只在**公网**地址强制要求 biscuit。私网/loopback 上的 standalone watchtower（多租户配置）完全跳过认证。

**严重级别**：🟠 High —— 实际可用攻击；资金损失；触发条件常见于自建 watchtower 群集。

**建议**：

```rust
// Option A: 即使在私网，若 watchtower 模块启用，强制要求 biscuit
if config.is_module_enabled("watchtower") && config.biscuit_public_key.is_none() {
    bail!("watchtower module requires biscuit_public_key");
}

// Option B: 在 require_rpc_context 路径下，enable_auth=false 时拒绝调用
if !self.enable_auth && rule.require_rpc_context {
    tracing::warn!("rejecting watchtower-context method '{}' in local-auth mode", req.method);
    return false;
}
```

### 3.2 F2 (🟡 Medium) — `auth_call` local bypass：未注册规则的方法默认放行

**位置**：`middleware.rs:107-111`

```rust
match self.auth.get_rule(&req.method) {
    Ok(rule) => { ... return true; }
    Err(err) => {
        tracing::debug!("Failed get_rule #{err:?}");
        // no auth rule, but allow local rpc to proceed.
        return true;          // ← fail-OPEN
    }
}
```

对照 `enable_auth=true` 分支 (line 72-90)：`check_permission` 失败（包括 `get_rule` 失败）一律 `return false`，fail-closed。两条路径的安全模型不一致。

**风险**：
- 任何未在 `build_rules()` 显式声明的 RPC method 在本地模式下永远放行。
- 开发者新增 RPC handler（例如未来 `dev::admin_xxx` 或第三方插件）忘记同步 `build_rules` 时，方法默认 public。grep 找到的当前未注册方法：
  - `submit_signed_funding_tx` ✓ 已注册
  - 但 `dev` 模块全部已注册
  - 检查 `pubsub::register_pub_sub_rpc` (mod.rs:387-395) 注册的 sub/unsub 方法 —— **未注册 in `build_rules`**

**确认未注册的方法**：

经 grep 比对 `build_rules()` (`biscuit.rs:75-162`) 与 `pubsub.rs:70-95`、各 `*RpcServer` trait：
- `unsubscribe_store_changes` (`pubsub.rs:72`) — **未在 `build_rules()` 中声明**
- 部分 `dev` 模块方法（开发构建启用）若新增需手动同步

`unsubscribe_store_changes` 本身无副作用，但展示了 fail-open 模式的隐患：未来任何新增的 RPC handler 默认在 local 模式无认证。

**严重级别**：🟡 Medium —— 当前直接影响有限（已注册的敏感方法覆盖完整），但属于**结构性 fail-open** 漏洞，长期维护中极易引入新的越权。

**建议**：将本地分支 `Err` 路径同样改为 `return false`，并在 `build_rules` 缺失时启动期 `panic!()` 或编译期 enum 强制（用 `enum RpcMethod` 替代 `&'static str`）。

```rust
Err(err) => {
    tracing::warn!("Method '{}' has no auth rule; rejecting (fail-secure)", req.method);
-   return true;
+   return false;
}
```

### 3.3 F3 (🟡 Medium) — CORS 默认 `Any` + Authorization 头可被跨域携带 → CSRF / 跨站 token 滥用

**位置**：`mod.rs:211-216`

```rust
let cors_layer = if cors_allowed_origins.is_empty() {
    // If no specific origins configured, allow all origins
    CorsLayer::new()
        .allow_origin(Any)        // ← *
        .allow_methods(Any)
        .allow_headers(Any)       // ← 包含 Authorization
};
```

**风险**：
- `Access-Control-Allow-Origin: *` + `allow_headers: Any` 允许任意网站的 JavaScript 通过浏览器向本节点发送带 `Authorization: Bearer <token>` 的 POST 请求；
- 浏览器规范禁止 `Allow-Origin: *` + `Allow-Credentials: true` 组合，故 cookie/HTTP basic auth 不会自动附带 —— 但 **Bearer token 是 JS 显式从 localStorage/sessionStorage 注入的**，规范不限制；
- 攻击场景：
  1. 用户在 Fiber web 控制台（合法源 A）登录后，token 存储于 localStorage；
  2. 用户访问恶意网站 B，B 通过 XSS 已知 origin A 的 localStorage（或诱骗用户复制 token），现在 B 的 JS 直接向 `http://localhost:<rpc_port>` 发起 `send_payment` 请求；
  3. 因 CORS=Any，浏览器允许跨域 POST + 自定义 header；token 经 ed25519 验证通过 → 转账成功。

CORS 通常被视作浏览器侧防御 —— 本配置等价于**完全禁用浏览器侧防御**。

**严重级别**：🟡 Medium —— 需配合 token 泄露才能利用，但 `cors_enabled=true` + 默认 `Any` 是常见 dev 配置易遗留到生产。

**建议**：

```rust
let cors_layer = if cors_allowed_origins.is_empty() {
-   CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any)
+   // Fail-secure: if CORS enabled but no allowed origins configured,
+   // refuse to start rather than open all origins.
+   bail!("cors_enabled=true requires explicit cors_allowed_origins list");
};
```

或至少改 `allow_headers` 不包含 `AUTHORIZATION`，并在文档中明确警告。

### 3.4 F4 (🟢 Low) — 撤销 token 错误信息泄露完整 token 到日志

**位置**：`biscuit.rs:234-235`

```rust
if b.revocation_identifiers().iter().any(|rev_id| self.revocation_list.contains(rev_id)) {
    tracing::debug!("revoked token: {token}");                           // ← 泄露
    return Err(anyhow::anyhow!("Token is in revocation list: {token}"));  // ← 泄露到 anyhow::Error
}
```

Token 即使被撤销，其内容仍包含权限列表 + node_id 等结构信息（base64 解码即可读）。日志被外泄场景下：
- 撤销原因常常是 token 泄露 → 攻击者已掌握内容，泄漏低风险；
- 但若是 **管理性撤销**（轮换、最小权限调整），原 token 仍未公开 → 日志泄漏将该 token 副本传播到日志聚合系统、第三方 SaaS、备份等。

**严重级别**：🟢 Low —— 隐私 / 日志卫生。

**建议**：

```rust
- tracing::debug!("revoked token: {token}");
- return Err(anyhow::anyhow!("Token is in revocation list: {token}"));
+ tracing::debug!("revoked token used (id prefix: {:?})", &token[..token.len().min(8)]);
+ return Err(anyhow::anyhow!("Token is in revocation list"));
```

### 3.5 F5 (🟢 Low) — `auth_notify` 缺少 `enable_auth=false` 本地放行分支

**位置**：`middleware.rs:117-127`

```rust
fn auth_notify(&self, notify: &Notification<'_>) -> bool {
    let token = match self.auth_token() {
        Ok(token) => token,
        Err(err) => { return false; }   // ← 无 enable_auth=false 分支
    };
    let res = self.auth.check_permission(notify.method_name(), &token);
    res.is_ok()
}
```

与 `auth_call` 不一致：`auth_call` 在 `enable_auth=false` 时绕过 token，`auth_notify` 总是要求 token。后果：
- 本地模式（`biscuit_public_key` 未配）下，JSON-RPC notification（无 id 的请求）一律失败。本地调试 / 内部工具可能受影响；
- 不会被攻击者利用（fail-closed 反而更安全），但属于 API 一致性 bug。

**严重级别**：🟢 Low —— 功能性瑕疵 / 一致性。

### 3.6 F6 (🟢 Low) — `Authorization: Bearer` 前缀大小写敏感

**位置**：`middleware.rs:19, 36-38`

```rust
const BEARER_PREFIX: &str = "Bearer ";
let token = auth_str.strip_prefix(BEARER_PREFIX)
    .ok_or_else(|| anyhow!("invalid authorization header"))?;
```

RFC 7235 §2.1 规定 auth-scheme 大小写不敏感。`curl -H "authorization: bearer xxx"` / `BEARER xxx` 会被拒。

**严重级别**：🟢 Low —— 互操作性问题，无安全后果。

**建议**：

```rust
- let token = auth_str.strip_prefix(BEARER_PREFIX)
+ let token = auth_str.strip_prefix(BEARER_PREFIX)
+     .or_else(|| auth_str.strip_prefix("bearer "))
+     .or_else(|| auth_str.strip_prefix("BEARER "))
```

### 3.7 F7 (🟢 Low) — `extract_node_id` 在每次 require_rpc_context 调用打 `tracing::warn!`

**位置**：`biscuit.rs:260`

```rust
pub fn extract_node_id(token: &Biscuit) -> Result<NodeId> {
    ...
    tracing::warn!("fetch {id:?} {node_id:?}");   // ← 每次 watchtower RPC 调用都打 warn
    Ok(node_id)
}
```

每次 watchtower 客户端调用（`update_revocation` 等高频）都打 `warn!` 级别日志，泄露 node_id（属于公开信息，但仍是隐私维度的 metadata），且生产日志噪音。

**严重级别**：🟢 Low —— 日志噪音 + 隐私 metadata 泄漏。

**建议**：降级为 `trace!`，或删除该日志。

### 3.8 F8 (🟢 Low) — 无 RPC 鉴权失败的速率限制 / 黑名单

**位置**：整个 middleware 层无 rate-limit。

- biscuit 签名验证本身依赖 ed25519，暴力不可行；
- 但**撤销 token 枚举**（已泄露的 token 列表的字典攻击）仍然 cheap：每次请求成本只是一次 ed25519 验证 + datalog 评估；
- 单 IP 高频失败请求也可作为 DoS 资源耗尽预热（结合 jsonrpsee 默认每连接资源）。

**严重级别**：🟢 Low —— 实际利用门槛较高（需先获取一批潜在 token），但 defense-in-depth 缺失。

**建议**：集成 tower-governor 或 `tower::limit::ConcurrencyLimit` + per-IP failed-auth counter（>=5 failed/min 退避）。

### 3.9 F9 (ℹ️ Info / Pass) — biscuit 签名 + 撤销 + 时间约束

- ed25519 签名验证由 biscuit-auth 库完成（依赖 ed25519-zebra v4）✓
- 撤销列表 HashSet 查询 O(1)，无并发竞态（启动期一次性配置）✓
- 时间约束（`check if time($t), $t <= 2026-..`）由 token 内容自带，rule 注入 `time` fact 后 datalog 评估 ✓
- 测试覆盖：签名验证、撤销、超时、跨密钥拒绝、真实生产 token 解析 ✓

**Pass**。

### 3.10 F10 (ℹ️ Info / Pass) — `is_public_addr` IPv6/IPv4 私网判定

`mod.rs:248-264`：

- IPv4：`is_private | is_loopback | is_link_local | is_documentation` 取反 → 公网；
- IPv6：`!(is_loopback || is_unique_local)` → 公网。

IPv6 link-local (`fe80::/10`) 不是 `unique_local`，被归类为公网 → 强制要求 biscuit → **安全（过严）**。

IPv4 未覆盖：`100.64.0.0/10` (CGN)、`198.18.0.0/15` (benchmark)、`240.0.0.0/4` (reserved) —— 但这些罕见，且都不是真正"公网可路由"，被分类为公网亦为过严 → **安全**。

**Pass**（如严格定义可记为 minor Improvement，本审计接受现状）。

## 4. 结论

| 子项 | 严重 | 状态 |
|---|---|---|
| F1 — standalone watchtower 无 biscuit 时所有客户端共享 NodeId | 🟠 High | ⚠️ 未修复 |
| F2 — `auth_call` local bypass fail-open 未注册方法 | 🟡 Medium | ⚠️ 未修复 |
| F3 — CORS `Any` + Authorization 头跨域可达 | 🟡 Medium | ⚠️ 未修复 |
| F4 — 撤销 token 日志泄露完整 token | 🟢 Low | ⚠️ 未修复 |
| F5 — `auth_notify` 缺 local bypass | 🟢 Low | ⚠️ 未修复 |
| F6 — Bearer 前缀大小写敏感 | 🟢 Low | ⚠️ 未修复 |
| F7 — `extract_node_id` warn 噪音 + metadata 泄漏 | 🟢 Low | ⚠️ 未修复 |
| F8 — 无 rate-limit / 失败黑名单 | 🟢 Low | ⚠️ 未修复 |
| F9 — biscuit 签名/撤销/超时 | ℹ️ Pass | — |
| F10 — `is_public_addr` 私网判定 | ℹ️ Pass | — |
| 整体 | 🟠 High (F1 主导) | — |

**最严重场景 (F1)**：多租户私网部署 standalone watchtower 时（如自建 watchtower 服务集群），任何拥有 RPC 端口访问权的 Fiber 节点（或同 LAN/docker bridge 上的攻击者）可：

1. 调用 `update_revocation(victim_channel_id, attacker_crafted_revocation)` 覆盖受害者已注册的 revocation tx，使 watchtower 在 cheat 发生时**广播无效 revocation 而非惩罚 cheat**；
2. 调用 `remove_watch_channel(victim_channel_id)` 解除监视；
3. 调用 `remove_preimage(payment_hash)` 删除受害者的 settlement preimage。

由于这些操作的 store key 是 `(NodeId::local(), channel_id)`，与受害者的 entry 完全共享。攻击者只需 channel_id（gossip 网络公开）即可。

## 5. Follow-ups

- **AUDIT-AUTH-001-FOLLOWUP-A**：F1 修复 —— 在 `mod.rs:285` 区域，若 `watchtower` 模块启用而 `biscuit_public_key.is_none()` 时强制 `bail!`，或将 `enable_auth=false && require_rpc_context` 改为 `return false`；编写 PoC：两台 Fiber 节点接到同一无密钥 standalone watchtower，互相覆盖对方的 revocation_data。
- **AUDIT-AUTH-001-FOLLOWUP-B**：F2 修复 —— 把 `auth_call` 的 unknown-method 分支改为 `return false`（fail-secure），并将 `build_rules` 用类型系统强制完备性。
- **AUDIT-AUTH-001-FOLLOWUP-C**：F3 修复 —— 默认 CORS allowed_origins 空时禁止 `Any`，或至少排除 `AUTHORIZATION` 头。
- **AUDIT-AUTH-001-FOLLOWUP-D**：F4/F5/F6/F7 一并修复（cosmetic + 一致性补丁）。
- **AUDIT-AUTH-001-FOLLOWUP-E**：F8 引入 tower-governor 速率限制。
