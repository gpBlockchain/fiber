# AUDIT-XMOD-005 — RPC ↔ Auth ↔ Biscuit ↔ Network 鉴权穿透链

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟠 **High**（多租户 / 浏览器 / DNS rebinding 鉴权穿透） |
| 状态 | [!] 发现弱设计（静态可达，无 PoC） |
| 出处 | 本次跨模块审计补强；基于 AUTH-001/003 + INPUT-003 + "rpc cors" / "rpc input validation" 记忆 |
| 关联代码 | `crates/fiber-lib/src/rpc/middleware.rs:30-40, 92-114`（`is_public_addr` 唯一 gate；CORS layer 在 biscuit 外）<br>`crates/fiber-lib/src/rpc/mod.rs:76, 128-129, 207-235, 248-264, 285-287`（CORS 配置与启用顺序）<br>`crates/fiber-lib/src/rpc/config.rs:1-38`（`RpcConfig`：默认 `enable_auth=false` 私网；`cors_enabled=false`）<br>`crates/fiber-lib/src/rpc/biscuit.rs:234, 260`（token Display 泄露 + leftover `warn!`）<br>`crates/fiber-lib/Cargo.toml:63, 87-88`（jsonrpsee 0.25.1 / tower-http 0.6） |
| 关联 finding | AUDIT-AUTH-001（本地 NodeId）、AUDIT-AUTH-003.F1/F4（CORS / Host header）、AUDIT-INPUT-003.F5（私网默认无鉴权） |

## 1. 现象

fiber RPC 默认对**公网监听**强制鉴权，对**私网/loopback**默认放行。其鉴权防线由 4 个独立检查组合而成，每个检查都有 fall-through 路径，**任意一项**触发即整条链可被穿透：

| 防线 | 实现 | 失效条件 |
|---|---|---|
| L1 是否 public_addr | `middleware.rs:92-114 is_public_addr` | 私网 / loopback / Docker bridge 网络 → 跳过鉴权 |
| L2 biscuit token | `biscuit.rs` | `enable_auth=false` 默认；`biscuit_public_key.is_none()` 时 standalone watchtower 直接放行 |
| L3 CORS | `mod.rs:207-235` | `cors_enabled=true && cors_allowed_origins=[]` → `CorsLayer::new().allow_origin(Any)` 全通配 |
| L4 Host header | （不存在） | 无 allowlist → DNS rebinding |

## 2. 4 条独立的穿透链

### 2.1 同主机多租户（L1 失效）
- INPUT-003.F5：私网监听默认 `enable_auth=false` → 同主机/同 Docker 网络命名空间任意用户可调全套 channel/payment/cch RPC。
- 与 STORE-001（DB 0o644）协同：拿到 RPC 控制 + 读 commitment_seed 即可主动驱动 cheat。

### 2.2 浏览器跨域（L3 失效）
- AUTH-003.F1：若用户启用 `cors_enabled=true` 但忘记填 `cors_allowed_origins`，`filter_map(parse().ok())` 把空列表"静默接受"，`mod.rs:248-264` fall-through 到 `CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any)`。
- 攻击者诱导用户访问 evil.com → JS `fetch(node:8114, method=POST, ...)`：浏览器允许（CORS 全通配）→ 节点处理 RPC。
- 节点无 cookie/credential 凭证（`fetch` 默认不带 credentials），但若启用了私网默认无鉴权（链 2.1），单 CORS 失效即可。

### 2.3 DNS rebinding（L4 失效）
- AUTH-003.F4：无 Host header allowlist。攻击者控制 evil.com DNS → 浏览器先解析到 IP_evil → 短 TTL 后切到 127.0.0.1 → 浏览器仍把请求发往 evil.com 名义、但实际打到 victim 的 loopback fiber RPC（同源策略以名义判定）→ JS 任意调 RPC。

### 2.4 Standalone watchtower（L2 失效）
- AUTH-001.F1：standalone watchtower 部署模式下，`biscuit_public_key.is_none()` 时 `NodeId::local()` 返回空 vec → 任意客户端共享同一 keyspace → 互踩 / 互改其它租户的 monitoring 数据。

## 3. 跨模块攻击组合

四条链可组合："私网默认无鉴权" + "CORS 失效" + "DNS rebinding" → 即便用户开了 `enable_auth=true`，浏览器侧仍能通过名义同源绕过 biscuit token 要求。

## 4. 与已有发现的区别

- 单独 AUTH-001 / AUTH-003 / INPUT-003 各看一层；本条强调 4 层防线的组合：**任一层失效 → 全 RPC 控制权**。
- 浏览器 wallet（fiber-wasm）场景下，L3 + L4 是默认威胁模型，必须按"假设浏览器恶意"设计。

## 5. 影响评估

- 全 RPC 表面（channel / payment / cch / dev）可远程驱动；
- 私钥本身不直接泄露，但通过 channel/payment RPC 可主动驱动资金移动；
- 与 XMOD-002 / XMOD-006 协同：可远程驱动 CCH 单边损失 / 触发 cheat 链。

## 6. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | P1 | 敏感模块（payment / channel / cch / watchtower / dev）**强制** biscuit token；不再依赖 `is_public_addr`。info / graph / peer 可保留宽松。复用 AUTH-001.F1。 |
| F2 | P1 | `cors_enabled=true && cors_allowed_origins=[]` 启动 fail-fast；任一 origin parse 失败 fail-fast；不再 silent drop。复用 AUTH-003.F1。 |
| F3 | P1 | 强制 Host header allowlist：默认 `127.0.0.1:<port>`、`localhost:<port>`、`[::1]:<port>` 字面值；其余请求 403。复用 AUTH-003.F4。 |
| F4 | P1 | standalone watchtower 启动若 `biscuit_public_key.is_none()` 直接 `bail!`；不再 fall-through 到空 NodeId。复用 AUTH-001.F1。 |
| F5 | P2 | biscuit.rs:234 改 `anyhow!("Token revoked")` 不带 token；biscuit.rs:260 删除 leftover `warn!`。 |

## 7. 验证测试

- `rpc::tests::test_private_addr_requires_biscuit_for_payment`：私网调 `send_payment` 无 token → 401。
- `rpc::tests::test_cors_empty_allowlist_fail_fast`：启用 cors + 空列表，server start 直接 Err。
- `rpc::tests::test_host_header_allowlist`：Host=evil.com → 403。
- `watchtower::tests::test_standalone_requires_biscuit_pk`：缺 key 启动 bail。

## 8. 状态

- F1+F2+F3+F4 必须同时合入；F5 可独立合入。
- 关联 PR：暂无。
