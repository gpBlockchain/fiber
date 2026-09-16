# AUDIT-XMOD-011 — Watchtower ↔ Tracing ↔ RPC 日志泄露 preimage

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟡 Medium（默认 ERROR-only 即可看到 preimage；同主机/日志聚合泄露） |
| 状态 | [!] 发现弱设计（确定可达，依赖部署日志栈） |
| 出处 | 本次跨模块审计新发现；记忆 "logging redaction" |
| 关联代码 | `crates/fiber-lib/src/watchtower/actor.rs:181`（`tracing::error!` 直接 ERROR 级别打印 `preimage:?` 全 hex）<br>`crates/fiber-lib/src/rpc/biscuit.rs:234`（`anyhow!("Token is in revocation list: {token}")` 把 token 进 Error Display）<br>`crates/fiber-lib/src/rpc/biscuit.rs:260`（leftover `warn!("fetch {id:?} {node_id:?}")`）<br>`crates/fiber-types/src/primitives.rs:215-217, 358-369`（`Hash256` Debug 完整 hex；**`Preimage` 无独立 newtype 与 `payment_hash` 共用 `Hash256`**）<br>`crates/fiber-bin/src/main.rs:84-89`（默认 `EnvFilter::from_default_env()` = ERROR-only） |
| 关联 finding | AUDIT-AUTH-001（token 泄露）、AUDIT-CRYPTO-003（secret 卫生）、AUDIT-ERR-002 |

## 1. 现象

四个独立小问题叠加形成"默认配置即泄 preimage"：

1. **watchtower 主动 ERROR 级别打印 preimage**：`watchtower/actor.rs:181 tracing::error!(..., preimage = ?preimage, ...)`。
2. **类型系统无防护**：`Preimage` 复用 `Hash256` 没独立 newtype，`Hash256` Debug 输出完整 hex (`primitives.rs:215-217, 358-369`)，未来任何 `{preimage:?}` / `format!("{:?}", preimage)` 都会泄露，无编译期警告。
3. **多入口 leftover 日志**：
   - `biscuit.rs:234 anyhow!("Token is in revocation list: {token}")` token 进 Error Display；
   - `biscuit.rs:260 warn!("fetch {id:?} {node_id:?}")` leftover 调试日志，每次 watchtower 鉴权调用都打。
4. **默认 `EnvFilter::from_default_env()` = ERROR-only**：表面看保守，**但 watchtower 主动用 ERROR 级别打 preimage** → 默认配置即可见。

## 2. 跨模块攻击链 / 泄露路径

```
[远程 RPC] create_preimage(...) ──┐
                                  ▼
[fiber actor] preimage 经 watchtower 落地
                                  ▼
[watchtower] tracing::error!(preimage=?...)   ← ERROR 级别（默认显示）
                                  ▼
[同主机日志]  systemd journal / docker stdout / k8s container log
                                  ▼
[次级攻击者] 同主机非特权用户读 journalctl / docker log / k8s log
```

- "远程可诱导"：`create_preimage` 类 RPC 由 RPC 端点接收 → 攻击者通过 RPC 制造 preimage → 触发 watchtower 路径 → log。
- "同主机泄露"：日志聚合（journald / docker / k8s）默认 world-readable 或同组可读，次级用户 / sidecar / log shipper 可见。
- "跨链泄露"：fiber preimage 在 CCH 跨链场景下与 LN 共用秘密 → 泄露 preimage = 跨链上游 LN HTLC 可被任意人取走 → 跨链 BTC 损失。

## 3. 与已有发现的区别

- 单 finding 视角是"日志卫生"（一般 Medium-Low）；
- 本条强调四点叠加：
  1. 敏感字段类型系统无防护（`Preimage` 无 newtype）；
  2. 远程 RPC 可诱导触发；
  3. watchtower **主动 ERROR 级别**打印（不是 trace/debug）；
  4. 默认 log filter 不过滤 ERROR；
- **跨链场景**下 preimage 直接 = 资金。

## 4. 影响评估

- 同主机 / 日志聚合环境下可见；
- 与 XMOD-013 钱包凭据生命周期共享"敏感数据散落"问题；
- 转化为资金损失需要 CCH 跨链场景（fiber↔BTC HTLC 共用 preimage）。

## 5. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | P1 | 引入 `Preimage(Hash256)` newtype，`Debug` 实现统一返回 `"<redacted preimage>"`；`Display` 同。`From<Hash256>` 仅供反序列化路径使用。 |
| F2 | P1 | 全仓 `grep '\{preimage'` / `grep 'preimage =' / 'preimage:'` 复审；所有打印改为 `payment_hash` 或 `<redacted>`；watchtower/actor.rs:181 立即改为 `error!(payment_hash=?ph, "preimage_observed")`。 |
| F3 | P1 | `biscuit.rs:234` 改 `anyhow!("Token is in revocation list")` 不带 token；外加 trace 级别 fingerprint(token) 仅 debug 用。 |
| F4 | P2 | `biscuit.rs:260` 删除 leftover `warn!`。 |
| F5 | P2 | `main.rs` 默认 `EnvFilter` 显式排除 `fiber_lib::watchtower::actor=warn`（短期止血，长期靠 F1 类型系统）。 |
| F6 | P2 | 添加 clippy `disallowed_methods` 配置：禁止 `{preimage:?}` 风格 format。 |

## 6. 验证测试

- `primitives::tests::test_preimage_debug_redacted`：`format!("{:?}", preimage)` 必须为 `<redacted preimage>`。
- `watchtower::tests::test_preimage_event_log_redacted`：触发 preimage 事件 → 捕获 tracing → 断言输出不含 hex。
- `rpc::biscuit::tests::test_revoked_token_error_redacted`：返回的 error display 不含 token 字面值。
- clippy CI：禁用模式触发 build 失败。

## 7. 状态

- F1+F2+F3 优先合入即可关键面闭环；F4-F6 后置加固。
- 关联 PR：暂无。
