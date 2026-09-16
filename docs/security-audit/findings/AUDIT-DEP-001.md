# AUDIT-DEP-001 — GitHub Advisory DB 比对

| 字段 | 值 |
|---|---|
| 维度 | DIM-DEPS |
| 优先级 | 🟠 P1-High |
| 状态 | **[i] 信息性 — 本轮 surveyed 依赖均无已知 CVE** |
| 审计会话 | S1 (2026-05-13) |

## 1. 检查对象

从 `Cargo.toml` / `Cargo.lock` 中挑选与资金安全 / 网络面 / 密码学高度相关的 12 个依赖：

| 包 | 版本 | 生态 |
|---|---|---|
| `secp256k1` | 0.30.0 | rust |
| `musig2` | 0.2.4 | rust |
| `aes-gcm` | 0.10.x | rust |
| `scrypt` | 0.11.0 | rust |
| `bitcoin` | 0.32.0 | rust |
| `fiber-sphinx` | 2.3.0 | rust |
| `lightning-invoice` | 0.33.0 | rust |
| `jsonrpsee` | 0.25.1 | rust |
| `biscuit-auth` | 6.0.0-beta.3 | rust |
| `tentacle` | 0.7.0 | rust |
| `molecule` | 0.9.2 | rust |
| `bech32` | 0.9.1 | rust |

## 2. 结果

`gh-advisory-database` 工具于 2026-05-13 比对，**全部依赖未发现已知漏洞**。

## 3. 残留风险（需要单独审计项跟进）

| 依赖 | 残留风险 | 跟进项 |
|---|---|---|
| `biscuit-auth = 6.0.0-beta.3` | **pre-release 版本**，可能含未公开缺陷 / API 变更 | AUDIT-DEP-002 |
| `pprof` | 仓库 git rev pin (非 crates.io 发布版本)，feature `pprof` 下启用 | AUDIT-DEP-003 |
| `rocksdb` | 大量 C++ 代码，CVE 在 advisory DB 覆盖可能滞后 | 建议手动跟踪 |
| `fiber-sphinx 2.3` | 项目方自维护 crate，advisory DB 覆盖度依赖发布者 | 建议在 AUDIT-CRYPTO-002 中协同审查上游源码 |

## 4. 建议

1. **CI 集成**：在 `.github/workflows/` 中增加：
   ```yaml
   - run: cargo install --locked cargo-audit
   - run: cargo audit --deny warnings
   ```
   或使用 [`rustsec/audit-check`](https://github.com/rustsec/audit-check) Action。
2. **定期**：每月 cron 触发依赖审计；高敏依赖订阅 GitHub Security Advisories。
3. **依赖治理**：禁止使用 git rev pin 进入 release profile（针对 `pprof` 等）；如必须使用，固化在 feature gate 下并在文档中标注。
4. **beta 治理**：制定政策约束 release 中 pre-release 依赖（`biscuit-auth 6.0.0-beta.3`）的接受标准。

## 5. 结论

当前依赖图在已知 CVE 维度上是干净的。建议固化 `cargo audit` CI 步骤，并按 AUDIT-DEP-002 / DEP-003 跟进 beta / git pin 依赖的人工评估。
