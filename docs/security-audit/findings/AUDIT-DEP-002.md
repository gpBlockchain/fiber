# AUDIT-DEP-002 — biscuit-auth = 6.0.0-beta.3 (pre-release) evaluation

| 字段 | 值 |
|---|---|
| 维度 | DIM-DEPS |
| 严重度 | 🟡 Medium (Info × 1 + Low × 2 + Improvement × 1) |
| 状态 | [!] 发现弱设计 |
| 关联代码 | `crates/fiber-lib/Cargo.toml:58, 96`, `crates/fiber-lib/src/rpc/biscuit.rs`, `middleware.rs` |
| 上游 | https://github.com/biscuit-auth/biscuit-rust |

## 1. 背景

fiber RPC 鉴权链选择 `biscuit-auth = "6.0.0-beta.3"` (含 wasm feature 双引用)，是 Biscuit v3 Rust 实现 6.x 系列的预发布版。AUDIT-AUTH-001 已对鉴权语义做了功能审计；本项专门评估「采用预发布版」本身带来的供应链/稳定性风险。

## 2. 发现

### F1 ℹ️ Info — 预发布版语义不稳定

- 6.0.0-beta.3 (2024-Q4 发布) 未冻结公共 API；upstream 6.0.0 GA / 6.0.0-beta.4+ 可能引入破坏性变更。
- Cargo caret 解析下 `6.0.0-beta.3` 不会自动升 `6.0.0-beta.4`（pre-release 比较规则），但 `cargo update --precise` 升级路径无回归测试。
- GitHub Advisory DB 当前对 6.0.0-beta.3 无 CVE 报告（AUDIT-DEP-001 已确认）；biscuit-rust 历史也无 critical 漏洞记录。

### F2 🟢 Low — `wasm` feature 与生产路径混合启用

- `Cargo.toml:96` 在 wasm 目标条件下额外打开 `features = ["wasm"]`：当前未审计 wasm feature 是否引入 `getrandom` 替换、密钥派生差异等。

### F3 🟢 Low — 没有 backup auth 方案

- 一旦 biscuit-auth 上游废弃 6.x 直接跳 7.x（已发生在 5.x→6.x 的 KeyPair API），fiber 升级路径会涉及 token 撤销列表迁移；当前 `BiscuitAuth::set_revoked_tokens` 用 `Vec<TokenId>` 自定义类型未做 schema 版本化。

### F4 ⚠️ Improvement — pin precise + CI check

- 建议：(a) `biscuit-auth = "=6.0.0-beta.3"` 严格 pin (= 而非 caret) 避免 cargo update 拉到不兼容 beta；(b) CI 中加 `cargo deny check bans` 拒绝 pre-release crate 进 release artifact 除显式 allow-list；(c) 跟踪 biscuit-auth 6.0.0 GA tag 与 fiber 自身 release 协同。

## 3. 影响

- 直接安全风险：低（无 CVE，API 稳定性问题，非完整性问题）
- 运维风险：中（升级窗口可能与 fiber release cycle 冲突，token 撤销列表迁移路径无文档）

## 4. 修复建议

| 优先级 | 建议 | 估改动 |
|---|---|---|
| P2 | Cargo.toml 改 `=6.0.0-beta.3` pin | 1 行 |
| P2 | 跟踪 6.0.0 GA + 评估升级；编写 token 撤销列表迁移方案 | 跨发布周期任务 |
| P3 | 评估弃用 biscuit-auth 改 stable 替代（macaroons / paseto-rust）的可行性 | 长期 |

## 5. Pass

- 调用方代码 (`rpc/biscuit.rs`, `middleware.rs`) 仅使用 stable subset (KeyPair / PublicKey / Biscuit::builder/parse / revocation_list)，未触碰 pre-release 内部 API。
- AUDIT-DEP-001 已确认 biscuit-auth 当前版本无 CVE。

## 6. 跟踪项

- AUDIT-DEP-002-FOLLOWUP-A：评估升级到 biscuit-auth 6.0.0 GA 后撤销列表/keypair API 迁移路径。
- AUDIT-DEP-002-FOLLOWUP-B：审计 `wasm` feature 启用后的 entropy/密钥派生路径差异。
