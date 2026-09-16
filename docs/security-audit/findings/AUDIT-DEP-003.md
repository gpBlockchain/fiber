# AUDIT-DEP-003 — `pprof` git rev pin (feature `pprof`) evaluation

| 字段 | 值 |
|---|---|
| 维度 | DIM-DEPS |
| 严重度 | 🟢 Low (Low × 2 + Info × 1 + Pass × 1) |
| 状态 | [!] 发现弱设计 |
| 关联代码 | `crates/fiber-lib/Cargo.toml:93, 123` |

## 1. 背景

```toml
# crates/fiber-lib/Cargo.toml:93
pprof = { git = "https://github.com/tikv/pprof-rs.git",
          rev = "01cff82dbe6fe110a707bf2b38d8ebb1d14a18f8",
          features = ["flamegraph", "protobuf-codec", "frame-pointer"],
          optional = true }

# line 123:
pprof = ["dep:pprof"]
```

fiber 使用 `pprof-rs` 作为可选的 CPU profiling 集成。该 crate 通过 git rev 指定，而不是 crates.io 版本号。

## 2. 发现

### F1 🟢 Low — 直接 git rev pin 绕过 crates.io 供应链信号

- `git+https://github.com/tikv/pprof-rs.git#01cff82dbe6fe110a707bf2b38d8ebb1d14a18f8` 跳过了 crates.io 发布渠道：
  - GitHub Advisory DB 的依赖扫描不一定覆盖 git-rev 形式（取决于 cargo metadata 输出，依赖扫描器实现）。
  - `cargo deny check bans/advisories` 默认对 git deps 兼容度参差不齐。
  - 上游分支可被强推改写历史（即便 rev 字面值不变，Git 对象指向也可能被劫持，理论风险）。
- pprof-rs 已有 crates.io 发布版本 (0.14+)；fiber 采用 git rev 通常是为了等某 unreleased fix 入主线 — 但当前 fiber.lock 已 lock 该 rev 后多次 cargo update 未跟踪上游主线，可能漏掉安全修复。

### F2 🟢 Low — `frame-pointer` feature + unwind 在 release build 中可能与 panic backtrace 交互

- `frame-pointer` feature 强制保留 frame pointer (`-C force-frame-pointers`)，对 panic backtrace / DWARF 解析无负面影响，但在静态链接 jemalloc / mimalloc 时与 unwinder 实现有兼容性历史问题（不针对当前依赖，是一般性提醒）。
- 当前 fiber profile 没有 `panic = "abort"`，意味着 pprof 收集时遇 SIGPROF 与 stack-unwind 重入有理论争用窗口；上游 pprof-rs 通过 spinlock guard 处理，已实测稳定。

### F3 ℹ️ Info — `optional = true` + feature `pprof = ["dep:pprof"]` 实施了正确的 opt-in

- 默认 build 不引入 pprof；只有显式 `--features pprof` 才生效。
- 生产 release artifact 默认无此风险。

### F4 ✅ Pass — 攻击面受限

- pprof 仅在节点运维主动开启时启用，且只暴露给本地 stdout/file，无 RPC 触发面。
- 即便 pprof-rs 自身存在漏洞，也只影响开启 profiling 的节点（运维场景），不影响默认部署。

## 3. 影响

- 直接安全风险：低（opt-in feature，无 RPC 入口暴露）
- 供应链/合规风险：低-中（git rev 形式弱化扫描器信号；上游变更跟踪缺失）

## 4. 修复建议

| 优先级 | 建议 | 估改动 |
|---|---|---|
| P3 | 改用 `pprof = "0.14"` (或最新 crates.io 版本) 替代 git rev | 1 行 + 兼容性测试 |
| P3 | 如必须 git rev，加注释说明 unreleased fix 的 issue/PR 链接和迁移条件 | 注释 |
| P3 | CI: `cargo deny check bans` 配置允许该单一 git source（白名单）+ 定期 cargo update 流程 | 配置 |

## 5. 跟踪项

- AUDIT-DEP-003-FOLLOWUP-A：评估迁移到 `pprof = "0.14"` crates.io 版本 / 跟踪上游主线 release。
- AUDIT-DEP-003-FOLLOWUP-B：在 CI 中将 `cargo deny check sources` 加入 lint 步骤。
