# AUDIT-XMOD-013 — fiber-bin ↔ env ↔ fiber/key ↔ store ↔ ckb 钱包凭据生命周期

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟡 Medium（同主机非特权攻击者；本地 LPE / 容器逃逸场景） |
| 状态 | [!] 发现弱设计（静态可达，无 PoC） |
| 出处 | 本次跨模块审计补强；基于 CRYPTO-003 + STORE-001 + "store layer security" 记忆 |
| 关联代码 | `crates/fiber-bin/src/main.rs`（启动序列：cfg → `read_secret_key` → 初始化 CkbChainActor / signer）<br>`crates/fiber-lib/src/ckb/config.rs::read_secret_key`（从磁盘 keyfile + `FIBER_SECRET_KEY_PASSWORD` env 解密 scrypt + AES-GCM）<br>`crates/fiber-lib/src/utils/encrypt_decrypt_file.rs`（加解密原语）<br>`crates/fiber-lib/src/fiber/key.rs`（`Privkey` 实例化与持有）<br>`crates/fiber-lib/src/ckb/signer.rs`（CKB 签名路径）<br>`crates/fiber-store/src/native.rs:17-105`（DB 目录 0o755/0o644，存放 `commitment_seed` / watchtower `Privkey`） |
| 关联 finding | AUDIT-CRYPTO-003（加解密本身）、AUDIT-STORE-001（DB 权限）、AUDIT-INPUT-004、AUDIT-XMOD-003（store 三层叠加） |

## 1. 现象

fiber 钱包凭据生命周期横跨 5 个模块，每模块单独看都"合理"，但**端到端无人收口**：

| 阶段 | 模块 | 失防表现 |
|---|---|---|
| 加载 | fiber-bin / ckb/config.rs | `FIBER_SECRET_KEY_PASSWORD` env 由父进程继承；fiber 启动后不主动清空；子进程继承同一 env |
| 内存 | fiber/key.rs / ckb/signer.rs | `Privkey` 无 `Zeroize` / `Drop` 清零；无 `mlock`；core dump 时 secret 进 dump 文件 |
| 落盘 | fiber-store/native.rs | DB 目录 0o755 / 文件 0o644；`commitment_seed`（资金敏感）+ watchtower `Privkey` 直接存其中 |
| 签名 | ckb/signer.rs | 每次链上交易构造时被调用，持有 secret key 引用；无周期性 rotate / re-derive |
| 健康检查 | （不存在） | 无模块负责"凭据是否仍合法可用 / 是否泄露" |

## 2. 同主机攻击面（与 XMOD-003 协同）

同主机非特权用户可通过三个独立路径拿到不同片段：

1. **`/proc/<fiber_pid>/environ`**：在进程启动后短时间内可读（取决于 `dumpable` 属性）— 拿到 `FIBER_SECRET_KEY_PASSWORD` env 值。
2. **`/proc/<fiber_pid>/maps` + `mem`**（需 CAP_SYS_PTRACE 或同 UID）：dump 内存搜 `Privkey` 字段（secp256k1 `SecretKey` 是 32B；可启发式定位）。
3. **DB 文件 0o644**：直接读 `commitment_seed` / watchtower `Privkey`（XMOD-003 已覆盖权限部分）。

任一路径成功 → 资金或反 cheat 能力丧失。

## 3. 与已有发现的区别

- CRYPTO-003 只看"加解密本身是否正确"（scrypt + AES-GCM 实现 OK）；
- STORE-001 只看"DB 权限"；
- INPUT-004 只看"反序列化严格性"；
- 本条把**"磁盘 → env → 内存 → store(0o644) → signer"** 端到端路径作为一条链审计，强调 5 个模块的协同硬化。

## 4. 攻击场景

### 4.1 Container sidecar 偷凭据
1. 用户用 docker-compose 跑 fiber + sidecar（log shipper / metrics exporter）；
2. sidecar 共享 PID namespace（如 `pid: host` 误配）或共享 volume（`/data` bind mount）；
3. sidecar 内任意非 root 用户读 `/proc/fiber_pid/environ` 拿密码 + 读 DB 拿 commitment_seed → 完整复活节点 / cheat。

### 4.2 Core dump 泄露
1. fiber crash（如 XMOD-009 / XMOD-010 触发的 panic）；
2. systemd-coredump 默认把 core 文件写到 `/var/lib/systemd/coredump`，权限取决于配置；
3. 同主机管理员/同组用户 dump 中能搜出 secret key。

### 4.3 Swap 持久化
1. fiber 内存压力大时 secret 被 swap 到磁盘（无 mlock）；
2. swap 分区在节点掉电后仍可读 → 物理访问 / 同主机另一 UID 接触 swap dev 即可。

## 5. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | P1 | `fiber-bin` 启动后立即 `prctl(PR_SET_DUMPABLE, 0)` 防 core dump；Linux `mlock_all` 防 swap；加 cfg gate（非 Linux 跳过）。 |
| F2 | P1 | `FIBER_SECRET_KEY_PASSWORD` 读完后立即用 unsafe `std::env::remove_var` 移除；推荐改为读取一次性 fd / unix socket（systemd `LoadCredentialEncrypted=` 模式）。 |
| F3 | P1 | `Privkey`、`commitment_seed`、watchtower secret 全部 wrap 进 `zeroize::Zeroizing<...>`，Drop 时清零；`Debug` 实现 → `<redacted>`（与 XMOD-011 F1 同源）。 |
| F4 | P0 | 合并 STORE-001.F1：DB 目录 0o700 / 文件 0o600；启动权限不达标 fail-fast。（与 XMOD-003.F1 共享） |
| F5 | P2 | signer 路径加 in-process token：每次 RPC 触发签名前校验请求来源；防 actor 内任意 message 直接调 signer。 |

## 6. 验证测试

- `tests/security/credential_lifecycle.rs`：综合断言
  - (a) DB 目录创建后 stat 权限断言 0o700 / 0o600；
  - (b) `/proc/self/status` `Dumpable: 0`；
  - (c) 启动后 `std::env::var("FIBER_SECRET_KEY_PASSWORD")` 返回 Err；
  - (d) `Privkey::drop` 后通过 unsafe 直读那块栈/堆内存，必须为零；
  - (e) `format!("{:?}", privkey)` 输出 `<redacted>`。
- 跨平台：F1 仅 Linux 启用，Windows/macOS 跳过 + 警告日志（"core dump protection unavailable on this platform"）。

## 7. 状态

- F1+F2+F3+F4 协同合入；F5 后置。
- 关联 PR：暂无。
