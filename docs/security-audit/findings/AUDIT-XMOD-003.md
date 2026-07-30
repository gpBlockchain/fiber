# AUDIT-XMOD-003 — Store 权限 + Migration 版本无完整性 + bincode 宽松默认三层叠加

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟡 Medium（同主机离线攻击者；需本地非特权账户）|
| 状态 | [!] 发现弱设计（静态可达，无 PoC） |
| 出处 | 本次跨模块审计补强；基于 STORE-001、INPUT-004 与 "storage migration framework" / "store layer security" 记忆扩展 |
| 关联代码 | `crates/fiber-store/src/native.rs:17-105`（DB 默认 0o644/0o755）<br>`crates/fiber-store/src/sqlite.rs:20-181`（SQLite 后端无独占 advisory lock）<br>`crates/fiber-store/src/migration.rs:41,152-156,213-312`（`MIGRATION_VERSION_KEY = b"db-version"` 无签名；`auto_migrate.pending.is_empty()→stamp latest`；`add_migration` BTreeMap silent overwrite）<br>`crates/fiber-store/Cargo.toml:19-25`（bincode 1.3.3 + serde — 默认接受 trailing bytes / struct prefix-overlap）<br>`crates/fiber-store/src/migrations/mig_20260511_channel_connectivity_state.rs:42-86`（典型 `if let Ok(_new) = bincode::deserialize::<NewT>(&value) { skipped }` 模式） |
| 关联 finding | AUDIT-STORE-001.F1（DB 权限）、AUDIT-INPUT-004.F1/F2（bincode 严格性）、AUDIT-LOGIC-002 |

## 1. 现象

三个独立的"小问题"叠加形成永久数据损坏面：

1. **DB 文件默认 mode 0o644 / 目录 0o755**（`native.rs::open_db` 未 `set_permissions`）。同主机任意 UID 可读，任意能写文件 ACL 的次级账户可改写（如同组用户、Docker bind mount 暴露给 root-on-host）。
2. **`MIGRATION_VERSION_KEY = b"db-version"` 无完整性签名**：版本号是裸字符串 key/value。改成"未来版本号"即可让 `auto_migrate.pending.is_empty()→stamp latest` 跳过本应跑的迁移。
3. **bincode 1.3.3 默认接受尾随字节 + struct prefix-overlap**：实测 `B { x: u32 }` 可以从 `A { x: u32, y: u64 }` 编码反序列化成功，余下字节静默丢弃。配合 migration 内"`if let Ok(_new) = bincode::deserialize::<NewT>(&value) { skip }`" 幂等模式，**删字段 / 重命名 / enum 重排 / 字段顺序变** 都会被错误地判断为"已升级"。

## 2. 跨模块攻击链

攻击者前提：能在 fiber 节点宿主机以非 owner 用户访问 DB 目录（共享 host / 共享容器 volume / 误用 bind mount / 备份恢复操作）。

1. 节点关停或重启间隙，攻击者：
   - 读取 `db-version` 当前值（如 `20260511`）；
   - 改写为 `99999999`（或更大）；
   - 不需要改其它任何数据。
2. 节点重启时 `auto_migrate`：扫描 `pending = migrations.iter().filter(|m| m.version > db_version)`；新 db_version 远大于所有 migration → `pending.is_empty()` → 不跑任何 migration、立即把 db-version stamp 为 latest（实际还是攻击者写的更大值，无校验回退）。
3. 节点继续运行，所有读路径用**新代码**对**旧编码**做 bincode `deserialize::<NewT>`：
   - 字段删减 → 旧编码尾部静默丢；
   - 字段顺序变 → 类型对应位置错位，可能仍 OK（u32→u32），数据语义错位但不报错；
   - enum 重排 → 旧 tag 在新枚举里指错 variant。
4. 受影响数据包括 `ChannelActorState`（`commitment_seed` / `local_tlc_signing_keys` / commitment_number / 最新 revocation_data），导致：
   - commitment_number 倒退或错位 → 重新签名旧 commitment 上链 → 对端视为 cheat 取走资金；
   - 签名密钥派生路径错位 → 签名失败 → channel-stuck；
   - watchtower secret 错位 → 失去防 cheat 能力。

## 3. 与已有发现的区别

- STORE-001.F1 只看 DB 权限本身；
- INPUT-004.F1/F2 只看 bincode 严格性；
- migration 框架审计只看 add_migration 与版本号字段；
- 三者**单独**都判为 Medium-Low；本条强调三者**链式组合**就能实现"同主机离线触发资金罚没"。

## 4. 影响评估

- **资金罚没**风险（commitment_number 错位 → cheat tx）；
- 单一非特权账户即可触发；
- 攻击痕迹少：只改 db-version 一个 key，无应用级日志。

## 5. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | P1 | `native.rs::open_db` / `sqlite.rs::open` 创建后立即 `set_permissions` 0o700（目录）+ 0o600（文件）；权限不达标启动 fail-fast。复用 STORE-001.F1。 |
| F2 | P1 | bincode 全仓改 `bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()`，封装成 `store/codec.rs::deserialize_strict`；提交一次性脚本审计所有 `bincode::deserialize` 调用点。复用 INPUT-004.F1。 |
| F3 | P1 | `db-version` 改为 HMAC-SHA256(`node_secret`, latest_version) 写入；启动时校验失败 → bail 而非 stamp latest。`add_migration` 版本号格式校验（YYYYMMDD_NN）。 |
| F4 | P1 | migration 框架的"幂等检测"改为：直接 try-deserialize OLD → 若成功就 *必须* 跑 migration；不再用"deserialize as NEW success ⇒ skip"语义。 |
| F5 | P2 | SQLite 后端补 `PRAGMA locking_mode = EXCLUSIVE` 或文件 `flock` advisory lock（XMOD-014 共享修复）。 |

## 6. 验证测试

- `store::migration::tests::test_tampered_version_rejected`：构造 db-version=`99999999`，断言启动 bail。
- `store::codec::tests::test_strict_decode_rejects_trailing`：`A → B { x }` 解码必须失败。
- 权限断言测试：启动后 stat DB 目录/文件确认 0o700/0o600。

## 7. 状态

- 修复必须 F1+F2+F3+F4 同时合入。
- 关联 PR：暂无。
