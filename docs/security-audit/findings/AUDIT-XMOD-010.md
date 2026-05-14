# AUDIT-XMOD-010 — Primitives ↔ Channel ↔ Store 曲线代数 panic 永久 brick 通道

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟡 Medium（一条 P2P 消息永久 brick 单通道；不影响其它通道） |
| 状态 | [!] 发现弱设计（数学构造可行，待 PoC 实测） |
| 出处 | 本次跨模块审计新发现；记忆 "curve algebra panic" |
| 关联代码 | `crates/fiber-types/src/primitives.rs:503-508`（`Pubkey::from_slice` — 正确范本，返回 Result）<br>`crates/fiber-types/src/primitives.rs:511-519`（`Pubkey::tweak` 末尾 `.not_inf().expect("valid public key")`）<br>`crates/fiber-types/src/primitives.rs:403-412`（`Privkey::tweak`：本地 secret only，Low）<br>`crates/fiber-types/src/schema/fiber.mol:41-42, 58-59`（OpenChannel/AcceptChannel：`tlc_basepoint` 与 `first_per_commitment_point` 均 attacker-controlled）<br>`crates/fiber-types/src/channel.rs:1158-1179`<br>`crates/fiber-lib/src/fiber/channel.rs:6097-6126`（`derive_tlc_pubkey` 首次调用 / `get_tlc_pubkeys` / `get_tlc_keys`）<br>`crates/fiber-lib/src/fiber/channel.rs:8748-8762`（OpenChannel 入参处理无两公钥关系校验） |
| 关联 finding | AUDIT-CRYPTO-002（曲线 strictness）、AUDIT-LOGIC-001、AUDIT-STORE-001（状态持久化先于 panic） |

## 1. 现象

`Pubkey::tweak` 等价于 `T + blake2b(Q)·G`，末尾用 `.not_inf().expect("valid public key")`：若结果落到无穷远点 O，立刻 panic。

OpenChannel / AcceptChannel 消息内（schema `fiber.mol:41-42, 58-59`）`tlc_basepoint` 与 `first_per_commitment_point` 都由对端选择，且 `channel.rs:8748-8762` 入参处理路径**无两公钥之间的关系校验**：

- `Pubkey::from_slice` (503-508) 接受任意有效压缩 secp256k1 点；
- 攻击者可以独立挑选 Q（任意 secp256k1 点）→ blake2b(Q) 是确定标量 `h`；
- 攻击者可挑选 T = (-h·G)（已知离散对数 `-h`，因为 `h` 公开）→ tweak 输出 = `T + h·G = O`。
- 即攻击者**完全可构造**一对 `(T, Q)` 使 victim `derive_tlc_pubkey` 调用瞬间 panic。

进一步：channel state 在 panic 之前已经 commit 到 store（OpenChannel/AcceptChannel handler 把 `ChannelActorState` 持久化先于真正派生）→ 节点重启后 ChannelActor 加载该 state → 又走 derive_tlc_pubkey → 又 panic → **永久 brick 该通道**（无法收发 TLC、无法协作关闭、无法签 force-close 路径需要的脚本）。

## 2. 数学构造（攻击 recipe）

```
1. 任选 Q ∈ secp256k1 G（256-bit）；
2. 计算 h = blake2b_256(Q.compressed()) 视作标量 mod n；
3. 计算 t_secret = (-h) mod n；
4. 设 T = t_secret · G；
5. 把 (T, Q) 作为 (tlc_basepoint, first_per_commitment_point) 发给 victim；
6. victim derive_tlc_pubkey: result = T + h·G = (-h)·G + h·G = O → expect panic。
```

构造成本：1 次 blake2b + 1 次 scalar mult。

## 3. 与已有发现的区别

- 单一视角看 `primitives.rs::tweak` 只是密码学库 strictness，看不到攻击触发面；
- 单一视角看 `channel.rs::OpenChannel` 只是消息处理，看不到 panic 性；
- 单一视角看 store 只是持久化策略，看不到为何 panic 会"永久化"；
- **三层组合**才形成"一条 P2P 消息 → 永久 brick"。
- 与 AUDIT-CRYPTO-002 不同：CRYPTO-002 列出 strictness 一般化问题；本条聚焦 tweak 这条具体路径的 attacker reachability。

## 4. 影响评估

- 单通道永久不可用，资金需走 force-close + 时间锁恢复（前提是 force-close 路径未被同一 panic 阻塞）；
- 远程零授权（任意 fiber peer 可发 OpenChannel）；
- 不影响其它通道，但批量可针对所有公开节点；
- 与 STORE-001 状态持久化协同形成永久性。

## 5. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | P1 | `Pubkey::tweak` 改返回 `Result<Pubkey, KeyError>` 或 `Option<Pubkey>`；调用方在 `derive_tlc_pubkey` / `derive_*_pubkey` / `get_tlc_pubkeys` 显式处理 None → 返回 channel reject。 |
| F2 | P1 | `OpenChannel` / `AcceptChannel` handler **持久化前**预跑一次 `derive_tlc_pubkey` 与 `derive_revocation_pubkey`、`derive_payment_pubkey`、`derive_delayed_payment_pubkey`、`derive_htlc_pubkey` 做 "early validation"；任意失败 → reject channel **且不持久化**。 |
| F3 | P1 | ChannelActor 启动加载 channel state 时若派生失败，把该 channel 标 `bricked` 并允许 force-close（不持有 OpenChannel 期 secret 时也允许 emit force-close tx）；不再 panic。 |
| F4 | P2 | `Privkey::tweak`（403-412）`.not_zero().expect`：本地 secret only，blake2b 第二原像不可行，保留可。 |
| F5 | P2 | 单元 fuzz：`cargo fuzz add tlc_pubkey_derivation`，corpus 包含构造的 (T,Q) → 必须返回 Err 而非 panic。 |

## 6. 验证测试

- `primitives::tests::test_pubkey_tweak_returns_err_on_inf`：构造 (T,Q) 使 tweak=O，断言返回 Err。
- `channel::tests::test_open_channel_rejects_brick_pubkeys`：发 OpenChannel with brick (T,Q) → ChannelActor 拒绝、**store 中无 channel 记录**。
- `channel::tests::test_load_bricked_channel_no_panic`：手动在 store 写入 brick state，重启 ChannelActor，断言 channel 标 `bricked` 不 panic。

## 7. 状态

- F1+F2+F3 必须协同；F4 可保留；F5 后置加固。
- 关联 PR：暂无。
