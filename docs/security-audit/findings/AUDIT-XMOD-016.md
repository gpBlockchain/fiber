# AUDIT-XMOD-016 — onion_service ↔ network ↔ gossip 单一 `announced_addrs` 列表破坏 Tor 隐私边界

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟡 Medium（隐私边界穿透；不直接资金损失但与运营商安全模型冲突） |
| 状态 | [!] 发现弱设计（静态可达，启用 `listen_on_onion=true` 即触发） |
| 出处 | 本次跨模块审计新发现；AUTH-002.F2/F3 提到明文 TCP 监听问题但未把 NodeAnnouncement / RPC 出站层独立提级 |
| 关联代码 | `crates/fiber-lib/src/fiber/network.rs:5676-5742`（`announced_addrs` 单一 Vec：clearnet listening + `config.announced_addrs` + 私网过滤）<br>`crates/fiber-lib/src/fiber/network.rs:5744-5765`（onion 启动后 `announced_addrs.push(addr)` **追加** 到同一 Vec）<br>`crates/fiber-lib/src/fiber/network.rs:3734-3760`（`get_or_create_new_node_announcement_message`：直接 `let addresses = self.announced_addrs.clone();` 全量签名进 NodeAnnouncement）<br>`crates/fiber-lib/src/fiber/network.rs:2463-2475`（`NodeInfo` RPC 同样回 `state.announced_addrs.clone()` 全量）<br>`crates/fiber-lib/src/fiber/onion_service.rs:35`（`pub listen_on_onion: bool`）<br>`crates/fiber-lib/src/fiber/config.rs:147`（`pub(crate) announced_addrs: Vec<String>`） |
| 关联 finding | AUDIT-AUTH-002.F2 / F3（onion 与明文 TCP 并存）、AUDIT-NET-001（admission 绕过）、AUDIT-XMOD-005（鉴权穿透） |

## 1. 现象

启用 `listen_on_onion=true` 的合理预期是**隐私模式**：节点对外只暴露 Tor `.onion` 地址，clearnet IP 不被关联。但当前实现：

1. `network.rs:5676-5742`：`announced_addrs` 是一个 `Vec<Multiaddr>`，先 push clearnet listening 地址（`announce_listening_addr=true` 时），再合并 `config.announced_addrs`（运营商手填）；
2. `network.rs:5744-5765`：onion service 启动后**直接 `announced_addrs.push(addr)`**，与 clearnet 共用同一 Vec；
3. `network.rs:3734-3760` `get_or_create_new_node_announcement_message`：把整个 Vec 写进 NodeAnnouncement gossip 消息 — **签名后向全网广播**；
4. `network.rs:2463-2475` `NodeInfo` RPC：同样回完整 Vec；
5. 没有任何 "tor-only" 模式开关：没有 `announce_only_onion` / `tor_strict_mode` / `disable_clearnet_advertise`，也没有自动检测"clearnet 地址在启用 onion 时应被剥离"的逻辑。

`announce_private_addr=false` 仅过滤 `!is_addr_reachable` 的私网地址（`network.rs:5740-5742`），**公网 IP 仍被广播**。

## 2. 跨模块攻击 / 隐私破坏路径

```
deployer 配置 listen_on_onion=true（预期：Tor-only）
        │
        ▼ network.rs:5676-5710
   announce_listening_addr 默认 true → clearnet TCP 监听地址被 push
   config.announced_addrs（如用户在 yaml 里写了公网 IP / 反向代理 IP）也被 push
        │
        ▼ network.rs:5744-5765
   onion service 启动 → onion .onion:port 被 push（追加，不替换）
        │
        ▼ network.rs:3734-3760 + gossip broadcast
   NodeAnnouncement.addresses = [clearnet_ip:port, onion_address.onion:port]
        │
        ▼ 全网邻居收到签名后的 NodeAnnouncement
   攻击者把 pubkey ↔ clearnet_ip ↔ onion_address 三元组关联
        │
        ▼
   1) clearnet IP 被反向解析到 ISP / 地理位置；
   2) onion-only 期望的"不可关联性"失效；
   3) 后续若该 IP 暴露其它服务（SSH / RPC / WS），均与该 fiber 节点关联。
```

同时影响 **RPC**（`info` 模块）：客户端通过 `node_info` 即可枚举 onion + clearnet 两套地址。

## 3. 跨模块边映射

对照 `MODULES.md`：
- `fiber/onion_service` (子模块) → `fiber/network` (`announced_addrs` 状态)；
- `fiber/network` → `fiber/gossip` (O1 出站广播 NodeAnnouncement)；
- `fiber/network` → `rpc/info` (E5 入站，但反向暴露)；
- 跨"信任边界 ①P2P + ②RPC + 隐私边界（新引入）"。

**核心信任不变量违反**：节点的 *广播身份* 应与 *底层连通性* 在 Tor 模式下解耦；当前 `announced_addrs` 把两者合并，无法独立配置。

## 4. 与 AUDIT-AUTH-002 的区别

AUTH-002.F2/F3 指出"clearnet TCP 监听端口仍然打开" — 这是**入站连通性**问题（被扫描 / 直连）。本条聚焦**出站广播 / 主动暴露**：即便外部扫描者不能找到 fiber 节点的 clearnet IP，节点也**主动**把它写进签名后的 NodeAnnouncement 推到 gossip 全网；任一邻居都能从签名消息把 onion 身份与 clearnet IP 关联。两者独立、互补：
- AUTH-002.F2/F3：堵入站（关闭明文 TCP / 强制 onion-only listen）；
- XMOD-016：堵出站（NodeAnnouncement 与 RPC 出站隐私 filter）。

只修 AUTH-002 不够 — 运营商可能合理需要明文 TCP（与可信子网通信），但仍希望 gossip 不泄露真实 IP。

## 5. 影响评估

- **隐私穿透**：把 fiber pubkey ↔ clearnet IP 双向锁定；适用于审查环境、企业内网→公网混合部署、记者/活动家匿名场景。
- **横向风险**：若 clearnet IP 同时托管 SSH / Web，攻击者把 fiber 节点身份与服务器其它指纹关联，扩大攻击面。
- **触发成本**：零；只要 deployer 启用 `listen_on_onion=true` 且没有手动把 `announce_listening_addr` 设 false、也没把 `announced_addrs` 列表清空，就触发。当前文档（`docs/specs/p2p-message.md` 没有 onion 隐私章节，SPEC-001.F-onion）也不提示风险。
- **不可逆**：NodeAnnouncement 一旦签名广播，被 gossip 邻居持久化（`fiber/gossip.rs::save_node_announcement`）；后续即便修复，旧记录仍在网络中流传至 timestamp 失效。

## 6. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | **P1** | `OnionServiceConfig` 加 `tor_strict_mode: bool`（默认 false，向后兼容；为避免破坏现有部署不能直接 default=true）；当 true 时：(a) `announced_addrs` 在 push onion 前**清空** clearnet 条目；(b) **强制** `announce_listening_addr=false`；(c) `config.announced_addrs` 仅允许 `.onion` 形式 — 配置加载阶段 fail-fast。**文档**：yaml 默认配置注释明确"隐私保护需显式 opt-in `tor_strict_mode=true`"；运行 `make gen-rpc-doc` 与 `make check-dirty-rpc-doc`（若 `node_info` 输出 schema 因 F2 改动）。 |
| F2 | **P1** | `get_or_create_new_node_announcement_message` 与 `NodeInfo` RPC 出站前增加 `filter_for_announce(&addrs, &state.privacy_policy)`：根据策略决定是否剥离 clearnet。 |
| F3 | P1 | 把 `announced_addrs` 类型由 `Vec<Multiaddr>` 拆为 `AnnouncedAddrs { tor: Vec<_>, clearnet: Vec<_> }`，编译期强制调用方显式选择 — 避免后续新代码无意把 clearnet 加进 broadcast 路径。 |
| F4 | P2 | `docs/specs/p2p-message.md` 增 `节点身份与广播地址隐私` 章节；与 SPEC-001 / AUTH-002 链接；明确"启用 onion 后默认不广播 clearnet"为协议级 SHOULD。 |
| F5 | P2 | `info_node` RPC 与 `node_info` JSON 输出在 `tor_strict_mode` 下仅返回 onion 地址（防御 XMOD-005 鉴权穿透时的隐私二次泄露）。 |
| F6 | P3 | 启动时检测 onion 私钥已加载但 `announced_addrs` 含 clearnet → warn!，给运营商醒目提醒。 |

## 7. 验证测试

- `network::tests::test_tor_strict_mode_excludes_clearnet_from_announce`：配 onion + `tor_strict_mode=true`，断言 NodeAnnouncement.addresses 仅含 `.onion`。
- `network::tests::test_announced_addrs_split_type_disallows_silent_mix`：F3 重构后，编译期断言只有 broadcast helper 能取 clearnet vec。
- `rpc::tests::test_node_info_respects_privacy_policy`：策略=tor-only 时 RPC 不返回 clearnet。
- 集成测试：mock gossip 邻居，断言收到 NodeAnnouncement 不含 clearnet。

## 8. 状态

- F1+F2 必须协同；F3 是结构性硬化，建议合并提交。
- 与 AUTH-002.F2/F3 同 PR 处理可减少重复部署文档变更。
- 关联 PR：暂无。
