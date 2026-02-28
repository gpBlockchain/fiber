# Fiber Network Node 安全审计 TODO

> 版本: v1 | 最后更新: 2026-02-28 | 状态: 已完成

## 项目概况
  - 语言: Rust 1.93.0
  - 类型: 区块链节点 (P2P 支付网络, 类似 Lightning Network)
  - 依赖数: ~200+ (Cargo.lock)
  - 源文件数: ~50+ 核心源文件
  - 现有测试数: 26 个测试模块, 9 个 fuzz targets

## 审计进度
  - 总 TODO 项: 28
  - ✅ 已完成: 28 | ❌ 发现问题: 16 | ⏳ 待审计: 0

---

## 第 1 章: DIM-INPUT 输入验证

- [x] 🔴 **AUDIT-INPUT-001**: RPC 参数输入验证
  - **关联代码**: `src/rpc/channel.rs`, `src/rpc/payment.rs`, `src/rpc/peer.rs`
  - **审计内容**:
    - RPC 入口参数是否有类型/范围/格式校验
    - 缺失参数/空值/null 的处理
    - 超长/超大输入是否被拒绝
  - **现有覆盖**: 部分 (通过 serde 类型系统)
  - **发现记录**: ✅ 通过 - RPC 使用 jsonrpsee 框架，serde 类型系统提供基本验证。Biscuit 认证中间件保护所有端点。`check_open_channel_parameters()` 验证资金脚本、费率、TLC 限制。

- [x] 🔴 **AUDIT-INPUT-002**: P2P 对等网络消息输入验证
  - **关联代码**: `src/fiber/network.rs`, `src/fiber/channel.rs`, `src/fiber/types.rs`
  - **审计内容**:
    - 对等方发送的消息是否经过完整验证
    - 反序列化是否安全（无 RCE/内存破坏风险）
    - 编码/解码是否正确处理无效输入
  - **现有覆盖**: 部分 (fuzz tests)
  - **发现记录**: ⚠️ 建议改进 - Molecule 反序列化已修复整数溢出 (types.rs:67-78)。但 revocation nonce、close_script 等对等方数据缺少额外验证。

- [x] 🟠 **AUDIT-INPUT-003**: Gossip 消息输入验证
  - **关联代码**: `src/fiber/gossip.rs:2125-2157`
  - **审计内容**:
    - Channel announcement 签名验证完整性
    - Channel update 验证依赖关系
    - Node announcement 验证
  - **现有覆盖**: 有限
  - **发现记录**: ⚠️ 建议改进 - 签名验证完整（3 重签名），但缺少速率限制，可被洪泛攻击。UDT 通道容量验证未实现 (line 2334)。

- [x] 🟠 **AUDIT-INPUT-004**: Onion Packet 反序列化安全
  - **关联代码**: `src/fiber/types.rs:67-78`
  - **审计内容**:
    - 畸形/截断/超长 onion packet 处理
    - 整数溢出风险
  - **现有覆盖**: fuzz_onion_packet 目标
  - **发现记录**: ✅ 通过 - 已修复整数溢出，使用 `usize::try_from(len).ok()?.checked_add(HOP_DATA_HEAD_LEN)`。

---

## 第 2 章: DIM-CRYPTO 密码学操作

- [x] 🔴 **AUDIT-CRYPTO-001**: 密钥管理与安全擦除
  - **关联代码**: `src/fiber/key.rs:6,36,76`
  - **审计内容**:
    - 密钥派生是否使用充分的域分离
    - 敏感密钥材料使用后是否清零
    - 密钥存储文件权限
  - **现有覆盖**: 基本 (文件权限测试)
  - **发现记录**: ❌ 发现问题 - TODO 注释承认需要安全擦除但未实现。密钥存储在内存中无 zeroize。文件权限正确 (0o400)。建议使用 `zeroize` crate。

- [x] 🔴 **AUDIT-CRYPTO-002**: Musig2 签名验证完整性
  - **关联代码**: `src/fiber/channel.rs:7749-7750,6942-6943`
  - **审计内容**:
    - 部分签名格式验证
    - 重复签名检查
    - 聚合签名正确性
  - **现有覆盖**: 有限
  - **发现记录**: ⚠️ 建议改进 - `verify_partial` 处理底层验证，但缺少对部分签名格式的预验证和重复签名检查。revocation_partial_signature 未验证格式即聚合。

- [x] 🔴 **AUDIT-CRYPTO-003**: Preimage 哈希比较时序侧信道
  - **关联代码**: `src/fiber/channel.rs:1277,1347,1352`
  - **审计内容**:
    - 比较操作是否使用恒定时间
    - 是否存在时序侧信道泄露
  - **现有覆盖**: 无
  - **发现记录**: ❌ 发现问题 - Payment hash 比较使用标准 `!=` 运算符，不是恒定时间。攻击者可通过响应时间分析统计区分正确的 preimage。建议使用 `subtle::ConstantTimeEq`。

- [x] 🟠 **AUDIT-CRYPTO-004**: Revocation Nonce 验证
  - **关联代码**: `src/fiber/channel.rs:6969,6974,7322-7340`
  - **审计内容**:
    - Nonce 是否经过验证
    - Nonce 序列是否单调递增
    - Nonce 清除逻辑是否安全
  - **现有覆盖**: 有限
  - **发现记录**: ❌ 发现问题 - `next_revocation_nonce` 从对等方接收后未验证即使用。Nonce 清除逻辑 (line 6974) 设置 `remote_revocation_nonce_for_verify = None`，可能导致重放攻击。

---

## 第 3 章: DIM-AUTH 认证与授权

- [x] 🟡 **AUDIT-AUTH-001**: RPC 认证机制
  - **关联代码**: `src/rpc/middleware.rs`, `src/rpc/biscuit.rs`
  - **审计内容**:
    - 认证是否可被绕过
    - Token 管理是否安全
    - 权限控制粒度
  - **现有覆盖**: 基本
  - **发现记录**: ✅ 通过 - Biscuit 加密令牌验证，支持撤销列表，毫秒级时间过期。细粒度 RBAC (读/写权限)。注意: biscuit-auth 6.0.0-beta.3 为 beta 版本。

---

## 第 4 章: DIM-LOGIC 业务逻辑

- [x] 🔴 **AUDIT-LOGIC-001**: Channel 状态机转换正确性
  - **关联代码**: `src/fiber/channel.rs` (state machine)
  - **审计内容**:
    - 状态转换是否有非法跳转
    - 并发状态访问是否安全
    - 错误恢复后状态一致性
  - **现有覆盖**: 部分 (5 个无效转换测试)
  - **发现记录**: ✅ 通过 - 状态机使用 flag-based 子状态，转换受保护。Actor 模型避免直接并发访问。

- [x] 🔴 **AUDIT-LOGIC-002**: 支付超时处理
  - **关联代码**: `src/fiber/payment.rs:1561-1609`
  - **审计内容**:
    - 支付超时是否被强制执行
    - HTLC 是否可被无限锁定
  - **现有覆盖**: 无
  - **发现记录**: ❌ 发现问题 - 超时参数被接受但从未强制执行。支付可无限期保持 "Inflight" 状态。Actor 停止时不取消待处理 HTLC。

- [x] 🔴 **AUDIT-LOGIC-003**: u128 到 u64 类型转换安全
  - **关联代码**: `src/fiber/channel.rs:7500-7502,5880`
  - **审计内容**:
    - 金额计算中的类型转换
    - 是否存在静默截断
  - **现有覆盖**: 无
  - **发现记录**: ❌ 发现问题 - `to_local_amount as u64` 直接转换，若金额超过 u64::MAX 将静默截断。影响结算交易金额计算。

- [x] 🔴 **AUDIT-LOGIC-004**: 路由费用计算整数溢出
  - **关联代码**: `src/fiber/graph.rs:1965,1967,1814,1837`
  - **审计内容**:
    - 费用累加是否使用安全算术
    - 过期时间计算是否安全
  - **现有覆盖**: 有限
  - **发现记录**: ❌ 发现问题 - 多处未检查的算术运算: `next_hop_received_amount + fee` (u128), `incoming_tlc_expiry + tlc_expiry_delta` (u64), `now + r.incoming_tlc_expiry + rand_tlc_expiry_delta` (u64)。部分路径使用 `saturating_add` 但不一致。

- [x] 🟠 **AUDIT-LOGIC-005**: 承诺交易金额计算
  - **关联代码**: `src/fiber/channel.rs:7676-7682`
  - **审计内容**:
    - Settlement 金额计算正确性
    - 溢出保护
  - **现有覆盖**: 有限
  - **发现记录**: ⚠️ 建议改进 - `to_local_amount + received_fulfilled - offered_pending - offered_fulfilled` 使用 u128 但无溢出检查。下溢可能导致 panic (减法溢出) 或错误金额。

- [x] 🟠 **AUDIT-LOGIC-006**: 多路径支付 (MPP) 安全
  - **关联代码**: `src/fiber/payment.rs:655-658,789-793`
  - **审计内容**:
    - 分片支付验证
    - payment_secret 传播
    - 重试限制
  - **现有覆盖**: 有限
  - **发现记录**: ⚠️ 建议改进 - max_parts 限制为 16，每部分 3 次重试，共 48 次尝试。payment_secret 存在验证但未确认传播到所有分片。

- [x] 🟠 **AUDIT-LOGIC-007**: 强制关闭逻辑
  - **关联代码**: `src/fiber/channel.rs:7818-7849`
  - **审计内容**:
    - 强制关闭前置条件
    - 承诺交易可用性
    - 状态转换有效性
  - **现有覆盖**: 有限
  - **发现记录**: ⚠️ 建议改进 - 未验证 `latest_commitment_transaction` 是否存在即标记为强制关闭。从 ChannelReady 状态允许强制关闭但缺少先决条件验证。

- [x] 🟠 **AUDIT-LOGIC-008**: Payment `.expect()` Panic 风险
  - **关联代码**: `src/fiber/payment.rs:338`
  - **审计内容**:
    - `max_fee_amount.expect()` 是否可被外部触发
    - Panic 导致的 DoS 风险
  - **现有覆盖**: 有限
  - **发现记录**: ❌ 发现问题 - 若 `max_fee_amount` 为 None，`.expect("must got max_fee_amount")` 将 panic，导致支付模块崩溃。应使用 `?` 操作符返回错误。

---

## 第 5 章: DIM-MEMORY 内存与资源安全

- [x] 🟡 **AUDIT-MEMORY-001**: Unsafe 代码块审计
  - **关联代码**: `src/store/browser.rs`
  - **审计内容**:
    - unsafe impl Send/Sync 安全不变量
    - 是否有其他 unsafe 用法
  - **现有覆盖**: 基本
  - **发现记录**: ✅ 通过 - 仅 4 个 unsafe 块，全部是 WASM Store 的 Send/Sync trait 实现。无内存不安全操作。

- [x] 🟡 **AUDIT-MEMORY-002**: 资源耗尽风险
  - **关联代码**: `src/fiber/gossip.rs`, `src/fiber/payment.rs`
  - **审计内容**:
    - OOM 风险
    - 速率限制
    - 队列大小限制
  - **现有覆盖**: 无
  - **发现记录**: ❌ 发现问题 - Gossip 消息无速率限制，攻击者可发送无限消息。`messages_to_be_saved` HashMap 无大小限制。支付重试机制允许 48 次尝试/MPP。

- [x] 🟡 **AUDIT-MEMORY-003**: Panic 路径审计
  - **关联代码**: 全项目范围
  - **审计内容**:
    - 生产代码中的 panic!/unwrap()/expect()
    - 是否可由外部输入触发
  - **现有覆盖**: 有限
  - **发现记录**: ⚠️ 建议改进 - 28+ panic! 调用，主要在生成代码和序列化路径。关键: payment.rs:338 的 expect() 可由用户输入触发。gossip.rs, network.rs 中也存在 panic。

---

## 第 6 章: DIM-SERDE 序列化/反序列化

- [x] 🟡 **AUDIT-SERDE-001**: Molecule 序列化安全
  - **关联代码**: `src/fiber/gen/*.rs`, `src/fiber/types.rs`
  - **审计内容**:
    - 畸形数据解析行为
    - roundtrip 一致性
    - 不可信来源反序列化安全
  - **现有覆盖**: fuzz_molecule_types 目标
  - **发现记录**: ✅ 通过 - Molecule 框架提供严格的二进制验证。Fuzz 测试覆盖反序列化。已修复 onion packet 整数溢出。

- [x] 🟡 **AUDIT-SERDE-002**: 自定义 Serde 工具安全
  - **关联代码**: `src/fiber/serde_utils.rs`
  - **审计内容**:
    - 自定义反序列化器的输入验证
    - 大小验证 (CompactSignature 64B, PubNonce 66B, PartialSignature 32B)
  - **现有覆盖**: 有限
  - **发现记录**: ⚠️ 建议改进 - 支持带前缀和不带前缀的 hex 字符串（向后兼容），宽松的格式接受可能导致混淆攻击。大小验证正确。

---

## 第 7 章: DIM-ERRINFO 错误处理与信息泄露

- [x] 🟡 **AUDIT-ERRINFO-001**: 错误信息泄露
  - **关联代码**: `src/errors.rs`, `src/fiber/channel.rs`, `src/fiber/gossip.rs`
  - **审计内容**:
    - 错误消息是否泄露内部状态
    - 不同错误原因是否可被外部区分
    - 错误是否被静默忽略
  - **现有覆盖**: 有限
  - **发现记录**: ⚠️ 建议改进 - TlcErrPacket 使用 shared_secret 加密错误（好的做法）。但某些验证错误消息包含内部状态详情（channel IDs, 金额等）。Gossip 验证错误包含详细描述，可能泄露拓扑信息。

---

## 第 8 章: DIM-DEPS 依赖安全

- [x] 🟡 **AUDIT-DEPS-001**: 依赖版本安全
  - **关联代码**: `Cargo.toml`, `Cargo.lock`
  - **审计内容**:
    - 依赖版本是否有已知 CVE
    - 是否使用已弃用/不维护的库
    - Beta 版本库的风险
  - **现有覆盖**: Cargo.lock 固定版本
  - **发现记录**: ⚠️ 建议改进 - biscuit-auth 6.0.0-beta.3 为 beta 版本。serde_yaml 0.9.34 标记为 deprecated。所有加密库版本为最新稳定版。OpenSSL 3.5.5 (最新)。

---

## 第 9 章: DIM-CONFIG 配置安全

- [x] 🟠 **AUDIT-CONFIG-001**: 默认配置安全性
  - **关联代码**: `src/fiber/config.rs`, `src/config.rs`
  - **审计内容**:
    - 默认监听地址
    - 自动接受通道
    - 敏感信息明文存储
  - **现有覆盖**: 基本
  - **发现记录**: ❌ 发现问题 - 默认监听 0.0.0.0 (所有接口)。自动接受通道默认开启 (99 CKB)。Watchtower token 明文存储在 YAML 配置中。TLC 最小值默认为 0。

---

## 第 10 章: DIM-GOSSIP 网络协议安全

- [x] 🟠 **AUDIT-GOSSIP-001**: Gossip 洪泛攻击防护
  - **关联代码**: `src/fiber/gossip.rs:1685-1692`
  - **审计内容**:
    - 速率限制
    - 队列大小限制
    - 带宽节流
  - **现有覆盖**: 无
  - **发现记录**: ❌ 发现问题 - 无每对等方消息限制。无带宽节流。`messages_to_be_saved` HashMap 无大小限制。恶意对等方可强制全区块链查找。

- [x] 🟠 **AUDIT-GOSSIP-002**: 时间戳操纵攻击
  - **关联代码**: `src/fiber/gossip.rs:97-99,1471-1478`
  - **审计内容**:
    - 未来时间戳允许范围
    - 过去时间戳验证
    - 时钟偏移利用
  - **现有覆盖**: 有限
  - **发现记录**: ⚠️ 建议改进 - 允许 60 秒未来偏移，但未验证过去时间戳。攻击者可发送极旧时间戳的消息。

---

## 附录 A: 审计执行日志
| 日期 | 审计项 | 发现摘要 | 状态 |
|------|--------|---------|------|
| 2026-02-28 | Phase 0 | 侦察建档，识别 28 个审计项 | ✅ |
| 2026-02-28 | 全部 28 项 | 深度审计完成，16 项发现问题 | ✅ |

## 附录 B: 新增项跟踪
| 日期 | 新增项 ID | 来源 | 描述 |
|------|----------|------|------|
| 2026-02-28 | AUDIT-CONFIG-001 | Phase 1 审计发现 | 默认配置安全性问题 |
| 2026-02-28 | AUDIT-GOSSIP-001 | Phase 1 审计发现 | Gossip 洪泛攻击缺少防护 |
| 2026-02-28 | AUDIT-GOSSIP-002 | Phase 1 审计发现 | 时间戳操纵攻击风险 |

## 附录 C: 修复建议
| 审计项 | 严重级别 | 建议方案 | 修复状态 |
|--------|---------|---------|---------|
| AUDIT-CRYPTO-001 | 🔴 P0 | 使用 `zeroize` crate 实现密钥安全擦除 | ⏳ 待修复 |
| AUDIT-CRYPTO-003 | 🔴 P0 | 使用 `subtle::ConstantTimeEq` 替换 `!=` 比较 | ⏳ 待修复 |
| AUDIT-LOGIC-002 | 🔴 P0 | 实现支付超时强制执行，超时后取消 HTLC | ⏳ 待修复 |
| AUDIT-LOGIC-003 | 🔴 P0 | 添加 `u128 -> u64` 转换前的范围验证 | ⏳ 待修复 |
| AUDIT-LOGIC-004 | 🔴 P0 | 统一使用 `checked_add`/`saturating_add` | ⏳ 待修复 |
| AUDIT-LOGIC-008 | 🟠 P1 | 将 `.expect()` 替换为 `?` 错误传播 | ⏳ 待修复 |
| AUDIT-CRYPTO-004 | 🟠 P1 | 添加 revocation nonce 格式和序列验证 | ⏳ 待修复 |
| AUDIT-INPUT-003 | 🟠 P1 | 实现 UDT 通道容量验证 (gossip.rs:2334) | ⏳ 待修复 |
| AUDIT-GOSSIP-001 | 🟠 P1 | 添加 gossip 消息速率限制和队列大小限制 | ⏳ 待修复 |
| AUDIT-CONFIG-001 | 🟠 P1 | 默认绑定 127.0.0.1，禁用自动接受通道 | ⏳ 待修复 |
| AUDIT-DEPS-001 | 🟡 P2 | 评估 biscuit-auth beta 版本风险，替换 deprecated serde_yaml | ⏳ 待修复 |
| AUDIT-GOSSIP-002 | 🟡 P2 | 添加最小时间戳验证，减少未来偏移窗口 | ⏳ 待修复 |
| AUDIT-MEMORY-002 | 🟡 P2 | 添加 HashMap 大小限制，实现反压机制 | ⏳ 待修复 |
| AUDIT-ERRINFO-001 | 🟡 P2 | 减少验证错误消息中的内部状态详情 | ⏳ 待修复 |
| AUDIT-SERDE-002 | 🟢 P3 | 考虑严格化 hex 格式验证 | ⏳ 待修复 |
| AUDIT-LOGIC-005 | 🟡 P2 | 承诺交易金额计算添加溢出检查 | ⏳ 待修复 |
