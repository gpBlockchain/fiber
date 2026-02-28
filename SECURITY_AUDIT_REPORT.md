# 安全审计报告: Fiber Network Node

## 1. 执行摘要

### 项目信息
- **项目名称**: Fiber Network Node (FNN)
- **项目类型**: 区块链 P2P 支付网络节点 (类似 Lightning Network，基于 CKB 区块链)
- **编程语言**: Rust 1.93.0
- **审计日期**: 2026-02-28
- **审计范围**: 核心库 (fiber-lib) 全部源码，重点覆盖通道管理、支付路由、密码学操作、Gossip 协议、RPC 接口
- **审计方法**: 静态代码审查 (正向逻辑审查 + 逆向攻击思维 + 上下文关联审查)

### 关键数字
| 指标 | 数值 |
|------|------|
| 审计项总数 | 28 |
| 发现问题数 | 16 |
| Critical 级别 | 5 |
| High 级别 | 5 |
| Medium 级别 | 4 |
| Low 级别 | 2 |
| 通过项 | 12 |

---

## 2. 风险评级

| 级别 | 数量 | 描述 |
|------|------|------|
| ■ Critical (P0) | 5 项 | 可导致资金损失、协议绕过或节点崩溃 |
| ■ High (P1) | 5 项 | 可导致功能异常、安全降级或 DoS |
| ■ Medium (P2) | 4 项 | 可导致信息泄露、配置风险或性能下降 |
| ■ Low (P3) | 2 项 | 代码质量改进建议 |

---

## 3. 关键发现（按严重级别降序）

### 3.1 Critical (P0) 级别发现

#### ❌ FINDING-001: u128 到 u64 类型转换无验证导致静默截断
- **审计项**: AUDIT-LOGIC-003
- **严重级别**: 🔴 Critical
- **影响**: 通道结算金额可能被错误截断，导致资金损失
- **描述**: 在通道关闭/结算逻辑中，`to_local_amount` 和 `to_remote_amount` 存储为 `u128` 类型，但在构建关闭交易时直接通过 `as u64` 转换，无任何范围验证。若 UDT 通道中的金额超过 `u64::MAX` (约 18.4 × 10¹⁸)，转换将静默截断低 64 位，导致结算交易金额严重错误。
- **复现路径**:
  1. 打开一个 UDT 通道，金额接近 u128 范围
  2. 触发协作关闭流程
  3. `build_shutdown_tx` 中 `self.to_local_amount as u64` 将静默截断
- **代码引用**:
  ```rust
  // src/fiber/channel.rs:7500-7502
  let local_value = self.to_local_amount as u64 + self.local_reserved_ckb_amount - local_shutdown_fee;
  let remote_value = self.to_remote_amount as u64 + self.remote_reserved_ckb_amount - remote_shutdown_fee;
  
  // src/fiber/channel.rs:5880
  (self.to_remote_amount as u64 + self.remote_reserved_ckb_amount)
  ```
- **修复建议**:
  ```rust
  let local_value: u64 = self.to_local_amount
      .try_into()
      .map_err(|_| ProcessingChannelError::InvalidState("Amount exceeds u64 range".into()))?;
  let local_value = local_value + self.local_reserved_ckb_amount - local_shutdown_fee;
  ```

---

#### ❌ FINDING-002: 路由费用计算多处未检查整数溢出
- **审计项**: AUDIT-LOGIC-004
- **严重级别**: 🔴 Critical
- **影响**: 支付路由金额可能溢出导致错误路由或资金损失
- **描述**: 在路径查找和费用计算中，多处算术运算未使用安全方法（`checked_add`/`saturating_add`），而相同模块的其他路径已正确使用了安全算术。这种不一致性表明是遗漏而非设计决策。
- **代码引用**:
  ```rust
  // src/fiber/graph.rs:1965 - 费用累加 (u128 + u128)
  amount_to_send: next_hop_received_amount + fee,
  
  // src/fiber/graph.rs:1967 - 过期时间累加 (u64 + u64)
  incoming_tlc_expiry: incoming_tlc_expiry + tlc_expiry_delta,
  
  // src/fiber/graph.rs:1814 - 三值相加 (u64 + u64 + u64)
  expiry: now + r.incoming_tlc_expiry + rand_tlc_expiry_delta,
  
  // src/fiber/graph.rs:1837 - 相同模式
  expiry: now + last_expiry_delta + rand_tlc_expiry_delta,
  
  // src/fiber/graph.rs:1492 - Trampoline 路由
  amount_to_forward: final_amount + (fees[idx + 1..].iter().sum::<u128>()),
  ```
- **对比**: 同文件中的正确实现:
  ```rust
  // graph.rs:2347 - 正确使用 saturating_add
  let amount_to_send = next_hop_received_amount.saturating_add(fee);
  ```
- **修复建议**: 统一使用 `checked_add()` 或 `saturating_add()`，对 `checked_add` 返回 `None` 的情况返回 `PathFindError`。

---

#### ❌ FINDING-003: Payment hash 比较使用非恒定时间操作
- **审计项**: AUDIT-CRYPTO-003
- **严重级别**: 🔴 Critical
- **影响**: 攻击者可通过时序分析推断正确的 preimage
- **描述**: 支付哈希验证使用标准 `!=` 运算符进行字节比较。这允许攻击者通过测量响应时间差异来逐字节猜测正确的 payment preimage，理论上将 256 位的安全性降低到每次尝试 ~8 位。
- **代码引用**:
  ```rust
  // src/fiber/channel.rs:1277
  if add_tlc.payment_hash != filled_payment_hash {
      return Err(ProcessingChannelError::FinalIncorrectPreimage);
  }
  
  // src/fiber/channel.rs:1347
  if tlc.payment_hash != hash {
      // ...
  }
  
  // src/fiber/channel.rs:1352
  if tlc.payment_hash != hash {
      // ...
  }
  ```
- **修复建议**:
  ```rust
  use subtle::ConstantTimeEq;
  if !bool::from(add_tlc.payment_hash.as_ref().ct_eq(filled_payment_hash.as_ref())) {
      return Err(ProcessingChannelError::FinalIncorrectPreimage);
  }
  ```

---

#### ❌ FINDING-004: 支付超时未强制执行，HTLC 可被无限锁定
- **审计项**: AUDIT-LOGIC-002
- **严重级别**: 🔴 Critical
- **影响**: 支付资金可被无限期锁定，造成流动性攻击
- **描述**: 支付 API 接受 `timeout` 参数（`src/fiber/payment.rs:471`），但该参数被存储后从未在任何逻辑中检查。`handle_check_payment_status` 函数只在 Actor 停止时记录警告日志，但不取消待处理的 HTLC 或将支付标记为失败。这使得中间节点可以无限期持有支付，锁定发送方的流动性。
- **代码引用**:
  ```rust
  // src/fiber/payment.rs:1561-1593
  fn handle_check_payment_status(...) {
      if session.status.is_final() {
          myself.stop(...);
      } else {
          // Line 1581-1593: 仅记录警告，不取消支付!
          warn!("Payment {:?} is still not final...");
          myself.stop(...);  // 停止 Actor 但支付保持 "Inflight"
      }
  }
  ```
- **修复建议**: 实现超时检查逻辑，在超时后主动取消所有相关 HTLC 并将支付标记为失败。

---

#### ❌ FINDING-005: 密钥材料使用后未安全擦除
- **审计项**: AUDIT-CRYPTO-001
- **严重级别**: 🔴 Critical
- **影响**: 进程崩溃或核心转储可暴露私钥
- **描述**: `KeyPair` 结构体包装 `[u8; 32]` 数组存储 secp256k1 私钥，但 Drop 时不清零内存。代码中明确存在 TODO 注释承认此问题。在进程崩溃、核心转储或内存换页到磁盘的情况下，私钥可能被恢复。
- **代码引用**:
  ```rust
  // src/fiber/key.rs:6
  // TODO: we need to securely erase the key
  
  // src/fiber/key.rs:8
  pub struct KeyPair(pub(crate) [u8; 32]);
  ```
- **修复建议**:
  ```rust
  use zeroize::Zeroize;
  
  #[derive(Zeroize)]
  #[zeroize(drop)]
  pub struct KeyPair(pub(crate) [u8; 32]);
  ```

---

### 3.2 High (P1) 级别发现

#### ⚠️ FINDING-006: Gossip 消息无速率限制，存在洪泛攻击风险
- **审计项**: AUDIT-GOSSIP-001
- **严重级别**: 🟠 High
- **影响**: 恶意节点可耗尽目标节点的 CPU/内存/带宽
- **描述**: Gossip 协议缺乏任何形式的速率限制。恶意对等方可发送无限量的消息，每条消息都触发完整的验证流程（包括链上查询）。`messages_to_be_saved` HashMap 无大小限制，可导致内存耗尽。
- **代码引用**:
  ```rust
  // src/fiber/gossip.rs:1685-1692
  ExtendedGossipMessageStoreMessage::SaveMessages(peer, messages) => {
      for message in messages {
          if let Err(error) = state.insert_message_to_be_saved_list(&peer, &message).await {
              trace!("Failed to save message: {:?}, error: {:?}", message, error);
          }
      }
  }
  ```
- **修复建议**: 
  1. 添加每对等方消息速率限制（令牌桶算法）
  2. 限制 `messages_to_be_saved` HashMap 大小
  3. 超过限制后断开恶意对等方连接

---

#### ⚠️ FINDING-007: Revocation Nonce 未验证即使用
- **审计项**: AUDIT-CRYPTO-004
- **严重级别**: 🟠 High
- **影响**: 可能导致撤销签名无效或重放攻击
- **描述**: 从对等方接收的 `next_revocation_nonce` 未经验证即存储和使用。Nonce 清除逻辑将 `remote_revocation_nonce_for_verify` 设置为 None，如果后续流程未正确重新设置，可能允许重放之前的撤销签名。
- **代码引用**:
  ```rust
  // src/fiber/channel.rs:6969
  self.remote_revocation_nonce_for_next = Some(next_revocation_nonce);
  
  // src/fiber/channel.rs:6974
  self.remote_revocation_nonce_for_verify = None;
  ```
- **修复建议**: 在存储前验证 `PubNonce` 格式有效性，添加 nonce 使用追踪防止重放。

---

#### ⚠️ FINDING-008: UDT 通道容量验证未实现
- **审计项**: AUDIT-INPUT-003
- **严重级别**: 🟠 High
- **影响**: 恶意节点可宣布虚假的 UDT 通道容量
- **描述**: Gossip 协议中 UDT 通道容量验证完全缺失，存在明确的 TODO 注释。非 UDT 通道正确验证了链上容量与宣布容量的一致性，但 UDT 通道跳过了此检查。
- **代码引用**:
  ```rust
  // src/fiber/gossip.rs:2332-2335
  if channel_announcement.udt_type_script.is_some() {
      // TODO: verify the capacity of the UDT
  }
  ```
- **修复建议**: 实现 UDT 通道的链上容量验证逻辑，与非 UDT 通道保持一致。

---

#### ⚠️ FINDING-009: Payment `.expect()` 可被外部触发导致 Panic
- **审计项**: AUDIT-LOGIC-008
- **严重级别**: 🟠 High
- **影响**: 攻击者可触发支付模块 panic，导致 DoS
- **描述**: 支付验证逻辑中对 `max_fee_amount` 使用 `.expect()` 而非安全的错误传播。若代码路径中 `max_fee_amount` 为 None 时调用 validate，将导致 panic。
- **代码引用**:
  ```rust
  // src/fiber/payment.rs:338
  if amount
      .checked_add(self.max_fee_amount.expect("must got max_fee_amount"))
      .is_none()
  ```
- **修复建议**:
  ```rust
  let max_fee = self.max_fee_amount.ok_or("max_fee_amount is required")?;
  if amount.checked_add(max_fee).is_none() {
  ```

---

#### ⚠️ FINDING-010: 默认配置存在安全风险
- **审计项**: AUDIT-CONFIG-001
- **严重级别**: 🟠 High
- **影响**: 新节点以不安全的默认配置运行
- **描述**: 多个默认配置值对安全不利:
  1. **监听地址**: 默认 `0.0.0.0`（所有网络接口）
  2. **自动接受通道**: 默认开启，资金 99 CKB
  3. **自动节点宣布**: 默认开启
  4. **TLC 最小值**: 默认 0
  5. **Watchtower Token**: 明文存储在 YAML 配置文件中
- **代码引用**:
  ```rust
  // src/fiber/config.rs:21
  pub const DEFAULT_LISTENING_ADDR: &str = "/ip4/0.0.0.0/tcp/0";
  
  // src/fiber/config.rs:26-30
  // auto_accept_channel_ckb_funding_amount defaults to 99 CKB
  ```
- **修复建议**:
  1. 默认绑定 `127.0.0.1`
  2. 默认禁用自动接受通道
  3. 设置合理的 TLC 最小值
  4. 加密 Watchtower Token 或使用环境变量

---

### 3.3 Medium (P2) 级别发现

#### ⚠️ FINDING-011: 时间戳操纵攻击
- **审计项**: AUDIT-GOSSIP-002
- **严重级别**: 🟡 Medium
- **影响**: 可能导致缓存混淆或过期消息接受
- **描述**: Gossip 消息时间戳验证只检查未来 60 秒偏移，不验证过去时间戳。攻击者可使用极旧时间戳的消息污染网络。
- **代码引用**:
  ```rust
  // src/fiber/gossip.rs:97-99
  fn max_acceptable_gossip_message_timestamp() -> u64 {
      now_timestamp_as_millis_u64() + MAX_BROADCAST_MESSAGE_TIMESTAMP_DRIFT_MILLIS
  }
  ```
- **修复建议**: 添加最小时间戳验证（例如当前时间减去 4 周）。

---

#### ⚠️ FINDING-012: 资源耗尽 - Gossip HashMap 无大小限制
- **审计项**: AUDIT-MEMORY-002
- **严重级别**: 🟡 Medium
- **影响**: 内存耗尽导致节点崩溃
- **描述**: `messages_to_be_saved` HashMap 和支付重试机制 (48 次/MPP) 缺乏有效的资源限制。
- **修复建议**: 添加 HashMap 容量上限和反压机制。

---

#### ⚠️ FINDING-013: 承诺交易金额计算无溢出保护
- **审计项**: AUDIT-LOGIC-005
- **严重级别**: 🟡 Medium
- **影响**: 结算金额计算错误
- **代码引用**:
  ```rust
  // src/fiber/channel.rs:7676-7682
  let mut to_local_value =
      self.to_local_amount + received_fulfilled - offered_pending - offered_fulfilled;
  ```
- **修复建议**: 使用 `checked_add`/`checked_sub` 并正确处理溢出。

---

#### ⚠️ FINDING-014: 依赖库风险
- **审计项**: AUDIT-DEPS-001
- **严重级别**: 🟡 Medium
- **影响**: Beta 版本库可能存在未发现的漏洞
- **描述**: `biscuit-auth 6.0.0-beta.3` 为 beta 版本，`serde_yaml 0.9.34` 已标记废弃。
- **修复建议**: 评估 biscuit-auth 稳定版替代方案；迁移到 `serde_yml` 或其他维护中的 YAML 库。

---

### 3.4 Low (P3) 级别发现

#### ℹ️ FINDING-015: 错误消息包含过多内部状态信息
- **审计项**: AUDIT-ERRINFO-001
- **严重级别**: 🟢 Low
- **影响**: 可能泄露网络拓扑或通道信息
- **描述**: 部分验证错误消息包含 channel IDs、金额、对等方信息等。TlcErrPacket 正确使用 shared_secret 加密（好的做法），但 Gossip 验证错误消息过于详细。

---

#### ℹ️ FINDING-016: 自定义 Serde 格式过于宽松
- **审计项**: AUDIT-SERDE-002
- **严重级别**: 🟢 Low
- **影响**: 可能导致格式混淆
- **描述**: 支持带前缀 ("0x") 和不带前缀的 hex 字符串，宽松的格式接受可能在跨实现场景中导致不一致。

---

## 4. 审计覆盖矩阵

| 模块/组件 | INPUT | CRYPTO | AUTH | LOGIC | MEMORY | SERDE | ERRINFO | DEPS |
|-----------|-------|--------|------|-------|--------|-------|---------|------|
| channel.rs | ✅⚠️ | ✅❌ | N/A | ✅❌ | ✅ | ✅ | ✅⚠️ | N/A |
| payment.rs | ✅ | N/A | N/A | ✅❌ | ✅⚠️ | N/A | ✅ | N/A |
| graph.rs | ✅ | N/A | N/A | ✅❌ | ✅ | N/A | ✅ | N/A |
| gossip.rs | ✅⚠️ | ✅ | N/A | ✅⚠️ | ✅❌ | ✅ | ✅⚠️ | N/A |
| network.rs | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| key.rs | ✅ | ✅❌ | N/A | N/A | ✅❌ | N/A | N/A | N/A |
| types.rs | ✅ | N/A | N/A | ✅ | ✅ | ✅ | N/A | N/A |
| config.rs | N/A | N/A | ✅❌ | ✅❌ | N/A | N/A | N/A | N/A |
| rpc/* | ✅ | N/A | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| funding/* | ✅ | ✅ | N/A | ✅ | ✅ | N/A | ✅ | N/A |
| 依赖库 | N/A | N/A | N/A | N/A | N/A | N/A | N/A | ✅⚠️ |

图例: ✅ 通过 | ❌ 发现漏洞 | ⚠️ 建议改进 | N/A 不适用

---

## 5. 依赖安全状态

| 依赖 | 版本 | 状态 | 说明 |
|------|------|------|------|
| secp256k1 | 0.30.0 | ✅ 安全 | 最新稳定版 |
| musig2 | 0.2.4 | ✅ 安全 | 活跃维护 |
| aes-gcm | 0.10.3 | ✅ 安全 | 当前版本 |
| tokio | 1.x | ✅ 安全 | 长期支持 |
| tentacle | 0.7 | ✅ 安全 | P2P 网络库 |
| jsonrpsee | 0.25.1 | ✅ 安全 | RPC 框架 |
| openssl | 0.10.75 | ✅ 安全 | OpenSSL 3.5.5 |
| biscuit-auth | 6.0.0-beta.3 | ⚠️ Beta | 非稳定版本 |
| serde_yaml | 0.9.34 | ⚠️ 废弃 | 已标记 deprecated |
| molecule | 0.8.0 | ✅ 安全 | CKB 序列化框架 |
| rocksdb (ckb) | 0.21.1 | ✅ 安全 | 数据库 |

---

## 6. 改进建议（非漏洞类）

### 6.1 测试覆盖增强
1. **激活 Fuzz 测试**: 9 个 fuzz targets 已配置但未在 CI 中运行，建议添加到 CI pipeline
2. **状态机测试**: 当前仅 5 个无效转换测试，建议添加 property-based 测试覆盖完整状态机
3. **安全专项测试**: 缺少针对恶意输入、整数溢出、边界条件的专项安全测试
4. **经济攻击测试**: 缺少尘埃攻击、通道堵塞、费用提取的测试

### 6.2 代码质量
1. **算术安全**: 统一项目中的算术安全策略 — 要么全部使用 `checked_*`，要么启用 overflow-checks（已在 release profile 启用，好的做法）
2. **错误处理一致性**: 减少 `unwrap()`/`expect()` 在生产代码中的使用
3. **文档**: 为安全关键函数添加安全不变量文档

### 6.3 运维安全
1. **TLS/mTLS**: RPC 通信（特别是 Watchtower 连接）应支持 TLS
2. **监控**: 添加安全事件监控和告警（异常 gossip 消息、签名验证失败等）
3. **配置验证**: 启动时对安全敏感配置进行审查并发出警告

---

## 7. 安全审计总结

### 整体安全态势: 中等

**优势**:
- ✅ Musig2 多签名实施正确，使用两轮签名协议
- ✅ Biscuit 加密令牌认证，细粒度 RBAC
- ✅ TlcErrPacket 使用 shared_secret 加密防止错误源泄露
- ✅ Channel announcement 三重签名验证
- ✅ Release profile 启用 overflow-checks
- ✅ Onion packet 整数溢出已修复
- ✅ 资金交易验证严格（防止对等方注入恶意输入/输出）
- ✅ Actor 模型避免直接并发访问

**需改进**:
- ❌ 5 个 Critical 级别问题需要优先修复
- ❌ 算术安全策略不一致（部分路径使用 safe math，部分未使用）
- ❌ 密钥安全擦除未实现（已知 TODO）
- ❌ Gossip 协议缺乏 DoS 防护
- ❌ 支付超时机制未实现

### 修复优先级建议
1. **立即修复** (P0): FINDING-001 ~ FINDING-005
2. **尽快修复** (P1): FINDING-006 ~ FINDING-010
3. **计划修复** (P2): FINDING-011 ~ FINDING-014
4. **评估修复** (P3): FINDING-015 ~ FINDING-016

---

## 附录: 完整 TODO 文档终态

见 [SECURITY_AUDIT_TODO.md](./SECURITY_AUDIT_TODO.md)
