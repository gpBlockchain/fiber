# Bug-Fix Context

## Project Understanding

Fiber Network - 基于 Nervos CKB 的点对点支付/交换网络，类似于 Lightning Network。
主要组件：
- fiber-lib: 核心库
- fiber-cli: CLI 工具
- fiber-types: 类型定义
- fiber-store: 存储
- fiber-json-types: JSON 类型

## Test Coverage Gaps

1. **config.rs** - NO TESTS (592 lines)
2. **key.rs** - NO TESTS (139 lines)
3. **in_flight_ckb_tx_actor.rs** - NO TESTS (340 lines)
4. **payment.rs** - Partial coverage (SendPaymentDataBuilder validation needs tests)
5. **channel.rs** - Partial coverage (state transition validation needs tests)
6. **network.rs** - Minimal tests (1 test only for 5,771 lines)

## Known Bugs

1. **test_send_payment_with_same_invoice** - 不稳定测试 (flaky test)
   - 模块: `fnn fiber::tests::payment`
   - 状态: 不稳定 - 有时通过，有时失败
   - 问题: 竞态条件 - 3个节点同时用同一个 invoice 发送支付
   - 预期: 只有 1 个成功，但实际可能 0 或 >1 成功
   - 注意: 这是一个时序敏感的测试

## What Works

1. **fee.rs tests** - 14 new unit tests added and passing
   - `calculate_fee_with_base` - fee calculation with overflow checking
   - `calculate_tlc_forward_fee` - TLC forwarding fee calculation
   - `calculate_commitment_tx_fee` - commitment transaction fee
   - `calculate_shutdown_tx_fee` - shutdown transaction fee

## What Doesn't Work

(None yet)

## Ideas Backlog — Tests to Write

1. 边界条件测试
2. 错误路径测试
3. 并发测试
4. 缺失的单元测试

## Ideas Backlog — Bugs to Fix

1. 调查并修复 `test_send_payment_with_same_invoice` 失败

## Categories Tried

| Category | Type | Attempts | Kept | Last Tried |
|----------|------|----------|------|------------|
