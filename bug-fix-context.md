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

待分析...

## Known Bugs

1. **test_send_payment_with_same_invoice** - 不稳定测试 (flaky test)
   - 模块: `fnn fiber::tests::payment`
   - 状态: 不稳定 - 有时通过，有时失败
   - 问题: 竞态条件 - 3个节点同时用同一个 invoice 发送支付
   - 预期: 只有 1 个成功，但实际可能 0 或 >1 成功
   - 注意: 这是一个时序敏感的测试

## What Works

(None yet — baseline established)

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
