# AUDIT-XMOD-004 — RPC ↔ Invoice ↔ CCH 解析 panic 多入口共享

| 字段 | 值 |
|---|---|
| 维度 | DIM-XMOD (跨模块) |
| 严重度 | 🟠 **High**（远程零授权全进程崩溃；至少 3 个入口） |
| 状态 | [!] 发现弱设计（静态可达，无 PoC） |
| 出处 | 本次跨模块审计补强；基于 AUDIT-INPUT-002 与 "invoice parsing DoS" 记忆扩展 |
| 关联代码 | `crates/fiber-types/src/invoice.rs:610,887,902,1024,1042,1052,1085,1088`（多处 `.expect()` / `panic!`：ar_decompress、Description/FallbackAddr UTF-8、PayeePublicKey from_slice）<br>`crates/fiber-lib/src/rpc/invoice.rs:289-300, 302-369`（`parse_invoice`、`new_invoice`）<br>`crates/fiber-lib/src/rpc/payment.rs:315-343`（`send_payment` 接 invoice 字符串）<br>`crates/fiber-lib/src/cch/actor.rs:450-457, 628`（`receive_btc` 调 invoice 解析）<br>`crates/fiber-lib/src/rpc/mod.rs:160`（jsonrpsee Server 默认无 panic guard） |
| 关联 finding | AUDIT-INPUT-002（invoice panic 总账）、AUDIT-INPUT-003（RPC body size / conns）、AUDIT-SPEC-002.F6/F7（fallback addr 规范） |

## 1. 现象

`CkbInvoice::from_str` 内部多处用 `.expect()` 或 `panic!` 处理解码错误，可直接 panic Rust thread。这些 panic 通过 **三个独立跨模块入口** 都能被远程攻击者触发：

1. **JSON-RPC `parse_invoice`**（`rpc/invoice.rs:289-300`）：任意远端 client（若启用 `enable_auth=false` 或私网默认）一行调用即可。
2. **JSON-RPC `send_payment` 的 `invoice: String` 字段**（`rpc/payment.rs:315-343`）：相同 panic 面，鉴权要求更松（同一 RPC 模块）。
3. **CCH `receive_btc` 接受 LND 上游 bolt11**（`cch/actor.rs:628`）：攻击者只需是 *LN 主网* 任一节点能 route 到 CCH 即可送入恶意 invoice 字符串；CCH 在 fiber 侧的预处理对 bolt11 调 `CkbInvoice::from_str` 类似路径（或 fiber-types 共享 panic 函数）。

具体 panic 触发点（来自记忆 + grep）：
- `invoice.rs:887, 902`：`ar_decompress` / UTF-8 decode `.expect()`；
- `invoice.rs:1024, 1042, 1052`：Description / FallbackAddr UTF-8 `.expect()`；
- `invoice.rs:1085, 1088`：PayeePublicKey `from_slice` `.expect()`；
- `invoice.rs:610`：`panic!` 分支。

jsonrpsee `Server::builder()` **不**在请求级别 catch_unwind（panic 直接终止 Tokio worker → 进程级 `panic = abort` 默认 unwind 但若有 `panic = abort` 则直接退）。

## 2. 跨模块攻击链

```
任意 LN 节点 ──→ CCH receive_btc(bolt11=<恶意>) ──┐
RPC 客户端 ─────→ parse_invoice(invoice=<恶意>)  ─┤── ckb-invoice::from_str ─┐
RPC 客户端 ─────→ send_payment(invoice=<恶意>)   ─┘                         │
                                                                            ▼
                                                  .expect()/panic!  ── crash thread ── 进程退出
```

无需鉴权（CCH 入口在 LN 路径上完全无 fiber 侧鉴权；私网 RPC 默认 `enable_auth=false`）。

## 3. 与已有发现的区别

- AUDIT-INPUT-002 已点名 invoice 内部 panic，但只把它作为"内部错误处理"问题；
- 本条强调"**同一 panic 面被 3 个跨模块入口共享**"，特别是 CCH 入口（攻击者不需要直连 fiber RPC，只需要 LN 网络可达 CCH）。
- 与 AUDIT-INPUT-003（RPC 限流）正交：即便严格限流，单条 invoice 即可崩溃。

## 4. 攻击场景

### 4.1 远程 LN → CCH crash
攻击者作为 LN routing peer，向 CCH 发起一笔 BTC payment 把 `description` 字段塞满非 UTF-8 字节（或构造无效 PayeePublicKey）→ CCH actor 解析 → `from_slice.expect()` panic → `cch_actor` 退出 → 整个 fiber 进程因 ractor supervisor 设置可能进一步 panic（参见 AUDIT-XMOD-009）。

### 4.2 浏览器 RPC → 节点 crash
通过 CORS fall-through（AUDIT-XMOD-005.F2）或私网默认无鉴权，浏览器 evil.com POST `parse_invoice` 一次 → 节点 panic。

### 4.3 持续重启 → 永久 DoS
节点重启后若 watchdog 自动复活，攻击者重复发同一 invoice → 拒绝服务无上限。

## 5. 影响评估

- **可用性**：远程零授权全进程崩溃；
- **资金**：进程崩溃期间 watchtower 无法响应链上 cheat tx（窗口期 = 启动到下次 periodic_check 时间）→ 转化为资金风险（与 AUDIT-XMOD-006 协同）；
- **审计追踪**：crash 日志可能不写到磁盘，溯源困难。

## 6. 修复建议（FOLLOWUP）

| 编号 | 优先级 | 修复要点 |
|---|---|---|
| F1 | P0 | `invoice.rs` 所有 `.expect()` / `panic!` 改为 `Result<_, InvoiceParseError>`；上层 `From → TryFrom`。复用 AUDIT-INPUT-002.F1。 |
| F2 | P0 | 3 个入口（`parse_invoice` / `send_payment` / `cch.receive_btc`）外层加 `std::panic::catch_unwind` 包装（短期止血）；返回 RPC error / cch 拒绝订单。 |
| F3 | P1 | jsonrpsee 中间件层统一 `catch_unwind` middleware，所有 RPC 方法默认 panic→500，不再让 panic 冒泡到 Tokio worker。 |
| F4 | P1 | CCH `receive_btc` 在调 invoice 解析前对长度/字符集做 cheap pre-filter（长度 ≤ 2KB，prefix 必须 `lnbc`/`ckbinvoice`）。 |
| F5 | P1 | 单元 fuzz：`cargo fuzz add invoice_decode`，corpus 至少覆盖 8 个已知 panic 点。 |

## 7. 验证测试

- `invoice::tests::test_panic_paths_now_return_err`：8 个已知 panic 输入逐个断言 `Err`。
- `rpc::invoice::tests::test_parse_invoice_panic_isolation`：在 jsonrpsee 内部触发 panic，断言 server 仍存活。
- `cch::tests::test_receive_btc_malformed_bolt11`：恶意 bolt11 返回 `OrderRejected`，不 crash actor。

## 8. 状态

- F1+F2 必须同时合入才算消项；F3 中期；F4/F5 深度防御。
- 关联 PR：暂无。
