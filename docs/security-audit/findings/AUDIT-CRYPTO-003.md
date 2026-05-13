# AUDIT-CRYPTO-003 — 钱包私钥加密/解密

| 字段 | 值 |
|---|---|
| 维度 | DIM-CRYPTO + DIM-INPUT |
| 优先级 | 🔴 P0-Critical |
| 状态 | **[!] 多项建议改进 — Medium × 2, Low × 3, Design × 1** |
| 审计会话 | S1 (2026-05-13) |

## 1. 范围

- `crates/fiber-lib/src/utils/encrypt_decrypt_file.rs` — 加密/解密原语 (scrypt + AES-256-GCM)
- `crates/fiber-lib/src/ckb/config.rs:114-146` — `read_secret_key` 启动入口
- `crates/fiber-lib/src/fiber/key.rs` — P2P 身份密钥 (**未加密**)

## 2. 分析

### 2.1 加密格式

```
| VERSION(1) | SALT(16) | NONCE(12) | CIPHERTEXT(N) || TAG(16) |
```

- `VERSION = 0x00`（写入端固定）。
- `salt` / `nonce` 由 `rand::thread_rng()` (ChaCha20-based, CSPRNG) 生成。
- 密钥派生 `scrypt(password, salt, Params::recommended(), 32B)`。

### 2.2 逐项 finding

#### F1 — VERSION 字节读但**从未校验** (🟡 Medium)

`decrypt_from_file` (`encrypt_decrypt_file.rs:48-51`):
```rust
let file_bytes = fs::read(file).unwrap();
let salt = &file_bytes[1..SALT_LEN + 1];
let nonce = &file_bytes[SALT_LEN + 1..SALT_LEN + NONCE_LEN + 1];
let ciphertext = &file_bytes[SALT_LEN + NONCE_LEN + 1..];
```
跳过了 `file_bytes[0]` (VERSION)，但**从未断言**它等于 `VERSION = 0`。

影响：未来若引入 v1 格式（如 scrypt 参数升级），v0 节点读取 v1 文件会得到错误的 salt/nonce 切分但仍尝试 AES-GCM 解密 → 错误信息含糊；攻击者可借此构造旧格式回滚以利用更弱的旧 KDF 参数。

#### F2 — 缺少长度校验，短文件触发 panic (🟡 Medium — robustness / DoS)

若 `file_bytes.len() < 1 + SALT_LEN + NONCE_LEN + 16`（16 = AES-GCM tag 最小），上述切片越界会 panic。

最小有效密文长度 = 1 + 16 + 12 + 16 = **45 字节**；任何更短文件 → panic。

影响：
- 任意写入 `<data-dir>/ckb/key` 为 1 字节的攻击者（本地权限失误、备份恢复脚本错误、WASM 浏览器 IndexedDB 篡改）可让节点启动崩溃。
- 在 WASM 环境下，IndexedDB 数据被同源页面读写，可能更易触达。

#### F3 — `fs::read(file).unwrap()` panic 不优雅 (🟢 Low)

同 F2 入口：若 `path` 在解密时已不存在/无权限，整个进程 panic 而非返回 `Err`。

#### F4 — 无 zeroize / 敏感数据残留 (🟢 Low；TODO 注释已存在)

- `derive_key_from_password` 中的 `let mut key = [0u8; 32]` 在函数返回后未显式 `zeroize`。Rust 栈帧 drop 不保证清零。
- `password_bytes` 来自 `std::env::var(...)` —— `String` 在 drop 时不会 zeroize。
- `decrypt_from_file` 返回 `Vec<u8>`，上层 `read_secret_key` 把它喂给 `SecretKey::from_slice` 后 `Vec` drop，但内容可能残留。
- `fiber/key.rs:8` 已经留有 `// TODO: we need to securely erase the key.`，是已知问题。

影响：内存取证 / coredump / swap 文件中可能恢复出私钥。资金敏感系统下应根除。

#### F5 — 配置层"明文→加密"迁移路径 (🟢 Low)

`ckb/config.rs:126-138`：
```rust
if let Ok(plain_key_hex) = fs::read_to_string(&path) {
    ...
    encrypt_to_file(&path, plain_key.as_ref(), password_bytes)?;
}
```
- `encrypt_to_file` 使用 `OpenOptions::new().create(true).truncate(true).write(true)` —— 原文件被截断覆写；但**未 fsync**，在断电场景下可能留下半写状态。
- 旧的明文 hex 字符串仍可能存在于 RocksDB / WAL / 文件系统 journal 中。
- 没有覆写多遍或 `shred` 行为。
- `plain_key_hex` 是 `String`，drop 时不 zeroize。

#### F6 — P2P 身份密钥 (`fiber/key.rs::KeyPair`) **明文落盘** (🟡 Medium — 设计性)

`fiber/key.rs:40-60` 写文件时虽然设置了 `0o400` 权限，但**没有任何加密**。`SecioKeyPair` 派生自该 32 字节明文。

虽然 P2P 身份密钥不直接控制链上资产（仅控制对端识别和 onion service 身份），但：
- 它被用于 `node_signature`（`channel.rs:5415` `sign_network_message`），间接绑定 channel announcement。
- 泄露后攻击者可在网络上冒充本节点（与已建立的远端通道伪造合法对话）。

建议同等加密（同 `encrypt_decrypt_file` 路径），或至少与 CKB 钱包密钥统一密码门控。

#### F7 — `Debug` bound on path (信息性)

`decrypt_from_file<P: AsRef<Path> + Debug>` —— path 若在 panic 消息中被打印，会泄露 keyfile 路径（一般属合理日志信息，但严格化建议移除 `Debug`）。

### 2.3 不构成 finding 的点（✅ 通过）

- `scrypt::Params::recommended()` — 当前推荐参数 (N=17, r=8, p=1)，OK。
- AES-256-GCM 96-bit random nonce — 碰撞概率 ≈ 2⁻⁹⁶/(N²)，单一文件场景可忽略。
- `Aes256Gcm` 来自 RustCrypto，无已知 CVE（见 AUDIT-DEP-001）。
- 文件权限 `0o400` 写入路径在 `fiber/key.rs::write_to_file` 中正确设置（但加密文件路径 `encrypt_to_file` **未显式设置 0o400**，依赖 umask — 见 F8）。

#### F8 (隐性) — `encrypt_to_file` 未显式设置 0o400 权限 (🟢 Low)

`encrypt_to_file` 写完后使用 `fs::write`，权限由 umask 决定。虽然内容已加密，但仍建议显式 chmod 0o400，对齐 `fiber/key.rs` 行为。

## 3. 关键代码引用

```rust
// crates/fiber-lib/src/utils/encrypt_decrypt_file.rs:44-58
pub fn decrypt_from_file<P: AsRef<Path> + Debug>(
    file: P,
    password: &[u8],
) -> Result<Vec<u8>, String> {
    let file_bytes = fs::read(file).unwrap();   // ← F3 panic
    let salt = &file_bytes[1..SALT_LEN + 1];    // ← F2 panic if too short
    let nonce = &file_bytes[SALT_LEN + 1..SALT_LEN + NONCE_LEN + 1];
    let ciphertext = &file_bytes[SALT_LEN + NONCE_LEN + 1..];
    // ← F1 VERSION 未校验
    let key = derive_key_from_password(password, salt);
    let cipher = Aes256Gcm::new(&key);
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|err| format!("decryption failed: {}", err))
}
```

## 4. 修复建议

```rust
pub fn decrypt_from_file<P: AsRef<Path>>(
    file: P,
    password: &[u8],
) -> Result<Vec<u8>, String> {
    const MIN_LEN: usize = 1 + SALT_LEN + NONCE_LEN + 16; // tag is 16
    let file_bytes = fs::read(&file)
        .map_err(|e| format!("failed to read key file: {e}"))?;
    if file_bytes.len() < MIN_LEN {
        return Err("key file is too short / corrupted".into());
    }
    if file_bytes[0] != VERSION {
        return Err(format!("unsupported key file version: {}", file_bytes[0]));
    }
    let salt = &file_bytes[1..1 + SALT_LEN];
    let nonce = &file_bytes[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN];
    let ciphertext = &file_bytes[1 + SALT_LEN + NONCE_LEN..];

    let key = derive_key_from_password(password, salt);    // 见下方 zeroize
    let cipher = Aes256Gcm::new(&key);
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|err| format!("decryption failed: {err}"))
}
```

并将 `derive_key_from_password` 改为返回 `zeroize::Zeroizing<[u8; 32]>` / `Key<Aes256Gcm>` 包装，所有 `plain_key` / `password` 改用 `zeroize` 类型。

P2P 密钥 (`fiber/key.rs`)：评估在 `read_or_generate` 路径接入同一加密格式（或独立的 `fiber/key` 加密文件），由 `FIBER_SECRET_KEY_PASSWORD` 统一保护。

## 5. 新增审计项

- **AUDIT-CRYPTO-003-FOLLOWUP-A**：评估 `fiber/key.rs::KeyPair` 明文落盘的修复方案与回退兼容性。
- **AUDIT-INPUT-006**：审查项目内所有 `fs::read(...).unwrap()`，列入 DIM-INPUT。

## 6. 结论

不构成可远程利用漏洞（密钥文件本地化），但启动鲁棒性、加密格式版本化、密钥内存生命周期、设计性密钥统一管理仍需改进。优先级：F1/F2 ≥ F6 > F3/F4/F5/F8。
