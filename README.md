# Folder Lock

一个 Windows 文件夹加密/隐藏工具。将 `folder_lock.exe` 放入任意文件夹运行，即可用密码保护整个文件夹。

## 两种加密模式

| 模式 | 速度 | 安全性 | 原理 |
|------|------|--------|------|
| **完全加密** | 较慢（逐文件加密） | 最高 | AES-256-GCM 加密所有文件内容 |
| **简单加密** | 瞬时（大文件夹也秒完成） | 中等 | NTFS ADS 流隐藏文件，AES 仅加密文件名清单 |

### 完全加密
- 使用 AES-256-GCM 认证加密保护每个文件
- 密钥由 Argon2id（64 MiB / 3 轮）从密码派生，抗暴力破解
- 文件内容完全不可读，vault 被篡改也会被 GCM 标签检测

### 简单加密
- 文件原始内容存入 NTFS Alternate Data Streams（`文件:流名`）
- 文件本体设为隐藏+系统属性，ADS 在资源管理器和普通 `dir` 中完全不可见
- 仅文件名清单（manifest）用 AES-256-GCM 加密
- 适合大文件夹，速度极快

> **注意**：简单加密只"隐藏"文件而不加密内容。任何能读取 ADS 的工具（如 `dir /r`）都能看到文件数据。

## 使用方式

### GUI 程序（`folder_lock.exe`）

1. 将 `folder_lock.exe` 复制到目标文件夹
2. 双击运行
3. 选择加密模式（完全加密 / 简单加密）
4. 设置密码并确认
5. 加密完成后，文件夹内除 exe 外所有文件消失
6. 再次运行输入密码即可解密恢复

### 命令行（`flock_cli.exe`）

```cmd
flock_cli status                              查看文件夹状态
flock_cli encrypt <密码>                      完全加密
flock_cli encrypt-simple <密码>               简单加密
flock_cli decrypt <密码>                      解密
```

## 技术细节

| 组件 | 说明 |
|------|------|
| 加密算法 | AES-256-GCM（认证加密） |
| 密钥派生 | Argon2id，64 MiB 内存，3 轮迭代 |
| 随机数 | 每次加密生成随机 salt（16 字节）+ nonce（12 字节） |
| Vault 文件 | `.flockvault` — 隐藏+系统属性，包含 salt + 模式 + 加密清单 |
| ADS 载体 | `.flockhost` — 隐藏+系统属性，承载所有文件的 ADS 流（简单模式） |
| 图标 | 文件夹+锁简约风格 |
| 界面 | Win32 原生对话框，Segoe UI 字体，DWM 深色标题栏，Win11 圆角 |

## Vault 格式

```
[salt: 16 bytes]            明文 salt
[mode: 1 byte]              0 = 完全加密，1 = 简单加密
[manifest ciphertext...]    nonce || AES-256-GCM(manifest)
```

解密时自动检测模式，无需用户指定。

## 构建

```cmd
cargo build --release
```

需要 Rust GNU 工具链 + LLVM MinGW（提供 `windres` 用于编译图标资源）。

## 安全须知

- **密码不可找回** — 无后门，忘记密码则无法解密
- 简单加密模式的文件内容未经加密存储，仅通过 NTFS ADS 隐藏
- 建议重要文件使用完全加密模式
- 不要在非 NTFS 卷（如 FAT32/exFAT/U盘）上使用简单加密，ADS 不支持
