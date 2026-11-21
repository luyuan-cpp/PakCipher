# PakCipher

PakCipher 是一个离线文件夹加密工具。使用接收方的 OpenPGP RSA 公钥生成单个 `.pak` 文件，再用对应的私钥恢复原始目录结构。CLI 和桌面 GUI 共用同一套归档格式。

## 构建和运行

```sh
cargo build --locked --release --workspace
cargo test --locked --workspace --release
```

上述命令的产物在 `target/release/`。GitHub Actions 会在下列平台构建并运行集成测试，产物位于对应运行记录的 **Artifacts** 区域。下载后先解压 GitHub 提供的 ZIP，再解开其中的 `.tar.gz`（如有）。

| 平台 | 架构 | CLI 和桌面程序 |
| --- | --- | --- |
| Windows | x64 | `pakcipher.exe` 和 `pakcipher-gui.exe` |
| Linux | x64、ARM64 | `.tar.gz` 内含 `pakcipher` 和 `pakcipher-gui` |
| macOS | Intel、Apple Silicon | `.tar.gz` 内含 `pakcipher` 和 `PakCipher.app` |

### Windows

Windows 发布版使用 MSVC 工具链静态链接 C 运行库，以便在未安装 Visual C++ 运行库的 Windows 上运行。使用 PowerShell 本地构建时，产物位于 `target/x86_64-pc-windows-msvc/release/`。

```powershell
$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = '-C target-feature=+crt-static'
cargo build --locked --workspace --release --target x86_64-pc-windows-msvc
```

### Linux

CI 的 Linux 产物基于 Ubuntu 22.04 构建。在 Ubuntu 上从源码构建桌面版时，先安装以下依赖。

```sh
sudo apt-get install pkg-config libgl1-mesa-dev libxkbcommon-dev libwayland-dev libx11-dev
cargo build --locked --release --workspace
```

在 X11 或 Wayland 桌面会话中运行 `./pakcipher-gui`。GUI 的文件选择器使用桌面的 XDG Desktop Portal，需要处于活跃的图形会话，并安装桌面环境对应的 Portal 后端。CLI 可以在终端或无桌面环境中运行。

### macOS

在构建前安装 Xcode 命令行工具。构建完成后，可以直接运行 `target/release/pakcipher-gui`，或打包成 Finder 可打开的 `PakCipher.app`。

```sh
cargo build --locked --release --workspace
bash scripts/package-macos.sh target/release target/pakcipher-macos.tar.gz
```

macOS CI 产物使用 ad hoc 签名，未经 Apple 公证。下载时请选择与 Mac 处理器匹配的架构。

## 准备密钥

接收方可使用 GnuPG 生成包含 RSA 加密子密钥的证书，然后将公钥导出给发送方。将下面的邮箱替换为自己的邮箱。

```sh
gpg --quick-generate-key "PakCipher User <user@example.com>" rsa4096 cert,sign
gpg --list-keys --with-fingerprint user@example.com
gpg --quick-add-key YOUR_FINGERPRINT rsa4096 encr
gpg --armor --output public.key --export YOUR_FINGERPRINT
gpg --armor --output private.key --export-secret-keys YOUR_FINGERPRINT
```

公钥可以发给加密方。私钥由接收方保管。PakCipher 直接读取 ASCII 装甲或二进制 OpenPGP 密钥文件，运行时无需安装 GnuPG。加密前通过双方信任的渠道核对公钥指纹。

## CLI

```sh
pakcipher encrypt ./photos --key-file ./public.key --output ./photos.pak
pakcipher decrypt ./photos.pak --key-file ./private.key --output ./photos-restored --ask-passphrase
```

私钥没有口令时，省略 `--ask-passphrase`。输出的上级目录必须已存在，目标路径必须是新文件或新目录。加密包要写在源目录之外。解密还原目录内容，而输出目录名由调用者选择。

## GUI

打开 `pakcipher-gui`，在 **Encrypt** 页选择源目录、公钥和归档路径，或在 **Decrypt** 页选择归档、私钥和新的输出目录。加密和解密在后台运行，各自的页面会显示进度和操作结果，成功后保留 100% 进度条。使用受保护私钥时，在解密页输入口令。

## 归档格式 v1

整数使用小端序。头部为 `PAKC`、两字节版本号 `1` 和六字节保留字段。头部之后依次是 `u32` 密钥封装长度、OpenPGP RSA 加密的 32 字节随机种子封装、`u32` 条目数、`u64` 明文字节总数和条目序列。封装本身是一个 OpenPGP 加密消息。

条目以 `u16` 路径字节数、UTF-8 相对路径和 `u64` 原始大小开头。路径用斜杠分隔，目录条目用 `u64::MAX` 标记且没有数据。普通文件以 1 MiB 为上限分块用 AES-256-GCM 加密，每块附 16 字节标签。空文件也有一个标签。96 位 nonce 由从零开始的 `u32` 条目序号和 `u64` 块序号组成，条目头作为附加认证数据。

HKDF-SHA256 从归档种子派生两个独立的 32 字节密钥。盐为 `PakCipher v1`，两次派生的 info 分别为 `content AES-256-GCM` 和 `archive HMAC-SHA256`，均为 ASCII 字节。32 字节 HMAC-SHA256 尾部覆盖前面所有字节。恢复前先验证整个归档的 HMAC，写入文件前再验证对应块的 GCM 标签。

文件名、目录名和大小可从归档读取。空目录会恢复，符号链接和 Windows 重解析点会被拒绝。归档保存目录结构和文件内容。使用由自己控制的源目录和输出上级目录，操作期间避免并发修改。进程被强制终止时，可能留下未完成的输出。
