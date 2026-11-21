# PakCipher

PakCipher 是一个离线文件夹加密工具。使用接收方的 OpenPGP RSA 公钥生成单个 `.pak` 文件或一组加密分卷，再用对应的私钥恢复原始目录结构。CLI 和桌面 GUI 共用同一套归档格式。

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

CI 的 Linux 产物基于 Ubuntu 22.04 构建。在终端运行 `uname -m`，按照输出选择 GitHub Actions 中的产物。

| `uname -m` 输出 | 下载的产物 |
| --- | --- |
| `x86_64` | `pakcipher-linux-x64` |
| `aarch64` | `pakcipher-linux-arm64` |

#### 下载并运行

先解开 GitHub 下载的 ZIP，再解开里面的 `.tar.gz`。以下以 x64 的下载包为例，在 `.tar.gz` 所在目录运行。

```sh
mkdir -p pakcipher-linux
tar -xzf pakcipher-linux-x64.tar.gz -C pakcipher-linux
cd pakcipher-linux
./pakcipher --version
```

使用桌面版时，在 X11 或 Wayland 图形会话中运行 `./pakcipher-gui`。窗口的 `Browse…` 按钮使用 XDG Desktop Portal。如果文件选择窗口打不开，检查当前桌面会话及其 Portal 后端。Ubuntu 可用 `sudo apt install libgl1 libegl1 libxkbcommon0 xdg-desktop-portal xdg-desktop-portal-gtk` 补装常用运行依赖。无桌面服务器可直接使用 CLI。

#### 加密、恢复和验证

按下文[准备密钥](#准备密钥)，将 `public.key` 和 `private.key` 放到工作目录。下面以新建的 `sample` 目录为例。

```sh
mkdir -p sample/nested sample/empty
printf 'PakCipher sample\n' > sample/nested/notes.txt
./pakcipher encrypt sample --key-file public.key --output sample.pak
./pakcipher decrypt sample.pak --key-file private.key --output sample-restored --ask-passphrase
diff -r sample sample-restored
```

私钥没有口令时，省略 `--ask-passphrase`。`sample.pak` 和 `sample-restored` 应使用尚未存在的路径。`diff -r` 无输出且退出码为 0，表示两份目录内容一致。

使用 GUI 时，在 **Encrypt** 页选择 `sample`、`public.key` 和归档路径。点击 **Encrypt** 后切换到 **Decrypt** 页，选择生成的归档、`private.key` 和新的输出目录，再点击 **Restore**。两页的进度条在对应操作成功后都应显示 100%。若已经用 CLI 跑过一遍，请为 GUI 选择新的归档和输出目录。

#### 从源码构建

在 Ubuntu 上构建桌面版需要以下开发库。

```sh
sudo apt-get install pkg-config libgl1-mesa-dev libxkbcommon-dev libwayland-dev libx11-dev
cargo build --locked --release --workspace
```

运行 `target/release/pakcipher` 或 `target/release/pakcipher-gui`。只构建 CLI 时使用 `cargo build --locked --release -p pakcipher`。

### macOS

在构建前安装 Xcode 命令行工具。构建完成后，可以直接运行 `target/release/pakcipher-gui`，或打包成 Finder 可打开的 `PakCipher.app`。

```sh
cargo build --locked --release --workspace
bash scripts/package-macos.sh target/release target/pakcipher-macos.tar.gz
```

macOS CI 产物使用 ad hoc 签名，未经 Apple 公证。下载时请选择与 Mac 处理器匹配的架构。

## 准备密钥

在 GUI 菜单中打开 **Generate keys**（生成密钥）。输入密钥标签，选择一个尚不存在的输出目录，再输入并确认私钥口令。点击 **Generate key pair** 后，应用会在本机生成包含 RSA 3072 位加密子密钥的 OpenPGP 密钥对，保存为 `public.key` 和 `private.key`。标签会出现在公钥中，请只填愿意公开的内容。

在 **Encrypt** 页选用 `public.key`。在 **Decrypt** 页选用 `private.key` 并输入生成时设置的口令。请保管好私钥和口令。应用不会覆盖已有输出目录。

也可使用 GnuPG 生成包含 RSA 加密子密钥的证书，然后将公钥导出给发送方。将下面的邮箱替换为自己的邮箱。

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

## 大目录分卷

归档目前**不压缩**。输出总量约为源文件体积加上目录清单、认证标签和归档头。分卷限制单个文件的大小，对总量的影响仅是每卷增加 32 字节头部。

```sh
pakcipher encrypt ./photos --key-file ./public.key --min-volume-size 10 --max-volume-size 100 --output ./photos-volumes
pakcipher decrypt ./photos-volumes --key-file ./private.key --output ./photos-restored --ask-passphrase
```

`--min-volume-size` 和 `--max-volume-size` 可以单独或一起设定，单位为 MiB。只设置最大值时，最小值默认为 1 MiB；只设置最小值时，最大值默认为最小值的两倍。也可用 `--volume-size 10:100` 同时设置两个值。每卷大小在设定的范围内随机选取，最后一卷可小于下限。最小值和最大值相同时使用固定大小。加密输出应是一个尚不存在的目录，内含 `part-000001.pak`、`part-000002.pak` 等文件。私钥没有口令时可省略 `--ask-passphrase`。

在 GUI 的 **Encrypt** 页可独立填写 **Minimum** 和 **Maximum**，两项都留空时生成单个 `.pak`。恢复时把同一组分卷放在同一目录，保持文件名不变。在 **Decrypt** 页选择第一卷，或在 CLI 传入第一卷或整个分卷目录。程序会检查所有分卷，再写出恢复结果，不需要预先合并。

验证时可加密一个超过上限的样例目录，检查各卷大小，再比较恢复前后的内容。把中间或最后一个分卷临时移走后，尝试恢复到新路径，应报错且不创建输出目录。

## 归档格式 v2

整数使用小端序。公开头部为 `PAKC`、两字节版本号 `2`、六字节保留字段、`u32` 密钥封装长度和 OpenPGP RSA 加密的 32 字节随机种子封装。之后的条目数（`u32`）和明文字节总数（`u64`）合成一个 AES-256-GCM 加密块。

每个条目的路径字节数（`u16`）和原始大小（`u64`）一起加密，UTF-8 相对路径单独加密。两部分各有 16 字节认证标签。路径用斜杠分隔，目录条目用 `u64::MAX` 标记且没有数据。普通文件以 1 MiB 为上限分块用 AES-256-GCM 加密，每块附 16 字节标签，空文件也有一个标签。96 位 nonce 由 `u32` 条目号和 `u64` 块号组成。内容使用正常块号（从零开始），条目长度与大小使用块号 `u64::MAX`，路径使用 `u64::MAX - 1`，包级清单使用条目号 `u32::MAX` 和块号零。清单块的附加认证数据是 ASCII `PakCipher v2 metadata`，内容块则绑定到该条目的路径和大小。

HKDF-SHA256 从归档种子派生两个独立的 32 字节密钥。盐为 `PakCipher v1`，两次派生的 info 分别为 `content AES-256-GCM` 和 `archive HMAC-SHA256`，均为 ASCII 字节。32 字节 HMAC-SHA256 尾部覆盖前面所有字节。恢复前先验证整个归档的 HMAC，写入文件前再验证对应块的 GCM 标签。

v2 隐藏归档内的文件名、目录名、各文件的原始大小和条目数量。归档本身的总大小以及使用分卷时的卷数仍可从磁盘获知。新版软件仍能恢复旧的 v1 归档，旧版软件需要升级才能打开 v2 归档。v1 的文件清单是明文；要隐藏旧归档的清单，请用新版恢复后重新加密。空目录会恢复，符号链接和 Windows 重解析点会被拒绝。使用由自己控制的源目录和输出上级目录，操作期间避免并发修改。进程被强制终止时，可能留下未完成的输出。

打包前会拒绝同一目录下仅大小写不同的文件名或目录名，例如 `report.txt` 和 `REPORT.txt`，以便归档能在大小写不敏感的文件系统上恢复。在 GUI 中，任务执行期间关窗会等待任务成功后再退出。如果任务失败，窗口会保留，便于查看错误。

分卷在同一逻辑归档流外加一层封装。每卷以 32 字节头部开头，依次为 `PKV1`、从 1 开始的 `u32` 卷号、逻辑归档总长度 `u64` 和 16 字节的随机卷组标识。按卷号读取各卷去掉头部后的内容，即得到原始的归档流。
