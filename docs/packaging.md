# autoban 打包与安装

本文说明如何构建和安装 autoban 的 Debian/Ubuntu `.deb` 与 Alpine `.apk` 包。两个包都显式依赖 `nftables`，并显式与 `fail2ban` 冲突。

## 1. 构建

在仓库根目录执行：

```bash
make deb       # Debian/Ubuntu
make apk       # Alpine
make packages  # 同时构建 .deb 和 .apk
```

产物位于 `dist/`：

```text
dist/autoban_<version>_<arch>.deb
dist/autoban-<version>-r0.apk
dist/apk-keys/*.rsa.pub
```

构建依赖：

- Debian 包：`dpkg-deb`（Debian/Ubuntu 自带）。
- Alpine 包：`docker`。`scripts/build-apk.sh` 会生成源码 tarball，并在 `golang:1.26-alpine` 中运行 `abuild`。如果构建机是 arm64，Docker 会使用 arm64 镜像并生成 aarch64 包；包架构跟随构建容器。

`VERSION` 默认从 `internal/engine/engine.go` 的 `Version` 常量读取，也可以覆盖：

```bash
make VERSION=0.2.0 packages
```

## 2. Debian/Ubuntu

### 2.1 包元数据

`.deb` 的 control 字段包含：

```text
Depends: nftables
Conflicts: fail2ban
```

因此：

- 系统必须安装 `nftables`；
- 已安装 `fail2ban` 时，`dpkg -i` 会直接报冲突；`apt install` 会要求先移除 `fail2ban`（或在确认后自动移除）；
- autoban 不会接管 fail2ban 已有的防火墙规则。卸载 fail2ban 后如果仍有残留规则，请先清理，再启动 autoban。

### 2.2 安装与启动

```bash
sudo apt install ./dist/autoban_0.1.0_amd64.deb
```

或：

```bash
sudo dpkg -i dist/autoban_0.1.0_amd64.deb
sudo apt -f install
```

`postinst` 会执行 `systemd-sysusers`、`systemctl daemon-reload`、`systemctl enable autoban` 和 `systemctl restart autoban`。

验证：

```bash
systemctl is-active autoban
systemctl is-enabled autoban
sudo autoban-ctl -config /etc/autoban status
sudo autoban-ctl -config /etc/autoban status sshd
sudo nft list table inet "autoban-sshd"
```

### 2.3 安装路径

| 路径 | 用途 |
|---|---|
| `/usr/bin/autoban` | 守护进程 |
| `/usr/bin/autoban-ctl` | 控制 CLI |
| `/usr/bin/autoban-regex` | 离线过滤器测试工具 |
| `/etc/autoban/autoban.conf` | 守护进程配置 |
| `/etc/autoban/jail.local` | 默认 SSH jail |
| `/etc/autoban/filter.d/` | 内置过滤器 |
| `/etc/autoban/action.d/` | 内置动作 |
| `/usr/lib/systemd/system/autoban.service` | systemd unit |
| `/var/lib/autoban/autoban.db` | 封禁状态数据库 |
| `/var/log/autoban/autoban.log` | 守护进程日志 |
| `/run/autoban/autoban.sock` | 控制 socket |

默认 jail：

```ini
[sshd]
enabled = true
filter = sshd
logpath = /var/log/auth.log
banaction = nftables
```

nftables 动作为每个 jail 创建独立表：

```text
table inet autoban-sshd
  set banned4 { type ipv4_addr }
  set banned6 { type ipv6_addr }
```

### 2.4 权限模型

systemd unit 以 `autoban` 用户运行，只授予 `CAP_NET_ADMIN`，不需要完整 root：

```ini
User=autoban
Group=autoban
SupplementaryGroups=adm
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
```

`adm` 附加组用于读取 Debian/Ubuntu 的 `/var/log/auth.log`。如果目标系统的日志权限不同，请调整 unit 或使用 ACL。

管理账号需要加入 `autoban` 组才能使用 `0660` 控制 socket：

```bash
sudo usermod -aG autoban "$USER"
```

重新登录后生效。

## 3. Alpine

### 3.1 包元数据

`APKBUILD` 包含：

```text
depends="nftables !fail2ban"
```

`apk` 会将 `!fail2ban` 解释为冲突。安装后可以检查：

```bash
apk info -R autoban
```

输出中应包含：

```text
nftables
!fail2ban
```

### 3.2 构建

```bash
make apk
```

`scripts/build-apk.sh` 使用 `abuild` 生成真正的 v2 APK，而不是手工拼装的 tar 包。abuild 会用临时 RSA 密钥签名，公钥复制到 `dist/apk-keys/`。

### 3.3 安装

如果使用本次构建生成的密钥：

```bash
sudo cp dist/apk-keys/*.rsa.pub /etc/apk/keys/
sudo apk add ./dist/autoban-0.1.0-r0.apk
```

如果没有安装对应公钥，可以使用：

```bash
sudo apk add --allow-untrusted ./dist/autoban-0.1.0-r0.apk
```

`--allow-untrusted` 只跳过签名校验，不会跳过依赖或冲突检查。测试环境如果需要绕过已损坏的仓库索引，可以额外加 `--force-broken-world`，但生产环境不建议这样做。

### 3.4 服务与路径

Alpine 包使用 OpenRC：

| 路径 | 用途 |
|---|---|
| `/usr/bin/autoban` | 守护进程 |
| `/usr/bin/autoban-ctl` | 控制 CLI |
| `/usr/bin/autoban-regex` | 离线过滤器测试工具 |
| `/etc/autoban/autoban.conf` | 守护进程配置 |
| `/etc/autoban/jail.local` | 默认 SSH jail |
| `/etc/init.d/autoban` | OpenRC 服务脚本 |
| `/var/lib/autoban/autoban.db` | 封禁状态数据库 |
| `/var/log/autoban/autoban.log` | 守护进程日志 |
| `/run/autoban/autoban.sock` | 控制 socket |

默认 jail 使用 Alpine 的日志路径：

```ini
[sshd]
enabled = true
filter = sshd
logpath = /var/log/messages
banaction = nftables
```

验证：

```bash
rc-service autoban status
sudo autoban-ctl -config /etc/autoban status sshd
sudo nft list table inet "autoban-sshd"
```

Alpine 包当前通过 OpenRC 以 root 启动，因为 nftables 需要特权，且 `/var/log/messages` 的权限在不同 Alpine 镜像中可能不同。包会创建 `autoban` 用户/组，但 init 脚本没有切换用户。若需要更严格的权限模型，可以自行改为 `command_user` 并配置 `CAP_NET_ADMIN`、日志读取权限和目录属主。

### 3.5 Alpine 3.23 / apk-tools 3

`abuild` 生成的包在 Alpine 3.23（apk-tools 3.0.9）上已验证可安装。注意：

- 包架构必须与目标机一致，例如 x86_64 包不能安装到 aarch64；
- 旧版 `scripts/build-apk.sh` 手工生成的 tar 包缺少 apk-tools 3 需要的元数据，已被 abuild 构建流程替换；
- 如果 `apk add` 报 `v2 package format error`，请确认使用的是 `make apk` 新生成的包，而不是旧的 `dist/autoban-0.1.0-r0.apk` 手工包。

## 4. 卸载

Debian/Ubuntu：

```bash
sudo systemctl stop autoban
sudo apt remove autoban
# 同时删除配置和状态：
sudo apt purge autoban
```

`prerm` 会停止服务，正常情况下 `actionstop` 会删除 nftables 表。`postrm purge` 会删除 `/var/lib/autoban`、`/var/log/autoban` 和 `/run/autoban`；`/etc/autoban` 由 dpkg 按 conffile 规则处理。

Alpine：

```bash
sudo rc-service autoban stop
sudo apk del autoban
```

`autoban.pre-deinstall` 会停止并移除 OpenRC 服务。卸载后如需确认规则已清理：

```bash
sudo nft list tables | grep autoban || true
```

## 5. 注意事项

1. 两个包都要求 `nftables`。autoban 的默认动作不会回退到 iptables。
2. 两个包都显式冲突 `fail2ban`。不要在同一台机器上同时运行两个守护进程，否则它们可能重复封禁或互相清理规则。
3. 默认只启用 `sshd` jail。切换动作前，建议先用 `dummy` 验证过滤器。
4. 封禁表按 jail 命名，例如 `autoban-sshd`。检查时必须引用表名：
   ```bash
   nft list table inet "autoban-sshd"
   ```
5. 生产环境建议使用稳定的 APK 签名密钥，而不是每次构建都生成临时密钥。当前脚本生成的临时公钥适合本地安装和测试。
