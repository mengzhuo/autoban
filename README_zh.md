# autoban

[English](README.md) | **简体中文**

> 用 Go 写的轻量级 fail2ban：日志驱动、Jail 管理、自动封禁与解封。

![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
[![GitHub](https://img.shields.io/badge/GitHub-mengzhuo%2Fautoban-181717?logo=github)](https://github.com/mengzhuo/autoban)
[![CI](https://github.com/mengzhuo/autoban/actions/workflows/ci.yml/badge.svg)](https://github.com/mengzhuo/autoban/actions/workflows/ci.yml)

autoban 持续读取 SSH、nginx、Apache 等日志，用 `failregex` 识别失败登录、扫描和认证错误；在 `findtime` 内累计到 `maxretry` 后执行 `actionban`，封禁到期后自动执行 `actionunban`。

配置格式、`filter.d` / `action.d` 语义尽量贴近 fail2ban，现有 jail、过滤器和动作脚本可以较低成本迁移。项目只依赖 Go 标准库，适合作为轻量级入侵防护服务，也适合学习 fail2ban 的内部实现。

## 目录

- [特性](#特性)
- [快速开始](#快速开始)
- [命令](#命令)
- [配置](#配置)
- [架构](#架构)
- [生产部署](#生产部署)
- [fail2ban 兼容性](#fail2ban-兼容性)
- [限制](#限制)
- [安全注意事项](#安全注意事项)
- [开发与测试](#开发与测试)
- [文档](#文档)
- [参与贡献](#参与贡献)
- [License](#license)

## 特性

- **fail2ban 风格配置**：`autoban.conf` / `jail.conf` / `.local`，支持 `[DEFAULT]`、`%(option)s` 插值、`[INCLUDES] before/after` 和多行值。
- **过滤器引擎**：`failregex`、`ignoreregex`、`prefregex`，支持 `<HOST>`、`<ADDR>`、`<SUBNET>`、`<USER>` 等占位符。
- **Filter mode 与参数**：`filter = name[mode=aggressive]`，支持 `<mode>` / `<mdre-<mode>>` 递归标签展开和 filter 参数覆盖。
- **104 个内置过滤器**：SSH、Web 服务器、Web 应用/面板、邮件、FTP、VPN/VoIP、数据库和基础设施；见 [docs/filters.md](docs/filters.md)。
- **日志时间识别**：内置 syslog、ISO-8601、nginx、Apache、epoch 格式，支持 `datepattern` 自定义。
- **完整封禁生命周期**：`maxretry`、`findtime`、`bantime`、永久封禁、`ignoreip`、`ignorecommand`、`bantime.increment`。
- **动作系统**：`actioncheck/start/stop/ban/unban/flush`，多动作链，占位符替换，执行超时和进程组清理。
- **文件后端**：logpath glob、轮转、截断、半行、新文件检测。
- **状态持久化**：封禁、失败计数、封禁历史写入 JSON 快照；重启恢复，并重新应用未过期规则。
- **运行时控制**：Unix socket + JSON 协议，支持状态查询、启停 jail、手动封禁/解封、修改参数、热重载。
- **零第三方依赖**：使用 Go 标准库；目标平台 Linux。
- **非 root 运行**：示例 systemd unit 使用专用用户，仅授予 `CAP_NET_ADMIN` ambient capability。

## 快速开始

要求：Go 1.22+、Linux。

```bash
git clone https://github.com/mengzhuo/autoban.git
cd autoban
make build
```

如果只需要安装命令到 `$GOBIN`：

```bash
go install github.com/mengzhuo/autoban/cmd/autoban@latest
go install github.com/mengzhuo/autoban/cmd/autoban-ctl@latest
go install github.com/mengzhuo/autoban/cmd/autoban-regex@latest
```

生成三个可执行文件：

```text
bin/autoban          守护进程
bin/autoban-ctl      控制 CLI
bin/autoban-regex    离线过滤器测试工具
```

运行内置演示（使用 `dummy` 动作和 `/tmp/autoban*` 路径，不会修改防火墙）：

```bash
make demo
```

手动启动：

```bash
mkdir -p /tmp/autoban-demo
: > /tmp/autoban-demo/auth.log

# 终端 1：启动守护进程
./bin/autoban -config ./config

# 终端 2：查看状态
./bin/autoban-ctl -config ./config status
./bin/autoban-ctl -config ./config status sshd

# 注入一条失败登录日志
echo "$(date '+%b %e %H:%M:%S') demo sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2" \
  >> /tmp/autoban-demo/auth.log

# 达到 maxretry 后查看封禁列表
./bin/autoban-ctl -config ./config banned sshd
```

## 命令

| 命令 | 用途 |
|---|---|
| `autoban` | 守护进程，前台运行，建议由 systemd 托管 |
| `autoban-ctl` | 控制 CLI，通过 Unix socket 操作运行中的服务 |
| `autoban-regex` | 离线加载 filter，对日志文件做匹配统计 |

常用控制命令：

```bash
autoban-ctl -config ./config status
autoban-ctl -config ./config status sshd
autoban-ctl -config ./config banned sshd
autoban-ctl -config ./config failures sshd
autoban-ctl -config ./config start sshd
autoban-ctl -config ./config stop sshd
autoban-ctl -config ./config restart sshd
autoban-ctl -config ./config banip sshd 203.0.113.9
autoban-ctl -config ./config unbanip sshd 203.0.113.9
autoban-ctl -config ./config flush sshd
autoban-ctl -config ./config get sshd bantime
autoban-ctl -config ./config set sshd maxretry 5
autoban-ctl -config ./config reload
autoban-ctl -config ./config stop          # 不带 jail 参数时停止整个服务
```

离线验证过滤器：

```bash
autoban-regex -config ./config /var/log/auth.log sshd
autoban-regex -v -config ./config /var/log/auth.log sshd
autoban-regex /var/log/auth.log 'Failed password for .* from <HOST>'
```

## 配置

默认配置目录：当前目录存在 `config/autoban.conf` 时使用 `./config`，否则使用 `/etc/autoban`。也可以显式指定：

```bash
autoban -config /etc/autoban
autoban -config /etc/autoban,/etc/autoban-local
autoban-ctl -config /etc/autoban status
```

加载顺序（后加载覆盖先加载）：

1. `autoban.conf`
2. `autoban.local`
3. `jail.conf`
4. `jail.local`

如果完全没有 `autoban.conf` / `autoban.local`，会回退读取 `fail2ban.conf` / `fail2ban.local`，方便从 fail2ban 配置迁移。`filter.d/<name>.conf` 与 `.local`、`action.d/<name>.conf` 与 `.local` 也会按顺序合并。

最小配置：

```ini
# autoban.conf
[Definition]
socket = /run/autoban/autoban.sock
pidfile = /run/autoban/autoban.pid
dbfile = /var/lib/autoban/autoban.db
logtarget = /var/log/autoban/autoban.log
loglevel = INFO
```

```ini
# jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
maxretry = 5
findtime = 10m
bantime = 1h

[sshd]
enabled = true
filter = sshd
logpath = /var/log/auth.log
port = ssh
action = iptables-multiport[name=%(__name__)s, port="ssh", protocol=tcp, chain=INPUT]
```

`%(__name__)s` 是当前 jail 名。动作参数在方括号内用逗号分隔，值可以用单引号或双引号包裹。

更完整的全局选项、jail 选项、过滤器占位符和动作占位符见 [docs/configuration.md](docs/configuration.md)。

## 架构

```text
autoban (daemon)
├── config loader        autoban.conf / jail.conf(.local)
│   ├── filter.d         编译 failregex、ignoreregex、datepattern
│   └── action.d         加载脚本、参数和超时
├── polling backend      跟随 logpath，处理轮转/截断/半行
├── filter               提取 <HOST> 与日志时间
├── ban.Tracker          findtime 窗口、maxretry、ban 生命周期
├── action               <ip>/<matches> 等占位符替换，执行 shell
├── store                JSON 快照（bans/failures/ban history）
└── control socket       JSON 请求/响应，供 autoban-ctl 使用

autoban-ctl ── Unix socket ──> autoban
autoban-regex ── 离线验证 filter
```

数据流：

1. 后端读取完整日志行。
2. filter 应用 `prefregex`、`ignoreregex`、`failregex`，提取 `<HOST>` 和日志时间。
3. `ignoreip` / `ignorecommand` 过滤已知安全来源。
4. `ban.Tracker` 清理 `findtime` 之外的失败记录并累计次数。
5. 达到 `maxretry` 后创建封禁，计算递增后的 `bantime`，执行所有 `actionban`。
6. 后台定时器检查到期封禁，执行 `actionunban`。
7. 状态写入 JSON 数据库；重启时恢复未过期封禁，并在 `actionstart` 后重新应用规则。

## 生产部署

```bash
# 安装二进制
sudo install -m 0755 bin/autoban bin/autoban-ctl bin/autoban-regex /usr/local/bin/

# 安装配置（示例配置使用 /tmp 路径，生产环境请改成 /etc、/run、/var/lib）
sudo install -d /etc/autoban
sudo cp config/autoban.conf config/jail.conf /etc/autoban/
sudo cp -r config/filter.d config/action.d /etc/autoban/

# 创建服务用户/组并安装 systemd unit
sudo install -D -m 0644 contrib/autoban.sysusers /etc/sysusers.d/autoban.conf
sudo systemd-sysusers
sudo install -m 0644 contrib/autoban.service /etc/systemd/system/autoban.service
sudo systemctl daemon-reload
sudo systemctl enable --now autoban

# 允许管理账号使用控制 socket（socket 模式 0660）
sudo usermod -aG autoban "$USER"
```

部署要点：

1. unit 以非 root 的 `autoban` 用户运行；通过 `AmbientCapabilities=` / `CapabilityBoundingSet=` 只授予 `CAP_NET_ADMIN`，不需要完整 root 权限。
2. 确保 `autoban` 用户能读取被监控日志。unit 已加入 Debian/Ubuntu 的 `adm` 附加组以读取 `auth.log`；如果日志仅 root 可读（例如 `/var/log/secure`），请添加 ACL 或调整 `SupplementaryGroups=`。
3. 管理账号需要加入 `autoban` 组才能通过 `0660` socket 使用 `autoban-ctl`；修改组后需要重新登录。
4. UFW 动作会写 `/etc/ufw` 和 `/var/lib/ufw`。在 `ProtectSystem=strict` 下建议使用 iptables/nftables，或额外开放可写路径和权限。
5. 先将 `banaction` 设为 `dummy` 验证日志和正则，再切换到 `iptables-multiport`、`nftables` 或 `ufw`。
6. 示例 iptables 动作只处理 IPv4；IPv6 需要 `ip6tables` 变体。
7. 日志轮转推荐 rename+create；copytruncate 在新内容长度大于旧偏移时存在边界情况。

### 安装包

仓库可以直接构建 Debian 和 Alpine 包：

```bash
make deb       # dist/autoban_<version>_<arch>.deb
make apk       # dist/autoban-<version>-r0.apk
make packages  # 同时构建
```

两个包都显式依赖 `nftables`，并显式与 `fail2ban` 冲突。

- Debian/Ubuntu：systemd 服务，专用 `autoban` 用户，只授予 `CAP_NET_ADMIN`，默认 SSH 日志为 `/var/log/auth.log`。
- Alpine：OpenRC 服务，默认 SSH 日志为 `/var/log/messages`；由于 nftables 需要特权，当前以 root 运行。

构建、安装、签名和卸载细节见 [docs/packaging.md](docs/packaging.md)。

## fail2ban 兼容性

| 能力 | 状态 |
|---|---|
| `autoban.conf` / `jail.conf` / `.local` 分层配置 | ✅ |
| `filter.d` failregex / ignoreregex / prefregex | ✅ |
| `action.d` 生命周期、参数、多动作 | ✅ |
| `ignoreip`、`usedns`、`ignorecommand` | ✅ |
| `bantime.increment/factor/maxtime/rndtime` | ✅ |
| 文件轮转/截断跟随 | ✅ |
| Python 正则 lookaround / 反向引用 | ❌ RE2 不支持 |
| systemd journal 后端 | ❌ 仅文件轮询 |
| SQLite 数据库 | ❌ 使用 JSON 快照 |
| `fail2ban-client` 协议 | ❌ 使用 autoban 的 JSON 协议 |
| 完整多行 ticket 聚合 | ⚠️ 仅支持常见 prefregex 标记 |

本项目不包含 fail2ban 源码，也不兼容其 `fail2ban-client` 协议；配置格式和核心语义尽量贴近 fail2ban。详细差异分析见 [docs/fail2ban-analysis.md](docs/fail2ban-analysis.md)。

## 限制

- Go 标准库正则使用 RE2，不支持 lookahead、lookbehind、反向引用；部分复杂上游过滤器需要调整。
- 只实现文件轮询后端，不支持 systemd journal、inotify/gamin。
- 持久化是 JSON 快照，不是 SQLite。
- `prefregex` 和 `<F-MLFID>` 只实现常见场景，没有完整多行状态机。
- 仅支持 Linux；依赖 Unix socket、flock 和进程组信号。
- 守护进程不自行降权；请使用提供的 systemd unit，或以专用用户加所需 capability 运行。

## 安全注意事项

- 动作脚本通过 `/bin/sh -c` 执行。`<ip>` 会经过 IP/主机名校验，但 `<matches>` 来自日志，攻击者可以控制内容。**不要在动作脚本中不加引号地插入 `<matches>` / `<ipmatches>`**。
- 示例 systemd unit 以非 root 用户运行，并且只授予 `CAP_NET_ADMIN`。如果手动以 root 启动，程序本身不会主动降权。
- 推荐使用专用服务用户（或 `DynamicUser=yes`），不建议使用 `nobody`/`nouser` 这类共享账号，因为 socket、状态目录和日志权限更难管理。
- `usedns = raw` 会把主机名直接交给动作脚本；建议使用 `usedns = no` 或 `warn`。
- JSON 数据库包含封禁历史和日志片段，权限为 `0600`，请按敏感数据保护。
- 生产环境先使用 `dummy` 动作验证规则，再切换到真实防火墙动作。

## 开发与测试

```bash
make build      # 构建三个命令
make test       # 单元 + 端到端测试
make race       # race detector
make vet        # go vet
make demo       # 端到端演示
go test ./internal/filter -run TestReal -v   # 脱敏真实日志样本
```

GitHub Actions 会运行四个独立任务：`fmt`、`lint`、`build`、`test`，配置见 [.github/workflows/ci.yml](.github/workflows/ci.yml)。

项目结构：

```text
cmd/autoban/        守护进程
cmd/autoban-ctl/    控制 CLI
cmd/autoban-regex/  离线过滤器测试工具
internal/config/    INI 解析、插值、include、jail/filter/action 加载
internal/filter/    failregex 编译、<HOST> 展开、时间解析
internal/ban/       失败计数、封禁、递增、忽略列表、快照
internal/action/    动作脚本执行与占位符替换
internal/backend/   文件轮询后端
internal/jail/      jail 运行时编排
internal/engine/    配置、socket、生命周期、热重载
internal/store/     JSON 持久化
internal/api/       socket 协议与客户端类型
config/             演示配置与动作/过滤器示例
docs/               功能分析与配置参考
contrib/            systemd unit 与 sysusers 定义
scripts/demo.sh     端到端演示
.github/            GitHub Actions CI
```

测试覆盖配置解析、IPv4/IPv6、日期格式、封禁策略、动作超时、日志轮转、端到端封禁、重启恢复和热重载。过滤器测试还包含所有内置过滤器的脱敏真实格式日志样本，位于 `internal/filter/testdata/`；格式已对照 fail2ban 上游 `filter.d` 和测试语料。

## 文档

- [配置参考](docs/configuration.md)
- [打包与安装](docs/packaging.md)
- [内置过滤器目录](docs/filters.md)
- [fail2ban 上游源码核对记录](docs/upstream-review.md)
- [fail2ban 功能分析与 autoban 实现映射](docs/fail2ban-analysis.md)
- [systemd unit](contrib/autoban.service)
- [sysusers 定义](contrib/autoban.sysusers)
- [演示脚本](scripts/demo.sh)

## 参与贡献

欢迎提交 Issue 和 Pull Request：<https://github.com/mengzhuo/autoban>

## License

MIT
