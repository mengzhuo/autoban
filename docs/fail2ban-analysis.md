# fail2ban 功能分析与 autoban 实现映射

## 1. fail2ban 是什么

fail2ban 是一个日志驱动的入侵防护守护进程。它持续读取日志，用正则识别失败登录、扫描、认证错误等事件；在指定时间窗口内对同一来源累计次数，超过阈值后调用防火墙/系统命令封禁来源，并在封禁时间结束后自动解封。

它本身不抓包、不做协议解析，也不直接理解 SSH / nginx / Apache 的语义；这些语义完全由 `filter.d` 中的正则定义。它也不实现防火墙，具体封禁方式由 `action.d` 中的 shell 脚本或外部命令定义。

## 2. 核心组成

| 组件 | 职责 |
|---|---|
| `fail2ban-server` | 守护进程：加载配置、启动 jail、读日志、计数、封禁、持久化 |
| `fail2ban-client` | 通过 Unix socket 控制服务端：状态、启停 jail、封禁/解封、修改参数 |
| `fail2ban-regex` | 离线工具：用指定 filter 测试日志，输出匹配行与提取到的主机 |
| `fail2ban.conf` | 全局配置：日志级别、控制 socket、pidfile、数据库、日志目标 |
| `jail.conf` / `jail.local` | jail 定义和本地覆盖 |
| `filter.d/*.conf` | 过滤器：`failregex`、`ignoreregex`、`prefregex`、`datepattern` |
| `action.d/*.conf` | 动作：`actionstart/stop/check/ban/unban/flush` 及参数 |
| `fail2ban.sqlite3` | 失败记录、封禁记录、封禁历史，用于重启恢复与递增封禁 |

## 3. 配置系统

### 3.1 分层与覆盖

fail2ban 的配置是 INI 风格：

```ini
[DEFAULT]
bantime = 10m
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
action = iptables-multiport[name=sshd, port=ssh]
```

主要规则：

- `[DEFAULT]` 提供给所有 section 继承。
- `%(option)s` 在同一个 section 或 `[DEFAULT]` 中插值。
- `.local` 文件覆盖 `.conf` 中的同名 section/option。
- `[INCLUDES]` 支持 `before = ...` / `after = ...`，用于按发行版拆分公共路径。
- 多行值用缩进续行表示，action 脚本和 failregex 都依赖这个特性。
- `jail` 的 `action` 可以包含多个动作，通常用换行分隔。
- filter/action 名称对应 `filter.d/<name>.conf`、`action.d/<name>.conf`，并可能再加载 `.local`。
- `__name__` 是 jail 名，常用于动作参数：`action = ... [name=%(__name__)s]`。

### 3.2 配置解析中的关键点

- 重复 key 在 Python ConfigParser 中通常报错或被覆盖；多值主要通过多行值表达。
- 插值可以跨 `[DEFAULT]`，且值可能递归引用其他变量。
- `%%` 是转义后的 `%`，因为 strptime 的 `%Y` 等格式占用 `%`。
- 注释仅支持整行 `#` / `;`，不能随意剥离行内 `#`，否则会破坏正则和 shell 命令。
- include 路径相对当前配置文件目录解析。

## 4. 运行时数据流

```text
日志文件 / journal
      │
      ▼
backend（polling / pyinotify / gamin / systemd）
      │  一行完整日志
      ▼
filter
  ├─ prefregex（可选，提取 F-CONTENT）
  ├─ ignoreregex（命中则丢弃）
  ├─ failregex（提取 <HOST>，可多条）
  └─ datepattern / 内置日期解析
      │  host + timestamp + matched line
      ▼
ignoreip / ignorecommand
      │
      ▼
FailManager
  ├─ 按 IP 保存失败记录队列
  ├─ 清理 findtime 之外的记录
  └─ len >= maxretry ?
      │
      ▼
BanManager
  ├─ 计算 bantime（可递增、随机、上限）
  ├─ 保存 ban 记录与历史
  └─ 触发 actionban
      │
      ▼
action.d 脚本（iptables/nftables/ufw/...）

定时器 ── 到期 ──> actionunban ──> 删除 ban 记录
```

## 5. 功能点拆解

### 5.1 后端（Backend）

- 跟随一个或多个 `logpath`，可以是 glob。
- 首次启动通常从文件末尾开始，避免把历史日志重新封禁一遍。
- 检测日志轮转（inode 变化）、截断（文件变小）、新文件出现。
- 只处理完整行；半行留到下一次轮询。
- 支持 `backend = auto/polling/pyinotify/gamin/systemd`；`auto` 根据平台选择。
- `maxlines`、`logencoding` 等影响读取和编码行为。

Go 实现：`internal/backend`，只实现轮询后端；首次启动 seek 到末尾，之后按偏移读取，检测 inode/大小变化。新文件从 0 开始读取。

### 5.2 过滤器（Filter）

- `failregex`：一条或多条正则；命中任意一条即视为失败。
- `ignoreregex`：命中则忽略，优先级高于 failregex。
- `prefregex`：先做一次宽匹配，常与 `<F-CONTENT>...</F-CONTENT>` 配合，把真正要匹配的片段交给 failregex。
- 正则占位符：
  - `<HOST>`：IPv4 / IPv6 / 可选主机名（由 `usedns` 决定）。
  - `<ADDR>`：仅 IP。
  - `<SUBNET>` / `<CIDR>`：IP 或 CIDR。
  - `<USER>` / `<F-USER>`：用户名占位。
  - `<F-CONTENT>`、`<F-MLFID>`、`<F-MLFGAINED>`：prefilter/多行相关标记。
- 主机名策略 `usedns`：
  - `no`：只匹配 IP。
  - `yes`：解析主机名。
  - `warn`：解析并告警。
  - `raw`：不解析，直接把原始主机名交给 action。
- 日期解析：`datepattern` 使用 strptime 风格；没有时间戳时使用当前时间；内置常见格式回退。

Go 实现：`internal/filter`。将 fail2ban 占位符展开为 RE2 兼容正则，命名捕获组 `host` 保存来源；`internal/filter/date.go` 负责时间解析。

### 5.3 失败计数与封禁策略

`FailManager` 为每个 IP 保存失败时间序列：

- 新失败只保留 `findtime` 窗口内的记录。
- 次数达到 `maxretry` 后创建 Ban。
- 创建 Ban 后清空该 IP 的失败队列。
- 已封禁 IP 的后续失败通常不再重复触发 actionban。
- `ignoreip` 支持 CIDR、单个 IP、主机名。
- `ignorecommand` 运行命令，退出码 0 表示忽略该 IP。

`BanManager` 管理：

- 当前封禁集合、到期时间。
- `bantime`：`-1` 表示永久。
- `bantime.increment = true` 时按 `factor^(n-1)` 递增，`bantime.maxtime` 封顶，`bantime.rndtime` 加入随机抖动。
- autoban 额外支持 `bantime.multiplier` 线性模式：`max(bancount * multiplier, bantime)`；设置后优先于指数模式。
- 封禁历史用于计算第 n 次封禁；按 `dbpurgeage` 清理。
- 解封、flush、重启恢复。

Go 实现：`internal/ban`，把两者合并成一个 `Tracker`，用互斥锁保护 `entries`、`bans`、`history`。

### 5.4 动作（Action）

动作文件一般包含：

```ini
[Definition]
actionstart = ...
actionstop = ...
actioncheck = ...
actionban = ...
actionunban = ...
actionflush = ...

[Init]
name = default
port = ssh
protocol = tcp
chain = INPUT
blocktype = REJECT
```

- `actionstart`：jail 启动时创建链/表/规则；`actionstop` 清理。
- `actioncheck`：检查动作是否可用；失败会导致 jail 启动失败。
- `actionban` / `actionunban`：封禁/解封单个 IP。
- `actionflush`：清空整个 jail 的封禁。
- 多行动作脚本以换行分隔，整体交给 shell。
- 动作参数来自 `[Init]` 和 jail 中 `name[...]` 的覆盖，使用 `%(option)s` 插值。
- 运行时占位符：
  - `<ip>`、`<family>`（inet/inet6）、`<name>`、`<jail>`
  - `<failures>`、`<ipfailures>`、`<ipjailfailures>`
  - `<time>`、`<bantime>`、`<maxtime>`、`<bantime.increment>`、`<restored>`、`<bancount>`
  - `<matches>`、`<ipmatches>`、`<ipjailmatches>`
  - `<fid>`
- 超时与输出处理由执行器负责。

Go 实现：`internal/action`。参数先合并 `[Init]` 与 action ref，再递归替换脚本中的 `<tag>`；命令通过 `/bin/sh -c` 执行，使用进程组 kill 保证超时可控。

### 5.5 持久化

fail2ban 使用 SQLite，保存：

- 当前封禁（IP、开始时间、结束时间、bantime、失败次数、匹配片段）。
- 失败记录，用于重启后继续累计。
- 封禁历史，用于 `bantime.increment`。
- 数据库按 `dbpurgeage` 清理。
- 重启后 `actionstart` 重建空链，再对未过期封禁执行一次 `actionban`（`<restored>` 为 true），避免规则丢失。

Go 实现：`internal/store`，使用 JSON 快照：

- 写入临时文件 + `fsync` + rename，避免半写。
- 读取损坏时重命名为 `.corrupt-<timestamp>` 并以空状态启动。
- 文件权限 `0600`。
- 状态变化立即保存，另有 30 秒周期保存，减少异常退出时的失败计数丢失。
- 支持 `dbfile =` 空值关闭持久化。

### 5.6 控制接口

fail2ban 的 `fail2ban-client` 通过 Unix socket 与 server 通信，支持：

- `status [jail]`
- `start/stop/restart <jail>`
- `banip/unbanip <jail> <ip>`
- `set/get <jail> <option>`
- `flush <jail>`
- `reload`
- `stop`

Go 实现：`internal/api` + `cmd/autoban-ctl`，使用换行分隔的 JSON 请求/响应，而不是 fail2ban 的旧文本协议。命令语义保持接近。

### 5.7 日志、信号与运维

- 日志级别和输出目标可配置。
- `SIGHUP` 重载配置。
- `SIGTERM` 优雅退出：停止后端、执行 `actionstop`、保存数据库、删除 socket/pidfile。
- pidfile 加锁防止重复启动。
- systemd 托管是推荐部署方式。

Go 实现：`internal/logging`、`internal/engine`、`cmd/autoban`。

## 6. 关键算法

### 6.1 findtime 窗口

对每个 IP 维护失败记录 `[]Failure{Time, Line}`。处理新失败时：

```text
cutoff = now - findtime
删除 Time < cutoff 的记录
追加新记录
if len(records) >= maxretry:
    ban(ip)
```

日志时间来自日期解析；无法解析时使用当前时间。明显早于窗口的日志行会被标记 stale 并丢弃，避免重放旧日志导致误封。

### 6.2 bantime 递增

设基础 `bantime = B`，第 n 次封禁：

```text
duration = B * factor^(n-1)
duration = min(duration, maxtime)      # maxtime > 0 时
duration += random(-rndtime, +rndtime) # 可选
```

`n` 来自按 `dbpurgeage` 清理后的历史记录数量。手动封禁也计入历史。

### 6.3 主机提取

fail2ban 的 `<HOST>` 展开为一个能匹配 IPv4/IPv6/主机名的复杂正则，并通过命名组保存 host。Go 实现使用：

```regexp
(?P<host>(?:IPv4-mapped-IPv6|IPv6|IPv4|hostname))
```

`<ADDR>` 不包含主机名；`usedns = no` 时 `<HOST>` 也只含 IP。

### 6.4 动作参数替换

动作执行前构造 tag 字典：

```text
params（Init + action ref 覆盖）
+ ip / family / failures / bantime / time
+ matches / ipmatches / ...
+ name（若参数未提供则用 jail 名）
```

然后对脚本做最多 8 层递归替换，允许参数值本身包含 `<ip>` 这类 tag。未解析的 tag 保留并记录 warning。

## 7. Go 实现映射

| fail2ban 概念 | Go 包/文件 | 说明 |
|---|---|---|
| ConfigParser + includes | `internal/config/ini.go` | 自定义 INI 解析、`%%`/`%()s`、`[INCLUDES]` |
| jail 配置 | `internal/config/jail.go` | `JailSpec`、`Global`、filter/action 加载 |
| 时间单位 | `internal/config/duration.go` | `10m`、`1d`、`-1` |
| 过滤器 | `internal/filter/filter.go` | 正则展开、匹配、prefilter |
| 日期解析 | `internal/filter/date.go` | 内置格式 + `datepattern` 子集 |
| FailManager + BanManager | `internal/ban/manager.go` | `Tracker` |
| Action | `internal/action/action.go` | shell 执行、tag 替换、超时 |
| Backend | `internal/backend/backend.go` | 文件轮询、轮转/截断 |
| Jail 运行时 | `internal/jail/jail.go` | 组合 filter/tracker/action/backend |
| 服务端 | `internal/engine/engine.go` | 生命周期、socket、热重载 |
| 持久化 | `internal/store/store.go` | JSON 快照 |
| 控制协议 | `internal/api/api.go` | JSON request/response |
| CLI | `cmd/autoban-ctl` | 人类可读输出 |
| 正则测试 | `cmd/autoban-regex` | 离线匹配统计 |

## 8. 设计差异与取舍

### 8.1 正则引擎

fail2ban 使用 Python `re`，支持 lookahead/lookbehind、反向引用、条件分组等；Go 标准库 `regexp` 是 RE2，**不支持**这些特性。为了保证零依赖，本项目选择 RE2：

- 大部分日常过滤器（SSH、nginx、Apache、WordPress 等）可以工作。
- 复杂的上游过滤器可能出现编译错误；错误会指出具体 failregex。
- 多行匹配能力有限；`<SKIPLINES>` 仅作为行尾标记。

### 8.2 数据库

SQLite 提供 SQL 查询和并发写入；JSON 快照更简单、可读、无 CGO。代价是：

- 每次状态变化可能重写整个文件（适合中小规模）。
- 不支持外部 SQL 查询。
- 崩溃恢复依赖 rename 原子性。

### 8.3 后端

只实现 polling。没有 systemd journal、inotify、gamin 支持，因此：

- 默认轮询间隔 1 秒，可通过 `pollinterval` 调整。
- 不能直接读取 journal 字段。
- 文件轮转/截断处理已覆盖常见场景；copytruncate 且新内容超过旧偏移时无法完美检测。

### 8.4 控制协议

不复刻 fail2ban 的 socket 协议，避免依赖其内部消息格式。使用 JSON 的优点是易调试、易扩展；代价是现有 fail2ban 客户端/监控脚本不能直接连接。

### 8.5 prefregex 与多行

支持常见的 `<F-CONTENT>...</F-CONTENT>`、`<F-MLFID>`、`<F-MLFGAINED>` 标记，但没有实现 fail2ban 完整的多行 ticket 聚合状态机。多行日志建议在 filter 中使用单行可判定的特征，或先由日志收集器合并。

### 8.6 动作安全

fail2ban 同样把日志内容替换进 shell 脚本；风险取决于 action 配置。本项目对 `<ip>` 做了 IP/主机名校验，但 `<matches>` 仍可能包含攻击者可控的 shell 元字符。生产动作应只使用 `<ip>` 等受控字段，并对日志内容使用安全的引用方式。

## 9. 验证

```bash
go test ./...
go test -race ./...
go vet ./...
make demo
```

端到端测试覆盖：

1. 写入日志 → 过滤器命中 → 达到 maxretry → actionban。
2. bantime 到期 → actionunban。
3. 重启进程 → JSON 数据库恢复封禁 → 手动解封。
4. 文件轮转/截断/半行/新文件。
5. 动作超时进程组清理。

## 10. 可扩展方向

- `backend = journal`：通过 sd-journal API 读取 systemd 日志。
- SQLite 存储：替换 `internal/store`，保留 `ban.Snapshot` 接口。
- `fail2ban-client` 协议适配层：在 JSON engine 前增加兼容 socket。
- 完整 prefregex 多行状态机：维护每个日志源的 pending lines。
- 动作插件/沙箱：用参数数组而不是 shell 执行，降低注入风险。
- 指标导出：Prometheus `/metrics` 或 status JSON 定时采集。
- 动态 jail API：运行时创建/删除 jail，而不仅是 reload 配置文件。
