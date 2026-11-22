# gojail 配置参考

## 1. 配置目录与加载顺序

默认目录：

- 当前工作目录下存在 `config/gojail.conf` 时使用 `./config`；
- 否则使用 `/etc/gojail`。

也可以显式指定：

```bash
gojail -config /etc/gojail
gojail -config /etc/gojail,/etc/gojail-local
gj -config /etc/gojail status
```

加载顺序（后加载覆盖先加载）；若一个 `gojail.conf`/`gojail.local` 都不存在，会回退读取 `fail2ban.conf`/`fail2ban.local`：

1. 每个目录的 `gojail.conf`
2. 每个目录的 `gojail.local`
3. 每个目录的 `jail.conf`
4. 每个目录的 `jail.local`

filter 名称 `sshd` 会加载：

1. `<dir>/filter.d/sshd.conf`
2. `<dir>/filter.d/sshd.local`

action 名称 `iptables-multiport` 会加载：

1. `<dir>/action.d/iptables-multiport.conf`
2. `<dir>/action.d/iptables-multiport.local`

配置文件语法：

- section：`[name]`
- option：`key = value` 或 `key: value`
- 整行注释：`#` 或 `;`
- 多行值：后续缩进行会以换行拼接到当前值
- 插值：`%(key)s`，先查当前 section，再查 `[DEFAULT]`
- 转义：`%%` 表示字面量 `%`
- include：

```ini
[INCLUDES]
before = common.conf
after = paths-local.conf
```

路径相对当前配置文件所在目录，支持 glob。

## 2. 全局选项（gojail.conf）

全局选项读取 `[Definition]`，不存在时回退到 `[DEFAULT]`。

| 选项 | 默认值 | 说明 |
|---|---|---|
| `loglevel` | `INFO` | `DEBUG` / `INFO` / `WARN` / `ERROR` |
| `logtarget` | `STDERR` | `STDOUT`、`STDERR`、`SYSLOG` 或文件路径 |
| `socket` | `/run/gojail/gojail.sock` | 控制 Unix socket |
| `socketmode` | `0660` | socket 权限（八进制） |
| `pidfile` | `/run/gojail/gojail.pid` | pidfile；加 flock 防止重复启动 |
| `dbfile` | `/var/lib/gojail/gojail.db` | JSON 快照；空字符串关闭持久化 |
| `dbpurgeage` | `1d` | 封禁历史保留时间，用于 `bantime.increment` |
| `pollinterval` | `1s` | 文件后端默认轮询间隔 |

示例：

```ini
[Definition]
loglevel = INFO
logtarget = /var/log/gojail/gojail.log
socket = /run/gojail/gojail.sock
socketmode = 0660
pidfile = /run/gojail/gojail.pid
dbfile = /var/lib/gojail/gojail.db
dbpurgeage = 1d
pollinterval = 1s
```

## 3. Jail 选项

每个非 `DEFAULT` section 是一个 jail。默认 `enabled = false`。

| 选项 | 默认值 | 说明 |
|---|---|---|
| `enabled` | `false` | 是否在启动时启用 |
| `filter` | 无 | `filter.d` 名称，必填（启用时） |
| `logpath` | 无 | 一个或多个日志路径/glob，换行或空格分隔 |
| `backend` | `auto` | 仅支持 `auto` / `polling` |
| `maxretry` | `5` | 触发封禁的失败次数 |
| `findtime` | `10m` | 失败计数窗口 |
| `bantime` | `10m` | 封禁时长；`-1` 永久 |
| `ignoreip` | `127.0.0.1/8 ::1` | 忽略的 IP/CIDR/主机名，逗号或空白分隔 |
| `usedns` | `warn` | `yes` / `no` / `warn` / `raw` |
| `ignorecommand` | 无 | 对每个候选 IP 执行，退出码 0 表示忽略 |
| `maxlines` | 继承 filter（默认 1） | 匹配行历史大小 |
| `bantime.increment` | `false` | 是否按历史封禁次数递增 |
| `bantime.factor` | `2` | 递增因子 |
| `bantime.maxtime` | 无上限 | 递增后的最大 bantime |
| `bantime.rndtime` | `0` | 随机抖动范围，例如 `5m` |
| `pollinterval` | 全局值 | 该 jail 的轮询间隔 |
| `datepattern` | 继承 filter | 覆盖 filter 的日期格式 |
| `action` | 继承 `[DEFAULT]` | 一个或多个动作 |

时间格式：

- 纯数字：秒，例如 `600`。
- 后缀：`s`、`m`、`h`、`d`、`w`、`mo`（30 天）、`y`（365 天）。
- 组合：`1h30m`。
- 负数：`-1` 表示永久封禁（用于 `bantime`）。

动作写法：

```ini
action = iptables-multiport[name=sshd, port="ssh,http", protocol=tcp]
```

多个动作：

```ini
action = iptables-multiport[name=sshd, port=ssh]
         sendmail[name=sshd, dest=admin@example.com]
```

或使用顶层逗号分隔（参数方括号内的逗号不会被拆分）。

`%(__name__)s` 在解析时替换为 jail 名：

```ini
[DEFAULT]
banaction = iptables-multiport
action_ = %(banaction)s[name=%(__name__)s]
action = %(action_)s
```

## 4. Filter 选项

filter 文件读取 `[Definition]`，可以用 `[Init]` 定义被 `%(...)s` 引用的变量。

| 选项 | 说明 |
|---|---|
| `failregex` | 必填；一条或多条正则，每条必须包含可提取主机的 token |
| `ignoreregex` | 命中则忽略该行 |
| `prefregex` | 预匹配；可用 `<F-CONTENT>...</F-CONTENT>` 指定子片段 |
| `datepattern` | 日志时间格式（strptime 子集） |
| `maxlines` | 匹配行历史大小，默认 1 |
| `usedns` | 过滤器级主机名策略（jail 可覆盖） |
| `ignorecommand` | filter 级忽略命令（jail 可覆盖） |

示例：

```ini
[Definition]
failregex = ^.*Failed password for (?:invalid user )?\S+ from <HOST> port \d+(?: ssh2)?\s*$
            ^.*Invalid user \S+ from <HOST>(?: port \d+)?\s*$
ignoreregex = ^.*from 192\.0\.2\.10 port .*$
```

### 4.1 正则 token

| Token | 含义 |
|---|---|
| `<HOST>` | IPv4 / IPv6 / 主机名（由 `usedns` 决定是否包含主机名） |
| `<F-HOST>` | 同 `<HOST>` |
| `<ADDR>` / `<F-ADDR>` | 仅 IPv4/IPv6 |
| `<IP4>` / `<IP6>` | 指定地址族 |
| `<SUBNET>` / `<CIDR>` | IP 或 CIDR |
| `<USER>` / `<F-USER>` | 非空白用户名 |
| `<SKIPLINES>` | 行尾/换行标记 |
| `<F-CONTENT>` | prefregex 内容捕获开始 |
| `</F-CONTENT>` | prefregex 内容捕获结束 |
| `<F-MLFID>` / `</F-MLFID>` | 多行 ID 标记（忽略） |
| `<F-MLFGAINED>` | 多行匹配开始标记（近似行尾） |
| `<KNOWN>` / `<MODERATE>` / `<HARD>` / `<INVALID>` | 近似为 `\S+` |

Go 的 `regexp` 使用 RE2：**不支持 lookahead、lookbehind、反向引用、条件分组**。如果 failregex 编译失败，守护进程会报告具体表达式。

RE2 支持 `(?i)`、`(?m)`、`(?s)`、非贪婪量词、命名组 `(?P<name>...)` 等。

### 4.2 日期格式

未配置 `datepattern` 时自动识别：

- `2024-01-02T03:04:05Z`
- `2024-01-02 03:04:05.123 +0800`
- `Jan  2 03:04:05`（syslog，无年份）
- `02/Jan/2024:03:04:05 +0800`（Apache/nginx）
- `2024/01/02 03:04:05`
- 10 位/13 位 Unix 时间戳

`datepattern` 支持常用 strptime 指令：

`%Y %y %m %d %e %H %I %M %S %f %z %Z %b %B %a %A %p %j %s %n %t`

以及 `{^LN-BEG}` / `{^L-BEG}` 行首标记。`%Y-%m-%dT%H:%M:%S` 这类简单格式可以精确工作；复杂正则式 datepattern 可能退回内置识别。

示例：

```ini
datepattern = {^LN-BEG}%Y-%m-%dT%H:%M:%S
```

## 5. Action 选项

### 5.1 命令

| 选项 | 说明 |
|---|---|
| `actioncheck` | 启动前检查；非 0 退出码导致 jail 启动失败 |
| `actionstart` | jail 启动时执行一次 |
| `actionstop` | jail 停止时执行一次 |
| `actionban` | 封禁单个 IP |
| `actionunban` | 解封单个 IP |
| `actionflush` | 清空 jail 时执行 |
| `actionreload` | 预留，重载当前不会单独调用 |
| `timeout` | 单次命令超时，默认 30s |

动作脚本由 `/bin/sh -c` 执行；多行值会整体作为脚本传入。超时后会杀掉整个进程组。

### 5.2 参数

`[Init]` 提供默认参数，jail 的 `action = name[...]` 覆盖同名参数：

```ini
[Definition]
actionstart = <iptables> -N f2b-<name>
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>

[Init]
name = default
chain = INPUT
blocktype = REJECT
iptables = iptables -w
```

### 5.3 运行时占位符

| 占位符 | 含义 |
|---|---|
| `<ip>` | 被封禁的主机（IP 或 `usedns=raw` 的主机名） |
| `<family>` | `inet` 或 `inet6` |
| `<name>` | 动作参数 `name`；未配置时回退为 jail 名 |
| `<jail>` | jail 名 |
| `<failures>` / `<ipfailures>` / `<ipjailfailures>` | 触发封禁的失败次数 |
| `<time>` | 事件时间，`YYYY-MM-DD HH:MM:SS` |
| `<bantime>` | 本次封禁秒数；永久为 `-1` |
| `<maxtime>` | `bantime.maxtime` 秒数 |
| `<bantime.increment>` | `true` / `false` |
| `<restored>` | 是否为重启恢复的封禁 |
| `<bancount>` | 这是该 IP 第几次封禁 |
| `<matches>` | 触发封禁的日志行，换行分隔 |
| `<ipmatches>` / `<ipjailmatches>` | 同上（当前实现未区分全局/jail） |
| `<fid>` | 基于 IP/时间/匹配行的事件 ID |

参数值本身也可以包含 `<ip>` 等占位符，替换会递归进行（最多 8 层）。

### 5.4 示例动作

演示动作（无需 root）：

```ini
[Definition]
actionstart = printf '%s\n' "start <name>" >> "<logpath>"
actionstop = printf '%s\n' "stop <name>" >> "<logpath>"
actioncheck =
actionban = printf '%s\n' "ban <ip> <family> <bantime>" >> "<logpath>"
actionunban = printf '%s\n' "unban <ip>" >> "<logpath>"

[Init]
name = default
logpath = /tmp/gojail/actions.log
```

iptables：

```ini
[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j RETURN
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <iptables> -F f2b-<name>
             <iptables> -X f2b-<name>
actioncheck = <iptables> -n -L <chain> >/dev/null 2>&1
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

[Init]
name = default
port = ssh
protocol = tcp
chain = INPUT
blocktype = REJECT
iptables = iptables -w
```

注意：示例 iptables 动作只处理 IPv4；IPv6 请使用 `ip6tables` 变体。

## 6. CLI

```text
gj [options] <command> [args]

status [jail]              服务端或 jail 状态
banned <jail>              当前封禁列表
failures <jail>            当前失败计数
start <jail>               启动 jail
stop [jail]                停止 jail；不带参数则停止服务端
restart <jail>             重启 jail
banip <jail> <ip>          手动封禁
unbanip <jail> <ip>        手动解封
flush <jail>               清空 jail 封禁
get <jail> <option>        读取运行参数
set <jail> <option> <val>  修改运行参数
reload                     重载 jail 配置
ping                       探活
version                    服务端版本
```

可修改的运行参数：`maxretry`、`findtime`、`bantime`、`ignoreip`、`usedns`、`maxlines`、`ignorecommand`、`bantime.increment`、`bantime.factor`、`bantime.maxtime`、`bantime.rndtime`。

`set usedns` 只改变运行时的解析策略；filter 是否编译主机名匹配取决于启动时的 `usedns`，需要 `reload` 才完全生效。

`-json` 输出原始 JSON，便于脚本处理：

```bash
gj -json -config ./config status sshd
```

## 7. 控制协议

Unix socket 使用换行分隔 JSON：

请求：

```json
{"cmd":"status","jail":"sshd"}
```

响应：

```json
{"ok":true,"data":{"name":"sshd","currentlyBanned":1}}
```

错误：

```json
{"ok":false,"error":"jail \"x\" is not configured"}
```

支持的命令：`ping`、`version`、`status`、`jail.status`、`jail.start`、`jail.stop`、`jail.restart`、`jail.banip`、`jail.unbanip`、`jail.banned`、`jail.failures`、`jail.flush`、`jail.get`、`jail.set`、`reload`、`stop`。

## 8. 持久化文件

示例：

```json
{
  "version": 1,
  "savedAt": "2026-11-22T12:00:00Z",
  "jails": {
    "sshd": {
      "bans": [
        {
          "ip": "203.0.113.7",
          "start": "2026-11-22T12:00:00Z",
          "until": "2026-11-22T13:00:00Z",
          "duration": 3600000000000,
          "failures": 3,
          "matches": ["Failed password ..."],
          "banCount": 1,
          "restored": true
        }
      ],
      "banHistory": {
        "203.0.113.7": ["2026-11-22T12:00:00Z"]
      }
    }
  }
}
```

- 写入采用临时文件 + rename。
- 文件权限 `0600`。
- 损坏文件会重命名为 `*.corrupt-<unix>` 后以空状态启动。
- 重启时，已过期封禁会保留到 `actionstart` 之后，再执行 `actionunban` 清理防火墙。
- 未过期的封禁会在 `actionstart` 之后重新执行 `actionban`，并以 `<restored>true` 标记，确保空链重建后规则仍在。

## 9. 安全清单

- 动作脚本尽量只使用 `<ip>`、`<family>` 等受控字段。
- 不要不加引号地插入 `<matches>`；日志内容可被攻击者控制。
- socket 权限限制为管理组；不要把 socket 暴露到不可信目录。
- `usedns = raw` 会把主机名交给动作脚本，确认动作能安全处理。
- 生产环境先使用 `dummy` 动作验证规则，再切换到真实防火墙动作。
- 以 root 运行时，定期审计 `action.d` 和命令参数。
