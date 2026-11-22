# fail2ban 上游源码核对记录

为避免“凭印象写正则”，过滤器格式已对照 fail2ban 上游源码和测试语料核对。

- 上游仓库：`https://github.com/fail2ban/fail2ban`
- 核对提交：`cae17d2`（本地只读 clone）
- 主要参考文件：
  - `config/filter.d/*.conf`
  - `fail2ban/tests/files/logs/*`
  - `fail2ban/server/filter.py`
  - `fail2ban/server/failregex.py`
  - `fail2ban/server/datedetector.py`

## 一个关键差异

fail2ban 的 `processLine` 会先从日志行中切出时间戳，再把剩余内容交给 failregex：

```text
tupleLine = (line[:dateStart], dateText, line[dateEnd:])
```

因此上游很多 failregex 直接从日志正文开始，例如：

```regex
^\s*Logon\s+Login failed for user ...
```

gojail 当前保留完整日志行做匹配，所以需要显式加前缀：

```regex
^(?:\d{4}-... )?\s*Logon\s+Login failed ...
```

这也是本次修正中为什么多个过滤器增加了 `.*` 或显式时间戳前缀。

## 按上游语料修正的点

| 过滤器 | 上游实际格式 / 修正 |
|---|---|
| `dropbear` | 大小写不敏感；补充 `Exit before auth ... Max auth tries reached` |
| `lighttpd-auth` | 实际格式为 `username: user, IP: address`，不是 `(username "user")` |
| `haproxy-http-auth` | 只匹配 401 且 backend 为 `<NOSRV>` 的日志 |
| `traefik-auth` | normal 模式要求 basic-auth 用户名，匿名 `-` 不算认证失败 |
| `apache-auth` | 支持 `[client ...]` 和 `[remote ...]`、IPv6 方括号、AH01617/18/14/37/1792 等 auth/authz 错误 |
| `nginx-http-auth` | 支持 `error` / `crit`，补充 PAM 认证失败；删除上游不匹配的 `No user found` 样本 |
| `postfix` | 支持 `postfix/submission/smtpd`、`postfix/smtps/smtpd`、`[ip]:port`、4xx/5xx reject |
| `dovecot` | 补充 `dovecot-auth`、`auth-worker`、`auth(default): pam(...)`、v2.4 `Login aborted` |
| `sendmail-auth` | 改用 `possible SMTP attack: command=AUTH` 和 `AUTH failure ... relay=[ip]` |
| `courier-auth` | 改用 `LOGIN FAILED, ... ip=[ip]` |
| `cyrus-imap` | 改用 `badlogin: ... [ip] ... SASL(-13): authentication failure` |
| `vsftpd` | 补充 PAM `authentication failure` 和 `[pid ...] ... FAIL LOGIN` |
| `proftpd` | 补充 `no such user found`、`SECURITY VIOLATION`、`Maximum login attempts` |
| `asterisk` | 改用 `Registration from '...' failed for 'ip' - Wrong password` |
| `mysqld-auth` | 由 `mysql-auth` 重命名为上游名称；兼容 `130324 0:04:00 [Warning] ...` |
| `mssql-auth` | 改用 `Logon Login failed for user ... [CLIENT: ip]`，并排除注入前导文本 |
| `roundcube-auth` | 由 `roundcube` 重命名；支持 `FAILED login` 和 `IMAP Error: Login failed` |
| `phpmyadmin-syslog` | `phpMyAdmin` 大小写不敏感 |
| `webmin-auth` | 补充 `Non-existent login as ... from ip` |
| `froxlor-auth` | 支持 type1 `[Login Action ip]` 和 type2 JSON `"user":"ip"` |
| `directadmin` | 改用 `'ip' N failed login attempts` |
| `squid` | 上游匹配 `TCP_DENIED/403` 和 `NONE/405`，不是 407 |
| `portsentry` | 改用 `Host: ip/ip Port: N TCP|UDP Blocked` |

## 覆盖范围

- 上游当前约有 104 个 `filter.d`；本项目目前内置 56 个，覆盖最常见的默认/normal 日志格式。
- 本次按上游测试语料核对了各 filter 的代表性日志；没有逐字复制上游正则，而是按 gojail 的单行匹配模型重写。
- `filter = name[mode=...]` 参数和 `<mdre-<mode>>` 递归标签展开已实现；`freeswitch` 支持 normal/ddos/extra/aggressive。其他上游 filter 的 mode 分支尚未全部移植。
- `fail2ban-regex` 上游测试语料中的部分场景依赖多行 ticket（尤其旧版 MongoDB）或 Python 正则 lookaround；这些场景未纳入当前单行 RE2 实现。
- 上游还有 `apache-badbots`、`apache-noscript`、`nginx-limit-req`、`bitwarden`、`softethervpn`、`freeswitch`、`horde`、`sogo-auth`、`groupoffice`、`tine20`、`kerio` 等过滤器尚未移植；它们不是认证失败主路径，后续可以按同样方式补充。

## 上游没有对应实现的过滤器

以下过滤器在当前 fail2ban 上游 `filter.d` 中没有同名实现，是本项目自定义的，已按对应软件公开日志格式编写：

```text
caddy-auth
jenkins-auth
nextcloud-auth
rsync
samba
zimbra-auth
```

## 已知无法单行匹配的上游格式

`mongodb-auth` 在旧版 MongoDB 文本日志中采用多行关联：

```text
[conn1] Failed to authenticate ...
[conn1] end connection 192.0.2.35:53276
```

单行过滤器无法安全地只根据 `end connection` 封禁，因此当前实现保留 MongoDB 4+ JSON 日志格式；经典文本日志需要多行 ticket 支持。

## 许可说明

fail2ban 是 GPLv2 项目。本项目只阅读其源码与测试日志，用于理解真实日志格式和匹配语义；没有复制其源码、配置或测试文件。仓库中的日志 fixture 是重新编写的脱敏样本，正则也是针对 gojail 的单行匹配模型独立实现。
