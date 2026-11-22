# gojail 内置过滤器

`config/filter.d/` 目前包含 56 个过滤器。所有过滤器都使用 RE2 兼容正则，并有对应的真实格式日志样本和测试，位于 `internal/filter/testdata/`。

过滤器格式已对照 fail2ban 上游 `filter.d` 和 `tests/files/logs` 语料核对，差异与修正记录见 [upstream-review.md](upstream-review.md)。

## 系统与远程登录

| Filter | 软件 | 典型日志 |
|---|---|---|
| `sshd` | OpenSSH | `/var/log/auth.log`、`/var/log/secure` |
| `dropbear` | Dropbear SSH | syslog / auth.log |

## Web 服务器

| Filter | 软件 | 典型日志 |
|---|---|---|
| `nginx-http-auth` | nginx basic auth | `error.log` |
| `apache-auth` | Apache 2.4 / 2.2 auth/authz | `error.log`，AH01617/18/14/37/1792 等 |
| `caddy-auth` | Caddy | 启用 access log 后的 JSON 日志，`status=401` |
| `lighttpd-auth` | lighttpd | `error.log` |
| `haproxy-http-auth` | HAProxy | `<NOSRV>` 且 `401` 的 access log |
| `traefik-auth` | Traefik | Common/combined access log，命名用户 + `401` |
| `apache-badbots` | Apache | 已知恶意爬虫/邮件采集 User-Agent |
| `apache-noscript` | Apache | 缺失 PHP/CGI/脚本探测 |
| `apache-overflows` | Apache | 非法 method/URI、超长请求 |
| `nginx-limit-req` | nginx | `limiting requests` / `limiting connections` |
| `nginx-forbidden` | nginx | `access forbidden by rule` |
| `nginx-bad-request` | nginx | access log 中的 `400` |
| `nginx-botsearch` | nginx | 探测 phpMyAdmin/.env 等路径的 404 |

## Web 应用与控制面板

| Filter | 软件 | 典型日志 |
|---|---|---|
| `nextcloud-auth` | Nextcloud | JSON 日志中的 `Login failed` |
| `roundcube-auth` | Roundcube | `FAILED login` / `IMAP Error: Login failed` |
| `phpmyadmin-syslog` | phpMyAdmin | syslog 中的 `user denied` |
| `webmin-auth` | Webmin | `Invalid login` / `Non-existent login` |
| `directadmin` | DirectAdmin | `N failed login attempts` |
| `froxlor-auth` | Froxlor | classic `[Login Action IP]` / JSON `"user":"IP"` |
| `bitwarden` | Bitwarden | `[WRN] Failed login attempt` |
| `sogo-auth` | SOGo | `SOGoRootPage Login ... might not have worked` |
| `horde` | Horde/IMP | `FAILED LOGIN` |
| `groupoffice` | Group-Office | `LOGIN FAILED ... from IP` |
| `tine20` | Tine 2.0 | `Tinebase_Controller::login` failed |
| `centreon` | Centreon | `Authentication failed for ...` |

## 邮件

| Filter | 软件 | 典型日志 |
|---|---|---|
| `postfix` | Postfix | `mail.log`：SASL 失败、Relay access denied |
| `exim` | Exim | `mainlog`：认证失败、relay not permitted |
| `sendmail-auth` | Sendmail | `possible SMTP attack: command=AUTH`、`AUTH failure` |
| `dovecot` | Dovecot | `auth failed`、PAM、`auth-worker`、v2.4 `Login aborted` |
| `courier-auth` | Courier | `authdaemond` 认证失败 |
| `cyrus-imap` | Cyrus IMAP | `badlogin` |
| `zimbra-auth` | Zimbra | `mailbox.log` 中的 SOAP `authentication failed` |
| `sendmail-reject` | Sendmail | `ruleset=check_rcpt` / pre-greeting reject |
| `exim-spam` | Exim | `rejected by local_scan` / dnsbl / virus |
| `courier-smtp` | Courier ESMTP | `error,relay=IP` + 550/535 |
| `kerio` | Kerio Connect | SMTP spam/relay/auth failures |
| `assp` | ASSP | SSL negotiation / AUTH errors |

## FTP

| Filter | 软件 | 典型日志 |
|---|---|---|
| `vsftpd` | vsftpd | `FAIL LOGIN` |
| `proftpd` | ProFTPD | `Login failed` |
| `pure-ftpd` | Pure-FTPd | `Authentication failed` |

## VPN 与 VoIP

| Filter | 软件 | 典型日志 |
|---|---|---|
| `openvpn` | OpenVPN | `Username/Password authentication failed`、TLS handshake failed |
| `asterisk` | Asterisk SIP | 认证失败、注册失败 |
| `softethervpn` | SoftEther VPN | `User authentication failed ... from IP` |
| `freeswitch` | FreeSWITCH | sofia SIP auth failure/challenge；支持 `mode` |

## 数据库

| Filter | 软件 | 典型日志 |
|---|---|---|
| `mysqld-auth` | MySQL / MariaDB | error log 中的 `Access denied` |
| `mssql-auth` | Microsoft SQL Server | `Login failed for user ... [CLIENT: IP]` |
| `mongodb-auth` | MongoDB | MongoDB 4+ JSON 日志中的 `Authentication failed` |

## 其他基础设施

| Filter | 软件 | 典型日志 |
|---|---|---|
| `samba` | Samba | `check_ntlm_password` 认证失败 |
| `jenkins-auth` | Jenkins | `jenkins.log` 中的 `Login failure` |
| `squid` | Squid | `TCP_DENIED/403` 或 `NONE/405` |
| `rsync` | rsync daemon | `auth failed on module` |
| `portsentry` | PortSentry | `Host: IP/IP Port: N TCP|UDP Blocked` |
| `stunnel` | stunnel | 客户端证书失败 |
| `monit` | Monit | HTTP Basic Auth 失败 |

## 尚未移植的上游过滤器

Gojail 当前内置 56 个主流过滤器；上游 fail2ban 还有约 48 个 filter 尚未移植，例如：

- Web 服务器：`apache-botsearch`、`apache-fakegooglebot`、`apache-modsecurity`、`apache-nohome`、`apache-pass`、`apache-shellshock`、`nginx-nohome`、`nginx-noscript`、`nginx-overflows`、`nginx-req-limit`、`nginx-shellshock`
- 邮件：`exim-common`、`exim-spam` 已加一部分，仍有上游组合配置；`sendmail` 其余规则
- 其他：`boinc`、`counter-strike`、`froxlor` 其他模式、`openhab`、`squid` 其他 ACL、`wowza` 等

这些过滤器依赖各自的产品日志格式，可以按同样方式继续补充。当前未移植不代表不支持该软件，自定义 `failregex` 仍可使用。

以下软件核心默认没有稳定、包含来源 IP 的失败日志，通常需要插件/访问日志/ACL 方案：

- WordPress / Drupal / Joomla：依赖安全插件、Web 服务器 401/403 access log 或数据库 watchdog。
- FreeRADIUS、strongSwan、Kamailio：日志字段和连接/IP 关联方式差异较大，建议按实际版本自定义。

## Filter 参数与 mode

`filter` 支持和 action 一样的方括号参数：

```ini
[sshd]
filter = sshd[mode=aggressive]

[freeswitch]
filter = freeswitch[mode=ddos]
```

加载器会先替换 `%(...)s`，再递归展开 `<mode>`、`<mdre-<mode>>` 之类的标签。例如：

```ini
mode = extra
mdre-normal = ^SIP auth failure ...
mdre-ddos = ^SIP auth (?:failure|challenge) ...
mdre-extra = <mdre-ddos>
failregex = <mdre-<mode>>
```

`freeswitch` 当前支持 `normal`、`ddos`、`extra`、`aggressive`；其他过滤器是否支持 mode 取决于自身配置。未指定 mode 时使用 filter 内定义的默认值。

## 使用方式

```ini
[postfix]
enabled = true
filter = postfix
logpath = /var/log/mail.log
maxretry = 5
findtime = 10m
bantime = 1h
action = iptables-multiport[name=postfix, port="smtp,submission", protocol=tcp, chain=INPUT]
```

Apache 使用 error log，Caddy 需要先启用 access log：

```caddyfile
log {
    output file /var/log/caddy/access.log
}
```

测试过滤器：

```bash
gj-regex -config ./config /var/log/mail.log postfix
gj-regex -config ./config -mode ddos /var/log/freeswitch.log freeswitch
go test ./internal/filter -run 'TestReal|TestFreeswitchModes' -v
```
