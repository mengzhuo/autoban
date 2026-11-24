# autoban 内置过滤器

`config/filter.d/` 目前包含 104 个过滤器。所有过滤器都使用 RE2 兼容正则，并有对应的真实格式日志样本和测试，位于 `internal/filter/testdata/`。

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
| `wordpress` | WordPress | Caddy JSON access log 中 `POST /wp-login.php` 或 `POST /xmlrpc.php` 的失败请求 |
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

其余本轮新增的 47 个过滤器见上表。
## 本轮新增的 47 个过滤器

| Filter | 软件 / 场景 |
|---|---|
| `3proxy` | 3proxy 认证失败 |
| `apache-botsearch` | Apache webmail/phpMyAdmin/WordPress 探测 |
| `apache-fakegooglebot` | Apache Googlebot 访问日志（建议配合 ignorecommand 校验） |
| `apache-modsecurity` | ModSecurity access denied |
| `apache-nohome` | Apache `/~user` 枚举 |
| `apache-pass` | knockd 风格 `/knocking/` 成功请求 |
| `apache-shellshock` | Apache Shellshock CGI 探测 |
| `authelia` | Authelia 认证失败 |
| `counter-strike` | Counter-Strike Bad Rcon |
| `cowrie` | Cowrie 新 SSH 会话 |
| `dante` | Dante SOCKS 认证失败 |
| `domino-smtp` | HCL Domino SMTP 认证失败 |
| `drupal-auth` | Drupal watchdog 登录失败 |
| `ejabberd-auth` | ejabberd c2s 认证失败 |
| `gitlab` | GitLab 登录失败（文本/JSON） |
| `grafana` | Grafana 用户名/密码错误 |
| `gssftpd` | GSS FTP 重复登录失败 |
| `guacamole` | Guacamole 认证失败 |
| `monitorix` | Monitorix HTTP 访问错误 |
| `murmur` | Murmur 拒绝连接 |
| `nagios` | NRPE 主机不允许 |
| `named-refused` | BIND 拒绝查询/区域传送 |
| `nsd` | NSD 限速/ACL 拒绝 |
| `openhab` | openHAB 401 |
| `openwebmail` | OpenWebMail 登录/用户错误 |
| `oracleims` | Oracle Messaging Server 密码错误 |
| `pam-generic` | 通用 PAM 认证失败 |
| `perdition` | Perdition 代理认证失败 |
| `php-url-fopen` | PHP RFI access log |
| `proxmox` | Proxmox VE 认证失败 |
| `qmail` | qmail/rblsmtpd RBL 阻断 |
| `recidive` | 重复封禁（兼容 fail2ban 与 autoban 日志） |
| `routeros-auth` | MikroTik RouterOS 登录失败 |
| `scanlogd` | scanlogd 扫描报告 |
| `screensharingd` | macOS Screen Sharing 认证失败 |
| `selinux-ssh` | SELinux SSH 失败审计 |
| `sieve` | Cyrus timsieved 认证失败 |
| `solid-pop3d` | Solid POP3 认证失败 |
| `squirrelmail` | SquirrelMail 登录错误 |
| `suhosin` | Suhosin attacker 告警 |
| `uwimap-auth` | UW-IMAP/POP3 登录失败 |
| `vaultwarden` | Vaultwarden 登录/2FA/admin 错误 |
| `wuftpd` | wu-ftpd 登录失败 |
| `xinetd-fail` | xinetd 访问控制失败 |
| `xrdp` | xrdp-sesman 认证失败 |
| `znc-adminlog` | ZNC 登录失败 |
| `zoneminder` | ZoneMinder 登录失败 |

## 尚未移植的上游过滤器

当前还差 1 个上游过滤器：

- `slapd`：OpenLDAP 的失败日志需要把同一 `conn=...` 的 `ACCEPT from IP=...` 与后续 `RESULT ... err=49` 关联起来，属于多行 ticket；当前 autoban 的单行匹配模型无法安全实现，暂未启用。
- `apache-common`、`botsearch-common`、`common`、`exim-common`、`nginx-error-common`、`selinux-common` 是上游的 include 片段，不是独立 filter，本项目直接内联了所需规则。

因此除 `slapd` 多行关联外，上游独立 filter 已全部覆盖。

以下软件核心默认没有稳定、包含来源 IP 的失败日志，通常需要插件/访问日志/ACL 方案：

- Drupal / Joomla：依赖安全插件、Web 服务器 401/403 access log 或数据库 watchdog。
- WordPress：本项目提供 `wordpress` filter，读取 Caddy JSON access log 中的 `wp-login.php` / `xmlrpc.php` 请求；其他 Web 服务器需按实际日志格式调整。
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
autoban-regex -config ./config /var/log/mail.log postfix
autoban-regex -config ./config -mode ddos /var/log/freeswitch.log freeswitch
go test ./internal/filter -run 'TestReal|TestFreeswitchModes' -v
```
