# gojail 内置过滤器

`config/filter.d/` 目前包含 34 个过滤器。所有过滤器都使用 RE2 兼容正则，并有对应的真实格式日志样本和测试，位于 `internal/filter/testdata/`。

## 系统与远程登录

| Filter | 软件 | 典型日志 |
|---|---|---|
| `sshd` | OpenSSH | `/var/log/auth.log`、`/var/log/secure` |
| `dropbear` | Dropbear SSH | syslog / auth.log |

## Web 服务器

| Filter | 软件 | 典型日志 |
|---|---|---|
| `nginx-http-auth` | nginx basic auth | `error.log` |
| `apache-auth` | Apache 2.4 / 2.2 basic auth | `error.log` |
| `caddy-auth` | Caddy | 启用 access log 后的 JSON 日志，`status=401` |
| `lighttpd-auth` | lighttpd | `error.log` |
| `haproxy-http-auth` | HAProxy | 带 `401` 的 access log |
| `traefik-auth` | Traefik | Common/combined access log，`401` |

## Web 应用与控制面板

| Filter | 软件 | 典型日志 |
|---|---|---|
| `nextcloud-auth` | Nextcloud | JSON 日志中的 `Login failed` |
| `roundcube` | Roundcube | `errors.log` 中的 `Failed login` |
| `phpmyadmin-syslog` | phpMyAdmin | syslog 中的 `user denied` |
| `webmin-auth` | Webmin | `miniserv.log` / syslog 中的 `Invalid login` |
| `directadmin` | DirectAdmin | DirectAdmin 登录日志 |
| `froxlor-auth` | Froxlor | Froxlor 登录日志 |

## 邮件

| Filter | 软件 | 典型日志 |
|---|---|---|
| `postfix` | Postfix | `mail.log`：SASL 失败、Relay access denied |
| `exim` | Exim | `mainlog`：认证失败、relay not permitted |
| `sendmail-auth` | Sendmail | `maillog`：AUTH 失败、Relaying denied |
| `dovecot` | Dovecot | `mail.log`：`auth failed`、PAM 认证失败 |
| `courier-auth` | Courier | `authdaemond` 认证失败 |
| `cyrus-imap` | Cyrus IMAP | `badlogin` |
| `zimbra-auth` | Zimbra | `mailbox.log` 中的 SOAP `authentication failed` |

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

## 数据库

| Filter | 软件 | 典型日志 |
|---|---|---|
| `mysql-auth` | MySQL / MariaDB | error log 中的 `Access denied` |
| `mssql-auth` | Microsoft SQL Server | `Logon Error: 18456` |
| `mongodb-auth` | MongoDB | JSON 日志中的 `Authentication failed` |

## 其他基础设施

| Filter | 软件 | 典型日志 |
|---|---|---|
| `samba` | Samba | `check_ntlm_password` 认证失败 |
| `jenkins-auth` | Jenkins | `jenkins.log` 中的 `Login failure` |
| `squid` | Squid | access log 中的 `407` |
| `rsync` | rsync daemon | `auth failed on module` |
| `portsentry` | PortSentry | `attackalert: Connect from host` |

## 未内置的软件

以下软件没有稳定、默认、且包含来源 IP 的失败日志格式，因此没有直接内置过滤器：

- WordPress / Drupal / Joomla：核心默认不记录失败登录；通常依赖安全插件、Web 服务器 401/403 access log 或数据库 watchdog。
- SoftEther VPN、FreeSWITCH、Kamailio、FreeRADIUS、strongSwan：日志字段和连接/IP 关联方式差异较大，建议按实际版本自定义。
- Bitwarden、Sogo、Horde、Group-Office、Tine 2.0、TWiki、Zope、Wowza、Kerio：产品专用格式，建议按部署版本补 filter。

这些软件仍然可以通过自定义 `failregex` 接入。参考现有 filter 的结构，并在 `internal/filter/testdata/` 添加脱敏日志样本即可。

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
go test ./internal/filter -run TestReal -v
```
