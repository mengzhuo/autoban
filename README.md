# gojail

**English** | [简体中文](README_zh.md)

> A lightweight fail2ban implementation in Go: log-driven, jail-based, with automatic ban and unban actions.

![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
[![GitHub](https://img.shields.io/badge/GitHub-mengzhuo%2Fgojail-181717?logo=github)](https://github.com/mengzhuo/gojail)
[![CI](https://github.com/mengzhuo/gojail/actions/workflows/ci.yml/badge.svg)](https://github.com/mengzhuo/gojail/actions/workflows/ci.yml)

gojail watches SSH, nginx, Apache and other logs, matches failed logins, scans and authentication errors with `failregex`, counts failures per host within `findtime`, and runs `actionban` once `maxretry` is reached. Bans are removed automatically with `actionunban` when `bantime` expires.

The configuration format and `filter.d` / `action.d` semantics stay close to fail2ban, so existing jails, filters and action scripts can be migrated with minimal changes. gojail depends only on the Go standard library. It is intended both as a lightweight intrusion-prevention service and as a readable implementation for learning how fail2ban works.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Production Deployment](#production-deployment)
- [fail2ban Compatibility](#fail2ban-compatibility)
- [Limitations](#limitations)
- [Security](#security)
- [Development and Testing](#development-and-testing)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Features

- **fail2ban-style configuration**: `gojail.conf` / `jail.conf` / `.local`, with `[DEFAULT]` inheritance, `%(option)s` interpolation, `[INCLUDES] before/after` and multi-line values.
- **Filter engine**: `failregex`, `ignoreregex` and `prefregex`, with `<HOST>`, `<ADDR>`, `<SUBNET>`, `<USER>` and related placeholders.
- **Bundled filters**: OpenSSH, nginx HTTP auth, Apache 2.4/2.2 auth and Caddy JSON 401 access logs.
- **Log timestamp detection**: built-in syslog, ISO-8601, nginx, Apache and epoch formats, plus custom `datepattern` support.
- **Full ban lifecycle**: `maxretry`, `findtime`, `bantime`, permanent bans, `ignoreip`, `ignorecommand` and `bantime.increment`.
- **Action system**: `actioncheck/start/stop/ban/unban/flush`, multiple actions per jail, tag substitution, execution timeouts and process-group cleanup.
- **File backend**: logpath globs, rotation, truncation, partial lines and new-file detection.
- **Persistence**: bans, failure counters and ban history are stored in an atomic JSON snapshot; state is restored on restart and active rules are re-applied.
- **Runtime control**: a Unix socket with a JSON protocol for status, jail start/stop, manual ban/unban, live option changes, flush and reload.
- **Zero third-party dependencies**: standard library only; Linux target.
- **Unprivileged operation**: the sample systemd unit runs as a dedicated user with only `CAP_NET_ADMIN` as an ambient capability.

## Quick Start

Requirements: Go 1.22+ and Linux.

```bash
git clone https://github.com/mengzhuo/gojail.git
cd gojail
make build
```

If you only need the commands in `$GOBIN`:

```bash
go install github.com/mengzhuo/gojail/cmd/gojail@latest
go install github.com/mengzhuo/gojail/cmd/gj@latest
go install github.com/mengzhuo/gojail/cmd/gj-regex@latest
```

This produces three binaries:

```text
bin/gojail       daemon
bin/gj           control CLI
bin/gj-regex     offline filter tester
```

Run the built-in demo. It uses the `dummy` action and `/tmp/gojail*` paths, so it does not touch the firewall:

```bash
make demo
```

Manual run:

```bash
mkdir -p /tmp/gojail-demo
: > /tmp/gojail-demo/auth.log

# Terminal 1: start the daemon
./bin/gojail -config ./config

# Terminal 2: inspect status
./bin/gj -config ./config status
./bin/gj -config ./config status sshd

# Inject a failed login
echo "$(date '+%b %e %H:%M:%S') demo sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2" \
  >> /tmp/gojail-demo/auth.log

# Once maxretry is reached, inspect the ban list
./bin/gj -config ./config banned sshd
```

## Commands

| Command | Purpose |
|---|---|
| `gojail` | Daemon; runs in the foreground, preferably under systemd |
| `gj` | Control CLI; talks to the running daemon over a Unix socket |
| `gj-regex` | Offline filter tester for log files and failregex patterns |

Common control commands:

```bash
gj -config ./config status
gj -config ./config status sshd
gj -config ./config banned sshd
gj -config ./config failures sshd
gj -config ./config start sshd
gj -config ./config stop sshd
gj -config ./config restart sshd
gj -config ./config banip sshd 203.0.113.9
gj -config ./config unbanip sshd 203.0.113.9
gj -config ./config flush sshd
gj -config ./config get sshd bantime
gj -config ./config set sshd maxretry 5
gj -config ./config reload
gj -config ./config stop          # stop the whole service when no jail is given
```

Test a filter offline:

```bash
gj-regex -config ./config /var/log/auth.log sshd
gj-regex -v -config ./config /var/log/auth.log sshd
gj-regex /var/log/auth.log 'Failed password for .* from <HOST>'
```

## Configuration

The default config directory is `./config` when `config/gojail.conf` exists; otherwise `/etc/gojail` is used. Multiple directories can be specified explicitly:

```bash
gojail -config /etc/gojail
gojail -config /etc/gojail,/etc/gojail-local
gj -config /etc/gojail status
```

Load order (later files override earlier ones):

1. `gojail.conf`
2. `gojail.local`
3. `jail.conf`
4. `jail.local`

If neither `gojail.conf` nor `gojail.local` exists, `fail2ban.conf` / `fail2ban.local` are loaded as a fallback to ease migration. `filter.d/<name>.conf` and `.local`, as well as `action.d/<name>.conf` and `.local`, are merged in the same way.

Minimal configuration:

```ini
# gojail.conf
[Definition]
socket = /run/gojail/gojail.sock
pidfile = /run/gojail/gojail.pid
dbfile = /var/lib/gojail/gojail.db
logtarget = /var/log/gojail/gojail.log
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

`%(__name__)s` expands to the current jail name. Action parameters are comma-separated inside square brackets; values may be quoted with single or double quotes.

For the full global/jail option reference, filter placeholders and action tags, see [docs/configuration.md](docs/configuration.md).

## Architecture

```text
gojail (daemon)
├── config loader        gojail.conf / jail.conf(.local)
│   ├── filter.d         compile failregex, ignoreregex, datepattern
│   └── action.d         load scripts, parameters and timeouts
├── polling backend      follow logpath, handle rotation/truncation/partial lines
├── filter               extract <HOST> and log timestamp
├── ban.Tracker          findtime window, maxretry, ban lifecycle
├── action               substitute <ip>/<matches>, execute shell scripts
├── store                JSON snapshot (bans/failures/ban history)
└── control socket       JSON request/response used by gj

gj ── Unix socket ──> gojail
gj-regex ── offline filter validation
```

Data flow:

1. The backend reads a complete log line.
2. The filter applies `prefregex`, `ignoreregex` and `failregex`, extracting `<HOST>` and the timestamp.
3. `ignoreip` / `ignorecommand` removes known-safe sources.
4. `ban.Tracker` prunes failures outside `findtime` and increments the counter.
5. At `maxretry`, a ban is created, the effective `bantime` is computed, and all `actionban` scripts run.
6. A background timer expires bans and runs `actionunban`.
7. State is written to the JSON database; on restart, unexpired bans are restored and re-applied after `actionstart`.

## Production Deployment

```bash
# Install binaries
sudo install -m 0755 bin/gojail bin/gj bin/gj-regex /usr/local/bin/

# Install configuration (the demo config uses /tmp paths; adapt for production)
sudo install -d /etc/gojail
sudo cp config/gojail.conf config/jail.conf /etc/gojail/
sudo cp -r config/filter.d config/action.d /etc/gojail/

# Create the service user/group and install the systemd unit
sudo install -D -m 0644 contrib/gojail.sysusers /etc/sysusers.d/gojail.conf
sudo systemd-sysusers
sudo install -m 0644 contrib/gojail.service /etc/systemd/system/gojail.service
sudo systemctl daemon-reload
sudo systemctl enable --now gojail

# Allow an admin account to use the control socket (socket mode 0660)
sudo usermod -aG gojail "$USER"
```

Deployment notes:

1. The unit runs gojail as the unprivileged `gojail` user. Firewall access is limited to `CAP_NET_ADMIN` through `AmbientCapabilities=` / `CapabilityBoundingSet=`; full root is not required.
2. Ensure the `gojail` user can read the monitored logs. The unit grants the `adm` supplementary group for Debian/Ubuntu `auth.log`. On systems with root-only logs (for example `/var/log/secure`), add an ACL or adjust `SupplementaryGroups=`.
3. Admin users must be members of the `gojail` group to use `gj` over the `0660` socket. Re-login after changing group membership.
4. The UFW action writes `/etc/ufw` and `/var/lib/ufw`. With `ProtectSystem=strict`, prefer iptables/nftables or add the required writable paths and permissions.
5. Start with `banaction = dummy` to validate logs and regexes, then switch to `iptables-multiport`, `nftables` or `ufw`.
6. The sample iptables action only handles IPv4; use an `ip6tables` variant for IPv6.
7. Prefer rename+create for log rotation; copytruncate has an edge case when the new content is longer than the old offset.

## fail2ban Compatibility

| Capability | Status |
|---|---|
| `gojail.conf` / `jail.conf` / `.local` layering | ✅ |
| `filter.d` failregex / ignoreregex / prefregex | ✅ |
| `action.d` lifecycle, parameters, multiple actions | ✅ |
| `ignoreip`, `usedns`, `ignorecommand` | ✅ |
| `bantime.increment/factor/maxtime/rndtime` | ✅ |
| File rotation/truncation tracking | ✅ |
| Python regex lookaround / backreferences | ❌ not supported by RE2 |
| systemd journal backend | ❌ polling only |
| SQLite database | ❌ JSON snapshot |
| `fail2ban-client` protocol | ❌ gojail JSON protocol |
| Full multi-line ticket aggregation | ⚠️ common prefregex markers only |

gojail contains no fail2ban source code and is not wire-compatible with `fail2ban-client`. Configuration and core semantics intentionally follow fail2ban. See [docs/fail2ban-analysis.md](docs/fail2ban-analysis.md) for a detailed comparison.

## Limitations

- Go's standard `regexp` uses RE2, which lacks lookahead, lookbehind and backreferences; some complex upstream filters need adjustment.
- Only the file-polling backend is implemented; systemd journal, inotify and gamin are not supported.
- Persistence uses a JSON snapshot rather than SQLite.
- `prefregex` and `<F-MLFID>` support common cases only; there is no full multi-line state machine.
- Linux only; relies on Unix sockets, flock and process-group signals.
- The daemon does not drop privileges itself; use the provided systemd unit or run it as a dedicated user with the required capabilities.

## Security

- Action scripts run through `/bin/sh -c`. `<ip>` is validated as an IP or strict hostname, but `<matches>` comes from logs and is attacker-controlled. **Never interpolate `<matches>` / `<ipmatches>` into a shell script without quoting.**
- The sample systemd unit runs gojail as an unprivileged user with only `CAP_NET_ADMIN`. If you start it manually as root, it does not drop privileges itself.
- Prefer a dedicated service user (or `DynamicUser=yes`). Avoid shared accounts such as `nobody`/`nouser`; they make socket, state and log ownership harder to manage.
- `usedns = raw` passes hostnames directly to action scripts; prefer `usedns = no` or `warn`.
- The JSON database contains ban history and log fragments and is created with mode `0600`; protect it as sensitive data.
- Validate rules with the `dummy` action before switching to real firewall actions.

## Development and Testing

```bash
make build      # build all three commands
make test       # unit + end-to-end tests
make race       # race detector
make vet        # go vet
make demo       # end-to-end demo
go test ./internal/filter -run TestReal -v   # sanitized real-world log fixtures
```

GitHub Actions runs four independent jobs: `fmt`, `lint`, `build` and `test`; see [.github/workflows/ci.yml](.github/workflows/ci.yml).

Project layout:

```text
cmd/gojail/       daemon
cmd/gj/           control CLI
cmd/gj-regex/     offline filter tester
internal/config/  INI parsing, interpolation, includes, jail/filter/action loading
internal/filter/  failregex compilation, <HOST> expansion, time parsing
internal/ban/     failure counting, bans, increment, ignore list, snapshots
internal/action/  action execution and tag substitution
internal/backend/ file polling backend
internal/jail/    jail runtime orchestration
internal/engine/  configuration, socket, lifecycle, hot reload
internal/store/   JSON persistence
internal/api/     socket protocol and client types
config/           demo configuration, filters and actions
docs/             analysis and configuration reference
contrib/          systemd unit and sysusers definition
scripts/demo.sh   end-to-end demo
.github/          GitHub Actions CI
```

Tests cover configuration parsing, IPv4/IPv6, date formats, ban policy, action timeouts, log rotation, end-to-end banning, restart recovery and hot reload. The filter suite also includes sanitized real-world OpenSSH, nginx, Apache and Caddy log fixtures under `internal/filter/testdata/`.

## Documentation

- [Configuration reference](docs/configuration.md)
- [fail2ban feature analysis and gojail mapping](docs/fail2ban-analysis.md)
- [systemd unit](contrib/gojail.service)
- [sysusers definition](contrib/gojail.sysusers)
- [Demo script](scripts/demo.sh)

The detailed documentation is currently written in Chinese. The English README above is the default project overview.

## Contributing

Issues and pull requests are welcome at <https://github.com/mengzhuo/gojail>.

## License

MIT
