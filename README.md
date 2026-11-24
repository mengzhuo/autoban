# autoban

**English** | [简体中文](README_zh.md)

> A lightweight fail2ban implementation in Go: log-driven, jail-based, with automatic ban and unban actions.

![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
[![GitHub](https://img.shields.io/badge/GitHub-mengzhuo%2Fautoban-181717?logo=github)](https://github.com/mengzhuo/autoban)
[![CI](https://github.com/mengzhuo/autoban/actions/workflows/ci.yml/badge.svg)](https://github.com/mengzhuo/autoban/actions/workflows/ci.yml)

autoban watches SSH, nginx, Apache and other logs, matches failed logins, scans and authentication errors with `failregex`, counts failures per host within `findtime`, and runs `actionban` once `maxretry` is reached. Bans are removed automatically with `actionunban` when `bantime` expires.

The configuration format and `filter.d` / `action.d` semantics stay close to fail2ban, so existing jails, filters and action scripts can be migrated with minimal changes. autoban depends only on the Go standard library. It is intended both as a lightweight intrusion-prevention service and as a readable implementation for learning how fail2ban works.

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

- **fail2ban-style configuration**: `autoban.conf` / `jail.conf` / `.local`, with `[DEFAULT]` inheritance, `%(option)s` interpolation, `[INCLUDES] before/after` and multi-line values.
- **Filter engine**: `failregex`, `ignoreregex` and `prefregex`, with `<HOST>`, `<ADDR>`, `<SUBNET>`, `<USER>` and related placeholders.
- **Filter modes and parameters**: `filter = name[mode=aggressive]`, recursive `<mode>` / `<mdre-<mode>>` tag expansion and per-filter option overrides.
- **103 bundled filters**: SSH, web servers, web apps/panels, mail, FTP, VPN/VoIP, databases and infrastructure; see [docs/filters.md](docs/filters.md).
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
git clone https://github.com/mengzhuo/autoban.git
cd autoban
make build
```

If you only need the commands in `$GOBIN`:

```bash
go install github.com/mengzhuo/autoban/cmd/autoban@latest
go install github.com/mengzhuo/autoban/cmd/autoban-ctl@latest
go install github.com/mengzhuo/autoban/cmd/autoban-regex@latest
```

This produces three binaries:

```text
bin/autoban          daemon
bin/autoban-ctl      control CLI
bin/autoban-regex    offline filter tester
```

Run the built-in demo. It uses the `dummy` action and `/tmp/autoban*` paths, so it does not touch the firewall:

```bash
make demo
```

Manual run:

```bash
mkdir -p /tmp/autoban-demo
: > /tmp/autoban-demo/auth.log

# Terminal 1: start the daemon
./bin/autoban -config ./config

# Terminal 2: inspect status
./bin/autoban-ctl -config ./config status
./bin/autoban-ctl -config ./config status sshd

# Inject a failed login
echo "$(date '+%b %e %H:%M:%S') demo sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2" \
  >> /tmp/autoban-demo/auth.log

# Once maxretry is reached, inspect the ban list
./bin/autoban-ctl -config ./config banned sshd
```

## Commands

| Command | Purpose |
|---|---|
| `autoban` | Daemon; runs in the foreground, preferably under systemd |
| `autoban-ctl` | Control CLI; talks to the running daemon over a Unix socket |
| `autoban-regex` | Offline filter tester for log files and failregex patterns |

Common control commands:

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
autoban-ctl -config ./config stop          # stop the whole service when no jail is given
```

Test a filter offline:

```bash
autoban-regex -config ./config /var/log/auth.log sshd
autoban-regex -v -config ./config /var/log/auth.log sshd
autoban-regex /var/log/auth.log 'Failed password for .* from <HOST>'
```

## Configuration

The default config directory is `./config` when `config/autoban.conf` exists; otherwise `/etc/autoban` is used. Multiple directories can be specified explicitly:

```bash
autoban -config /etc/autoban
autoban -config /etc/autoban,/etc/autoban-local
autoban-ctl -config /etc/autoban status
```

Load order (later files override earlier ones):

1. `autoban.conf`
2. `autoban.local`
3. `jail.conf`
4. `jail.local`

If neither `autoban.conf` nor `autoban.local` exists, `fail2ban.conf` / `fail2ban.local` are loaded as a fallback to ease migration. `filter.d/<name>.conf` and `.local`, as well as `action.d/<name>.conf` and `.local`, are merged in the same way.

Minimal configuration:

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

`%(__name__)s` expands to the current jail name. Action parameters are comma-separated inside square brackets; values may be quoted with single or double quotes.

For the full global/jail option reference, filter placeholders and action tags, see [docs/configuration.md](docs/configuration.md).

## Architecture

```text
autoban (daemon)
├── config loader        autoban.conf / jail.conf(.local)
│   ├── filter.d         compile failregex, ignoreregex, datepattern
│   └── action.d         load scripts, parameters and timeouts
├── polling backend      follow logpath, handle rotation/truncation/partial lines
├── filter               extract <HOST> and log timestamp
├── ban.Tracker          findtime window, maxretry, ban lifecycle
├── action               substitute <ip>/<matches>, execute shell scripts
├── store                JSON snapshot (bans/failures/ban history)
└── control socket       JSON request/response used by autoban-ctl

autoban-ctl ── Unix socket ──> autoban
autoban-regex ── offline filter validation
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
sudo install -m 0755 bin/autoban bin/autoban-ctl bin/autoban-regex /usr/local/bin/

# Install configuration (the demo config uses /tmp paths; adapt for production)
sudo install -d /etc/autoban
sudo cp config/autoban.conf config/jail.conf /etc/autoban/
sudo cp -r config/filter.d config/action.d /etc/autoban/

# Create the service user/group and install the systemd unit
sudo install -D -m 0644 contrib/autoban.sysusers /etc/sysusers.d/autoban.conf
sudo systemd-sysusers
sudo install -m 0644 contrib/autoban.service /etc/systemd/system/autoban.service
sudo systemctl daemon-reload
sudo systemctl enable --now autoban

# Allow an admin account to use the control socket (socket mode 0660)
sudo usermod -aG autoban "$USER"
```

Deployment notes:

1. The unit runs autoban as the unprivileged `autoban` user. Firewall access is limited to `CAP_NET_ADMIN` through `AmbientCapabilities=` / `CapabilityBoundingSet=`; full root is not required.
2. Ensure the `autoban` user can read the monitored logs. The unit grants the `adm` supplementary group for Debian/Ubuntu `auth.log`. On systems with root-only logs (for example `/var/log/secure`), add an ACL or adjust `SupplementaryGroups=`.
3. Admin users must be members of the `autoban` group to use `autoban-ctl` over the `0660` socket. Re-login after changing group membership.
4. The UFW action writes `/etc/ufw` and `/var/lib/ufw`. With `ProtectSystem=strict`, prefer iptables/nftables or add the required writable paths and permissions.
5. Start with `banaction = dummy` to validate logs and regexes, then switch to `iptables-multiport`, `nftables` or `ufw`.
6. The sample iptables action only handles IPv4; use an `ip6tables` variant for IPv6.
7. Prefer rename+create for log rotation; copytruncate has an edge case when the new content is longer than the old offset.

### Packages

Local Debian and Alpine packages can be built from the repository:

```bash
make deb       # dist/autoban_<version>_<arch>.deb
make apk       # dist/autoban-<version>-r0.apk
make packages  # both
```

Both packages declare an explicit dependency on `nftables` and an explicit conflict with `fail2ban`.

- Debian/Ubuntu: systemd unit, dedicated `autoban` user, `CAP_NET_ADMIN`, default SSH log `/var/log/auth.log`.
- Alpine: OpenRC service, default SSH log `/var/log/messages`, runs as root because nftables needs privileged access.

See [docs/packaging.md](docs/packaging.md) for build, install, signing and uninstall details.

## fail2ban Compatibility

| Capability | Status |
|---|---|
| `autoban.conf` / `jail.conf` / `.local` layering | ✅ |
| `filter.d` failregex / ignoreregex / prefregex | ✅ |
| `action.d` lifecycle, parameters, multiple actions | ✅ |
| `ignoreip`, `usedns`, `ignorecommand` | ✅ |
| `bantime.increment/factor/maxtime/rndtime` | ✅ |
| File rotation/truncation tracking | ✅ |
| Python regex lookaround / backreferences | ❌ not supported by RE2 |
| systemd journal backend | ❌ polling only |
| SQLite database | ❌ JSON snapshot |
| `fail2ban-client` protocol | ❌ autoban JSON protocol |
| Full multi-line ticket aggregation | ⚠️ common prefregex markers only |

autoban contains no fail2ban source code and is not wire-compatible with `fail2ban-client`. Configuration and core semantics intentionally follow fail2ban. See [docs/fail2ban-analysis.md](docs/fail2ban-analysis.md) for a detailed comparison.

## Limitations

- Go's standard `regexp` uses RE2, which lacks lookahead, lookbehind and backreferences; some complex upstream filters need adjustment.
- Only the file-polling backend is implemented; systemd journal, inotify and gamin are not supported.
- Persistence uses a JSON snapshot rather than SQLite.
- `prefregex` and `<F-MLFID>` support common cases only; there is no full multi-line state machine.
- Linux only; relies on Unix sockets, flock and process-group signals.
- The daemon does not drop privileges itself; use the provided systemd unit or run it as a dedicated user with the required capabilities.

## Security

- Action scripts run through `/bin/sh -c`. `<ip>` is validated as an IP or strict hostname, but `<matches>` comes from logs and is attacker-controlled. **Never interpolate `<matches>` / `<ipmatches>` into a shell script without quoting.**
- The sample systemd unit runs autoban as an unprivileged user with only `CAP_NET_ADMIN`. If you start it manually as root, it does not drop privileges itself.
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
cmd/autoban/        daemon
cmd/autoban-ctl/    control CLI
cmd/autoban-regex/  offline filter tester
internal/config/    INI parsing, interpolation, includes, jail/filter/action loading
internal/filter/    failregex compilation, <HOST> expansion, time parsing
internal/ban/       failure counting, bans, increment, ignore list, snapshots
internal/action/    action execution and tag substitution
internal/backend/   file polling backend
internal/jail/      jail runtime orchestration
internal/engine/    configuration, socket, lifecycle, hot reload
internal/store/     JSON persistence
internal/api/       socket protocol and client types
config/             demo configuration, filters and actions
docs/               analysis and configuration reference
contrib/            systemd unit and sysusers definition
scripts/demo.sh     end-to-end demo
.github/            GitHub Actions CI
```

Tests cover configuration parsing, IPv4/IPv6, date formats, ban policy, action timeouts, log rotation, end-to-end banning, restart recovery and hot reload. The filter suite also includes sanitized real-world log fixtures for all bundled filters under `internal/filter/testdata/`; formats were cross-checked against fail2ban upstream `filter.d` and its test corpus.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Packaging and installation](docs/packaging.md)
- [Bundled filter catalog](docs/filters.md)
- [Upstream fail2ban source review](docs/upstream-review.md)
- [fail2ban feature analysis and autoban mapping](docs/fail2ban-analysis.md)
- [systemd unit](contrib/autoban.service)
- [sysusers definition](contrib/autoban.sysusers)
- [Demo script](scripts/demo.sh)

The detailed documentation is currently written in Chinese. The English README above is the default project overview.

## Contributing

Issues and pull requests are welcome at <https://github.com/mengzhuo/autoban>.

## License

MIT
