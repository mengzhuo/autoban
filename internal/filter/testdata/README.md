# Log fixtures

These fixtures use realistic OpenSSH and nginx error-log formats. All source
addresses are from documentation ranges (RFC 5737 / RFC 3849), and hostnames
and usernames are fictional. They are sanitized excerpts rather than copies of
production logs.

- `ssh/auth.log`: syslog and ISO-8601 OpenSSH authentication failures, IPv4,
  IPv6, IPv4-mapped IPv6, PAM messages and non-failure noise.
- `nginx/error.log`: nginx HTTP basic-auth failures plus unrelated error and
  notice lines.

The tests in `internal/filter/real_logs_test.go` load the shipped filters from
`config/filter.d` and assert the match and per-host counts.
