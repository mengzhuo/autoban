package filter_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mengzhuo/gojail/internal/config"
	"github.com/mengzhuo/gojail/internal/filter"
)

func loadFixtureFilter(t *testing.T, name string, ignore []string) *filter.Filter {
	t.Helper()
	fs, err := config.LoadFilter(name, []string{filepath.Join("..", "..", "config")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ignores := append([]string(nil), fs.IgnoreRegex...)
	ignores = append(ignores, ignore...)
	f, err := filter.Compile(filter.Options{
		Name:        name,
		FailRegex:   fs.FailRegex,
		IgnoreRegex: ignores,
		PreRegex:    fs.PreRegex,
		DatePattern: fs.DatePattern,
		MaxLines:    fs.MaxLines,
		UsedNS:      "no",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func scanFixture(t *testing.T, path string, f *filter.Filter, now time.Time) (matches map[string]int, total, matched int) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	matches = make(map[string]int)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		total++
		m, ok := f.Match(line, now)
		if !ok {
			continue
		}
		matched++
		matches[m.Host]++
		if m.Time.IsZero() {
			t.Fatalf("no timestamp parsed from %q", line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return matches, total, matched
}

func assertHostCounts(t *testing.T, got, want map[string]int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("host count = %d, want %d: got %#v", len(got), len(want), got)
	}
	for host, count := range want {
		if got[host] != count {
			t.Fatalf("host %s: got %d, want %d (all: %#v)", host, got[host], count, got)
		}
	}
}

func TestRealSSHLogFixture(t *testing.T) {
	f := loadFixtureFilter(t, "sshd", nil)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	hosts, total, matched := scanFixture(t, filepath.Join("testdata", "ssh", "auth.log"), f, now)
	if total != 18 || matched != 13 {
		t.Fatalf("total=%d matched=%d, want 18/13", total, matched)
	}
	assertHostCounts(t, hosts, map[string]int{
		"203.0.113.42":         1,
		"198.51.100.23":        1,
		"203.0.113.99":         1,
		"203.0.113.77":         1,
		"2001:db8::42":         1,
		"203.0.113.78":         1,
		"198.51.100.55":        1,
		"198.51.100.56":        1,
		"203.0.113.66":         1,
		"203.0.113.67":         1,
		"127.0.0.1":            1,
		"203.0.113.88":         1,
		"::ffff:198.51.100.77": 1,
	})
	statMatched, _ := f.Stats()
	if statMatched != 13 {
		t.Fatalf("filter stats matched=%d, want 13", statMatched)
	}
}

func TestRealSSHLogFixtureWithIgnoreRegex(t *testing.T) {
	f := loadFixtureFilter(t, "sshd", []string{`^.*from 127\.0\.0\.1 port .*$`})
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	hosts, _, matched := scanFixture(t, filepath.Join("testdata", "ssh", "auth.log"), f, now)
	if matched != 12 {
		t.Fatalf("matched=%d, want 12", matched)
	}
	assertHostCounts(t, hosts, map[string]int{
		"203.0.113.42":         1,
		"198.51.100.23":        1,
		"203.0.113.99":         1,
		"203.0.113.77":         1,
		"2001:db8::42":         1,
		"203.0.113.78":         1,
		"198.51.100.55":        1,
		"198.51.100.56":        1,
		"203.0.113.66":         1,
		"203.0.113.67":         1,
		"203.0.113.88":         1,
		"::ffff:198.51.100.77": 1,
	})
	_, ignored := f.Stats()
	if ignored != 1 {
		t.Fatalf("ignored=%d, want 1", ignored)
	}
}

func TestRealNginxLogFixture(t *testing.T) {
	f := loadFixtureFilter(t, "nginx-http-auth", nil)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	hosts, total, matched := scanFixture(t, filepath.Join("testdata", "nginx", "error.log"), f, now)
	if total != 7 || matched != 4 {
		t.Fatalf("total=%d matched=%d, want 7/4", total, matched)
	}
	assertHostCounts(t, hosts, map[string]int{
		"203.0.113.50":  1,
		"198.51.100.60": 1,
		"203.0.113.51":  1,
		"2001:db8::50":  1,
	})
}

func TestRealLogTimestampParsing(t *testing.T) {
	f := loadFixtureFilter(t, "sshd", nil)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	isoLine := `2024-01-15T03:14:00.123456+00:00 web01 sshd[12354]: Failed password for invalid user ftp from 203.0.113.88 port 60022 ssh2`
	m, ok := f.Match(isoLine, now)
	if !ok {
		t.Fatal("ISO line did not match")
	}
	wantISO := time.Date(2024, 1, 15, 3, 14, 0, 123456000, time.UTC)
	if !m.Time.Equal(wantISO) {
		t.Fatalf("ISO time = %v, want %v", m.Time, wantISO)
	}

	syslogLine := `Jan 15 03:12:44 web01 sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 51234 ssh2`
	m, ok = f.Match(syslogLine, now)
	if !ok {
		t.Fatal("syslog line did not match")
	}
	if m.Time.Month() != time.January || m.Time.Day() != 15 || m.Time.Hour() != 3 || m.Time.Minute() != 12 || m.Time.Second() != 44 {
		t.Fatalf("syslog time = %v", m.Time)
	}

	nginx := loadFixtureFilter(t, "nginx-http-auth", nil)
	nginxLine := `2024/01/15 03:20:10 [error] 2345#2345: *9876 user "admin": password mismatch, client: 203.0.113.50, server: _, request: "GET /admin HTTP/1.1", host: "example.com"`
	m, ok = nginx.Match(nginxLine, now)
	if !ok {
		t.Fatal("nginx line did not match")
	}
	wantNginx := time.Date(2024, 1, 15, 3, 20, 10, 0, time.Local)
	if !m.Time.Equal(wantNginx) {
		t.Fatalf("nginx time = %v, want %v", m.Time, wantNginx)
	}

	apache := loadFixtureFilter(t, "apache-auth", nil)
	apacheLine := `[Wed Oct 11 14:32:52.123456 2023] [auth_basic:error] [pid 1234:tid 5678] [client 203.0.113.20:54321] AH01617: user admin: authentication failure for "/admin": Password Mismatch`
	m, ok = apache.Match(apacheLine, now)
	if !ok {
		t.Fatal("apache line did not match")
	}
	wantApache := time.Date(2023, 10, 11, 14, 32, 52, 123456000, time.Local)
	if !m.Time.Equal(wantApache) {
		t.Fatalf("apache time = %v, want %v", m.Time, wantApache)
	}

	apache22 := `[Wed Oct 11 14:32:56 2023] [error] [client 203.0.113.22] user admin: authentication failure for "/admin": Password Mismatch`
	m, ok = apache.Match(apache22, now)
	if !ok {
		t.Fatal("apache 2.2 line did not match")
	}
	wantApache22 := time.Date(2023, 10, 11, 14, 32, 56, 0, time.Local)
	if !m.Time.Equal(wantApache22) {
		t.Fatalf("apache 2.2 time = %v, want %v", m.Time, wantApache22)
	}

	caddy := loadFixtureFilter(t, "caddy-auth", nil)
	caddyLine := `{"level":"info","ts":1705304700.123456,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"203.0.113.60","remote_port":"54321","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/admin","remote_addr":"203.0.113.60:54321"},"bytes_read":0,"user_id":"","duration":0.000123,"size":0,"status":401}`
	m, ok = caddy.Match(caddyLine, now)
	if !ok {
		t.Fatal("caddy line did not match")
	}
	wantCaddy := time.Unix(1705304700, 123456000)
	if !m.Time.Equal(wantCaddy) {
		t.Fatalf("caddy time = %v (%d), want %v (%d)", m.Time, m.Time.UnixNano(), wantCaddy, wantCaddy.UnixNano())
	}
}

func TestRealApacheLogFixture(t *testing.T) {
	f := loadFixtureFilter(t, "apache-auth", nil)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	hosts, total, matched := scanFixture(t, filepath.Join("testdata", "apache", "error.log"), f, now)
	if total != 7 || matched != 5 {
		t.Fatalf("total=%d matched=%d, want 7/5", total, matched)
	}
	assertHostCounts(t, hosts, map[string]int{
		"203.0.113.20":  1,
		"198.51.100.21": 1,
		"203.0.113.22":  1,
		"198.51.100.23": 1,
		"2001:db8::20":  1,
	})
}

func TestApacheAccessLogDoesNotMatchAuthFilter(t *testing.T) {
	f := loadFixtureFilter(t, "apache-auth", nil)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	_, total, matched := scanFixture(t, filepath.Join("testdata", "apache", "access.log"), f, now)
	if total != 3 || matched != 0 {
		t.Fatalf("access log total=%d matched=%d, want 3/0", total, matched)
	}
}

func TestRealCaddyLogFixture(t *testing.T) {
	f := loadFixtureFilter(t, "caddy-auth", nil)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	hosts, total, matched := scanFixture(t, filepath.Join("testdata", "caddy", "access.log"), f, now)
	if total != 5 || matched != 3 {
		t.Fatalf("total=%d matched=%d, want 5/3", total, matched)
	}
	assertHostCounts(t, hosts, map[string]int{
		"203.0.113.60":  1,
		"198.51.100.61": 1,
		"2001:db8::60":  1,
	})
}

func TestMoreRealLogFilters(t *testing.T) {
	cases := []struct {
		name    string
		filter  string
		fixture string
		total   int
		matched int
		hosts   map[string]int
	}{
		{"dropbear", "dropbear", "ssh/dropbear.log", 4, 2, map[string]int{"203.0.113.70": 1, "203.0.113.71": 1}},
		{"lighttpd", "lighttpd-auth", "web/lighttpd-auth.log", 3, 2, map[string]int{"203.0.113.73": 1, "203.0.113.74": 1}},
		{"haproxy", "haproxy-http-auth", "web/haproxy-http-auth.log", 3, 2, map[string]int{"203.0.113.75": 1, "2001:db8::76": 1}},
		{"traefik", "traefik-auth", "web/traefik-auth.log", 3, 2, map[string]int{"203.0.113.77": 1, "2001:db8::78": 1}},
		{"nextcloud", "nextcloud-auth", "webapps/nextcloud.log", 3, 2, map[string]int{"203.0.113.203": 1, "203.0.113.204": 1}},
		{"roundcube", "roundcube", "webapps/roundcube.log", 3, 2, map[string]int{"203.0.113.201": 1, "203.0.113.202": 1}},
		{"phpmyadmin", "phpmyadmin-syslog", "webapps/phpmyadmin.log", 3, 2, map[string]int{"203.0.113.202": 1, "203.0.113.203": 1}},
		{"webmin", "webmin-auth", "webapps/webmin.log", 3, 2, map[string]int{"203.0.113.200": 1, "203.0.113.201": 1}},
		{"postfix", "postfix", "mail/postfix.log", 3, 2, map[string]int{"203.0.113.90": 1, "203.0.113.91": 1}},
		{"dovecot", "dovecot", "mail/dovecot.log", 3, 2, map[string]int{"203.0.113.93": 1, "203.0.113.94": 1}},
		{"exim", "exim", "mail/exim.log", 3, 2, map[string]int{"203.0.113.95": 1, "203.0.113.96": 1}},
		{"vsftpd", "vsftpd", "ftp/vsftpd.log", 3, 2, map[string]int{"203.0.113.100": 1, "203.0.113.101": 1}},
		{"proftpd", "proftpd", "ftp/proftpd.log", 3, 2, map[string]int{"203.0.113.101": 1, "203.0.113.102": 1}},
		{"pure-ftpd", "pure-ftpd", "ftp/pure-ftpd.log", 3, 2, map[string]int{"203.0.113.102": 1, "203.0.113.103": 1}},
		{"openvpn", "openvpn", "vpn/openvpn.log", 3, 2, map[string]int{"203.0.113.110": 1, "203.0.113.111": 1}},
		{"asterisk", "asterisk", "voip/asterisk.log", 3, 2, map[string]int{"203.0.113.120": 1, "203.0.113.121": 1}},
		{"mysql", "mysql-auth", "db/mysql.log", 3, 2, map[string]int{"203.0.113.130": 1, "203.0.113.131": 1}},
		{"mongodb", "mongodb-auth", "db/mongodb.log", 3, 2, map[string]int{"203.0.113.131": 1, "203.0.113.132": 1}},
		{"samba", "samba", "other/samba.log", 3, 2, map[string]int{"203.0.113.140": 1, "203.0.113.141": 1}},
		{"jenkins", "jenkins-auth", "other/jenkins.log", 4, 2, map[string]int{"203.0.113.150": 1, "203.0.113.151": 1}},
		{"squid", "squid", "other/squid.log", 3, 2, map[string]int{"203.0.113.170": 1, "203.0.113.171": 1}},
		{"rsync", "rsync", "other/rsync.log", 3, 2, map[string]int{"203.0.113.180": 1, "203.0.113.181": 1}},
		{"sendmail", "sendmail-auth", "mail/sendmail.log", 3, 2, map[string]int{"203.0.113.210": 1, "203.0.113.211": 1}},
		{"courier", "courier-auth", "mail/courier.log", 3, 2, map[string]int{"203.0.113.211": 1, "203.0.113.212": 1}},
		{"cyrus", "cyrus-imap", "mail/cyrus.log", 3, 2, map[string]int{"203.0.113.212": 1, "203.0.113.213": 1}},
		{"zimbra", "zimbra-auth", "mail/zimbra.log", 3, 2, map[string]int{"203.0.113.214": 1, "203.0.113.215": 1}},
		{"mssql", "mssql-auth", "db/mssql.log", 3, 2, map[string]int{"203.0.113.215": 1, "203.0.113.216": 1}},
		{"directadmin", "directadmin", "webapps/directadmin.log", 3, 2, map[string]int{"203.0.113.218": 1, "203.0.113.219": 1}},
		{"froxlor", "froxlor-auth", "webapps/froxlor.log", 3, 2, map[string]int{"203.0.113.220": 1, "203.0.113.221": 1}},
		{"portsentry", "portsentry", "other/portsentry.log", 3, 2, map[string]int{"203.0.113.217": 1, "203.0.113.218": 1}},
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := loadFixtureFilter(t, tc.filter, nil)
			hosts, total, matched := scanFixture(t, filepath.Join("testdata", filepath.FromSlash(tc.fixture)), f, now)
			if total != tc.total || matched != tc.matched {
				t.Fatalf("total=%d matched=%d, want %d/%d", total, matched, tc.total, tc.matched)
			}
			assertHostCounts(t, hosts, tc.hosts)
		})
	}
}

func TestMoreRealLogTimestamps(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	nextcloud := loadFixtureFilter(t, "nextcloud-auth", nil)
	m, ok := nextcloud.Match(`{"reqId":"abc","level":2,"time":"2024-01-15T04:09:00+00:00","remoteAddr":"203.0.113.203","message":"Login failed: admin"}`, now)
	if !ok {
		t.Fatal("nextcloud line did not match")
	}
	wantNextcloud := time.Date(2024, 1, 15, 4, 9, 0, 0, time.UTC)
	if !m.Time.Equal(wantNextcloud) {
		t.Fatalf("nextcloud time = %v, want %v", m.Time, wantNextcloud)
	}

	roundcube := loadFixtureFilter(t, "roundcube", nil)
	m, ok = roundcube.Match(`[15-Jan-2024 04:07:00 +0000]: <abc123> Failed login for admin from 203.0.113.201 in /var/www/roundcube/index.php on line 1`, now)
	if !ok {
		t.Fatal("roundcube line did not match")
	}
	wantRoundcube := time.Date(2024, 1, 15, 4, 7, 0, 0, time.FixedZone("", 0))
	if !m.Time.Equal(wantRoundcube) {
		t.Fatalf("roundcube time = %v, want %v", m.Time, wantRoundcube)
	}
}

func TestAllBundledFiltersCompile(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "config", "filter.d", "*.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no bundled filters found")
	}
	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), ".conf")
		t.Run(name, func(t *testing.T) {
			fs, err := config.LoadFilter(name, []string{filepath.Join("..", "..", "config")}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := filter.Compile(filter.Options{
				Name:        name,
				FailRegex:   fs.FailRegex,
				IgnoreRegex: fs.IgnoreRegex,
				PreRegex:    fs.PreRegex,
				DatePattern: fs.DatePattern,
				MaxLines:    fs.MaxLines,
				UsedNS:      "no",
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
