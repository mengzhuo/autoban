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
