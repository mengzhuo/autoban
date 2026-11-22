package filter

import (
	"testing"
	"time"
)

func TestSSHDIPv4AndIPv6(t *testing.T) {
	f, err := Compile(Options{
		Name: "sshd",
		FailRegex: []string{
			`^.*Failed password for (?:invalid user )?\S+ from <HOST> port \d+(?: ssh2)?\s*$`,
		},
		UsedNS: "no",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.Local)
	for _, tc := range []struct {
		line string
		host string
	}{
		{"Nov 22 11:59:00 host sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 4444 ssh2", "203.0.113.7"},
		{"2026-11-22T11:59:00Z host sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2", "2001:db8::1"},
		{"2026-11-22T11:59:00Z host sshd[1]: Failed password for root from ::ffff:192.0.2.9 port 22 ssh2", "::ffff:192.0.2.9"},
	} {
		m, ok := f.Match(tc.line, now)
		if !ok {
			t.Fatalf("expected match for %q", tc.line)
		}
		if m.Host != tc.host {
			t.Fatalf("host = %q, want %q", m.Host, tc.host)
		}
		if m.Time.IsZero() {
			t.Fatalf("zero timestamp")
		}
	}
}

func TestIgnoreRegex(t *testing.T) {
	f, err := Compile(Options{
		Name:      "test",
		FailRegex: []string{`^bad from <HOST>$`},
		IgnoreRegex: []string{
			`from 192\.0\.2\.1$`,
		},
		UsedNS: "no",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Match("bad from 192.0.2.1", time.Now()); ok {
		t.Fatal("expected ignore")
	}
	if m, ok := f.Match("bad from 198.51.100.2", time.Now()); !ok || m.Host != "198.51.100.2" {
		t.Fatalf("match failed: %#v %v", m, ok)
	}
}

func TestPrefRegexWithContentMarkers(t *testing.T) {
	f, err := Compile(Options{
		Name:      "pre",
		PreRegex:  `^PREFIX <F-CONTENT>.+</F-CONTENT>$`,
		FailRegex: []string{`^bad from <HOST>$`},
		UsedNS:    "no",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Match("PREFIX bad from 198.51.100.2", time.Now()); !ok {
		t.Fatal("expected prefixed match")
	}
}

func TestDatePatterns(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.Local)
	cases := []struct {
		pattern string
		line    string
		want    time.Time
	}{
		{"{^LN-BEG}%Y-%m-%dT%H:%M:%S", "2024-03-04T05:06:07 hello", time.Date(2024, 3, 4, 5, 6, 7, 0, time.Local)},
		{"{^LN-BEG}%b %d %H:%M:%S", "Mar  4 05:06:07 hello", time.Date(2026, 3, 4, 5, 6, 7, 0, time.Local)},
	}
	for _, tc := range cases {
		p, warns, err := newDateParser(tc.pattern)
		if err != nil {
			t.Fatalf("%s: %v (warnings %v)", tc.pattern, err, warns)
		}
		got, ok := parseLogTime(tc.line, p, now)
		if !ok {
			t.Fatalf("no timestamp for %q", tc.line)
		}
		if !got.Equal(tc.want) {
			t.Fatalf("pattern %q: got %v, want %v", tc.pattern, got, tc.want)
		}
	}
}

func TestBuiltinDates(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.Local)
	cases := []struct {
		line string
		want time.Time
	}{
		{"2024-03-04T05:06:07Z hello", time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)},
		{"2024-03-04 05:06:07.123 hello", time.Date(2024, 3, 4, 5, 6, 7, 123000000, time.Local)},
		{"Mar  4 05:06:07 host app: hello", time.Date(2026, 3, 4, 5, 6, 7, 0, time.Local)},
		{"04/Mar/2024:05:06:07 +0800 hello", time.Date(2024, 3, 4, 5, 6, 7, 0, time.FixedZone("", 8*3600))},
	}
	for _, tc := range cases {
		got, ok := parseLogTime(tc.line, nil, now)
		if !ok {
			t.Fatalf("no timestamp for %q", tc.line)
		}
		if !got.Equal(tc.want) {
			t.Fatalf("line %q: got %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestBuiltinISOOFFSET(t *testing.T) {
	got, ok := parseLogTime("2024-03-04T05:06:07+0800 hello", nil, time.Now())
	if !ok {
		t.Fatal("no timestamp")
	}
	want := time.Date(2024, 3, 4, 5, 6, 7, 0, time.FixedZone("", 8*3600))
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestUsedNSHostnamePolicy(t *testing.T) {
	line := "bad evil.example.com"
	yes, err := Compile(Options{Name: "dns", FailRegex: []string{`^bad <HOST>$`}, UsedNS: "yes"})
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := yes.Match(line, time.Now()); !ok || m.Host != "evil.example.com" {
		t.Fatalf("yes: %#v %v", m, ok)
	}
	no, err := Compile(Options{Name: "nodns", FailRegex: []string{`^bad <HOST>$`}, UsedNS: "no"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := no.Match(line, time.Now()); ok {
		t.Fatal("usedns=no should not match a hostname")
	}
}
