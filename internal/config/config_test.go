package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestINIParsingInterpolationAndIncludes(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "inc.conf")
	if err := os.WriteFile(inc, []byte("[DEFAULT]\nbase = included\nfoo = from-include\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "jail.local")
	text := `[INCLUDES]
before = inc.conf

[DEFAULT]
foo = bar
list = one
       two
       three
quote = a%%b

[demo]
enabled = true
name = %(__name__)s
value = %(foo)s/%(base)s
`
	if err := os.WriteFile(main, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.LoadFile(main); err != nil {
		t.Fatal(err)
	}
	if v, err := c.Resolve("demo", "name", map[string]string{"__name__": "demo"}); err != nil || v != "demo" {
		t.Fatalf("name = %q, %v", v, err)
	}
	if v, err := c.Resolve("demo", "value", map[string]string{"__name__": "demo"}); err != nil || v != "bar/included" {
		t.Fatalf("value = %q, %v", v, err)
	}
	if v, ok := c.Raw("DEFAULT", "list"); !ok || v != "one\ntwo\nthree" {
		t.Fatalf("list = %q", v)
	}
	if v, err := c.Resolve("DEFAULT", "quote", nil); err != nil || v != "a%b" {
		t.Fatalf("quote = %q, %v", v, err)
	}
}

func TestInterpolationCycle(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.conf")
	if err := os.WriteFile(p, []byte("[DEFAULT]\na = %(b)s\nb = %(a)s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.LoadFile(p); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Resolve("DEFAULT", "a", nil); err == nil {
		t.Fatal("expected cycle error")
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"10":    10 * time.Second,
		"-1":    -time.Second,
		"30s":   30 * time.Second,
		"10m":   10 * time.Minute,
		"1h30m": 90 * time.Minute,
		"2d":    48 * time.Hour,
		"1w":    7 * 24 * time.Hour,
		"1mo":   30 * 24 * time.Hour,
		"1y":    365 * 24 * time.Hour,
		"1.5h":  90 * time.Minute,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseDuration("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseActionRefs(t *testing.T) {
	refs, err := ParseActionRefs(`iptables-multiport[name=sshd, port="ssh,http"]` + "\n" + `sendmail[name=sshd, dest=admin@example.com]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("got %d refs", len(refs))
	}
	if refs[0].Name != "iptables-multiport" || refs[0].Params["port"] != "ssh,http" || refs[0].Params["name"] != "sshd" {
		t.Fatalf("ref0 = %#v", refs[0])
	}
	if refs[1].Params["dest"] != "admin@example.com" {
		t.Fatalf("ref1 = %#v", refs[1])
	}
}

func TestBanTimeMultiplier(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.local")
	if err := os.WriteFile(path, []byte(`[DEFAULT]
bantime = 60s
bantime.multiplier = 10s

[demo]
enabled = false
`), 0o644); err != nil {
		t.Fatal(err)
	}
	specs, err := LoadJails([]string{dir}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0].BanTime != 60*time.Second || specs[0].BanTimeMultiplier != 10*time.Second {
		t.Fatalf("specs = %#v", specs)
	}
}

func TestLoadSampleConfig(t *testing.T) {
	dir := filepath.Join("..", "..", "config")
	g, err := LoadGlobal([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(g.Socket, "autoban.sock") {
		t.Fatalf("socket = %q", g.Socket)
	}
	specs, err := LoadJails([]string{dir}, g.PollInterval)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 5 {
		t.Fatalf("got %d jails", len(specs))
	}
	var sshd *JailSpec
	var wordpress *JailSpec
	for i := range specs {
		switch specs[i].Name {
		case "sshd":
			sshd = &specs[i]
		case "wordpress":
			wordpress = &specs[i]
		}
	}
	if sshd == nil {
		t.Fatal("sshd jail not found")
	}
	if wordpress == nil || wordpress.Enabled || wordpress.Filter != "wordpress" {
		t.Fatalf("wordpress = %#v", wordpress)
	}
	if !sshd.Enabled || sshd.MaxRetry != 3 || sshd.BanTime != time.Hour {
		t.Fatalf("sshd = %#v", sshd)
	}
	if !sshd.BanTimeIncrement || sshd.BanTimeFactor != 2 {
		t.Fatalf("increment = %#v", sshd)
	}
	if len(sshd.ActionRefs) != 1 || sshd.ActionRefs[0].Name != "dummy" || sshd.ActionRefs[0].Params["name"] != "sshd" {
		t.Fatalf("actions = %#v", sshd.ActionRefs)
	}
	fs, err := LoadFilter("sshd", []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs.FailRegex) < 5 {
		t.Fatalf("failregex count = %d", len(fs.FailRegex))
	}
	as, err := LoadAction(sshd.ActionRefs[0], []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if as.Params["logpath"] != "/tmp/autoban/actions.log" {
		t.Fatalf("action params = %#v", as.Params)
	}
	if !strings.Contains(as.Ban, "<ip>") {
		t.Fatalf("actionban = %q", as.Ban)
	}
}

func TestRawSectionDoesNotInheritDefault(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.conf")
	if err := os.WriteFile(p, []byte("[DEFAULT]\na=1\n[x]\nb=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.LoadFile(p); err != nil {
		t.Fatal(err)
	}
	m, _ := c.RawSection("x")
	if _, ok := m["a"]; ok {
		t.Fatalf("RawSection inherited DEFAULT: %#v", m)
	}
	if v, err := c.Resolve("x", "a", nil); err != nil || v != "1" {
		t.Fatalf("resolve fallback = %q, %v", v, err)
	}
}
