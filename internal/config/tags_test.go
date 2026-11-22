package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilterModeTagExpansion(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "filter.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	filterConf := `[Definition]
mode = normal
base = ^base <HOST>$
mdre-normal = ^normal <HOST>$
mdre-aggressive = ^aggressive <HOST>$
failregex = %(base)s
            <mdre-<mode>>
`
	if err := os.WriteFile(filepath.Join(dir, "filter.d", "moded.conf"), []byte(filterConf), 0o644); err != nil {
		t.Fatal(err)
	}

	normal, err := LoadFilter("moded", []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if normal.Mode != "normal" {
		t.Fatalf("normal mode = %q", normal.Mode)
	}
	if strings.Contains(strings.Join(normal.FailRegex, "\n"), "aggressive") {
		t.Fatalf("normal filter contains aggressive regex: %#v", normal.FailRegex)
	}

	aggressive, err := LoadFilter("moded", []string{dir}, map[string]string{"mode": "aggressive"})
	if err != nil {
		t.Fatal(err)
	}
	if aggressive.Mode != "aggressive" {
		t.Fatalf("aggressive mode = %q", aggressive.Mode)
	}
	joined := strings.Join(aggressive.FailRegex, "\n")
	if !strings.Contains(joined, "^base <HOST>$") || !strings.Contains(joined, "^aggressive <HOST>$") {
		t.Fatalf("unexpected failregex: %q", joined)
	}
	if strings.Contains(joined, "^normal <HOST>$") {
		t.Fatalf("aggressive filter contains normal regex: %q", joined)
	}
}

func TestJailFilterParams(t *testing.T) {
	dir := t.TempDir()
	jailConf := `[DEFAULT]
maxretry = 1
findtime = 10m
bantime = 10m
action = dummy

[demo]
enabled = true
filter = moded[mode=aggressive]
logpath = /tmp/demo.log
`
	if err := os.WriteFile(filepath.Join(dir, "jail.local"), []byte(jailConf), 0o644); err != nil {
		t.Fatal(err)
	}
	specs, err := LoadJails([]string{dir}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 {
		t.Fatalf("got %d specs", len(specs))
	}
	if specs[0].Filter != "moded" || specs[0].FilterMode != "aggressive" || specs[0].FilterParams["mode"] != "aggressive" {
		t.Fatalf("spec = %#v", specs[0])
	}
}
