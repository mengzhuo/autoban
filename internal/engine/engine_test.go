package engine_test

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mengzhuo/autoban/internal/api"
	"github.com/mengzhuo/autoban/internal/config"
	"github.com/mengzhuo/autoban/internal/engine"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeConfig(t *testing.T, dir string, bantime string) (authLog, actionLog string) {
	t.Helper()
	authLog = filepath.Join(dir, "auth.log")
	actionLog = filepath.Join(dir, "actions.log")
	if err := os.WriteFile(authLog, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "autoban.conf"), `[Definition]
socket = `+filepath.Join(dir, "autoban.sock")+`
pidfile = `+filepath.Join(dir, "autoban.pid")+`
dbfile = `+filepath.Join(dir, "autoban.db")+`
dbpurgeage = 1d
pollinterval = 100ms
loglevel = DEBUG
`)
	writeFile(t, filepath.Join(dir, "jail.local"), `[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
maxretry = 2
findtime = 10s
bantime = `+bantime+`
backend = auto
usedns = no
pollinterval = 100ms

[demo]
enabled = true
filter = demo
logpath = `+authLog+`
action = dummy[name=demo, logpath=`+actionLog+`]
`)
	writeFile(t, filepath.Join(dir, "filter.d", "demo.conf"), `[Definition]
failregex = ^BAD <HOST>$
ignoreregex =
`)
	writeFile(t, filepath.Join(dir, "action.d", "dummy.conf"), `[Definition]
actionstart = printf '%s\n' "start <name>" >> "<logpath>"
actionstop = printf '%s\n' "stop <name>" >> "<logpath>"
actioncheck =
actionban = printf '%s\n' "ban <ip> <family> <bancount>" >> "<logpath>"
actionunban = printf '%s\n' "unban <ip>" >> "<logpath>"

[Init]
name = default
logpath = /dev/null
`)
	return authLog, actionLog
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, desc string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

func fileContains(t *testing.T, path, substr string) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), substr)
}

func startEngine(t *testing.T, dir string) (*engine.Engine, *api.Client, *config.Global) {
	t.Helper()
	g, err := config.LoadGlobal([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := engine.New([]string{dir}, g, logger)
	if err := e.Build(); err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	return e, api.NewClient(g.Socket), g
}

func TestEngineBanAndExpire(t *testing.T) {
	dir := t.TempDir()
	authLog, actionLog := writeConfig(t, dir, "2s")
	e, client, g := startEngine(t, dir)
	defer e.Stop()

	appendLines(t, authLog, "BAD 203.0.113.9", "BAD 203.0.113.9")
	var st api.JailStatus
	waitFor(t, 5*time.Second, "ban", func() bool {
		st = api.JailStatus{}
		if err := client.Do(api.Request{Cmd: "status", Jail: "demo"}, &st); err != nil {
			return false
		}
		return st.CurrentlyBanned == 1
	})
	if len(st.BannedIPs) != 1 || st.BannedIPs[0] != "203.0.113.9" {
		t.Fatalf("banned = %#v", st.BannedIPs)
	}
	if st.TotalFailed != 2 {
		t.Fatalf("total failed = %d", st.TotalFailed)
	}
	waitFor(t, 2*time.Second, "ban action", func() bool {
		return fileContains(t, actionLog, "ban 203.0.113.9 inet 1")
	})

	waitFor(t, 6*time.Second, "expiry", func() bool {
		st = api.JailStatus{}
		if err := client.Do(api.Request{Cmd: "status", Jail: "demo"}, &st); err != nil {
			return false
		}
		return st.CurrentlyBanned == 0
	})
	waitFor(t, 2*time.Second, "unban action", func() bool {
		return fileContains(t, actionLog, "unban 203.0.113.9")
	})

	e.Stop()
	if _, err := os.Stat(g.Socket); !os.IsNotExist(err) {
		t.Fatalf("socket still exists: %v", err)
	}
}

func TestEngineMaxLinesLimitsBanMatches(t *testing.T) {
	dir := t.TempDir()
	authLog, _ := writeConfig(t, dir, "1h")
	appendLines(t, filepath.Join(dir, "jail.local"), "maxretry = 3", "maxlines = 2")
	e, client, _ := startEngine(t, dir)
	defer e.Stop()

	appendLines(t, authLog,
		"BAD 198.51.100.1",
		"BAD 198.51.100.1",
		"BAD 198.51.100.1",
	)
	var st api.JailStatus
	waitFor(t, 5*time.Second, "ban with maxlines", func() bool {
		st = api.JailStatus{}
		return client.Do(api.Request{Cmd: "status", Jail: "demo"}, &st) == nil && st.CurrentlyBanned == 1
	})
	if len(st.Banned) != 1 {
		t.Fatalf("banned = %#v", st.Banned)
	}
	if got := len(st.Banned[0].Matches); got != 2 {
		t.Fatalf("matches = %#v, want 2 lines", st.Banned[0].Matches)
	}
	if st.Banned[0].Failures != 3 {
		t.Fatalf("failures = %d, want 3", st.Banned[0].Failures)
	}

	if err := client.Do(api.Request{Cmd: "jail.set", Jail: "demo", Args: []string{"maxlines", "1"}}, nil); err != nil {
		t.Fatal(err)
	}
	var value api.Value
	if err := client.Do(api.Request{Cmd: "jail.get", Jail: "demo", Args: []string{"maxlines"}}, &value); err != nil {
		t.Fatal(err)
	}
	if value.Value != "1" {
		t.Fatalf("maxlines = %q, want 1", value.Value)
	}
}

func TestEngineReloadPreservesLogPosition(t *testing.T) {
	dir := t.TempDir()
	authLog, actionLog := writeConfig(t, dir, "1h")
	// Slow actionstop creates a deterministic window between the old jail
	// stopping and the new one starting.
	writeFile(t, filepath.Join(dir, "action.d", "dummy.conf"), `[Definition]
actionstart = true
actionstop = printf '%s\n' "stop" >> "<logpath>"; sleep 1
actioncheck =
actionban = true
actionunban = true

[Init]
name = default
logpath = /dev/null
`)
	e, client, _ := startEngine(t, dir)
	defer e.Stop()

	appendLines(t, authLog, "BAD 203.0.113.50")
	waitFor(t, 5*time.Second, "initial failure", func() bool {
		var st api.JailStatus
		return client.Do(api.Request{Cmd: "status", Jail: "demo"}, &st) == nil && st.TotalFailed == 1
	})

	done := make(chan error, 1)
	go func() { done <- client.Do(api.Request{Cmd: "reload"}, nil) }()
	waitFor(t, 5*time.Second, "old jail stop", func() bool {
		return fileContains(t, actionLog, "stop")
	})
	// This line is written after the old backend stopped but before the new
	// backend starts. It must not be skipped.
	appendLines(t, authLog, "BAD 203.0.113.50")

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reload did not finish")
	}

	waitFor(t, 5*time.Second, "failure written during reload", func() bool {
		var st api.JailStatus
		return client.Do(api.Request{Cmd: "status", Jail: "demo"}, &st) == nil && st.TotalFailed >= 2
	})
}

func TestEnginePersistenceAndManualUnban(t *testing.T) {
	dir := t.TempDir()
	authLog, actionLog := writeConfig(t, dir, "1h")
	e, client, g := startEngine(t, dir)

	appendLines(t, authLog, "BAD 198.51.100.7", "BAD 198.51.100.7")
	waitFor(t, 5*time.Second, "ban", func() bool {
		var st api.JailStatus
		return client.Do(api.Request{Cmd: "status", Jail: "demo"}, &st) == nil && st.CurrentlyBanned == 1
	})
	waitFor(t, 2*time.Second, "ban action", func() bool {
		return fileContains(t, actionLog, "ban 198.51.100.7")
	})
	e.Stop()

	e2, client2, g2 := startEngine(t, dir)
	defer e2.Stop()
	if g2.Socket != g.Socket {
		t.Fatalf("socket changed: %s vs %s", g.Socket, g2.Socket)
	}
	var st api.JailStatus
	if err := client2.Do(api.Request{Cmd: "status", Jail: "demo"}, &st); err != nil {
		t.Fatal(err)
	}
	if st.CurrentlyBanned != 1 || len(st.Banned) != 1 || st.Banned[0].IP != "198.51.100.7" || !st.Banned[0].Restored {
		t.Fatalf("restored status = %#v", st)
	}
	if !fileContains(t, actionLog, "start demo") {
		t.Fatalf("actionstart did not run after restart")
	}
	data, err := os.ReadFile(actionLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "ban 198.51.100.7") < 2 {
		t.Fatalf("restored ban was not re-applied after restart:\n%s", data)
	}

	// Reload the configuration and confirm the restored ban survives.
	jailPath := filepath.Join(dir, "jail.local")
	jailData, err := os.ReadFile(jailPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jailPath, []byte(strings.ReplaceAll(string(jailData), "maxretry = 2", "maxretry = 4")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := client2.Do(api.Request{Cmd: "reload"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := client2.Do(api.Request{Cmd: "status", Jail: "demo"}, &st); err != nil {
		t.Fatal(err)
	}
	if st.MaxRetry != 4 || st.CurrentlyBanned != 1 {
		t.Fatalf("after reload = %#v", st)
	}

	if err := client2.Do(api.Request{Cmd: "jail.unbanip", Jail: "demo", Args: []string{"198.51.100.7"}}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, "unban action", func() bool {
		return fileContains(t, actionLog, "unban 198.51.100.7")
	})
	if err := client2.Do(api.Request{Cmd: "status", Jail: "demo"}, &st); err != nil {
		t.Fatal(err)
	}
	if st.CurrentlyBanned != 0 {
		t.Fatalf("still banned: %#v", st)
	}
}

func TestJailRestartReplaysLinesAccumulatedWhileStopped(t *testing.T) {
	dir := t.TempDir()
	authLog, _ := writeConfig(t, dir, "1h")
	e, client, _ := startEngine(t, dir)
	defer e.Stop()

	if err := client.Do(api.Request{Cmd: "jail.stop", Jail: "demo"}, nil); err != nil {
		t.Fatal(err)
	}
	appendLines(t, authLog, "BAD 203.0.113.3", "BAD 203.0.113.3")
	// This used to deadlock: the backend replays accumulated lines from inside
	// Start, while processLine needs the jail status lock.
	if err := client.Do(api.Request{Cmd: "jail.start", Jail: "demo"}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "ban after restart", func() bool {
		var st api.JailStatus
		return client.Do(api.Request{Cmd: "status", Jail: "demo"}, &st) == nil && st.CurrentlyBanned == 1
	})
}
