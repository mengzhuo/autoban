package store

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mengzhuo/gojail/internal/ban"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSaveOpenRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	st, state, err := Open(path, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Jails) != 0 {
		t.Fatalf("initial state = %#v", state)
	}
	now := time.Now().UTC().Truncate(time.Second)
	states := map[string]ban.Snapshot{
		"sshd": {
			Bans: []ban.Ban{{
				IP:       "203.0.113.5",
				Start:    now,
				Until:    now.Add(time.Hour),
				Duration: time.Hour,
				Failures: 3,
				Matches:  []string{"bad"},
			}},
			TotalBanned: 1,
		},
	}
	if err := st.Save(states); err != nil {
		t.Fatal(err)
	}
	st2, state2, err := Open(path, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if st2.Path() != path {
		t.Fatalf("path = %q", st2.Path())
	}
	j, ok := state2.Jails["sshd"]
	if !ok || len(j.Bans) != 1 || j.Bans[0].IP != "203.0.113.5" || j.TotalBanned != 1 {
		t.Fatalf("state = %#v", state2)
	}
	if !j.Bans[0].Start.Equal(now) {
		t.Fatalf("start = %v, want %v", j.Bans[0].Start, now)
	}
}

func TestCorruptDatabaseIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, state, err := Open(path, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Jails) != 0 {
		t.Fatalf("state = %#v", state)
	}
	matches, err := filepath.Glob(path + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("quarantine files = %#v, %v", matches, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("corrupt file still exists")
	}
}

func TestPersistenceDisabled(t *testing.T) {
	st, state, err := Open("", testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if st.Path() != "" || len(state.Jails) != 0 {
		t.Fatalf("state = %#v", state)
	}
	if err := st.Save(map[string]ban.Snapshot{"x": {}}); err != nil {
		t.Fatal(err)
	}
}
