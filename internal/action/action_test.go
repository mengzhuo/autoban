package action

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mengzhuo/gojail/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestActionSubstitutionAndLifecycle(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.log")
	spec := &config.ActionSpec{
		Name: "test",
		Params: map[string]string{
			"name":      "chainname",
			"out":       out,
			"recursive": "<ip>",
		},
		Start:   `printf '%s\n' "start <name>" >> "<out>"`,
		Stop:    `printf '%s\n' "stop <name>" >> "<out>"`,
		Ban:     `printf '%s\n' "ban <ip> <family> <failures> <bantime> <bancount> <restored> <name> <recursive>" >> "<out>"`,
		Unban:   `printf '%s\n' "unban <ip>" >> "<out>"`,
		Timeout: 5 * time.Second,
	}
	a := New("jail1", spec, testLogger())
	ctx := context.Background()
	if err := a.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	ticket := Ticket{
		Jail:     "jail1",
		IP:       "2001:db8::1",
		Failures: 3,
		BanTime:  time.Hour,
		BanCount: 2,
		Restored: false,
	}
	if err := a.Ban(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	if err := a.Unban(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	if err := a.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"start chainname",
		"ban 2001:db8::1 inet6 3 3600 2 false chainname 2001:db8::1",
		"unban 2001:db8::1",
		"stop chainname",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func TestActionFailureAndTimeout(t *testing.T) {
	spec := &config.ActionSpec{
		Name:    "fail",
		Params:  map[string]string{"name": "x"},
		Ban:     `exit 7`,
		Timeout: time.Second,
	}
	a := New("jail", spec, testLogger())
	if err := a.Ban(context.Background(), Ticket{IP: "192.0.2.1"}); err == nil {
		t.Fatal("expected failure")
	}

	spec2 := &config.ActionSpec{
		Name:    "slow",
		Params:  map[string]string{"name": "x"},
		Ban:     `sleep 2`,
		Timeout: 50 * time.Millisecond,
	}
	b := New("jail", spec2, testLogger())
	err := b.Ban(context.Background(), Ticket{IP: "192.0.2.1"})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout, got %v", err)
	}
}
