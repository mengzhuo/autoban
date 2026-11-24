package backend

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func appendFile(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func recv(t *testing.T, ch <-chan string, timeout time.Duration) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(timeout):
		t.Fatal("timed out waiting for line")
		return ""
	}
}

func TestFileBackendSnapshotRestore(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")
	if err := os.WriteFile(logPath, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 10)
	newBackend := func() *FileBackend {
		return NewFileBackend([]string{logPath}, 100*time.Millisecond, func(s string) {
			lines <- s
		}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}

	first := newBackend()
	firstCtx, firstCancel := context.WithCancel(context.Background())
	defer firstCancel()
	if err := first.Start(firstCtx); err != nil {
		t.Fatal(err)
	}
	appendFile(t, logPath, "one\n")
	if got := recv(t, lines, 2*time.Second); got != "one" {
		t.Fatalf("got %q", got)
	}
	first.Stop()
	snap := first.Snapshot()

	// This line is written while no backend is running. A restored backend
	// must resume from the old offset and process it.
	appendFile(t, logPath, "two\n")
	second := newBackend()
	if err := second.Restore(snap); err != nil {
		t.Fatal(err)
	}
	secondCtx, secondCancel := context.WithCancel(context.Background())
	defer secondCancel()
	if err := second.Start(secondCtx); err != nil {
		t.Fatal(err)
	}
	defer second.Stop()

	if got := recv(t, lines, 2*time.Second); got != "two" {
		t.Fatalf("got %q, want resumed line", got)
	}
	select {
	case line := <-lines:
		t.Fatalf("line was replayed: %q", line)
	case <-time.After(250 * time.Millisecond):
	}
}

func TestFileBackendFollowRotateTruncate(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")
	if err := os.WriteFile(logPath, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 100)
	b := NewFileBackend([]string{filepath.Join(dir, "*.log")}, 100*time.Millisecond, func(s string) {
		lines <- s
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop()

	select {
	case line := <-lines:
		t.Fatalf("old line was read: %q", line)
	case <-time.After(250 * time.Millisecond):
	}

	appendFile(t, logPath, "new1\n")
	if got := recv(t, lines, 2*time.Second); got != "new1" {
		t.Fatalf("got %q", got)
	}

	appendFile(t, logPath, "partial")
	select {
	case line := <-lines:
		t.Fatalf("partial line was emitted: %q", line)
	case <-time.After(250 * time.Millisecond):
	}
	appendFile(t, logPath, " done\n")
	if got := recv(t, lines, 2*time.Second); got != "partial done" {
		t.Fatalf("got %q", got)
	}

	// Rotation: rename the file and create a new one.
	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("rotated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, lines, 2*time.Second); got != "rotated" {
		t.Fatalf("got %q", got)
	}

	// Truncation with copytruncate-style rotation.
	if err := os.WriteFile(logPath, []byte("trunc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, lines, 2*time.Second); got != "trunc" {
		t.Fatalf("got %q", got)
	}

	// A file that appears after startup is read from the beginning.
	newPath := filepath.Join(dir, "other.log")
	if err := os.WriteFile(newPath, []byte("appeared\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, lines, 2*time.Second); got != "appeared" {
		t.Fatalf("got %q", got)
	}
	if files := b.Files(); len(files) != 2 {
		t.Fatalf("files = %#v", files)
	}
}
