// Package backend implements log sources. The file polling backend mirrors
// fail2ban's backend=polling: it follows globbed files, handles rotation and
// truncation, and only emits complete lines.
package backend

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const initialReadBuffer = 64 * 1024

// FileBackend tails one or more log files by polling.
type FileBackend struct {
	patterns []string
	interval time.Duration
	handler  func(string)
	onError  func(error)
	log      *slog.Logger

	mu          sync.Mutex
	files       map[string]*fileState
	lastFiles   []string
	initial     bool
	started     bool
	everStarted bool
	stop        chan struct{}
	done        chan struct{}
}

type fileState struct {
	info   os.FileInfo
	offset int64
}

// NewFileBackend creates a polling backend. Patterns are file paths or globs.
func NewFileBackend(patterns []string, interval time.Duration, handler func(string), onError func(error), logger *slog.Logger) *FileBackend {
	if interval <= 0 {
		interval = time.Second
	}
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &FileBackend{
		patterns: append([]string(nil), patterns...),
		interval: interval,
		handler:  handler,
		onError:  onError,
		log:      logger,
		files:    make(map[string]*fileState),
	}
}

// Start performs the initial discovery (seeking existing files to EOF) and
// launches the polling loop.
func (b *FileBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return nil
	}
	b.started = true
	// On the very first start existing log content is skipped, matching
	// fail2ban. A restart (jail start after stop) resumes at the last known
	// offset and processes lines accumulated while the jail was stopped.
	b.initial = !b.everStarted
	b.everStarted = true
	b.stop = make(chan struct{})
	b.done = make(chan struct{})
	b.mu.Unlock()

	if err := b.ScanOnce(); err != nil {
		b.log.Warn("initial log scan", "error", err)
	}
	go b.loop(ctx)
	return nil
}

func (b *FileBackend) loop(ctx context.Context) {
	defer close(b.done)
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stop:
			return
		case <-ticker.C:
			if err := b.ScanOnce(); err != nil {
				b.report(err)
			}
		}
	}
}

// Stop terminates the polling loop.
func (b *FileBackend) Stop() {
	b.mu.Lock()
	started := b.started
	stop := b.stop
	done := b.done
	b.started = false
	b.mu.Unlock()
	if !started {
		return
	}
	select {
	case <-stop:
	default:
		close(stop)
	}
	<-done
}

// Files returns the currently matched file paths.
func (b *FileBackend) Files() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.lastFiles))
	copy(out, b.lastFiles)
	return out
}

// ScanOnce performs a single poll. It is exported for tests.
func (b *FileBackend) ScanOnce() error {
	b.mu.Lock()
	seen := make(map[string]bool)
	var lines []string
	var firstErr error
	for _, pattern := range b.patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("invalid logpath pattern %q: %w", pattern, err)
			}
			continue
		}
		sort.Strings(matches)
		for _, path := range matches {
			path = filepath.Clean(path)
			if seen[path] {
				continue
			}
			seen[path] = true
			got, err := b.scanFileLocked(path)
			lines = append(lines, got...)
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	for path := range b.files {
		if !seen[path] {
			delete(b.files, path)
		}
	}
	b.lastFiles = b.lastFiles[:0]
	for path := range seen {
		b.lastFiles = append(b.lastFiles, path)
	}
	sort.Strings(b.lastFiles)
	b.initial = false
	b.mu.Unlock()

	// Emit outside the lock: a ban action may take seconds, and unrelated
	// status requests must not block on the file backend.
	for _, line := range lines {
		if b.handler != nil {
			b.handler(line)
		}
	}
	return firstErr
}

func (b *FileBackend) scanFileLocked(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, nil
	}
	state := b.files[path]
	isNew := state == nil
	if isNew {
		state = &fileState{info: info}
		b.files[path] = state
		if b.initial {
			// Match fail2ban: do not process pre-existing log content on the
			// first start.
			state.offset = info.Size()
			return nil, nil
		}
		// A file that appeared after startup (e.g. after rotation) is read
		// from the beginning.
		state.offset = 0
	} else if !os.SameFile(state.info, info) || info.Size() < state.offset {
		// Rotated or truncated.
		state.offset = 0
	}
	state.info = info
	if state.offset >= info.Size() {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Seek(state.offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek %s: %w", path, err)
	}
	reader := bufio.NewReaderSize(f, initialReadBuffer)
	var lines []string
	for {
		line, readErr := reader.ReadString('\n')
		if line != "" {
			complete := strings.HasSuffix(line, "\n")
			if complete {
				state.offset += int64(len(line))
				line = strings.TrimSuffix(line, "\n")
				line = strings.TrimSuffix(line, "\r")
				lines = append(lines, line)
			} else if len(line) > 4<<20 {
				// Never buffer an unbounded partial line.
				b.log.Warn("dropping oversized partial log line", "file", path, "bytes", len(line))
				state.offset += int64(len(line))
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return lines, fmt.Errorf("read %s: %w", path, readErr)
		}
	}
	return lines, nil
}

func (b *FileBackend) report(err error) {
	if err == nil {
		return
	}
	if b.onError != nil {
		b.onError(err)
	} else {
		b.log.Warn("log backend error", "error", err)
	}
}
