// Package store persists jail state as an atomically replaced JSON file.
// fail2ban uses SQLite; a JSON snapshot keeps this implementation dependency
// free while providing the same restore semantics for bans and failures.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/mengzhuo/autoban/internal/ban"
)

const formatVersion = 1

// DiskState is the on-disk database format.
type DiskState struct {
	Version int                     `json:"version"`
	SavedAt time.Time               `json:"savedAt"`
	Jails   map[string]ban.Snapshot `json:"jails"`
}

// Store serialises access to the snapshot file.
type Store struct {
	path string
	log  *slog.Logger
	mu   chan struct{}
}

// Open loads path if it exists. A corrupt file is renamed and an empty state
// is returned so that the daemon can still start.
func Open(path string, logger *slog.Logger) (*Store, DiskState, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Store{path: path, log: logger, mu: make(chan struct{}, 1)}
	s.mu <- struct{}{}
	state := DiskState{Version: formatVersion, Jails: make(map[string]ban.Snapshot)}
	if path == "" {
		return s, state, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, state, nil
		}
		return nil, state, fmt.Errorf("read database %s: %w", path, err)
	}
	if len(data) == 0 {
		return s, state, nil
	}
	if err := json.Unmarshal(data, &state); err != nil {
		corrupt := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
		if renameErr := os.Rename(path, corrupt); renameErr != nil {
			logger.Error("database is corrupt and could not be moved", "path", path, "error", err, "renameError", renameErr)
		} else {
			logger.Warn("database is corrupt, starting empty", "path", path, "movedTo", corrupt, "error", err)
		}
		state = DiskState{Version: formatVersion, Jails: make(map[string]ban.Snapshot)}
		return s, state, nil
	}
	if state.Jails == nil {
		state.Jails = make(map[string]ban.Snapshot)
	}
	if state.Version > formatVersion {
		logger.Warn("database was written by a newer version", "path", path, "version", state.Version)
	}
	s.log.Debug("database loaded", "path", path, "jails", len(state.Jails), "savedAt", state.SavedAt)
	return s, state, nil
}

// Path returns the database path (empty when persistence is disabled).
func (s *Store) Path() string { return s.path }

// Save atomically writes states. An empty path disables persistence.
func (s *Store) Save(states map[string]ban.Snapshot) error {
	if s.path == "" {
		return nil
	}
	<-s.mu
	defer func() { s.mu <- struct{}{} }()

	state := DiskState{Version: formatVersion, SavedAt: time.Now(), Jails: states}
	if state.Jails == nil {
		state.Jails = make(map[string]ban.Snapshot)
	}
	data, err := json.MarshalIndent(&state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode database: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}
	tmp := fmt.Sprintf("%s.tmp-%d", s.path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary database: %w", err)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write database: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync database: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace database: %w", err)
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	s.log.Debug("database saved", "path", s.path, "jails", len(states))
	return nil
}
