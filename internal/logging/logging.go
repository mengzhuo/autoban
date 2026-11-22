// Package logging configures slog output for the daemon.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
)

// ParseLevel maps fail2ban log levels to slog levels.
func ParseLevel(s string) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "TRACE", "DBG", "DEBUG":
		return slog.LevelDebug
	case "INFO", "NOTICE":
		return slog.LevelInfo
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR", "ERR":
		return slog.LevelError
	case "CRITICAL", "CRIT":
		return slog.LevelError + 4
	default:
		return slog.LevelInfo
	}
}

// Setup opens target and returns a logger and cleanup function.
// target is STDOUT, STDERR, SYSLOG, or a file path.
func Setup(level, target string) (*slog.Logger, func(), error) {
	var w io.Writer
	var closers []io.Closer
	switch strings.ToUpper(strings.TrimSpace(target)) {
	case "", "STDERR":
		w = os.Stderr
	case "STDOUT":
		w = os.Stdout
	case "SYSLOG":
		sw, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "gojail")
		if err != nil {
			return nil, nil, fmt.Errorf("open syslog: %w", err)
		}
		w = sw
		closers = append(closers, sw)
	default:
		path := strings.TrimSpace(target)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, nil, fmt.Errorf("create log directory: %w", err)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file %s: %w", path, err)
		}
		w = f
		closers = append(closers, f)
	}
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{Level: ParseLevel(level)})
	logger := slog.New(handler).With("component", "gojail")
	slog.SetDefault(logger)
	cleanup := func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}
	return logger, cleanup, nil
}
