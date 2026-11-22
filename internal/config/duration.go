package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// ParseDuration parses fail2ban-style durations. A bare number is seconds.
// Supported suffixes: s, m (minutes), h, d, w, mo (30 days), y (365 days).
// Combinations such as 1h30m are accepted as well.
func ParseDuration(value string) (time.Duration, error) {
	s := strings.TrimSpace(value)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	sign := 1.0
	if strings.HasPrefix(s, "-") {
		sign = -1
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	if s == "" {
		return 0, fmt.Errorf("invalid duration %q", value)
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Duration(sign * n * float64(time.Second)), nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Duration(sign) * d, nil
	}

	total := 0.0
	rest := s
	for rest != "" {
		i := 0
		for i < len(rest) && (rest[i] >= '0' && rest[i] <= '9' || rest[i] == '.') {
			i++
		}
		if i == 0 {
			return 0, fmt.Errorf("invalid duration %q", value)
		}
		num, err := strconv.ParseFloat(rest[:i], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", value, err)
		}
		rest = rest[i:]
		unit := ""
		switch {
		case strings.HasPrefix(rest, "mo"):
			unit = "mo"
		case strings.HasPrefix(rest, "s"):
			unit = "s"
		case strings.HasPrefix(rest, "m"):
			unit = "m"
		case strings.HasPrefix(rest, "h"):
			unit = "h"
		case strings.HasPrefix(rest, "d"):
			unit = "d"
		case strings.HasPrefix(rest, "w"):
			unit = "w"
		case strings.HasPrefix(rest, "y"):
			unit = "y"
		default:
			return 0, fmt.Errorf("invalid duration unit in %q", value)
		}
		rest = rest[len(unit):]
		var mult time.Duration
		switch unit {
		case "s":
			mult = time.Second
		case "m":
			mult = time.Minute
		case "h":
			mult = time.Hour
		case "d":
			mult = 24 * time.Hour
		case "w":
			mult = 7 * 24 * time.Hour
		case "mo":
			mult = 30 * 24 * time.Hour
		case "y":
			mult = 365 * 24 * time.Hour
		}
		total += num * float64(mult)
	}
	if math.IsInf(total, 0) || math.IsNaN(total) {
		return 0, fmt.Errorf("invalid duration %q", value)
	}
	return time.Duration(sign * total), nil
}

// ParseDurationSeconds is like ParseDuration but returns whole seconds.
// This mirrors the integer values used in fail2ban configuration.
func ParseDurationSeconds(value string) (int64, error) {
	d, err := ParseDuration(value)
	if err != nil {
		return 0, err
	}
	return int64(d / time.Second), nil
}

// FormatDuration renders a duration in a compact human readable form,
// e.g. 1h30m0s, used by the CLI.
func FormatDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	if d < 0 {
		return "-" + FormatDuration(-d)
	}
	return d.Round(time.Second).String()
}
