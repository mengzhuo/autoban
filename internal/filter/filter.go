// Package filter implements fail2ban-style log filters: failregex/ignoreregex
// matching, the <HOST> token family, optional prefilters and log timestamp
// extraction.
package filter

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// Options configures a compiled filter.
type Options struct {
	Name        string
	FailRegex   []string
	IgnoreRegex []string
	PreRegex    string
	DatePattern string
	MaxLines    int
	UsedNS      string
}

// Match describes one accepted log line.
type Match struct {
	Host     string
	Line     string
	Time     time.Time
	RegexIdx int
}

// Filter is a compiled, concurrency-safe filter. Match may be called from
// several backend goroutines.
type Filter struct {
	name        string
	fail        []*regexp.Regexp
	ignore      []*regexp.Regexp
	pre         *regexp.Regexp
	date        *dateParser
	maxLines    int
	usedNS      string
	warnings    []string
	totalMatch  atomic.Int64
	totalIgnore atomic.Int64
}

// Compile builds a filter from configuration.
func Compile(opts Options) (*Filter, error) {
	f := &Filter{
		name:     opts.Name,
		maxLines: opts.MaxLines,
		usedNS:   opts.UsedNS,
	}
	if f.maxLines <= 0 {
		f.maxLines = 1
	}
	if f.usedNS == "" {
		f.usedNS = "warn"
	}

	if strings.TrimSpace(opts.PreRegex) != "" {
		expanded, _, err := expandRegex(opts.PreRegex, f.usedNS, true)
		if err != nil {
			return nil, fmt.Errorf("prefregex: %w", err)
		}
		re, err := regexp.Compile(expanded)
		if err != nil {
			return nil, fmt.Errorf("prefregex %q: %w", opts.PreRegex, err)
		}
		f.pre = re
	}

	for _, raw := range opts.FailRegex {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		expanded, _, err := expandRegex(raw, f.usedNS, false)
		if err != nil {
			return nil, fmt.Errorf("failregex %q: %w", raw, err)
		}
		re, err := regexp.Compile(expanded)
		if err != nil {
			return nil, fmt.Errorf("failregex %q: %w", raw, err)
		}
		if re.SubexpIndex("host") < 0 {
			return nil, fmt.Errorf("failregex %q contains no <HOST>/<ADDR> token", raw)
		}
		f.fail = append(f.fail, re)
	}
	if len(f.fail) == 0 {
		return nil, fmt.Errorf("filter %q has no failregex", opts.Name)
	}

	for _, raw := range opts.IgnoreRegex {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		expanded, _, err := expandRegex(raw, f.usedNS, false)
		if err != nil {
			return nil, fmt.Errorf("ignoreregex %q: %w", raw, err)
		}
		re, err := regexp.Compile(expanded)
		if err != nil {
			return nil, fmt.Errorf("ignoreregex %q: %w", raw, err)
		}
		f.ignore = append(f.ignore, re)
	}

	if strings.TrimSpace(opts.DatePattern) != "" {
		parser, warnings, err := newDateParser(opts.DatePattern)
		f.warnings = append(f.warnings, warnings...)
		if err != nil {
			f.warnings = append(f.warnings, fmt.Sprintf("datepattern disabled, using built-in detection: %v", err))
		} else {
			f.date = parser
		}
	}
	return f, nil
}

// Name returns the filter name.
func (f *Filter) Name() string { return f.name }

// MaxLines returns the configured match history size.
func (f *Filter) MaxLines() int { return f.maxLines }

// UsedNS returns the configured host resolution policy.
func (f *Filter) UsedNS() string { return f.usedNS }

// Warnings returns non-fatal configuration warnings.
func (f *Filter) Warnings() []string {
	out := make([]string, len(f.warnings))
	copy(out, f.warnings)
	return out
}

// Stats returns total matched and ignored line counts.
func (f *Filter) Stats() (matched, ignored int64) {
	return f.totalMatch.Load(), f.totalIgnore.Load()
}

// Match applies the prefilter, ignoreregex and failregex to line. It returns a
// Match containing the offending host as it appears in the log (which may be a
// hostname, depending on usedns).
func (f *Filter) Match(line string, now time.Time) (Match, bool) {
	candidate := line
	if f.pre != nil {
		sub := f.pre.FindStringSubmatch(line)
		if sub == nil {
			return Match{}, false
		}
		if idx := f.pre.SubexpIndex("content"); idx >= 0 && sub[idx] != "" {
			candidate = sub[idx]
		}
	}
	for _, re := range f.ignore {
		if re.MatchString(line) || (candidate != line && re.MatchString(candidate)) {
			f.totalIgnore.Add(1)
			return Match{}, false
		}
	}
	for i, re := range f.fail {
		loc := re.FindStringSubmatchIndex(candidate)
		if loc == nil {
			continue
		}
		hi := re.SubexpIndex("host")
		if hi < 0 || 2*hi+1 >= len(loc) || loc[2*hi] < 0 {
			continue
		}
		host := strings.TrimSpace(candidate[loc[2*hi]:loc[2*hi+1]])
		host = strings.Trim(host, "[]")
		if host == "" {
			continue
		}
		ts, ok := parseLogTime(line, f.date, now)
		if !ok {
			ts = now
		}
		f.totalMatch.Add(1)
		return Match{Host: host, Line: line, Time: ts, RegexIdx: i}, true
	}
	return Match{}, false
}

const (
	ipv4Pattern     = `(?:\d{1,3}\.){3}\d{1,3}`
	ipv4Mapped6     = `(?:::f{4,6}:)(?:\d{1,3}\.){3}\d{1,3}`
	ipv6Pattern     = `(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))`
	hostnamePattern = `[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?`
)

func ipOnlyPattern() string {
	return `(?:` + ipv4Mapped6 + `|` + ipv6Pattern + `|` + ipv4Pattern + `)`
}

func hostPattern(usedns string) string {
	if usedns == "no" {
		return ipOnlyPattern()
	}
	return `(?:` + ipv4Mapped6 + `|` + ipv6Pattern + `|` + ipv4Pattern + `|` + hostnamePattern + `)`
}

func subnetPattern() string {
	return `(?:` + ipOnlyPattern() + `(?:/\d{1,3})?)`
}

func isTagName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func expandRegex(pattern, usedns string, pref bool) (string, bool, error) {
	hostDeclared := strings.Contains(pattern, "(?P<host>")
	contentMarkers := strings.Contains(pattern, "</F-CONTENT>")
	hostCount := 0
	var b strings.Builder
	hostUsed := false

	wrapHost := func(inner string) string {
		if !hostDeclared && hostCount == 0 {
			hostCount++
			hostUsed = true
			return `(?P<host>` + inner + `)`
		}
		hostCount++
		return `(?:` + inner + `)`
	}

	for i := 0; i < len(pattern); {
		if pattern[i] != '<' {
			b.WriteByte(pattern[i])
			i++
			continue
		}
		if strings.HasPrefix(pattern[i:], "</F-CONTENT>") {
			if !pref {
				return "", false, fmt.Errorf("</F-CONTENT> is only valid in prefregex")
			}
			b.WriteByte(')')
			i += len("</F-CONTENT>")
			continue
		}
		if strings.HasPrefix(pattern[i:], "</F-MLFID>") {
			i += len("</F-MLFID>")
			continue
		}
		end := strings.IndexByte(pattern[i+1:], '>')
		if end < 0 {
			b.WriteByte(pattern[i])
			i++
			continue
		}
		end += i + 1
		tag := pattern[i+1 : end]
		if !isTagName(tag) {
			b.WriteString(pattern[i : end+1])
			i = end + 1
			continue
		}
		var repl string
		switch tag {
		case "HOST", "F-HOST", "IP", "F-IP":
			repl = wrapHost(hostPattern(usedns))
		case "ADDR", "F-ADDR":
			repl = wrapHost(ipOnlyPattern())
		case "IP4", "F-IP4":
			repl = wrapHost(ipv4Pattern)
		case "IP6", "F-IP6":
			repl = wrapHost(ipv6Pattern)
		case "SUBNET", "F-SUBNET", "CIDR", "F-CIDR":
			repl = subnetPattern()
		case "USER", "F-USER":
			repl = `\S+`
		case "SKIPLINES":
			repl = `(?:\n|$)`
		case "F-MLFGAINED":
			repl = `(?:\n|$)`
		case "F-NOFAIL":
			repl = ``
		case "F-DEF", "F-ALT":
			repl = ``
		case "KNOWN", "MODERATE", "HARD", "INVALID":
			// fail2ban's sshd "mode" candidate sets; approximated.
			repl = `\S+`
		case "F-MLFID":
			repl = ``
		case "F-CONTENT":
			if !pref {
				return "", false, fmt.Errorf("<F-CONTENT> is only valid in prefregex")
			}
			if contentMarkers {
				repl = `(?P<content>`
			} else {
				repl = `(?P<content>.*?)`
			}
		default:
			return "", false, fmt.Errorf("unsupported fail2ban regex tag <%s>", tag)
		}
		b.WriteString(repl)
		i = end + 1
	}
	return b.String(), hostUsed || hostDeclared, nil
}
