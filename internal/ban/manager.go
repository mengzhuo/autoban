// Package ban implements fail2ban's failure tracking and ban lifecycle:
// findtime windows, maxretry thresholds, ignoreip, bantime increment and
// persistent snapshots.
package ban

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Options controls a Tracker.
type Options struct {
	MaxRetry         int
	FindTime         time.Duration
	BanTime          time.Duration // negative means permanent
	IgnoreIP         []string
	BanTimeIncrement bool
	BanTimeFactor    float64
	BanTimeMax       time.Duration
	BanTimeRnd       time.Duration
	DBPurgeAge       time.Duration
	MaxLines         int
	Now              func() time.Time
}

// Failure is one matched log line associated with a host.
type Failure struct {
	Time time.Time `json:"time"`
	Line string    `json:"line"`
}

// Ban is one active ban.
type Ban struct {
	IP       string        `json:"ip"`
	Start    time.Time     `json:"start"`
	Until    time.Time     `json:"until,omitempty"`
	Duration time.Duration `json:"duration"`
	Failures int           `json:"failures"`
	Matches  []string      `json:"matches,omitempty"`
	BanCount int           `json:"banCount"`
	Restored bool          `json:"restored,omitempty"`
}

// Snapshot is the persistent state of a tracker.
type Snapshot struct {
	Bans          []Ban                  `json:"bans,omitempty"`
	Failures      map[string][]Failure   `json:"failures,omitempty"`
	BanHistory    map[string][]time.Time `json:"banHistory,omitempty"`
	TotalFailed   int64                  `json:"totalFailed,omitempty"`
	TotalBanned   int64                  `json:"totalBanned,omitempty"`
	TotalUnbanned int64                  `json:"totalUnbanned,omitempty"`
}

// AddResult reports how AddFailure treated a line.
type AddResult struct {
	Counted bool
	Stale   bool
	Count   int
	Ban     *Ban
}

// Status is a point-in-time summary of a tracker.
type Status struct {
	CurrentlyFailed int
	TotalFailed     int64
	CurrentlyBanned int
	TotalBanned     int64
	TotalUnbanned   int64
	Banned          []Ban
	FailureCounts   map[string]int
}

// FailureInfo describes failures for one host.
type FailureInfo struct {
	IP        string    `json:"ip"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

type entry struct {
	failures []Failure
}

// Tracker stores failures and bans for one jail. It is safe for concurrent use.
type Tracker struct {
	mu            sync.Mutex
	opts          Options
	entries       map[string]*entry
	bans          map[string]*Ban
	history       map[string][]time.Time
	prefix        []netip.Prefix
	names         map[string]bool
	totalFailed   int64
	totalBanned   int64
	totalUnbanned int64
}

// New creates a Tracker. It validates ignoreip entries.
func New(opts Options) (*Tracker, error) {
	if opts.MaxRetry < 1 {
		opts.MaxRetry = 1
	}
	if opts.FindTime <= 0 {
		return nil, fmt.Errorf("findtime must be positive")
	}
	if opts.BanTime == 0 {
		return nil, fmt.Errorf("bantime must not be zero")
	}
	if opts.BanTimeFactor <= 0 {
		opts.BanTimeFactor = 2
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	t := &Tracker{
		opts:    opts,
		entries: make(map[string]*entry),
		bans:    make(map[string]*Ban),
		history: make(map[string][]time.Time),
		names:   make(map[string]bool),
	}
	if err := t.setIgnoreIPLocked(opts.IgnoreIP); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tracker) now() time.Time {
	return t.opts.Now()
}

// NormalizeIP canonicalises an IPv4/IPv6 address. Hostnames are accepted for
// usedns=raw, but only when they look like a DNS name.
func NormalizeIP(host string) (string, error) {
	s := strings.TrimSpace(strings.Trim(host, "[]"))
	if s == "" {
		return "", fmt.Errorf("empty host")
	}
	// Strip an IPv6 zone identifier before storing: firewall actions do not
	// understand link-local zones.
	if i := strings.IndexByte(s, '%'); i > 0 && strings.Contains(s, ":") {
		s = s[:i]
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap().String(), nil
	}
	if looksLikeNumericHost(s) {
		return "", fmt.Errorf("invalid IP address %q", host)
	}
	if validHostname(s) {
		return strings.ToLower(strings.TrimSuffix(s, ".")), nil
	}
	return "", fmt.Errorf("invalid host %q", host)
}

func looksLikeNumericHost(s string) bool {
	if s == "" {
		return false
	}
	hasDigit := false
	for _, r := range s {
		if unicode.IsDigit(r) {
			hasDigit = true
			continue
		}
		if r != '.' && r != ':' {
			return false
		}
	}
	return hasDigit
}

func validHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, r := range label {
			alnum := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
			if alnum || r == '_' {
				continue
			}
			if r == '-' && i > 0 && i < len(label)-1 {
				continue
			}
			return false
		}
		first := label[0]
		last := label[len(label)-1]
		if !isASCIIAlnum(first) || !isASCIIAlnum(last) {
			return false
		}
	}
	return true
}

func isASCIIAlnum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// IsIPv6 reports whether host is an IPv6 address.
func IsIPv6(host string) bool {
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && addr.Is6() && !addr.Is4In6()
}

// AddFailure records a matched line for host. at is the log timestamp, or the
// zero time if the log line has no timestamp.
func (t *Tracker) AddFailure(host string, at time.Time, line string) AddResult {
	ip, err := NormalizeIP(host)
	if err != nil {
		return AddResult{}
	}
	now := t.now()
	if at.IsZero() {
		at = now
	}
	// Clamp timestamps slightly in the future (clock skew).
	if at.After(now.Add(5 * time.Minute)) {
		at = now
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	// Drop lines that are too old to be relevant.
	if at.Before(now.Add(-t.opts.FindTime)) {
		return AddResult{Stale: true}
	}
	if t.isIgnoredLocked(ip) {
		return AddResult{}
	}
	if _, banned := t.bans[ip]; banned {
		return AddResult{}
	}
	e := t.entries[ip]
	if e == nil {
		e = &entry{}
		t.entries[ip] = e
	}
	cutoff := now.Add(-t.opts.FindTime)
	keep := e.failures[:0]
	for _, f := range e.failures {
		if !f.Time.Before(cutoff) {
			keep = append(keep, f)
		}
	}
	e.failures = append(keep, Failure{Time: at, Line: line})
	t.totalFailed++

	if len(e.failures) < t.opts.MaxRetry {
		return AddResult{Counted: true, Count: len(e.failures)}
	}

	matches := make([]string, 0, len(e.failures))
	for _, f := range e.failures {
		matches = append(matches, f.Line)
	}
	if len(matches) > 100 {
		matches = matches[len(matches)-100:]
	}
	delete(t.entries, ip)
	b := t.createBanLocked(ip, now, len(e.failures), matches)
	return AddResult{Counted: true, Count: len(e.failures), Ban: b}
}

// BanIP creates a manual ban. It returns a nil Ban if the host was already
// banned.
func (t *Tracker) BanIP(host string) (*Ban, error) {
	ip, err := NormalizeIP(host)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.bans[ip]; ok {
		return nil, nil
	}
	delete(t.entries, ip)
	return t.createBanLocked(ip, t.now(), 0, nil), nil
}

func (t *Tracker) createBanLocked(ip string, now time.Time, failures int, matches []string) *Ban {
	history := t.history[ip]
	if t.opts.DBPurgeAge > 0 {
		cutoff := now.Add(-t.opts.DBPurgeAge)
		keep := history[:0]
		for _, ts := range history {
			if !ts.Before(cutoff) {
				keep = append(keep, ts)
			}
		}
		history = keep
	}
	history = append(history, now)
	t.history[ip] = history

	duration := t.opts.BanTime
	permanent := duration < 0
	if !permanent && t.opts.BanTimeIncrement && len(history) > 1 {
		factor := t.opts.BanTimeFactor
		if factor <= 0 {
			factor = 2
		}
		mult := math.Pow(factor, float64(len(history)-1))
		scaled := float64(duration) * mult
		if scaled >= float64(math.MaxInt64) {
			duration = time.Duration(math.MaxInt64)
		} else {
			duration = time.Duration(scaled)
		}
		if t.opts.BanTimeMax > 0 && duration > t.opts.BanTimeMax {
			duration = t.opts.BanTimeMax
		}
	}
	if !permanent && t.opts.BanTimeRnd > 0 {
		rnd := t.opts.BanTimeRnd
		delta := time.Duration(rand.Int64N(int64(rnd)*2+1)) - rnd
		duration += delta
		if duration < time.Second {
			duration = time.Second
		}
	}

	b := &Ban{
		IP:       ip,
		Start:    now,
		Duration: duration,
		Failures: failures,
		Matches:  matches,
		BanCount: len(history),
	}
	if !permanent {
		b.Until = now.Add(duration)
	}
	t.bans[ip] = b
	t.totalBanned++
	cp := *b
	cp.Matches = append([]string(nil), b.Matches...)
	return &cp
}

// Unban removes one ban.
func (t *Tracker) Unban(host string) (*Ban, error) {
	ip, err := NormalizeIP(host)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.bans[ip]
	if b == nil {
		return nil, nil
	}
	delete(t.bans, ip)
	delete(t.entries, ip)
	t.totalUnbanned++
	cp := *b
	cp.Matches = append([]string(nil), b.Matches...)
	return &cp, nil
}

// Expire removes all bans whose Until has passed.
func (t *Tracker) Expire(now time.Time) []Ban {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Ban
	for ip, b := range t.bans {
		if b.Until.IsZero() || now.Before(b.Until) {
			continue
		}
		delete(t.bans, ip)
		t.totalUnbanned++
		cp := *b
		cp.Matches = append([]string(nil), b.Matches...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	t.purgeLocked(now)
	return out
}

// Flush removes all active bans and failures.
func (t *Tracker) Flush() []Ban {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Ban, 0, len(t.bans))
	for _, b := range t.bans {
		cp := *b
		cp.Matches = append([]string(nil), b.Matches...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	t.bans = make(map[string]*Ban)
	t.entries = make(map[string]*entry)
	t.totalUnbanned += int64(len(out))
	return out
}

// Purge removes expired failure records and old ban history.
func (t *Tracker) Purge(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.purgeLocked(now)
}

func (t *Tracker) purgeLocked(now time.Time) {
	cutoff := now.Add(-t.opts.FindTime)
	for ip, e := range t.entries {
		keep := e.failures[:0]
		for _, f := range e.failures {
			if !f.Time.Before(cutoff) {
				keep = append(keep, f)
			}
		}
		if len(keep) == 0 {
			delete(t.entries, ip)
		} else {
			e.failures = keep
		}
	}
	if t.opts.DBPurgeAge > 0 {
		hcut := now.Add(-t.opts.DBPurgeAge)
		for ip, hist := range t.history {
			keep := hist[:0]
			for _, ts := range hist {
				if !ts.Before(hcut) {
					keep = append(keep, ts)
				}
			}
			if len(keep) == 0 {
				delete(t.history, ip)
			} else {
				t.history[ip] = keep
			}
		}
	}
}

// IsBanned reports whether host is currently banned.
func (t *Tracker) IsBanned(host string) bool {
	ip, err := NormalizeIP(host)
	if err != nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.bans[ip]
	return ok
}

// IsIgnored reports whether host matches ignoreip.
func (t *Tracker) IsIgnored(host string) bool {
	ip, err := NormalizeIP(host)
	if err != nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.isIgnoredLocked(ip)
}

// Status returns a snapshot of counters, bans and failure counts.
func (t *Tracker) Status(now time.Time) Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.purgeLocked(now)
	st := Status{
		CurrentlyFailed: len(t.entries),
		TotalFailed:     t.totalFailed,
		CurrentlyBanned: len(t.bans),
		TotalBanned:     t.totalBanned,
		TotalUnbanned:   t.totalUnbanned,
		FailureCounts:   make(map[string]int, len(t.entries)),
	}
	for ip, e := range t.entries {
		st.FailureCounts[ip] = len(e.failures)
	}
	st.Banned = make([]Ban, 0, len(t.bans))
	for _, b := range t.bans {
		cp := *b
		cp.Matches = append([]string(nil), b.Matches...)
		st.Banned = append(st.Banned, cp)
	}
	sort.Slice(st.Banned, func(i, j int) bool { return st.Banned[i].IP < st.Banned[j].IP })
	return st
}

// Failures returns per-host failure details within findtime.
func (t *Tracker) Failures(now time.Time) []FailureInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.purgeLocked(now)
	out := make([]FailureInfo, 0, len(t.entries))
	for ip, e := range t.entries {
		if len(e.failures) == 0 {
			continue
		}
		info := FailureInfo{IP: ip, Count: len(e.failures), FirstSeen: e.failures[0].Time, LastSeen: e.failures[len(e.failures)-1].Time}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// Options returns a copy of the tracker options.
func (t *Tracker) Options() Options {
	t.mu.Lock()
	defer t.mu.Unlock()
	o := t.opts
	o.IgnoreIP = append([]string(nil), t.opts.IgnoreIP...)
	return o
}

// SetMaxRetry updates the threshold.
func (t *Tracker) SetMaxRetry(n int) error {
	if n < 1 {
		return fmt.Errorf("maxretry must be >= 1")
	}
	t.mu.Lock()
	t.opts.MaxRetry = n
	t.mu.Unlock()
	return nil
}

// SetFindTime updates the failure window.
func (t *Tracker) SetFindTime(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("findtime must be positive")
	}
	t.mu.Lock()
	t.opts.FindTime = d
	t.mu.Unlock()
	return nil
}

// SetBanTime updates the base ban duration.
func (t *Tracker) SetBanTime(d time.Duration) error {
	if d == 0 {
		return fmt.Errorf("bantime must not be zero")
	}
	t.mu.Lock()
	t.opts.BanTime = d
	t.mu.Unlock()
	return nil
}

// SetIgnoreIP replaces ignoreip.
func (t *Tracker) SetIgnoreIP(entries []string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.setIgnoreIPLocked(entries); err != nil {
		return err
	}
	t.opts.IgnoreIP = append([]string(nil), entries...)
	return nil
}

// SetBanTimeIncrement toggles bantime.increment.
func (t *Tracker) SetBanTimeIncrement(enabled bool) {
	t.mu.Lock()
	t.opts.BanTimeIncrement = enabled
	t.mu.Unlock()
}

// SetBanTimeFactor updates bantime.factor.
func (t *Tracker) SetBanTimeFactor(f float64) error {
	if f <= 0 {
		return fmt.Errorf("bantime.factor must be positive")
	}
	t.mu.Lock()
	t.opts.BanTimeFactor = f
	t.mu.Unlock()
	return nil
}

// SetBanTimeMax updates bantime.maxtime.
func (t *Tracker) SetBanTimeMax(d time.Duration) error {
	if d < 0 {
		return fmt.Errorf("bantime.maxtime must not be negative")
	}
	t.mu.Lock()
	t.opts.BanTimeMax = d
	t.mu.Unlock()
	return nil
}

// SetBanTimeRnd updates bantime.rndtime.
func (t *Tracker) SetBanTimeRnd(d time.Duration) error {
	if d < 0 {
		return fmt.Errorf("bantime.rndtime must not be negative")
	}
	t.mu.Lock()
	t.opts.BanTimeRnd = d
	t.mu.Unlock()
	return nil
}

func (t *Tracker) setIgnoreIPLocked(entries []string) error {
	var prefixes []netip.Prefix
	names := make(map[string]bool)
	for _, raw := range entries {
		s := strings.TrimSpace(strings.Trim(raw, "[]"))
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p.Masked())
			continue
		}
		if p, err := netip.ParsePrefix(strings.TrimSuffix(s, "/")); err == nil {
			prefixes = append(prefixes, p.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			addr = addr.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		if validHostname(s) {
			names[strings.ToLower(strings.TrimSuffix(s, "."))] = true
			continue
		}
		return fmt.Errorf("invalid ignoreip entry %q", raw)
	}
	t.prefix = prefixes
	t.names = names
	return nil
}

func (t *Tracker) isIgnoredLocked(ip string) bool {
	if t.names[ip] {
		return true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range t.prefix {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Snapshot captures state for persistence.
func (t *Tracker) Snapshot(now time.Time) Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.purgeLocked(now)
	s := Snapshot{
		Failures:      make(map[string][]Failure, len(t.entries)),
		BanHistory:    make(map[string][]time.Time, len(t.history)),
		TotalFailed:   t.totalFailed,
		TotalBanned:   t.totalBanned,
		TotalUnbanned: t.totalUnbanned,
	}
	for ip, e := range t.entries {
		fs := make([]Failure, len(e.failures))
		copy(fs, e.failures)
		s.Failures[ip] = fs
	}
	for ip, hist := range t.history {
		s.BanHistory[ip] = append([]time.Time(nil), hist...)
	}
	for _, b := range t.bans {
		cp := *b
		cp.Matches = append([]string(nil), b.Matches...)
		s.Bans = append(s.Bans, cp)
	}
	sort.Slice(s.Bans, func(i, j int) bool { return s.Bans[i].IP < s.Bans[j].IP })
	return s
}

// Restore loads a snapshot. Expired bans are retained so the jail can run
// actionunban for them after actionstart, matching fail2ban's restore flow.
func (t *Tracker) Restore(s Snapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, b := range s.Bans {
		ip, err := NormalizeIP(b.IP)
		if err != nil {
			continue
		}
		b.IP = ip
		if b.Start.IsZero() {
			b.Start = now
		}
		if b.Duration == 0 && !b.Until.IsZero() {
			b.Duration = b.Until.Sub(b.Start)
		}
		b.Restored = true
		b.Matches = append([]string(nil), b.Matches...)
		t.bans[ip] = &b
	}
	for ip, fs := range s.Failures {
		nip, err := NormalizeIP(ip)
		if err != nil || len(fs) == 0 {
			continue
		}
		cutoff := now.Add(-t.opts.FindTime)
		keep := make([]Failure, 0, len(fs))
		for _, f := range fs {
			if f.Time.IsZero() || !f.Time.Before(cutoff) {
				keep = append(keep, f)
			}
		}
		if len(keep) > 0 {
			t.entries[nip] = &entry{failures: keep}
		}
	}
	for ip, hist := range s.BanHistory {
		nip, err := NormalizeIP(ip)
		if err != nil {
			continue
		}
		t.history[nip] = append([]time.Time(nil), hist...)
	}
	t.totalFailed = s.TotalFailed
	t.totalBanned = s.TotalBanned
	t.totalUnbanned = s.TotalUnbanned
	if t.totalBanned < int64(len(t.bans)) {
		t.totalBanned = int64(len(t.bans))
	}
	t.purgeLocked(now)
}
