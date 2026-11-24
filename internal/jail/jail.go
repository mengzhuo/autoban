// Package jail ties together a filter, a failure/ban tracker, actions and a
// log backend into one fail2ban jail.
package jail

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mengzhuo/autoban/internal/action"
	"github.com/mengzhuo/autoban/internal/api"
	"github.com/mengzhuo/autoban/internal/backend"
	"github.com/mengzhuo/autoban/internal/ban"
	"github.com/mengzhuo/autoban/internal/config"
	"github.com/mengzhuo/autoban/internal/filter"
)

// Jail is the runtime form of one [jail] section.
type Jail struct {
	spec     config.JailSpec
	filter   *filter.Filter
	tracker  *ban.Tracker
	actions  []*action.Action
	backend  *backend.FileBackend
	log      *slog.Logger
	onChange func()

	lifecycleMu   sync.Mutex
	mu            sync.RWMutex
	started       bool
	cancel        context.CancelFunc
	done          chan struct{}
	usedNS        string
	ignoreCommand string

	actionMu     sync.Mutex
	actionBans   atomic.Int64
	actionUnbans atomic.Int64

	dnsMu     sync.Mutex
	dnsCache  map[string]dnsEntry
	dnsWarned map[string]bool
}

type dnsEntry struct {
	addrs   []string
	expires time.Time
	err     error
}

// New builds a Jail. onChange is invoked after ban state changes so the engine
// can persist the database.
func New(spec config.JailSpec, f *filter.Filter, tracker *ban.Tracker, actions []*action.Action, logger *slog.Logger, onChange func()) *Jail {
	if logger == nil {
		logger = slog.Default()
	}
	j := &Jail{
		spec:          spec,
		filter:        f,
		tracker:       tracker,
		actions:       actions,
		log:           logger,
		onChange:      onChange,
		usedNS:        spec.UsedNS,
		ignoreCommand: spec.IgnoreCommand,
		dnsCache:      make(map[string]dnsEntry),
		dnsWarned:     make(map[string]bool),
	}
	j.backend = backend.NewFileBackend(spec.LogPaths, spec.PollInterval, j.processLine, func(err error) {
		j.log.Warn("log backend error", "jail", spec.Name, "error", err)
	}, logger)
	return j
}

// Name returns the jail name.
func (j *Jail) Name() string { return j.spec.Name }

// Started reports whether the jail is running.
func (j *Jail) Started() bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.started
}

// Start performs actioncheck/actionstart, starts the log backend and the ban
// expiry loop.
func (j *Jail) Start(ctx context.Context) error {
	// Serialise Start/Stop, but do not hold the status lock while running
	// actions or while the backend replays lines accumulated during a stop.
	j.lifecycleMu.Lock()
	defer j.lifecycleMu.Unlock()

	j.mu.RLock()
	started := j.started
	j.mu.RUnlock()
	if started {
		return nil
	}

	startedActions := make([]*action.Action, 0, len(j.actions))
	stopStarted := func() {
		for i := len(startedActions) - 1; i >= 0; i-- {
			_ = startedActions[i].Stop(context.Background())
		}
	}
	for _, a := range j.actions {
		if err := a.Check(ctx); err != nil {
			stopStarted()
			return fmt.Errorf("action %s check failed: %w", a.Name(), err)
		}
		if err := a.Start(ctx); err != nil {
			stopStarted()
			return fmt.Errorf("action %s start failed: %w", a.Name(), err)
		}
		startedActions = append(startedActions, a)
	}

	// actionstart typically recreates empty firewall chains, so re-apply every
	// ban that is still active before accepting new log lines. Expired bans
	// are removed first. This covers both database restores and a jail that
	// was stopped and started again.
	j.expireOnce()
	j.reapplyBans()

	runCtx, cancel := context.WithCancel(ctx)
	j.mu.Lock()
	j.cancel = cancel
	j.done = make(chan struct{})
	j.started = true
	j.mu.Unlock()

	// FileBackend.Start replays lines accumulated while the jail was stopped.
	// processLine must be able to take j.mu, so started is set and the status
	// lock is released first.
	if err := j.backend.Start(runCtx); err != nil {
		cancel()
		j.mu.Lock()
		j.started = false
		j.mu.Unlock()
		stopStarted()
		return fmt.Errorf("backend start: %w", err)
	}
	go j.expireLoop(runCtx)
	return nil
}

// Stop halts the backend, expiry loop and actions.
func (j *Jail) Stop(ctx context.Context) error {
	j.lifecycleMu.Lock()
	defer j.lifecycleMu.Unlock()
	j.mu.Lock()
	if !j.started {
		j.mu.Unlock()
		return nil
	}
	j.started = false
	cancel := j.cancel
	done := j.done
	j.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if j.backend != nil {
		j.backend.Stop()
	}
	if done != nil {
		<-done
	}
	j.actionMu.Lock()
	defer j.actionMu.Unlock()
	var errs []error
	for i := len(j.actions) - 1; i >= 0; i-- {
		stopCtx := ctx
		if stopCtx == nil || stopCtx.Err() != nil {
			var cancelStop context.CancelFunc
			stopCtx, cancelStop = context.WithTimeout(context.Background(), 30*time.Second)
			defer cancelStop()
		}
		if err := j.actions[i].Stop(stopCtx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (j *Jail) expireLoop(ctx context.Context) {
	defer close(j.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			j.expireOnce()
			ticks++
			if ticks%60 == 0 {
				j.tracker.Purge(time.Now())
			}
		}
	}
}

func (j *Jail) expireOnce() {
	expired := j.tracker.Expire(time.Now())
	if len(expired) == 0 {
		return
	}
	for _, b := range expired {
		j.runUnban(b)
	}
	j.notify()
}

// reapplyBans re-adds active bans after actionstart has (re)created the
// firewall state. It is called before the backend starts, so no new ban can
// race with it.
func (j *Jail) reapplyBans() {
	bans := j.tracker.Status(time.Now()).Banned
	if len(bans) == 0 {
		return
	}
	for _, b := range bans {
		j.runBan(b)
	}
	j.log.Info("active bans reapplied", "jail", j.spec.Name, "count", len(bans))
	j.notify()
}

func (j *Jail) processLine(line string) {
	j.mu.RLock()
	started := j.started
	j.mu.RUnlock()
	if !started {
		return
	}
	now := time.Now()
	m, ok := j.filter.Match(line, now)
	if !ok {
		return
	}
	ip, ok := j.resolveHost(m.Host)
	if !ok {
		return
	}
	j.mu.RLock()
	ignoreCommand := j.ignoreCommand
	j.mu.RUnlock()
	if ignoreCommand != "" && j.ignoredByCommand(ip, ignoreCommand) {
		j.log.Debug("ignored by ignorecommand", "jail", j.spec.Name, "ip", ip)
		return
	}
	res := j.tracker.AddFailure(ip, m.Time, line)
	if res.Ban != nil {
		j.runBan(*res.Ban)
		j.notify()
	}
}

func (j *Jail) resolveHost(host string) (string, bool) {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String(), true
	}
	j.mu.RLock()
	usedns := j.usedNS
	j.mu.RUnlock()
	switch usedns {
	case "no":
		return "", false
	case "raw":
		ip, err := ban.NormalizeIP(host)
		if err != nil {
			j.log.Debug("invalid raw host", "jail", j.spec.Name, "host", host, "error", err)
			return "", false
		}
		return ip, true
	}

	key := strings.ToLower(strings.TrimSuffix(host, "."))
	now := time.Now()
	j.dnsMu.Lock()
	if e, ok := j.dnsCache[key]; ok && now.Before(e.expires) {
		j.dnsMu.Unlock()
		if e.err != nil || len(e.addrs) == 0 {
			return "", false
		}
		return e.addrs[0], true
	}
	j.dnsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", key)
	var resolved []string
	for _, a := range addrs {
		a = a.Unmap()
		resolved = append(resolved, a.String())
	}
	// Prefer IPv4 for firewall actions that have separate IPv6 support.
	if len(resolved) > 1 {
		for i, s := range resolved {
			if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
				resolved[0], resolved[i] = resolved[i], resolved[0]
				break
			}
		}
	}
	ttl := 5 * time.Minute
	if err != nil || len(resolved) == 0 {
		ttl = time.Minute
	}
	j.dnsMu.Lock()
	j.dnsCache[key] = dnsEntry{addrs: resolved, expires: now.Add(ttl), err: err}
	warnDNS := usedns == "warn" && !j.dnsWarned[key]
	if warnDNS {
		j.dnsWarned[key] = true
	}
	j.dnsMu.Unlock()
	if warnDNS {
		j.log.Warn("hostname resolved via DNS; set usedns=no to match IPs only", "jail", j.spec.Name, "host", host)
	}

	if err != nil {
		j.log.Debug("DNS resolution failed", "jail", j.spec.Name, "host", host, "error", err)
		return "", false
	}
	if len(resolved) == 0 {
		return "", false
	}
	return resolved[0], true
}

func (j *Jail) ignoredByCommand(ip, script string) bool {
	script = strings.ReplaceAll(script, "<ip>", ip)
	script = strings.ReplaceAll(script, "<family>", familyOf(ip))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		j.log.Warn("ignorecommand failed", "jail", j.spec.Name, "error", err, "output", strings.TrimSpace(string(out)))
	}
	return false
}

func (j *Jail) runBan(b ban.Ban) {
	opts := j.tracker.Options()
	ticket := action.Ticket{
		Jail:             j.spec.Name,
		IP:               b.IP,
		Failures:         b.Failures,
		BanTime:          b.Duration,
		BanTimeMax:       opts.BanTimeMax,
		BanTimeIncrement: opts.BanTimeIncrement,
		Matches:          b.Matches,
		Restored:         b.Restored,
		BanCount:         b.BanCount,
		Time:             b.Start,
	}
	j.actionMu.Lock()
	for _, a := range j.actions {
		if err := a.Ban(context.Background(), ticket); err != nil {
			j.log.Error("ban action failed", "jail", j.spec.Name, "action", a.Name(), "ip", b.IP, "error", err)
		}
	}
	j.actionMu.Unlock()
	j.actionBans.Add(1)
	j.log.Info("ban", "jail", j.spec.Name, "ip", b.IP, "bantime", b.Duration.String(), "failures", b.Failures, "bancount", b.BanCount)
}

func (j *Jail) runUnban(b ban.Ban) {
	opts := j.tracker.Options()
	ticket := action.Ticket{
		Jail:             j.spec.Name,
		IP:               b.IP,
		Failures:         b.Failures,
		BanTime:          b.Duration,
		BanTimeMax:       opts.BanTimeMax,
		BanTimeIncrement: opts.BanTimeIncrement,
		Matches:          b.Matches,
		Restored:         b.Restored,
		BanCount:         b.BanCount,
		Time:             time.Now(),
	}
	j.actionMu.Lock()
	for _, a := range j.actions {
		if err := a.Unban(context.Background(), ticket); err != nil {
			j.log.Error("unban action failed", "jail", j.spec.Name, "action", a.Name(), "ip", b.IP, "error", err)
		}
	}
	j.actionMu.Unlock()
	j.actionUnbans.Add(1)
	j.log.Info("unban", "jail", j.spec.Name, "ip", b.IP, "bantime", b.Duration.String())
}

// BanIP manually bans host.
func (j *Jail) BanIP(host string) (api.BanInfo, error) {
	j.lifecycleMu.Lock()
	defer j.lifecycleMu.Unlock()
	if !j.Started() {
		return api.BanInfo{}, fmt.Errorf("jail %s is not started", j.spec.Name)
	}
	b, err := j.tracker.BanIP(host)
	if err != nil {
		return api.BanInfo{}, err
	}
	if b == nil {
		return api.BanInfo{}, fmt.Errorf("%s is already banned in %s", host, j.spec.Name)
	}
	j.runBan(*b)
	j.notify()
	return toBanInfo(*b), nil
}

// UnbanIP manually unbans host.
func (j *Jail) UnbanIP(host string) error {
	j.lifecycleMu.Lock()
	defer j.lifecycleMu.Unlock()
	b, err := j.tracker.Unban(host)
	if err != nil {
		return err
	}
	if b == nil {
		return fmt.Errorf("%s is not banned in %s", host, j.spec.Name)
	}
	j.runUnban(*b)
	j.notify()
	return nil
}

// Flush removes all bans and runs actionflush.
func (j *Jail) Flush() (int, error) {
	j.lifecycleMu.Lock()
	defer j.lifecycleMu.Unlock()
	bans := j.tracker.Flush()
	ticket := action.Ticket{Jail: j.spec.Name, Time: time.Now()}
	j.actionMu.Lock()
	var errs []error
	for _, a := range j.actions {
		if err := a.Flush(context.Background(), ticket); err != nil {
			errs = append(errs, err)
			j.log.Error("flush action failed", "jail", j.spec.Name, "action", a.Name(), "error", err)
		}
	}
	j.actionMu.Unlock()
	j.actionUnbans.Add(int64(len(bans)))
	j.notify()
	return len(bans), errors.Join(errs...)
}

// Status returns the jail status for the API.
func (j *Jail) Status() api.JailStatus {
	now := time.Now()
	st := j.tracker.Status(now)
	opts := j.tracker.Options()
	j.mu.RLock()
	started := j.started
	usedns := j.usedNS
	ignoreCommand := j.ignoreCommand
	j.mu.RUnlock()

	files := append([]string(nil), j.spec.LogPaths...)
	if j.backend != nil {
		if f := j.backend.Files(); len(f) > 0 {
			files = f
		}
	}
	actionNames := make([]string, len(j.actions))
	for i, a := range j.actions {
		actionNames[i] = a.Name()
	}
	banned := make([]api.BanInfo, len(st.Banned))
	ips := make([]string, len(st.Banned))
	for i, b := range st.Banned {
		banned[i] = toBanInfo(b)
		ips[i] = b.IP
	}
	return api.JailStatus{
		Name:             j.spec.Name,
		Filter:           j.spec.Filter,
		FilterMode:       j.spec.FilterMode,
		Backend:          j.spec.Backend,
		Files:            files,
		Actions:          actionNames,
		Started:          started,
		CurrentlyFailed:  st.CurrentlyFailed,
		TotalFailed:      st.TotalFailed,
		CurrentlyBanned:  st.CurrentlyBanned,
		TotalBanned:      st.TotalBanned,
		TotalUnbanned:    st.TotalUnbanned,
		BannedIPs:        ips,
		Banned:           banned,
		MaxRetry:         opts.MaxRetry,
		FindTime:         int64(opts.FindTime / time.Second),
		BanTime:          int64(opts.BanTime / time.Second),
		UsedNS:           usedns,
		IgnoreIP:         append([]string(nil), opts.IgnoreIP...),
		BanTimeIncrement: opts.BanTimeIncrement,
		BanTimeFactor:    opts.BanTimeFactor,
		BanTimeMax:       int64(opts.BanTimeMax / time.Second),
		BanTimeRnd:       int64(opts.BanTimeRnd / time.Second),
		MaxLines:         opts.MaxLines,
		IgnoreCommand:    ignoreCommand,
		DatePattern:      j.spec.DatePattern,
		FilterWarnings:   j.filter.Warnings(),
	}
}

// Failures returns current failure entries.
func (j *Jail) Failures() []api.FailureInfo {
	fs := j.tracker.Failures(time.Now())
	out := make([]api.FailureInfo, len(fs))
	for i, f := range fs {
		out[i] = api.FailureInfo{IP: f.IP, Count: f.Count, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen}
	}
	return out
}

// Set updates a runtime option.
func (j *Jail) Set(key, value string) error {
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	switch key {
	case "maxretry":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid maxretry %q", value)
		}
		return j.tracker.SetMaxRetry(n)
	case "findtime":
		d, err := config.ParseDuration(value)
		if err != nil {
			return err
		}
		return j.tracker.SetFindTime(d)
	case "bantime":
		d, err := config.ParseDuration(value)
		if err != nil {
			return err
		}
		return j.tracker.SetBanTime(d)
	case "ignoreip":
		entries := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
		if err := j.tracker.SetIgnoreIP(entries); err != nil {
			return err
		}
		j.mu.Lock()
		j.spec.IgnoreIP = entries
		j.mu.Unlock()
		return nil
	case "usedns":
		v := strings.ToLower(value)
		switch v {
		case "yes", "no", "warn", "raw":
		default:
			return fmt.Errorf("invalid usedns %q", value)
		}
		j.mu.Lock()
		j.usedNS = v
		j.spec.UsedNS = v
		j.spec.UsedNSExplicit = true
		j.mu.Unlock()
		return nil
	case "maxlines":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 {
			return fmt.Errorf("invalid maxlines %q", value)
		}
		if err := j.tracker.SetMaxLines(n); err != nil {
			return err
		}
		j.mu.Lock()
		j.spec.MaxLines = n
		j.mu.Unlock()
		return nil
	case "ignorecommand":
		j.mu.Lock()
		j.ignoreCommand = value
		j.spec.IgnoreCommand = value
		j.mu.Unlock()
		return nil
	case "bantime.increment":
		j.tracker.SetBanTimeIncrement(parseBool(value))
		return nil
	case "bantime.factor":
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("invalid bantime.factor %q", value)
		}
		return j.tracker.SetBanTimeFactor(f)
	case "bantime.maxtime":
		d, err := config.ParseDuration(value)
		if err != nil {
			return err
		}
		return j.tracker.SetBanTimeMax(d)
	case "bantime.rndtime":
		d, err := config.ParseDuration(value)
		if err != nil {
			return err
		}
		return j.tracker.SetBanTimeRnd(d)
	default:
		return fmt.Errorf("option %q cannot be changed at runtime", key)
	}
}

// Get returns a runtime option as a string.
func (j *Jail) Get(key string) (string, error) {
	opts := j.tracker.Options()
	j.mu.RLock()
	usedns := j.usedNS
	ignoreCommand := j.ignoreCommand
	j.mu.RUnlock()
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "maxretry":
		return strconv.Itoa(opts.MaxRetry), nil
	case "findtime":
		return strconv.FormatInt(int64(opts.FindTime/time.Second), 10), nil
	case "bantime":
		return strconv.FormatInt(int64(opts.BanTime/time.Second), 10), nil
	case "ignoreip":
		return strings.Join(opts.IgnoreIP, " "), nil
	case "usedns":
		return usedns, nil
	case "maxlines":
		return strconv.Itoa(opts.MaxLines), nil
	case "ignorecommand":
		return ignoreCommand, nil
	case "bantime.increment":
		return strconv.FormatBool(opts.BanTimeIncrement), nil
	case "bantime.factor":
		return strconv.FormatFloat(opts.BanTimeFactor, 'f', -1, 64), nil
	case "bantime.maxtime":
		return strconv.FormatInt(int64(opts.BanTimeMax/time.Second), 10), nil
	case "bantime.rndtime":
		return strconv.FormatInt(int64(opts.BanTimeRnd/time.Second), 10), nil
	case "filter":
		return j.spec.Filter, nil
	case "logpath":
		return strings.Join(j.spec.LogPaths, " "), nil
	case "backend":
		return j.spec.Backend, nil
	case "action":
		names := make([]string, len(j.actions))
		for i, a := range j.actions {
			names[i] = a.Name()
		}
		return strings.Join(names, " "), nil
	case "datepattern":
		return j.spec.DatePattern, nil
	default:
		return "", fmt.Errorf("unknown option %q", key)
	}
}

// Spec returns a copy of the jail configuration.
func (j *Jail) Spec() config.JailSpec {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.spec
}

// Tracker returns the failure tracker (used for persistence).
func (j *Jail) Tracker() *ban.Tracker { return j.tracker }

// BackendSnapshot captures log file positions for a configuration reload.
func (j *Jail) BackendSnapshot() backend.Snapshot {
	if j.backend == nil {
		return backend.Snapshot{}
	}
	return j.backend.Snapshot()
}

// RestoreBackend restores log file positions before the jail is started.
func (j *Jail) RestoreBackend(s backend.Snapshot) error {
	if j.backend == nil {
		return nil
	}
	return j.backend.Restore(s)
}

// Filter returns the compiled filter.
func (j *Jail) Filter() *filter.Filter { return j.filter }

// ActionBans returns the number of actionban executions.
func (j *Jail) ActionBans() int64 { return j.actionBans.Load() }

// ActionUnbans returns the number of actionunban executions.
func (j *Jail) ActionUnbans() int64 { return j.actionUnbans.Load() }

func (j *Jail) notify() {
	if j.onChange != nil {
		j.onChange()
	}
}

func toBanInfo(b ban.Ban) api.BanInfo {
	return api.BanInfo{
		IP:       b.IP,
		Start:    b.Start,
		Until:    b.Until,
		Duration: int64(b.Duration / time.Second),
		Failures: b.Failures,
		Matches:  append([]string(nil), b.Matches...),
		BanCount: b.BanCount,
		Restored: b.Restored,
	}
}

func familyOf(ip string) string {
	if ban.IsIPv6(ip) {
		return "inet6"
	}
	return "inet"
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "enable", "enabled":
		return true
	default:
		return false
	}
}

// Ensure net import is used on all build targets.
var _ = netip.Addr{}
