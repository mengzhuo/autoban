// Package action executes fail2ban-style action scripts with <tag>
// substitution.
package action

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mengzhuo/gojail/internal/config"
)

var tagRE = regexp.MustCompile(`<([A-Za-z0-9_.-]+)>`)

// Ticket carries the per-event values available to action tags.
type Ticket struct {
	Jail             string
	IP               string
	Failures         int
	BanTime          time.Duration
	BanTimeMax       time.Duration
	BanTimeIncrement bool
	Matches          []string
	Restored         bool
	BanCount         int
	Time             time.Time
}

// Action is a loaded action.d action instance.
type Action struct {
	spec    *config.ActionSpec
	jail    string
	log     *slog.Logger
	mu      sync.Mutex
	started bool
}

// New creates an action instance for a jail.
func New(jail string, spec *config.ActionSpec, logger *slog.Logger) *Action {
	if logger == nil {
		logger = slog.Default()
	}
	if spec.Timeout <= 0 {
		spec.Timeout = 30 * time.Second
	}
	return &Action{spec: spec, jail: jail, log: logger}
}

// Name returns the action.d name.
func (a *Action) Name() string { return a.spec.Name }

// Check runs actioncheck and returns an error if the action is unavailable.
func (a *Action) Check(ctx context.Context) error {
	return a.run(ctx, "check", a.spec.Check, a.tags(Ticket{}))
}

// Start runs actionstart if it has not run yet.
func (a *Action) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started {
		return nil
	}
	if err := a.run(ctx, "start", a.spec.Start, a.tags(Ticket{})); err != nil {
		return err
	}
	a.started = true
	return nil
}

// Stop runs actionstop once if the action was started.
func (a *Action) Stop(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.started {
		return nil
	}
	a.started = false
	return a.run(ctx, "stop", a.spec.Stop, a.tags(Ticket{}))
}

// Ban runs actionban.
func (a *Action) Ban(ctx context.Context, t Ticket) error {
	return a.run(ctx, "ban", a.spec.Ban, a.tags(t))
}

// Unban runs actionunban.
func (a *Action) Unban(ctx context.Context, t Ticket) error {
	return a.run(ctx, "unban", a.spec.Unban, a.tags(t))
}

// Flush runs actionflush.
func (a *Action) Flush(ctx context.Context, t Ticket) error {
	return a.run(ctx, "flush", a.spec.Flush, a.tags(t))
}

// Reload runs actionreload.
func (a *Action) Reload(ctx context.Context) error {
	return a.run(ctx, "reload", a.spec.Reload, a.tags(Ticket{}))
}

func (a *Action) tags(t Ticket) map[string]string {
	tags := make(map[string]string, len(a.spec.Params)+20)
	for k, v := range a.spec.Params {
		tags[strings.ToLower(k)] = v
	}
	if _, ok := tags["name"]; !ok {
		tags["name"] = a.jail
	}
	tags["jail"] = a.jail
	tags["ip"] = t.IP
	tags["family"] = family(t.IP)
	tags["failures"] = strconv.Itoa(t.Failures)
	tags["ipfailures"] = strconv.Itoa(t.Failures)
	tags["ipjailfailures"] = strconv.Itoa(t.Failures)
	tags["bantime"] = strconv.FormatInt(int64(t.BanTime/time.Second), 10)
	tags["bantime.increment"] = strconv.FormatBool(t.BanTimeIncrement)
	tags["maxtime"] = strconv.FormatInt(int64(t.BanTimeMax/time.Second), 10)
	tags["restored"] = strconv.FormatBool(t.Restored)
	tags["bancount"] = strconv.Itoa(t.BanCount)
	when := t.Time
	if when.IsZero() {
		when = time.Now()
	}
	tags["time"] = when.Format("2006-01-02 15:04:05")
	matches := strings.Join(t.Matches, "\n")
	tags["matches"] = matches
	tags["ipmatches"] = matches
	tags["ipjailmatches"] = matches
	sum := sha1.Sum([]byte(t.IP + "|" + when.Format(time.RFC3339Nano) + "|" + matches))
	tags["fid"] = hex.EncodeToString(sum[:8])
	return tags
}

func family(ip string) string {
	addr, err := netip.ParseAddr(strings.Trim(ip, "[]"))
	if err == nil && addr.Is6() && !addr.Is4In6() {
		return "inet6"
	}
	return "inet"
}

func (a *Action) run(ctx context.Context, op, script string, tags map[string]string) error {
	script = strings.TrimSpace(script)
	if script == "" {
		return nil
	}
	expanded, unknown := substitute(script, tags, 0)
	if len(unknown) > 0 {
		a.log.Warn("action contains unresolved tags", "jail", a.jail, "action", a.spec.Name, "op", op, "tags", unknown)
	}

	timeout := a.spec.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "/bin/sh", "-c", expanded)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 500 * time.Millisecond
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Start()
	if err == nil {
		waitCh := make(chan error, 1)
		go func() { waitCh <- cmd.Wait() }()
		select {
		case err = <-waitCh:
		case <-runCtx.Done():
			// Kill the whole process group so shell children (sleep, iptables
			// wrappers, etc.) cannot keep our output pipes open.
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			err = <-waitCh
		}
	}
	output := strings.TrimSpace(out.String())
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("action %s %s timed out after %s: %s", a.spec.Name, op, timeout, truncate(output, 2000))
		}
		return fmt.Errorf("action %s %s failed: %w: %s", a.spec.Name, op, err, truncate(output, 2000))
	}
	if output != "" {
		a.log.Debug("action output", "jail", a.jail, "action", a.spec.Name, "op", op, "output", truncate(output, 2000))
	} else {
		a.log.Debug("action executed", "jail", a.jail, "action", a.spec.Name, "op", op)
	}
	return nil
}

func substitute(script string, tags map[string]string, depth int) (string, []string) {
	if depth > 8 {
		return script, nil
	}
	unknownSet := make(map[string]bool)
	var replaced bool
	out := tagRE.ReplaceAllStringFunc(script, func(m string) string {
		key := strings.ToLower(m[1 : len(m)-1])
		if v, ok := tags[key]; ok {
			replaced = true
			return v
		}
		unknownSet[key] = true
		return m
	})
	if replaced {
		next, unknown := substitute(out, tags, depth+1)
		// The last pass has the authoritative view of still-unresolved tags.
		return next, unknown
	}
	unknown := make([]string, 0, len(unknownSet))
	for k := range unknownSet {
		unknown = append(unknown, k)
	}
	return out, unknown
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
