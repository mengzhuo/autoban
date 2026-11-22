// Package engine loads configuration, owns jails and serves the control
// socket.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mengzhuo/gojail/internal/action"
	"github.com/mengzhuo/gojail/internal/api"
	"github.com/mengzhuo/gojail/internal/ban"
	"github.com/mengzhuo/gojail/internal/config"
	"github.com/mengzhuo/gojail/internal/filter"
	"github.com/mengzhuo/gojail/internal/jail"
	"github.com/mengzhuo/gojail/internal/store"
)

// Version is the gojail release version.
const Version = "0.1.0"

// Engine is the daemon.
type Engine struct {
	dirs    []string
	global  *config.Global
	log     *slog.Logger
	store   *store.Store
	initial store.DiskState

	mu        sync.RWMutex
	jails     map[string]*jail.Jail
	specs     map[string]config.JailSpec
	startedAt time.Time

	opMu        sync.Mutex
	listener    net.Listener
	socketPath  string
	socketOwned bool
	pidPath     string
	pidFile     *os.File

	connMu sync.Mutex
	conns  map[net.Conn]struct{}
	connWG sync.WaitGroup

	saveMu       sync.Mutex
	saveStop     chan struct{}
	saveDone     chan struct{}
	acceptWG     sync.WaitGroup
	shuttingDown atomic.Bool
	stopOnce     sync.Once
	stopped      chan struct{}
}

// New creates an engine. Call Build before Start.
func New(dirs []string, global *config.Global, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		dirs:    append([]string(nil), dirs...),
		global:  global,
		log:     logger,
		jails:   make(map[string]*jail.Jail),
		specs:   make(map[string]config.JailSpec),
		conns:   make(map[net.Conn]struct{}),
		stopped: make(chan struct{}),
	}
}

// Build loads the database and compiles all configured jails.
func (e *Engine) Build() error {
	st, state, err := store.Open(e.global.DBFile, e.log)
	if err != nil {
		return err
	}
	e.store = st
	e.initial = state

	specs, err := config.LoadJails(e.dirs, e.global.PollInterval)
	if err != nil {
		return err
	}
	jails, specsMap, err := e.buildJails(specs, e.initial.Jails)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.jails = jails
	e.specs = specsMap
	e.mu.Unlock()
	e.log.Info("configuration loaded", "jails", len(jails), "configDirs", e.dirs, "database", e.global.DBFile)
	return nil
}

func (e *Engine) buildJails(specs []config.JailSpec, snapshots map[string]ban.Snapshot) (map[string]*jail.Jail, map[string]config.JailSpec, error) {
	jails := make(map[string]*jail.Jail)
	specsMap := make(map[string]config.JailSpec)
	for _, spec := range specs {
		specsMap[spec.Name] = spec
		if !spec.Enabled && !completeJail(spec) {
			e.log.Debug("skipping incomplete disabled jail", "jail", spec.Name)
			continue
		}
		var snap *ban.Snapshot
		if s, ok := snapshots[spec.Name]; ok {
			cp := s
			snap = &cp
		}
		j, err := e.buildJail(spec, snap)
		if err != nil {
			if spec.Enabled {
				return nil, nil, fmt.Errorf("jail [%s]: %w", spec.Name, err)
			}
			e.log.Warn("skipping invalid disabled jail", "jail", spec.Name, "error", err)
			continue
		}
		jails[spec.Name] = j
	}
	return jails, specsMap, nil
}

func completeJail(spec config.JailSpec) bool {
	return spec.Filter != "" && len(spec.LogPaths) > 0 && len(spec.ActionRefs) > 0
}

func (e *Engine) buildJail(spec config.JailSpec, snapshot *ban.Snapshot) (*jail.Jail, error) {
	switch spec.Backend {
	case "", "auto", "polling":
		spec.Backend = "polling"
	default:
		return nil, fmt.Errorf("backend %q is not supported (use auto or polling)", spec.Backend)
	}
	filterExtra := map[string]string{"__name__": spec.Name}
	for k, v := range spec.FilterParams {
		filterExtra[k] = v
	}
	fs, err := config.LoadFilter(spec.Filter, e.dirs, filterExtra)
	if err != nil {
		return nil, err
	}
	if fs.Mode != "" {
		spec.FilterMode = fs.Mode
	}
	if spec.MaxLines <= 0 {
		spec.MaxLines = fs.MaxLines
	}
	if spec.DatePattern == "" {
		spec.DatePattern = fs.DatePattern
	}
	if spec.IgnoreCommand == "" {
		spec.IgnoreCommand = fs.IgnoreCommand
	}
	usedns := spec.UsedNS
	if !spec.UsedNSExplicit && fs.UsedNS != "" {
		usedns = fs.UsedNS
	}
	if usedns == "" {
		usedns = "warn"
	}
	spec.UsedNS = usedns

	f, err := filter.Compile(filter.Options{
		Name:        spec.Filter,
		FailRegex:   fs.FailRegex,
		IgnoreRegex: fs.IgnoreRegex,
		PreRegex:    fs.PreRegex,
		DatePattern: spec.DatePattern,
		MaxLines:    spec.MaxLines,
		UsedNS:      usedns,
	})
	if err != nil {
		return nil, fmt.Errorf("filter %s: %w", spec.Filter, err)
	}
	for _, w := range f.Warnings() {
		e.log.Warn("filter warning", "jail", spec.Name, "warning", w)
	}

	actions := make([]*action.Action, 0, len(spec.ActionRefs))
	for _, ref := range spec.ActionRefs {
		as, err := config.LoadAction(ref, e.dirs)
		if err != nil {
			return nil, err
		}
		actions = append(actions, action.New(spec.Name, as, e.log))
	}

	tracker, err := ban.New(ban.Options{
		MaxRetry:         spec.MaxRetry,
		FindTime:         spec.FindTime,
		BanTime:          spec.BanTime,
		IgnoreIP:         spec.IgnoreIP,
		BanTimeIncrement: spec.BanTimeIncrement,
		BanTimeFactor:    spec.BanTimeFactor,
		BanTimeMax:       spec.BanTimeMax,
		BanTimeRnd:       spec.BanTimeRnd,
		DBPurgeAge:       e.global.DBPurgeAge,
		MaxLines:         spec.MaxLines,
		Now:              time.Now,
	})
	if err != nil {
		return nil, err
	}
	if snapshot != nil {
		tracker.Restore(*snapshot)
	}
	j := jail.New(spec, f, tracker, actions, e.log, e.save)
	return j, nil
}

// Start acquires the pidfile and socket and starts all enabled jails.
func (e *Engine) Start() error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if e.listener != nil {
		return fmt.Errorf("engine already started")
	}
	if e.store == nil {
		return fmt.Errorf("engine was not built")
	}
	e.startedAt = time.Now()
	if err := e.acquirePID(); err != nil {
		return err
	}
	ln, err := e.listenUnix()
	if err != nil {
		e.releasePID()
		return err
	}
	e.listener = ln
	e.acceptWG.Add(1)
	go e.acceptLoop()

	e.mu.RLock()
	names := make([]string, 0, len(e.jails))
	for name := range e.jails {
		names = append(names, name)
	}
	e.mu.RUnlock()
	sort.Strings(names)
	var started []*jail.Jail
	for _, name := range names {
		e.mu.RLock()
		j := e.jails[name]
		spec := e.specs[name]
		e.mu.RUnlock()
		if j == nil || !spec.Enabled {
			continue
		}
		if err := j.Start(context.Background()); err != nil {
			for i := len(started) - 1; i >= 0; i-- {
				_ = started[i].Stop(context.Background())
			}
			e.closeListener()
			e.releasePID()
			return fmt.Errorf("start jail %s: %w", name, err)
		}
		started = append(started, j)
		e.log.Info("jail started", "jail", name, "filter", spec.Filter, "files", spec.LogPaths)
	}
	e.save()
	e.startSaveLoop()
	e.log.Info("gojail started", "version", Version, "socket", e.global.Socket, "jails", len(started))
	return nil
}

func (e *Engine) startSaveLoop() {
	e.saveStop = make(chan struct{})
	e.saveDone = make(chan struct{})
	go func() {
		defer close(e.saveDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-e.saveStop:
				return
			case <-ticker.C:
				e.save()
			}
		}
	}()
}

func (e *Engine) stopSaveLoop() {
	if e.saveStop == nil {
		return
	}
	select {
	case <-e.saveStop:
	default:
		close(e.saveStop)
	}
	if e.saveDone != nil {
		<-e.saveDone
	}
	e.saveStop = nil
	e.saveDone = nil
}

// Reload compiles the new configuration while the old jails keep running, then
// swaps and restarts them.
func (e *Engine) Reload() error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if e.shuttingDown.Load() {
		return fmt.Errorf("engine is shutting down")
	}

	specs, err := config.LoadJails(e.dirs, e.global.PollInterval)
	if err != nil {
		return err
	}
	e.mu.RLock()
	oldJails := make(map[string]*jail.Jail, len(e.jails))
	for name, j := range e.jails {
		oldJails[name] = j
	}
	e.mu.RUnlock()

	// Build the replacement jails without restoring state yet, so a config
	// error leaves the running jails untouched.
	newJails, specsMap, err := e.buildJails(specs, nil)
	if err != nil {
		return fmt.Errorf("reload: %w", err)
	}

	// Stop the old jails first, then take their final snapshots. This keeps
	// bans and failures that happened while the new configuration was being
	// compiled.
	for name, j := range oldJails {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := j.Stop(ctx); err != nil {
			e.log.Error("stop jail during reload", "jail", name, "error", err)
		}
		cancel()
	}
	now := time.Now()
	for name, j := range newJails {
		if old, ok := oldJails[name]; ok {
			j.Tracker().Restore(old.Tracker().Snapshot(now))
		} else if snap, ok := e.initial.Jails[name]; ok {
			j.Tracker().Restore(snap)
		}
	}
	e.mu.Lock()
	e.jails = newJails
	e.specs = specsMap
	e.mu.Unlock()

	var errs []error
	names := make([]string, 0, len(newJails))
	for name := range newJails {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !specsMap[name].Enabled {
			continue
		}
		if err := newJails[name].Start(context.Background()); err != nil {
			errs = append(errs, fmt.Errorf("start jail %s: %w", name, err))
			continue
		}
		e.log.Info("jail started after reload", "jail", name)
	}
	e.save()
	e.log.Info("configuration reloaded", "jails", len(newJails))
	return errors.Join(errs...)
}

// Stop shuts down all jails, persists state and releases the socket/pidfile.
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		e.opMu.Lock()
		defer e.opMu.Unlock()
		e.shuttingDown.Store(true)
		e.log.Info("stopping")
		e.stopSaveLoop()
		e.closeListener()
		e.connMu.Lock()
		for c := range e.conns {
			_ = c.Close()
		}
		e.connMu.Unlock()
		e.acceptWG.Wait()
		e.connWG.Wait()

		e.mu.RLock()
		jails := make([]*jail.Jail, 0, len(e.jails))
		for _, j := range e.jails {
			jails = append(jails, j)
		}
		e.mu.RUnlock()
		sort.Slice(jails, func(i, j int) bool { return jails[i].Name() < jails[j].Name() })
		for _, j := range jails {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := j.Stop(ctx); err != nil {
				e.log.Error("stop jail", "jail", j.Name(), "error", err)
			}
			cancel()
		}
		e.save()
		e.releasePID()
		e.connMu.Lock()
		for c := range e.conns {
			_ = c.Close()
		}
		e.connMu.Unlock()
		close(e.stopped)
		e.log.Info("stopped")
	})
}

// Wait blocks until Stop has completed.
func (e *Engine) Wait() { <-e.stopped }

func (e *Engine) acquirePID() error {
	path := e.global.PIDFile
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create pidfile directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("open pidfile %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		data, _ := io.ReadAll(f)
		_ = f.Close()
		return fmt.Errorf("pidfile %s is locked (another instance running? pid=%s)", path, strings.TrimSpace(string(data)))
	}
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := fmt.Fprintf(f, "%d\n", os.Getpid()); err != nil {
		_ = f.Close()
		return err
	}
	_ = f.Sync()
	e.pidFile = f
	e.pidPath = path
	return nil
}

func (e *Engine) releasePID() {
	if e.pidFile == nil {
		return
	}
	_ = syscall.Flock(int(e.pidFile.Fd()), syscall.LOCK_UN)
	_ = e.pidFile.Close()
	_ = os.Remove(e.pidPath)
	e.pidFile = nil
}

func (e *Engine) listenUnix() (net.Listener, error) {
	path := e.global.Socket
	if path == "" {
		return nil, fmt.Errorf("socket path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("socket path %s exists and is not a unix socket", path)
		}
		if conn, derr := net.DialTimeout("unix", path, 300*time.Millisecond); derr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("another gojail instance is listening on %s", path)
		} else if errors.Is(derr, syscall.EACCES) || errors.Is(derr, syscall.EPERM) {
			return nil, fmt.Errorf("socket %s exists but cannot be accessed: %w", path, derr)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	mode := e.global.SocketMode
	if mode == 0 {
		mode = 0o660
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	e.socketPath = path
	e.socketOwned = true
	return ln, nil
}

func (e *Engine) closeListener() {
	if e.listener != nil {
		_ = e.listener.Close()
		e.listener = nil
	}
	if e.socketOwned {
		_ = os.Remove(e.socketPath)
		e.socketOwned = false
	}
}

func (e *Engine) acceptLoop() {
	defer e.acceptWG.Done()
	ln := e.listener
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e.shuttingDown.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			e.log.Error("socket accept", "error", err)
			return
		}
		e.connMu.Lock()
		e.conns[conn] = struct{}{}
		e.connMu.Unlock()
		e.connWG.Add(1)
		go e.handleConn(conn)
	}
}

func (e *Engine) handleConn(conn net.Conn) {
	defer e.connWG.Done()
	defer func() {
		e.connMu.Lock()
		delete(e.conns, conn)
		e.connMu.Unlock()
		_ = conn.Close()
		if r := recover(); r != nil {
			e.log.Error("control connection panic", "panic", r)
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	dec := json.NewDecoder(io.LimitReader(conn, 1<<20))
	enc := json.NewEncoder(conn)
	for {
		var req api.Request
		if err := dec.Decode(&req); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				e.log.Debug("control decode", "error", err)
			}
			return
		}
		data, err := e.handle(req)
		resp := api.Response{OK: err == nil}
		if err != nil {
			resp.Error = err.Error()
		} else if data != nil {
			raw, merr := json.Marshal(data)
			if merr != nil {
				resp.OK = false
				resp.Error = fmt.Sprintf("encode response: %v", merr)
			} else {
				resp.Data = raw
			}
		}
		if err := enc.Encode(&resp); err != nil {
			return
		}
	}
}

func (e *Engine) handle(req api.Request) (any, error) {
	cmd := strings.ToLower(strings.TrimSpace(req.Cmd))
	switch cmd {
	case "ping":
		return api.Pong{Pong: true}, nil
	case "version":
		return api.Value{Value: Version}, nil
	case "status", "jail.status":
		if req.Jail != "" {
			j, err := e.getJail(req.Jail)
			if err != nil {
				return nil, err
			}
			return j.Status(), nil
		}
		if cmd == "jail.status" {
			return nil, fmt.Errorf("jail name is required")
		}
		return e.serverStatus(), nil
	case "jail.start", "jail.stop", "jail.restart":
		j, err := e.getJail(req.Jail)
		if err != nil {
			return nil, err
		}
		switch cmd {
		case "jail.start":
			if j.Started() {
				return nil, fmt.Errorf("jail %s is already started", req.Jail)
			}
			if err := j.Start(context.Background()); err != nil {
				return nil, err
			}
			return api.Message{Message: "jail " + req.Jail + " started"}, nil
		case "jail.stop":
			if !j.Started() {
				return nil, fmt.Errorf("jail %s is already stopped", req.Jail)
			}
			if err := j.Stop(context.Background()); err != nil {
				return nil, err
			}
			return api.Message{Message: "jail " + req.Jail + " stopped"}, nil
		default:
			if j.Started() {
				if err := j.Stop(context.Background()); err != nil {
					return nil, err
				}
			}
			if err := j.Start(context.Background()); err != nil {
				return nil, err
			}
			return api.Message{Message: "jail " + req.Jail + " restarted"}, nil
		}
	case "jail.banip":
		j, err := e.getJail(req.Jail)
		if err != nil {
			return nil, err
		}
		if len(req.Args) < 1 {
			return nil, fmt.Errorf("banip requires an IP")
		}
		b, err := j.BanIP(req.Args[0])
		if err != nil {
			return nil, err
		}
		return b, nil
	case "jail.unbanip":
		j, err := e.getJail(req.Jail)
		if err != nil {
			return nil, err
		}
		if len(req.Args) < 1 {
			return nil, fmt.Errorf("unbanip requires an IP")
		}
		if err := j.UnbanIP(req.Args[0]); err != nil {
			return nil, err
		}
		return api.Message{Message: fmt.Sprintf("unbanned %s from %s", req.Args[0], req.Jail)}, nil
	case "jail.banned":
		j, err := e.getJail(req.Jail)
		if err != nil {
			return nil, err
		}
		return j.Status().Banned, nil
	case "jail.failures":
		j, err := e.getJail(req.Jail)
		if err != nil {
			return nil, err
		}
		return j.Failures(), nil
	case "jail.flush":
		j, err := e.getJail(req.Jail)
		if err != nil {
			return nil, err
		}
		n, err := j.Flush()
		if err != nil {
			return nil, err
		}
		return api.Message{Message: fmt.Sprintf("flushed %d bans from %s", n, req.Jail)}, nil
	case "jail.get":
		j, err := e.getJail(req.Jail)
		if err != nil {
			return nil, err
		}
		if len(req.Args) < 1 {
			return nil, fmt.Errorf("get requires an option name")
		}
		v, err := j.Get(req.Args[0])
		if err != nil {
			return nil, err
		}
		return api.Value{Value: v}, nil
	case "jail.set":
		j, err := e.getJail(req.Jail)
		if err != nil {
			return nil, err
		}
		if len(req.Args) < 2 {
			return nil, fmt.Errorf("set requires an option name and value")
		}
		if err := j.Set(req.Args[0], strings.Join(req.Args[1:], " ")); err != nil {
			return nil, err
		}
		return api.Message{Message: fmt.Sprintf("%s.%s updated", req.Jail, req.Args[0])}, nil
	case "reload":
		if err := e.Reload(); err != nil {
			return nil, err
		}
		return api.Message{Message: "reloaded"}, nil
	case "stop":
		time.AfterFunc(100*time.Millisecond, e.Stop)
		return api.Message{Message: "stopping"}, nil
	default:
		return nil, fmt.Errorf("unknown command %q", req.Cmd)
	}
}

func (e *Engine) getJail(name string) (*jail.Jail, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("jail name is required")
	}
	e.mu.RLock()
	j := e.jails[name]
	e.mu.RUnlock()
	if j == nil {
		return nil, fmt.Errorf("jail %q is not configured or not enabled", name)
	}
	return j, nil
}

func (e *Engine) serverStatus() api.ServerStatus {
	e.mu.RLock()
	names := make([]string, 0, len(e.jails))
	for name := range e.jails {
		names = append(names, name)
	}
	e.mu.RUnlock()
	sort.Strings(names)
	return api.ServerStatus{
		Version:    Version,
		PID:        os.Getpid(),
		Uptime:     int64(time.Since(e.startedAt) / time.Second),
		Jails:      names,
		JailCount:  len(names),
		Socket:     e.global.Socket,
		ConfigDirs: append([]string(nil), e.dirs...),
	}
}

func (e *Engine) save() {
	if e.store == nil {
		return
	}
	e.saveMu.Lock()
	defer e.saveMu.Unlock()
	e.mu.RLock()
	jails := make(map[string]*jail.Jail, len(e.jails))
	for name, j := range e.jails {
		jails[name] = j
	}
	e.mu.RUnlock()
	now := time.Now()
	states := make(map[string]ban.Snapshot, len(jails))
	for name, j := range jails {
		states[name] = j.Tracker().Snapshot(now)
	}
	if err := e.store.Save(states); err != nil {
		e.log.Error("save database", "error", err)
	}
}

// LoadGlobalForCLI is a convenience wrapper used by gj.
func LoadGlobalForCLI(dirs []string) (*config.Global, error) {
	return config.LoadGlobal(dirs)
}
