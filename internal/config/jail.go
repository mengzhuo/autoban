package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Global holds settings from gojail.conf/local that affect the daemon.
type Global struct {
	LogLevel     string
	LogTarget    string
	Socket       string
	SocketMode   os.FileMode
	PIDFile      string
	DBFile       string
	DBPurgeAge   time.Duration
	PollInterval time.Duration
	ConfigDirs   []string
}

// ActionRef is one entry of a jail's action option, e.g.
//
//	iptables-multiport[name=sshd, port="ssh,http"]
type ActionRef struct {
	Name   string
	Params map[string]string
}

// JailSpec is a fully resolved jail configuration.
type JailSpec struct {
	Name             string
	Enabled          bool
	Filter           string
	LogPaths         []string
	Backend          string
	MaxRetry         int
	FindTime         time.Duration
	BanTime          time.Duration
	IgnoreIP         []string
	UsedNS           string
	UsedNSExplicit   bool
	IgnoreCommand    string
	MaxLines         int
	BanTimeIncrement bool
	BanTimeFactor    float64
	BanTimeMax       time.Duration
	BanTimeRnd       time.Duration
	PollInterval     time.Duration
	ActionRefs       []ActionRef
	DatePattern      string
}

// FilterSpec is a resolved filter.d configuration.
type FilterSpec struct {
	Name          string
	FailRegex     []string
	IgnoreRegex   []string
	PreRegex      string
	DatePattern   string
	MaxLines      int
	UsedNS        string
	IgnoreCommand string
	Init          map[string]string
}

// ActionSpec is a resolved action.d configuration with all interpolation and
// action-reference parameters applied.
type ActionSpec struct {
	Name    string
	Params  map[string]string
	Check   string
	Start   string
	Stop    string
	Ban     string
	Unban   string
	Flush   string
	Reload  string
	Timeout time.Duration
}

const (
	defaultMaxRetry  = 5
	defaultFindTime  = 10 * time.Minute
	defaultBantime   = 10 * time.Minute
	defaultSocket    = "/run/gojail/gojail.sock"
	defaultPIDFile   = "/run/gojail/gojail.pid"
	defaultDBFile    = "/var/lib/gojail/gojail.db"
	defaultLogTarget = "STDERR"
)

// DefaultConfigDirs returns the conventional configuration locations.
// gojail.conf is preferred; fail2ban.conf is accepted as a legacy fallback
// so an existing fail2ban-style tree can be reused during migration.
func DefaultConfigDirs() []string {
	for _, file := range []string{"config/gojail.conf", "config/fail2ban.conf"} {
		if _, err := os.Stat(file); err == nil {
			return []string{"config"}
		}
	}
	for _, dir := range []string{"/etc/gojail"} {
		if _, err := os.Stat(dir); err == nil {
			return []string{dir}
		}
	}
	return []string{"/etc/gojail"}
}

// LoadGlobal loads gojail.conf and gojail.local from all config dirs. If no
// gojail config exists, fail2ban.conf/fail2ban.local are loaded as a legacy
// fallback.
func LoadGlobal(dirs []string) (*Global, error) {
	c := New()
	found := false
	for _, dir := range dirs {
		for _, name := range []string{"gojail.conf", "gojail.local"} {
			ok, err := c.LoadOptional(filepath.Join(dir, name))
			if err != nil {
				return nil, err
			}
			found = found || ok
		}
	}
	if !found {
		for _, dir := range dirs {
			for _, name := range []string{"fail2ban.conf", "fail2ban.local"} {
				ok, err := c.LoadOptional(filepath.Join(dir, name))
				if err != nil {
					return nil, err
				}
				found = found || ok
			}
		}
	}
	g := &Global{
		LogLevel:     "INFO",
		LogTarget:    defaultLogTarget,
		Socket:       defaultSocket,
		SocketMode:   0o660,
		PIDFile:      defaultPIDFile,
		DBFile:       defaultDBFile,
		DBPurgeAge:   24 * time.Hour,
		PollInterval: time.Second,
		ConfigDirs:   append([]string(nil), dirs...),
	}
	if !found {
		return g, nil
	}

	const sec = "Definition"
	strOpt := func(key string, dst *string) error {
		v, ok, err := resolveOptional(c, sec, key, nil)
		if err != nil {
			return err
		}
		if ok {
			*dst = v
		}
		return nil
	}
	if err := strOpt("loglevel", &g.LogLevel); err != nil {
		return nil, err
	}
	if err := strOpt("logtarget", &g.LogTarget); err != nil {
		return nil, err
	}
	if err := strOpt("socket", &g.Socket); err != nil {
		return nil, err
	}
	if err := strOpt("pidfile", &g.PIDFile); err != nil {
		return nil, err
	}
	if err := strOpt("dbfile", &g.DBFile); err != nil {
		return nil, err
	}
	if v, ok, err := resolveOptional(c, sec, "socketmode", nil); err != nil {
		return nil, err
	} else if ok && strings.TrimSpace(v) != "" {
		mode, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(v), "0o"), 8, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid socketmode %q: %w", v, err)
		}
		g.SocketMode = os.FileMode(mode)
	}
	if v, ok, err := resolveOptional(c, sec, "dbpurgeage", nil); err != nil {
		return nil, err
	} else if ok && strings.TrimSpace(v) != "" {
		d, err := ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid dbpurgeage: %w", err)
		}
		g.DBPurgeAge = d
	}
	if v, ok, err := resolveOptional(c, sec, "pollinterval", nil); err != nil {
		return nil, err
	} else if ok && strings.TrimSpace(v) != "" {
		d, err := ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid pollinterval: %w", err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("pollinterval must be positive")
		}
		g.PollInterval = d
	}
	g.LogLevel = strings.ToUpper(strings.TrimSpace(g.LogLevel))
	g.LogTarget = strings.TrimSpace(g.LogTarget)
	g.Socket = strings.TrimSpace(g.Socket)
	g.PIDFile = strings.TrimSpace(g.PIDFile)
	g.DBFile = strings.TrimSpace(g.DBFile)
	return g, nil
}

// LoadJails loads jail.conf and jail.local from all config dirs.
func LoadJails(dirs []string, pollDefault time.Duration) ([]JailSpec, error) {
	c := New()
	for _, dir := range dirs {
		for _, name := range []string{"jail.conf", "jail.local"} {
			if _, err := c.LoadOptional(filepath.Join(dir, name)); err != nil {
				return nil, err
			}
		}
	}
	if pollDefault <= 0 {
		pollDefault = time.Second
	}

	var specs []JailSpec
	for _, section := range c.SectionNames() {
		if section == "DEFAULT" || section == "INCLUDES" {
			continue
		}
		spec, err := resolveJail(c, section, pollDefault)
		if err != nil {
			return nil, fmt.Errorf("jail [%s]: %w", section, err)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func resolveJail(c *Config, name string, pollDefault time.Duration) (JailSpec, error) {
	extra := map[string]string{"__name__": name}
	spec := JailSpec{
		Name:          name,
		Backend:       "auto",
		MaxRetry:      defaultMaxRetry,
		FindTime:      defaultFindTime,
		BanTime:       defaultBantime,
		IgnoreIP:      []string{"127.0.0.1/8", "::1"},
		UsedNS:        "warn",
		MaxLines:      0,
		BanTimeFactor: 2,
		PollInterval:  pollDefault,
	}
	get := func(key string) (string, bool, error) {
		return resolveOptional(c, name, key, extra)
	}

	if v, ok, err := get("enabled"); err != nil {
		return spec, err
	} else if ok {
		spec.Enabled = parseBool(v, false)
	}
	if v, ok, err := get("filter"); err != nil {
		return spec, err
	} else if ok {
		spec.Filter = strings.TrimSpace(v)
	}
	if v, ok, err := get("logpath"); err != nil {
		return spec, err
	} else if ok {
		spec.LogPaths = splitList(v)
	}
	if v, ok, err := get("backend"); err != nil {
		return spec, err
	} else if ok && strings.TrimSpace(v) != "" {
		spec.Backend = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok, err := get("maxretry"); err != nil {
		return spec, err
	} else if ok && strings.TrimSpace(v) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 {
			return spec, fmt.Errorf("invalid maxretry %q", v)
		}
		spec.MaxRetry = n
	}
	if v, ok, err := get("findtime"); err != nil {
		return spec, err
	} else if ok && strings.TrimSpace(v) != "" {
		d, err := ParseDuration(v)
		if err != nil || d <= 0 {
			return spec, fmt.Errorf("invalid findtime %q", v)
		}
		spec.FindTime = d
	}
	if v, ok, err := get("bantime"); err != nil {
		return spec, err
	} else if ok && strings.TrimSpace(v) != "" {
		d, err := ParseDuration(v)
		if err != nil || d == 0 {
			return spec, fmt.Errorf("invalid bantime %q", v)
		}
		spec.BanTime = d
	}
	if v, ok, err := get("ignoreip"); err != nil {
		return spec, err
	} else if ok {
		spec.IgnoreIP = splitIgnoreIPs(v)
	}
	if v, ok, err := get("usedns"); err != nil {
		return spec, err
	} else if ok && strings.TrimSpace(v) != "" {
		spec.UsedNS = strings.ToLower(strings.TrimSpace(v))
		spec.UsedNSExplicit = true
	}
	switch spec.UsedNS {
	case "yes", "no", "warn", "raw":
	default:
		return spec, fmt.Errorf("invalid usedns %q (expected yes, no, warn or raw)", spec.UsedNS)
	}
	if v, ok, err := get("ignorecommand"); err != nil {
		return spec, err
	} else if ok {
		spec.IgnoreCommand = v
	}
	if v, ok, err := get("maxlines"); err != nil {
		return spec, err
	} else if ok && strings.TrimSpace(v) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 {
			return spec, fmt.Errorf("invalid maxlines %q", v)
		}
		spec.MaxLines = n
	}
	if v, ok, err := get("bantime.increment"); err != nil {
		return spec, err
	} else if ok {
		spec.BanTimeIncrement = parseBool(v, false)
	}
	if v, ok, err := get("bantime.factor"); err != nil {
		return spec, err
	} else if ok && strings.TrimSpace(v) != "" {
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || f <= 0 {
			return spec, fmt.Errorf("invalid bantime.factor %q", v)
		}
		spec.BanTimeFactor = f
	}
	if v, ok, err := get("bantime.maxtime"); err != nil {
		return spec, err
	} else if ok && strings.TrimSpace(v) != "" {
		d, err := ParseDuration(v)
		if err != nil || d < 0 {
			return spec, fmt.Errorf("invalid bantime.maxtime %q", v)
		}
		spec.BanTimeMax = d
	}
	if v, ok, err := get("bantime.rndtime"); err != nil {
		return spec, err
	} else if ok && strings.TrimSpace(v) != "" {
		d, err := ParseDuration(v)
		if err != nil || d < 0 {
			return spec, fmt.Errorf("invalid bantime.rndtime %q", v)
		}
		spec.BanTimeRnd = d
	}
	if v, ok, err := get("pollinterval"); err != nil {
		return spec, err
	} else if ok && strings.TrimSpace(v) != "" {
		d, err := ParseDuration(v)
		if err != nil || d <= 0 {
			return spec, fmt.Errorf("invalid pollinterval %q", v)
		}
		spec.PollInterval = d
	}
	if v, ok, err := get("datepattern"); err != nil {
		return spec, err
	} else if ok {
		spec.DatePattern = v
	}
	if v, ok, err := get("action"); err != nil {
		return spec, err
	} else if ok {
		refs, err := ParseActionRefs(v)
		if err != nil {
			return spec, fmt.Errorf("action: %w", err)
		}
		spec.ActionRefs = refs
	}
	if spec.Enabled {
		if spec.Filter == "" {
			return spec, fmt.Errorf("enabled jail has no filter")
		}
		if len(spec.LogPaths) == 0 {
			return spec, fmt.Errorf("enabled jail has no logpath")
		}
		if len(spec.ActionRefs) == 0 {
			return spec, fmt.Errorf("enabled jail has no action")
		}
	}
	return spec, nil
}

// LoadFilter loads filter.d/<name>.conf and .local. extra is used for
// interpolation inside [Init] (normally empty).
func LoadFilter(name string, dirs []string, extra map[string]string) (*FilterSpec, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("empty filter name")
	}
	c := New()
	found := false
	loadPath := func(p string) error {
		ok, err := c.LoadOptional(p)
		if err != nil {
			return err
		}
		found = found || ok
		return nil
	}
	if strings.ContainsAny(name, `/\`) || strings.HasSuffix(name, ".conf") || strings.HasSuffix(name, ".local") {
		candidates := []string{name}
		for _, dir := range dirs {
			candidates = append(candidates, filepath.Join(dir, name))
			if !strings.HasSuffix(name, ".conf") && !strings.HasSuffix(name, ".local") {
				candidates = append(candidates, filepath.Join(dir, "filter.d", name+".conf"))
			}
		}
		for _, p := range candidates {
			if err := loadPath(p); err != nil {
				return nil, err
			}
			if found {
				break
			}
		}
	} else {
		for _, dir := range dirs {
			if err := loadPath(filepath.Join(dir, "filter.d", name+".conf")); err != nil {
				return nil, err
			}
			if err := loadPath(filepath.Join(dir, "filter.d", name+".local")); err != nil {
				return nil, err
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("filter %q not found in %s", name, strings.Join(dirs, ", "))
	}

	init, err := c.ResolveAll("Init", extra)
	if err != nil {
		return nil, fmt.Errorf("filter %s [Init]: %w", name, err)
	}
	initExtra := make(map[string]string, len(init)+len(extra))
	for k, v := range init {
		initExtra[k] = v
	}
	for k, v := range extra {
		initExtra[k] = v
	}

	get := func(key string) (string, bool, error) {
		return resolveOptional(c, "Definition", key, initExtra)
	}
	spec := &FilterSpec{
		Name:     name,
		Init:     initExtra,
		MaxLines: 1,
	}
	if v, ok, err := get("failregex"); err != nil {
		return nil, fmt.Errorf("filter %s failregex: %w", name, err)
	} else if ok {
		spec.FailRegex = splitNonEmptyLines(v)
	}
	if len(spec.FailRegex) == 0 {
		return nil, fmt.Errorf("filter %q defines no failregex", name)
	}
	if v, ok, err := get("ignoreregex"); err != nil {
		return nil, fmt.Errorf("filter %s ignoreregex: %w", name, err)
	} else if ok {
		spec.IgnoreRegex = splitNonEmptyLines(v)
	}
	if v, ok, err := get("prefregex"); err != nil {
		return nil, fmt.Errorf("filter %s prefregex: %w", name, err)
	} else if ok {
		spec.PreRegex = strings.TrimSpace(v)
	}
	if v, ok, err := get("datepattern"); err != nil {
		return nil, fmt.Errorf("filter %s datepattern: %w", name, err)
	} else if ok {
		spec.DatePattern = strings.TrimSpace(v)
	}
	if v, ok, err := get("maxlines"); err != nil {
		return nil, fmt.Errorf("filter %s maxlines: %w", name, err)
	} else if ok && strings.TrimSpace(v) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 {
			return nil, fmt.Errorf("filter %s: invalid maxlines %q", name, v)
		}
		spec.MaxLines = n
	}
	if v, ok, err := get("usedns"); err != nil {
		return nil, fmt.Errorf("filter %s usedns: %w", name, err)
	} else if ok && strings.TrimSpace(v) != "" {
		spec.UsedNS = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok, err := get("ignorecommand"); err != nil {
		return nil, fmt.Errorf("filter %s ignorecommand: %w", name, err)
	} else if ok {
		spec.IgnoreCommand = v
	}
	return spec, nil
}

// LoadAction loads action.d/<ref.Name>.conf/.local and resolves it using the
// action reference parameters.
func LoadAction(ref ActionRef, dirs []string) (*ActionSpec, error) {
	name := strings.TrimSpace(ref.Name)
	if name == "" {
		return nil, fmt.Errorf("empty action name")
	}
	c := New()
	found := false
	loadPath := func(p string) error {
		ok, err := c.LoadOptional(p)
		if err != nil {
			return err
		}
		found = found || ok
		return nil
	}
	if strings.ContainsAny(name, `/\`) || strings.HasSuffix(name, ".conf") || strings.HasSuffix(name, ".local") {
		candidates := []string{name}
		for _, dir := range dirs {
			candidates = append(candidates, filepath.Join(dir, name))
			if !strings.HasSuffix(name, ".conf") && !strings.HasSuffix(name, ".local") {
				candidates = append(candidates, filepath.Join(dir, "action.d", name+".conf"))
			}
		}
		for _, p := range candidates {
			if err := loadPath(p); err != nil {
				return nil, err
			}
			if found {
				break
			}
		}
	} else {
		for _, dir := range dirs {
			if err := loadPath(filepath.Join(dir, "action.d", name+".conf")); err != nil {
				return nil, err
			}
			if err := loadPath(filepath.Join(dir, "action.d", name+".local")); err != nil {
				return nil, err
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("action %q not found in %s", name, strings.Join(dirs, ", "))
	}

	init, err := c.ResolveAll("Init", ref.Params)
	if err != nil {
		return nil, fmt.Errorf("action %s [Init]: %w", name, err)
	}
	params := make(map[string]string, len(init)+len(ref.Params))
	for k, v := range init {
		params[k] = v
	}
	for k, v := range ref.Params {
		params[k] = v
	}

	get := func(key string) (string, bool, error) {
		return resolveOptional(c, "Definition", key, params)
	}
	spec := &ActionSpec{
		Name:    name,
		Params:  params,
		Timeout: 30 * time.Second,
	}
	for key, dst := range map[string]*string{
		"actioncheck":  &spec.Check,
		"actionstart":  &spec.Start,
		"actionstop":   &spec.Stop,
		"actionban":    &spec.Ban,
		"actionunban":  &spec.Unban,
		"actionflush":  &spec.Flush,
		"actionreload": &spec.Reload,
	} {
		v, ok, err := get(key)
		if err != nil {
			return nil, fmt.Errorf("action %s %s: %w", name, key, err)
		}
		if ok {
			*dst = strings.TrimSpace(v)
		}
	}
	if strings.TrimSpace(spec.Ban) == "" {
		return nil, fmt.Errorf("action %q defines no actionban", name)
	}
	if v, ok, err := get("timeout"); err != nil {
		return nil, fmt.Errorf("action %s timeout: %w", name, err)
	} else if ok && strings.TrimSpace(v) != "" {
		d, err := ParseDuration(v)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("action %s: invalid timeout %q", name, v)
		}
		spec.Timeout = d
	}
	return spec, nil
}

// ParseActionRefs parses a jail action value into one or more action refs.
// Actions may be separated by newlines or top-level commas. Parameters are
// comma-separated key=value pairs inside [...], with single or double quotes.
func ParseActionRefs(value string) ([]ActionRef, error) {
	var refs []ActionRef
	for _, part := range splitTopLevelActions(value) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ref, err := parseActionRef(part)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func parseActionRef(s string) (ActionRef, error) {
	ref := ActionRef{Params: make(map[string]string)}
	open := strings.IndexByte(s, '[')
	if open < 0 {
		name := strings.TrimSpace(s)
		if name == "" {
			return ref, fmt.Errorf("empty action reference")
		}
		ref.Name = name
		return ref, nil
	}
	closeIdx := strings.LastIndexByte(s, ']')
	if closeIdx < open {
		return ref, fmt.Errorf("malformed action reference %q: missing ]", s)
	}
	if strings.TrimSpace(s[closeIdx+1:]) != "" {
		return ref, fmt.Errorf("malformed action reference %q: trailing text", s)
	}
	ref.Name = strings.TrimSpace(s[:open])
	if ref.Name == "" {
		return ref, fmt.Errorf("malformed action reference %q: empty name", s)
	}
	inner := s[open+1 : closeIdx]
	for _, token := range splitTopLevel(inner, ',') {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		eq := indexUnquoted(token, '=')
		if eq < 0 {
			return ref, fmt.Errorf("action %s: parameter %q has no =", ref.Name, token)
		}
		key := strings.ToLower(strings.TrimSpace(token[:eq]))
		if key == "" {
			return ref, fmt.Errorf("action %s: empty parameter name", ref.Name)
		}
		val, err := unquoteValue(strings.TrimSpace(token[eq+1:]))
		if err != nil {
			return ref, fmt.Errorf("action %s parameter %s: %w", ref.Name, key, err)
		}
		ref.Params[key] = val
	}
	return ref, nil
}

func resolveOptional(c *Config, section, key string, extra map[string]string) (string, bool, error) {
	if _, ok := c.Raw(section, key); !ok {
		return "", false, nil
	}
	v, err := c.Resolve(section, key, extra)
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func parseBool(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "enable", "enabled":
		return true
	case "0", "false", "no", "off", "disable", "disabled":
		return false
	default:
		return def
	}
}

func splitList(v string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(v, "\r", ""), "\n") {
		for _, f := range strings.Fields(line) {
			if f != "" {
				out = append(out, f)
			}
		}
	}
	return out
}

func splitIgnoreIPs(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

func splitNonEmptyLines(v string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(v, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func splitTopLevelActions(v string) []string {
	var parts []string
	var b strings.Builder
	depth := 0
	quote := rune(0)
	escaped := false
	for _, r := range v {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			b.WriteRune(r)
			escaped = true
			continue
		}
		if quote != 0 {
			b.WriteRune(r)
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
			b.WriteRune(r)
		case '[':
			depth++
			b.WriteRune(r)
		case ']':
			if depth > 0 {
				depth--
			}
			b.WriteRune(r)
		case '\n', ',':
			if depth == 0 {
				parts = append(parts, b.String())
				b.Reset()
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	parts = append(parts, b.String())
	return parts
}

func splitTopLevel(v string, sep rune) []string {
	var parts []string
	var b strings.Builder
	depth := 0
	quote := rune(0)
	escaped := false
	for _, r := range v {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			b.WriteRune(r)
			escaped = true
			continue
		}
		if quote != 0 {
			b.WriteRune(r)
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
			b.WriteRune(r)
		case '[', '(':
			depth++
			b.WriteRune(r)
		case ']', ')':
			if depth > 0 {
				depth--
			}
			b.WriteRune(r)
		default:
			if r == sep && depth == 0 {
				parts = append(parts, b.String())
				b.Reset()
			} else {
				b.WriteRune(r)
			}
		}
	}
	parts = append(parts, b.String())
	return parts
}

func indexUnquoted(s string, target rune) int {
	quote := rune(0)
	escaped := false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == target {
			return i
		}
	}
	return -1
}

func unquoteValue(s string) (string, error) {
	if len(s) < 2 {
		return s, nil
	}
	q := s[0]
	if (q != '\'' && q != '"') || s[len(s)-1] != q {
		return s, nil
	}
	inner := s[1 : len(s)-1]
	var b strings.Builder
	escaped := false
	for _, r := range inner {
		if escaped {
			switch r {
			case '\\', '\'', '"':
				b.WriteRune(r)
			default:
				b.WriteRune('\\')
				b.WriteRune(r)
			}
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteRune('\\')
	}
	return b.String(), nil
}
