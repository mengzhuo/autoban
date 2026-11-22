// Package config implements the fail2ban-like configuration format:
// INI files with [DEFAULT] inheritance, %(option)s interpolation,
// multi-line values and [INCLUDES] before/after directives.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Section is a single INI section. Option names are stored lower-case,
// matching Python's ConfigParser behaviour. Values are kept raw; use
// Config.Resolve to expand %(option)s references.
type Section struct {
	Name   string
	values map[string]string
	keys   []string
}

func (s *Section) set(key, value string) {
	key = strings.ToLower(strings.TrimSpace(key))
	if _, ok := s.values[key]; !ok {
		s.keys = append(s.keys, key)
	}
	s.values[key] = value
}

// Config is an ordered collection of INI sections.
type Config struct {
	sections map[string]*Section
	order    []string
	files    []string
}

// New returns an empty configuration.
func New() *Config {
	return &Config{sections: make(map[string]*Section)}
}

// Files returns the absolute paths loaded into this configuration.
func (c *Config) Files() []string {
	out := make([]string, len(c.files))
	copy(out, c.files)
	return out
}

// HasSection reports whether a section exists (case-sensitive, except DEFAULT).
func (c *Config) HasSection(name string) bool {
	_, ok := c.sections[name]
	return ok
}

// SectionNames returns section names in declaration order.
func (c *Config) SectionNames() []string {
	out := make([]string, 0, len(c.order))
	for _, name := range c.order {
		if name == "INCLUDES" {
			continue
		}
		out = append(out, name)
	}
	return out
}

// Raw returns an unexpanded option value from the named section or DEFAULT.
func (c *Config) Raw(section, key string) (string, bool) {
	if sec := c.sections[section]; sec != nil {
		if v, ok := sec.values[strings.ToLower(key)]; ok {
			return v, true
		}
	}
	if section != "DEFAULT" {
		if sec := c.sections["DEFAULT"]; sec != nil {
			if v, ok := sec.values[strings.ToLower(key)]; ok {
				return v, true
			}
		}
	}
	return "", false
}

// RawSection returns a copy of the raw options in a section (without inheriting
// DEFAULT). The second return value reports whether the section exists.
func (c *Config) RawSection(name string) (map[string]string, bool) {
	sec := c.sections[name]
	if sec == nil {
		return nil, false
	}
	out := make(map[string]string, len(sec.values))
	for k, v := range sec.values {
		out[k] = v
	}
	return out, true
}

// RawKeys returns the option names declared in a section, in file order.
func (c *Config) RawKeys(name string) []string {
	sec := c.sections[name]
	if sec == nil {
		return nil
	}
	out := make([]string, len(sec.keys))
	copy(out, sec.keys)
	return out
}

// Resolve expands %(option)s references in section/key. References are looked
// up in extra first, then in the requested section, then in [DEFAULT]. A
// missing reference or a reference cycle is returned as an error.
func (c *Config) Resolve(section, key string, extra map[string]string) (string, error) {
	k := strings.ToLower(strings.TrimSpace(key))
	raw, origin, ok := c.lookup(section, k)
	if !ok {
		return "", fmt.Errorf("option %q not found in [%s]", key, section)
	}
	stack := map[string]bool{}
	return c.resolveValue(raw, section, origin, k, extra, stack)
}

// ResolveAll resolves every option declared in a section.
func (c *Config) ResolveAll(section string, extra map[string]string) (map[string]string, error) {
	sec := c.sections[section]
	out := make(map[string]string)
	if sec == nil {
		return out, nil
	}
	for _, key := range sec.keys {
		v, err := c.Resolve(section, key, extra)
		if err != nil {
			return nil, err
		}
		out[key] = v
	}
	return out, nil
}

func (c *Config) lookup(section, key string) (string, string, bool) {
	if sec := c.sections[section]; sec != nil {
		if v, ok := sec.values[key]; ok {
			return v, section, true
		}
	}
	if section != "DEFAULT" {
		if sec := c.sections["DEFAULT"]; sec != nil {
			if v, ok := sec.values[key]; ok {
				return v, "DEFAULT", true
			}
		}
	}
	return "", "", false
}

func (c *Config) resolveValue(raw, section, origin, key string, extra map[string]string, stack map[string]bool) (string, error) {
	stackKey := origin + "/" + key
	if stack[stackKey] {
		return "", fmt.Errorf("interpolation cycle while resolving [%s] %s", origin, key)
	}
	stack[stackKey] = true
	defer delete(stack, stackKey)

	var b strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] != '%' {
			b.WriteByte(raw[i])
			i++
			continue
		}
		// %% is an escaped percent sign.
		if i+1 < len(raw) && raw[i+1] == '%' {
			b.WriteByte('%')
			i += 2
			continue
		}
		// %(name)s interpolation.
		if i+1 < len(raw) && raw[i+1] == '(' {
			rest := raw[i+2:]
			end := strings.Index(rest, ")s")
			if end < 0 {
				// Not a valid interpolation; keep it literal.
				b.WriteString(raw[i:])
				break
			}
			name := strings.ToLower(strings.TrimSpace(rest[:end]))
			val, err := c.resolveRef(section, name, extra, stack)
			if err != nil {
				return "", fmt.Errorf("[%s] %s: %w", origin, key, err)
			}
			b.WriteString(val)
			i += 2 + end + 2
			continue
		}
		b.WriteByte(raw[i])
		i++
	}
	return b.String(), nil
}

func (c *Config) resolveRef(section, name string, extra map[string]string, stack map[string]bool) (string, error) {
	if extra != nil {
		if v, ok := extra[name]; ok {
			return c.resolveValue(v, section, "extra", name, extra, stack)
		}
	}
	raw, origin, ok := c.lookup(section, name)
	if !ok {
		return "", fmt.Errorf("interpolation refers to undefined option %q", name)
	}
	return c.resolveValue(raw, section, origin, name, extra, stack)
}

// SectionMap returns resolved values for a section, without failing on
// unresolved interpolation: errors are returned for the first bad option.
func (c *Config) SectionMap(section string, extra map[string]string) (map[string]string, error) {
	return c.ResolveAll(section, extra)
}

// LoadFile parses path and merges it into c, processing [INCLUDES] before/after
// directives relative to the including file.
func (c *Config) LoadFile(path string) error {
	return c.loadFile(path, nil)
}

// LoadOptional loads a file if it exists. The bool reports whether it was read.
func (c *Config) LoadOptional(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, c.LoadFile(path)
}

func (c *Config) loadFile(path string, stack []string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for _, p := range stack {
		if p == abs {
			return fmt.Errorf("include cycle detected at %s", abs)
		}
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return err
	}
	parsed, err := parseINI(string(data))
	if err != nil {
		return fmt.Errorf("%s: %w", abs, err)
	}
	stack = append(stack, abs)

	if inc := parsed.sections["INCLUDES"]; inc != nil {
		before := inc.values["before"]
		if err := c.loadIncludes(before, filepath.Dir(abs), stack); err != nil {
			return fmt.Errorf("%s: before includes: %w", abs, err)
		}
	}

	for _, name := range parsed.order {
		if name == "INCLUDES" {
			continue
		}
		c.mergeSection(parsed.sections[name])
	}
	c.files = append(c.files, abs)

	if inc := parsed.sections["INCLUDES"]; inc != nil {
		after := inc.values["after"]
		if err := c.loadIncludes(after, filepath.Dir(abs), stack); err != nil {
			return fmt.Errorf("%s: after includes: %w", abs, err)
		}
	}
	return nil
}

func (c *Config) loadIncludes(value, baseDir string, stack []string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	for _, pattern := range strings.Fields(value) {
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(baseDir, pattern)
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("invalid include pattern %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			return fmt.Errorf("include %q matched no files", pattern)
		}
		sort.Strings(matches)
		for _, match := range matches {
			if err := c.loadFile(match, stack); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Config) mergeSection(src *Section) {
	if src == nil {
		return
	}
	dst := c.sections[src.Name]
	if dst == nil {
		dst = &Section{Name: src.Name, values: make(map[string]string)}
		c.sections[src.Name] = dst
		c.order = append(c.order, src.Name)
	}
	for _, k := range src.keys {
		dst.set(k, src.values[k])
	}
}

// Merge copies all sections from other into c. Values in other win.
func (c *Config) Merge(other *Config) {
	for _, name := range other.order {
		c.mergeSection(other.sections[name])
	}
	c.files = append(c.files, other.files...)
}

func (c *Config) ensureSection(name string) *Section {
	sec := c.sections[name]
	if sec == nil {
		sec = &Section{Name: name, values: make(map[string]string)}
		c.sections[name] = sec
		c.order = append(c.order, name)
	}
	return sec
}

func parseINI(text string) (*Config, error) {
	c := New()
	current := "DEFAULT"
	lastKey := ""

	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for lineNo, rawLine := range lines {
		line := strings.TrimSuffix(rawLine, "\r")
		if lineNo == 0 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			lastKey = ""
			continue
		}
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			if !strings.HasSuffix(trimmed, "]") {
				return nil, fmt.Errorf("line %d: malformed section header %q", lineNo+1, trimmed)
			}
			name := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			if name == "" {
				return nil, fmt.Errorf("line %d: empty section name", lineNo+1)
			}
			c.ensureSection(name)
			current = name
			lastKey = ""
			continue
		}
		indented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
		if indented && lastKey != "" {
			sec := c.sections[current]
			sec.values[lastKey] = sec.values[lastKey] + "\n" + strippedContinuation(line)
			continue
		}
		sep := -1
		for i, ch := range line {
			if ch == '=' || ch == ':' {
				sep = i
				break
			}
		}
		if sep <= 0 {
			return nil, fmt.Errorf("line %d: expected key=value, got %q", lineNo+1, trimmed)
		}
		key := strings.ToLower(strings.TrimSpace(line[:sep]))
		if key == "" {
			return nil, fmt.Errorf("line %d: empty option name", lineNo+1)
		}
		value := strings.TrimSpace(line[sep+1:])
		c.ensureSection(current).set(key, value)
		lastKey = key
	}
	return c, nil
}

func strippedContinuation(line string) string {
	// ConfigParser strips indentation from continuation lines. This matters
	// for failregex values, whose leading ^ must stay at the start of the
	// value, not after a tab.
	return strings.TrimSpace(line)
}
