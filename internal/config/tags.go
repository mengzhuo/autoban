package config

import (
	"fmt"
	"regexp"
	"strings"
)

var filterTagRE = regexp.MustCompile(`<([A-Za-z0-9_./-]+)>`)

// ExpandTags expands fail2ban-style configuration tags in a filter value:
//
//	<mode>            -> normal
//	<mdre-<mode>>     -> <mdre-normal> -> value of mdre-normal
//
// Tags that do not name a config option (for example <HOST>, <F-USER>) are
// left untouched so they can be handled by the regex/filter engine.
func (c *Config) ExpandTags(value, section string, extra map[string]string) (string, error) {
	return c.expandTags(value, section, extra, map[string]bool{})
}

func (c *Config) expandTags(value, section string, extra map[string]string, stack map[string]bool) (string, error) {
	for depth := 0; depth < 32; depth++ {
		locs := filterTagRE.FindAllStringSubmatchIndex(value, -1)
		if len(locs) == 0 {
			return value, nil
		}
		var b strings.Builder
		last := 0
		changed := false
		for _, loc := range locs {
			b.WriteString(value[last:loc[0]])
			name := value[loc[2]:loc[3]]
			resolved, ok, err := c.tagValue(section, name, extra, stack)
			if err != nil {
				return "", err
			}
			if ok {
				b.WriteString(resolved)
				changed = true
			} else {
				b.WriteString(value[loc[0]:loc[1]])
			}
			last = loc[1]
		}
		b.WriteString(value[last:])
		value = b.String()
		if !changed {
			return value, nil
		}
	}
	return "", fmt.Errorf("too many nested filter tags")
}

func (c *Config) tagValue(section, name string, extra map[string]string, stack map[string]bool) (string, bool, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if v, ok := extra[key]; ok {
		stackKey := "extra/" + key
		if stack[stackKey] {
			return "", false, fmt.Errorf("filter tag cycle at <%s>", name)
		}
		stack[stackKey] = true
		defer delete(stack, stackKey)
		v, err := c.expandTags(v, section, extra, stack)
		return v, true, err
	}

	sources := []string{section}
	if section != "Init" {
		sources = append(sources, "Init")
	}
	for _, src := range sources {
		_, found := c.Raw(src, key)
		if !found {
			continue
		}
		stackKey := src + "/" + key
		if stack[stackKey] {
			return "", false, fmt.Errorf("filter tag cycle at <%s>", name)
		}
		stack[stackKey] = true
		v, err := c.Resolve(src, key, extra)
		if err == nil {
			v, err = c.expandTags(v, section, extra, stack)
		}
		delete(stack, stackKey)
		if err != nil {
			return "", false, err
		}
		return v, true, nil
	}
	return "", false, nil
}
