package filter

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// dateParser parses the timestamp from a log line. It supports a subset of
// fail2ban's datepattern (strptime) syntax plus built-in detection of common
// syslog, ISO-8601, nginx and Apache formats.
type dateParser struct {
	parts []datePart
}

type datePart struct {
	re      *regexp.Regexp
	layouts []string
	epoch   bool
	hasYear bool
	hasDate bool
}

func newDateParser(pattern string) (*dateParser, []string, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, nil, fmt.Errorf("empty datepattern")
	}
	// fail2ban's special prefix tokens.
	replacer := strings.NewReplacer(
		"{^LN-BEG}", "^",
		"{^L-BEG}", "^",
		"{^LINE_BEG}", "^",
	)
	pattern = replacer.Replace(pattern)

	alternatives := splitDateAlternatives(pattern)
	var parts []datePart
	var warnings []string
	for _, alt := range alternatives {
		part, err := buildDatePart(alt)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		parts = append(parts, *part)
	}
	if len(parts) == 0 {
		return nil, warnings, fmt.Errorf("unsupported datepattern %q", pattern)
	}
	return &dateParser{parts: parts}, warnings, nil
}

func splitDateAlternatives(pattern string) []string {
	var out []string
	var b strings.Builder
	depth := 0
	for _, r := range pattern {
		switch r {
		case '(':
			depth++
			b.WriteRune(r)
		case ')':
			if depth > 0 {
				depth--
			}
			b.WriteRune(r)
		case '|':
			if depth == 0 {
				out = append(out, b.String())
				b.Reset()
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	out = append(out, b.String())
	return out
}

func buildDatePart(pattern string) (*datePart, error) {
	pattern = strings.TrimSpace(pattern)
	anchored := false
	if strings.HasPrefix(pattern, "^") {
		anchored = true
		pattern = pattern[1:]
	}
	var re strings.Builder
	if anchored {
		re.WriteString("^")
	}
	layouts := []string{""}
	part := &datePart{}

	addLayouts := func(suffixes ...string) {
		if len(suffixes) == 0 {
			return
		}
		next := make([]string, 0, len(layouts)*len(suffixes))
		for _, l := range layouts {
			for _, s := range suffixes {
				next = append(next, l+s)
			}
		}
		layouts = next
	}

	seenDirective := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c != '%' {
			re.WriteString(regexp.QuoteMeta(string(c)))
			continue
		}
		i++
		if i >= len(pattern) {
			return nil, fmt.Errorf("datepattern ends with %%")
		}
		if pattern[i] == '%' {
			re.WriteString("%")
			layouts = appendSuffix(layouts, "%")
			continue
		}
		unpadded := false
		if pattern[i] == '-' {
			unpadded = true
			i++
			if i >= len(pattern) {
				return nil, fmt.Errorf("datepattern ends with %%-")
			}
		}
		seenDirective = true
		switch pattern[i] {
		case 'Y':
			re.WriteString(`\d{4}`)
			addLayouts("2006")
			part.hasYear = true
			part.hasDate = true
		case 'y':
			re.WriteString(`\d{2}`)
			addLayouts("06")
			part.hasYear = true
			part.hasDate = true
		case 'm':
			if unpadded {
				re.WriteString(`\d{1,2}`)
				addLayouts("1")
			} else {
				re.WriteString(`\d{1,2}`)
				addLayouts("1")
			}
			part.hasDate = true
		case 'd':
			re.WriteString(`\d{1,2}`)
			addLayouts("2")
			part.hasDate = true
		case 'e':
			re.WriteString(`[ ]?\d{1,2}`)
			addLayouts("2", "_2")
			part.hasDate = true
		case 'H':
			re.WriteString(`\d{1,2}`)
			addLayouts("15")
		case 'I':
			re.WriteString(`\d{1,2}`)
			addLayouts("03")
		case 'M':
			re.WriteString(`\d{1,2}`)
			addLayouts("04")
		case 'S':
			re.WriteString(`\d{1,2}`)
			addLayouts("05")
		case 'f':
			re.WriteString(`(?:[.,]\d{1,9})?`)
			addLayouts(".999999999")
		case 'z':
			re.WriteString(`(?:Z|[+-]\d{2}:?\d{2})`)
			addLayouts("-0700", "-07:00", "Z07:00")
		case 'Z':
			re.WriteString(`[A-Za-z][A-Za-z0-9_+-]{1,5}`)
			addLayouts("MST")
		case 'b':
			re.WriteString(`[A-Za-z]{3}`)
			addLayouts("Jan")
			part.hasDate = true
		case 'B':
			re.WriteString(`[A-Za-z]+`)
			addLayouts("January")
			part.hasDate = true
		case 'a':
			re.WriteString(`[A-Za-z]{3}`)
			addLayouts("Mon")
		case 'A':
			re.WriteString(`[A-Za-z]+`)
			addLayouts("Monday")
		case 'p':
			re.WriteString(`[APap][Mm]`)
			addLayouts("PM")
		case 'j':
			re.WriteString(`\d{3}`)
			addLayouts("002")
			part.hasDate = true
		case 's':
			re.WriteString(`\d{9,13}`)
			part.epoch = true
		case 'n', 't':
			re.WriteString(`\s+`)
			addLayouts(" ")
		default:
			return nil, fmt.Errorf("unsupported datepattern directive %%%c", pattern[i])
		}
	}
	if !seenDirective {
		return nil, fmt.Errorf("datepattern %q contains no conversion directives", pattern)
	}
	if part.epoch && len(part.layouts) == 0 {
		part.layouts = []string{}
	} else {
		part.layouts = layouts
	}
	compiled, err := regexp.Compile(re.String())
	if err != nil {
		return nil, fmt.Errorf("invalid datepattern regex: %w", err)
	}
	part.re = compiled
	return part, nil
}

func appendSuffix(layouts []string, suffix string) []string {
	out := make([]string, len(layouts))
	for i, l := range layouts {
		out[i] = l + suffix
	}
	return out
}

// parseLogTime returns the timestamp of line. If no timestamp can be parsed,
// the bool is false (the caller should use the current time).
func parseLogTime(line string, parser *dateParser, now time.Time) (time.Time, bool) {
	if parser != nil {
		for _, part := range parser.parts {
			loc := part.re.FindStringSubmatchIndex(line)
			if loc == nil {
				continue
			}
			text := line[loc[0]:loc[1]]
			if t, ok := part.parse(text, now); ok {
				return t, true
			}
		}
	}
	return parseBuiltinTime(line, now)
}

func (p *datePart) parse(text string, now time.Time) (time.Time, bool) {
	text = strings.TrimSpace(strings.Trim(text, "[]"))
	if p.epoch {
		n, err := strconv.ParseInt(text, 10, 64)
		if err == nil {
			if len(text) >= 13 {
				n /= 1000
			}
			return time.Unix(n, 0), true
		}
	}
	variants := []string{text}
	normalized := strings.Join(strings.Fields(text), " ")
	if normalized != text {
		variants = append(variants, normalized)
	}
	for _, layout := range p.layouts {
		for _, v := range variants {
			t, ok := parseWithLayout(layout, v, p.hasYear, p.hasDate, now)
			if ok {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

func parseWithLayout(layout, text string, hasYear, hasDate bool, now time.Time) (time.Time, bool) {
	text = strings.ReplaceAll(text, ",", ".")
	t, err := time.ParseInLocation(layout, text, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	if !hasDate {
		t = time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
		if t.After(now.Add(time.Minute)) {
			t = t.AddDate(0, 0, -1)
		}
		return t, true
	}
	if !hasYear {
		t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
		if t.After(now.Add(24 * time.Hour)) {
			t = time.Date(now.Year()-1, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
		}
	}
	return t, true
}

type builtinDate struct {
	re      *regexp.Regexp
	layouts []string
	hasYear bool
	hasDate bool
	epoch   bool
}

var builtinDates = []builtinDate{
	{
		re: regexp.MustCompile(`^\s*\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)`),
		layouts: []string{
			"2006-01-02T15:04:05.999999999Z07:00",
			"2006-01-02T15:04:05.999999999-0700",
			"2006-01-02T15:04:05.999999999",
			"2006-01-02 15:04:05.999999999Z07:00",
			"2006-01-02 15:04:05.999999999-0700",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02T15:04:05-0700",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05Z07:00",
			"2006-01-02 15:04:05-0700",
			"2006-01-02 15:04:05",
		},
		hasYear: true,
		hasDate: true,
	},
	{
		re:      regexp.MustCompile(`^\s*\[?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)`),
		layouts: []string{"Jan 2 15:04:05.999999", "Jan 2 15:04:05"},
		hasDate: true,
	},
	{
		re:      regexp.MustCompile(`^\s*\[?(\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)`),
		layouts: []string{"2/Jan/2006:15:04:05 -0700", "2/Jan/2006:15:04:05"},
		hasYear: true,
		hasDate: true,
	},
	{
		re:      regexp.MustCompile(`^\s*\[?(\d{4}/\d{1,2}/\d{1,2}\s+\d{1,2}:\d{2}:\d{2})`),
		layouts: []string{"2006/1/2 15:04:05"},
		hasYear: true,
		hasDate: true,
	},
	{
		re:      regexp.MustCompile(`^\s*\[?(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2})`),
		layouts: []string{"1/2/2006 15:04:05"},
		hasYear: true,
		hasDate: true,
	},
	{
		re:      regexp.MustCompile(`^\s*\[?(\d{1,2}\.\d{1,2}\.\d{4}\s+\d{1,2}:\d{2}:\d{2})`),
		layouts: []string{"2.1.2006 15:04:05"},
		hasYear: true,
		hasDate: true,
	},
	{
		re:      regexp.MustCompile(`^\s*(\d{10})(?:\s|$)`),
		layouts: nil,
		epoch:   true,
	},
	{
		re:      regexp.MustCompile(`^\s*(\d{13})(?:\s|$)`),
		layouts: nil,
		epoch:   true,
	},
}

func parseBuiltinTime(line string, now time.Time) (time.Time, bool) {
	for _, b := range builtinDates {
		loc := b.re.FindStringSubmatchIndex(line)
		if loc == nil || loc[2] < 0 {
			continue
		}
		text := strings.TrimSpace(strings.Trim(line[loc[2]:loc[3]], "[]"))
		if b.epoch {
			n, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				continue
			}
			if len(text) >= 13 {
				n /= 1000
			}
			return time.Unix(n, 0), true
		}
		variants := []string{text}
		if normalized := strings.Join(strings.Fields(text), " "); normalized != text {
			variants = append(variants, normalized)
		}
		for _, layout := range b.layouts {
			for _, v := range variants {
				if t, ok := parseWithLayout(layout, v, b.hasYear, b.hasDate, now); ok {
					return t, true
				}
			}
		}
	}
	return time.Time{}, false
}
