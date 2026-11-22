// gj-regex is an offline filter tester, modelled after fail2ban-regex.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mengzhuo/gojail/internal/config"
	"github.com/mengzhuo/gojail/internal/filter"
)

func main() {
	var (
		configFlag = flag.String("config", "", "comma-separated configuration directories")
		usedns     = flag.String("usedns", "", "override usedns: yes, no, warn or raw")
		datepat    = flag.String("datepattern", "", "override datepattern")
		verbose    = flag.Bool("v", false, "print every matched line")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: gj-regex [options] <logfile|-> <filter|failregex>\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(2)
	}
	logPath, filterArg := flag.Arg(0), flag.Arg(1)
	dirs := config.DefaultConfigDirs()
	if strings.TrimSpace(*configFlag) != "" {
		dirs = nil
		for _, p := range strings.Split(*configFlag, ",") {
			if p = strings.TrimSpace(p); p != "" {
				dirs = append(dirs, p)
			}
		}
	}

	fs, err := config.LoadFilter(filterArg, dirs, nil)
	if err != nil {
		if !looksLikeRegex(filterArg) {
			fatal(err)
		}
		fs = &config.FilterSpec{Name: "inline", FailRegex: []string{filterArg}, MaxLines: 1}
	}
	policy := fs.UsedNS
	if *usedns != "" {
		policy = *usedns
	}
	if policy == "" {
		policy = "no"
	}
	pattern := fs.DatePattern
	if *datepat != "" {
		pattern = *datepat
	}
	f, err := filter.Compile(filter.Options{
		Name:        fs.Name,
		FailRegex:   fs.FailRegex,
		IgnoreRegex: fs.IgnoreRegex,
		PreRegex:    fs.PreRegex,
		DatePattern: pattern,
		MaxLines:    fs.MaxLines,
		UsedNS:      policy,
	})
	if err != nil {
		fatal(err)
	}

	var in *os.File
	if logPath == "-" {
		in = os.Stdin
	} else {
		in, err = os.Open(logPath)
		if err != nil {
			fatal(err)
		}
		defer func() { _ = in.Close() }()
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	total, matched := 0, 0
	var ignored int64
	hosts := make(map[string]int)
	now := time.Now()
	for scanner.Scan() {
		total++
		line := scanner.Text()
		m, ok := f.Match(line, now)
		if !ok {
			continue
		}
		matched++
		hosts[m.Host]++
		if *verbose {
			fmt.Printf("%s\t%s\t%s\n", m.Time.Local().Format("2006-01-02 15:04:05"), m.Host, line)
		}
	}
	if err := scanner.Err(); err != nil {
		fatal(err)
	}
	_, ignored = f.Stats()

	fmt.Printf("Lines: %d\n", total)
	fmt.Printf("Matched: %d\n", matched)
	fmt.Printf("Ignored (ignoreregex): %d\n", ignored)
	fmt.Printf("Unmatched: %d\n", int64(total)-int64(matched)-ignored)
	fmt.Printf("Hosts: %d\n", len(hosts))
	ips := make([]string, 0, len(hosts))
	for ip := range hosts {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		if hosts[ips[i]] == hosts[ips[j]] {
			return ips[i] < ips[j]
		}
		return hosts[ips[i]] > hosts[ips[j]]
	})
	for _, ip := range ips {
		fmt.Printf("  %-40s %d\n", ip, hosts[ip])
	}
	for _, w := range f.Warnings() {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	if matched == 0 {
		os.Exit(1)
	}
}

func looksLikeRegex(s string) bool {
	return strings.Contains(s, "<HOST>") || strings.ContainsAny(s, "^$[]()+*?\\|")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gj-regex: %v\n", err)
	os.Exit(1)
}
