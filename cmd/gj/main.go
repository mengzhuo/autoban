package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mengzhuo/gojail/internal/api"
	"github.com/mengzhuo/gojail/internal/config"
	"github.com/mengzhuo/gojail/internal/engine"
)

func main() {
	var (
		configFlag = flag.String("config", "", "comma-separated configuration directories")
		socketFlag = flag.String("socket", "", "control socket path")
		timeout    = flag.Duration("timeout", 30*time.Second, "control socket timeout")
		jsonOut    = flag.Bool("json", false, "print raw JSON")
		version    = flag.Bool("version", false, "print client version")
	)
	flag.Usage = usage
	flag.Parse()

	if *version {
		fmt.Printf("gj %s\n", engine.Version)
		return
	}
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	socket := *socketFlag
	if socket == "" {
		socket = resolveSocket(*configFlag)
	}
	client := api.NewClient(socket)
	client.Timeout = *timeout

	if err := run(client, args, *jsonOut); err != nil {
		fmt.Fprintf(os.Stderr, "gj: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: gj [options] <command> [args]

Commands:
  status [jail]              show server or jail status
  banned <jail>              list banned IPs
  failures <jail>            list hosts with failures
  start <jail>               start a jail
  stop [jail]                stop a jail, or the whole server
  restart <jail>             restart a jail
  banip <jail> <ip>          ban an IP manually
  unbanip <jail> <ip>        unban an IP
  flush <jail>               remove all bans in a jail
  get <jail> <option>        read a runtime option
  set <jail> <option> <val>  change a runtime option
  reload                     reload configuration
  ping                       check that the server is alive
  version                    show server version

Options:
`)
	flag.PrintDefaults()
}

func resolveSocket(configFlag string) string {
	dirs := config.DefaultConfigDirs()
	if strings.TrimSpace(configFlag) != "" {
		dirs = nil
		for _, p := range strings.Split(configFlag, ",") {
			if p = strings.TrimSpace(p); p != "" {
				dirs = append(dirs, p)
			}
		}
	}
	if g, err := config.LoadGlobal(dirs); err == nil && g.Socket != "" {
		return g.Socket
	}
	return "/run/gojail/gojail.sock"
}

func run(c *api.Client, args []string, jsonOut bool) error {
	cmd := strings.ToLower(args[0])
	rest := args[1:]
	switch cmd {
	case "ping":
		var out api.Pong
		if err := c.Do(api.Request{Cmd: "ping"}, &out); err != nil {
			return err
		}
		if jsonOut {
			return printJSON(out)
		}
		fmt.Println("pong")
		return nil
	case "version":
		var out api.Value
		if err := c.Do(api.Request{Cmd: "version"}, &out); err != nil {
			return err
		}
		if jsonOut {
			return printJSON(out)
		}
		fmt.Printf("gojail %s\n", out.Value)
		return nil
	case "status":
		if len(rest) > 0 {
			var out api.JailStatus
			if err := c.Do(api.Request{Cmd: "status", Jail: rest[0]}, &out); err != nil {
				return err
			}
			if jsonOut {
				return printJSON(out)
			}
			printJailStatus(out)
			return nil
		}
		var out api.ServerStatus
		if err := c.Do(api.Request{Cmd: "status"}, &out); err != nil {
			return err
		}
		if jsonOut {
			return printJSON(out)
		}
		printServerStatus(out)
		return nil
	case "banned":
		if len(rest) < 1 {
			return fmt.Errorf("banned requires a jail name")
		}
		var out []api.BanInfo
		if err := c.Do(api.Request{Cmd: "jail.banned", Jail: rest[0]}, &out); err != nil {
			return err
		}
		if jsonOut {
			return printJSON(out)
		}
		printBanned(out)
		return nil
	case "failures":
		if len(rest) < 1 {
			return fmt.Errorf("failures requires a jail name")
		}
		var out []api.FailureInfo
		if err := c.Do(api.Request{Cmd: "jail.failures", Jail: rest[0]}, &out); err != nil {
			return err
		}
		if jsonOut {
			return printJSON(out)
		}
		printFailures(out)
		return nil
	case "start":
		if len(rest) < 1 {
			return fmt.Errorf("start requires a jail name")
		}
		return message(c, api.Request{Cmd: "jail.start", Jail: rest[0]}, jsonOut)
	case "stop":
		if len(rest) > 0 {
			return message(c, api.Request{Cmd: "jail.stop", Jail: rest[0]}, jsonOut)
		}
		return message(c, api.Request{Cmd: "stop"}, jsonOut)
	case "restart":
		if len(rest) < 1 {
			return fmt.Errorf("restart requires a jail name")
		}
		return message(c, api.Request{Cmd: "jail.restart", Jail: rest[0]}, jsonOut)
	case "banip":
		if len(rest) < 2 {
			return fmt.Errorf("banip requires a jail and an IP")
		}
		var out api.BanInfo
		if err := c.Do(api.Request{Cmd: "jail.banip", Jail: rest[0], Args: []string{rest[1]}}, &out); err != nil {
			return err
		}
		if jsonOut {
			return printJSON(out)
		}
		fmt.Printf("Banned %s in %s until %s\n", out.IP, rest[0], formatUntil(out))
		return nil
	case "unbanip":
		if len(rest) < 2 {
			return fmt.Errorf("unbanip requires a jail and an IP")
		}
		return message(c, api.Request{Cmd: "jail.unbanip", Jail: rest[0], Args: []string{rest[1]}}, jsonOut)
	case "flush":
		if len(rest) < 1 {
			return fmt.Errorf("flush requires a jail name")
		}
		return message(c, api.Request{Cmd: "jail.flush", Jail: rest[0]}, jsonOut)
	case "get":
		if len(rest) < 2 {
			return fmt.Errorf("get requires a jail and an option")
		}
		var out api.Value
		if err := c.Do(api.Request{Cmd: "jail.get", Jail: rest[0], Args: []string{rest[1]}}, &out); err != nil {
			return err
		}
		if jsonOut {
			return printJSON(out)
		}
		fmt.Println(out.Value)
		return nil
	case "set":
		if len(rest) < 3 {
			return fmt.Errorf("set requires a jail, an option and a value")
		}
		return message(c, api.Request{Cmd: "jail.set", Jail: rest[0], Args: append([]string{rest[1]}, rest[2:]...)}, jsonOut)
	case "reload":
		return message(c, api.Request{Cmd: "reload"}, jsonOut)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func message(c *api.Client, req api.Request, jsonOut bool) error {
	var out api.Message
	if err := c.Do(req, &out); err != nil {
		return err
	}
	if jsonOut {
		return printJSON(out)
	}
	fmt.Println(out.Message)
	return nil
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func printServerStatus(st api.ServerStatus) {
	fmt.Println("Status")
	fmt.Printf("|- Version: %s\n", st.Version)
	fmt.Printf("|- Number of jail: %d\n", st.JailCount)
	if len(st.Jails) == 0 {
		fmt.Println("`- Jail list:")
		return
	}
	fmt.Printf("`- Jail list: %s\n", strings.Join(st.Jails, ", "))
}

func printJailStatus(st api.JailStatus) {
	suffix := ""
	if !st.Started {
		suffix = " (stopped)"
	}
	fmt.Printf("Status for the jail: %s%s\n", st.Name, suffix)
	fmt.Println("|- Filter")
	fmt.Printf("|  |- Currently failed: %d\n", st.CurrentlyFailed)
	fmt.Printf("|  |- Total failed: %d\n", st.TotalFailed)
	if len(st.FilterWarnings) > 0 {
		fmt.Printf("|  |- Warnings: %s\n", strings.Join(st.FilterWarnings, "; "))
	}
	fmt.Printf("|  `- File list: %s\n", strings.Join(st.Files, ", "))
	fmt.Println("`- Actions")
	fmt.Printf("   |- Currently banned: %d\n", st.CurrentlyBanned)
	fmt.Printf("   |- Total banned: %d\n", st.TotalBanned)
	if len(st.BannedIPs) == 0 {
		fmt.Println("   `- Banned IP list:")
	} else {
		fmt.Printf("   `- Banned IP list: %s\n", strings.Join(st.BannedIPs, " "))
	}
	fmt.Println()
	fmt.Printf("Configuration: filter=%s backend=%s maxretry=%d findtime=%s bantime=%s usedns=%s\n",
		st.Filter, st.Backend, st.MaxRetry, time.Duration(st.FindTime)*time.Second, banTimeString(st.BanTime), st.UsedNS)
	fmt.Printf("Ignore IP: %s\n", strings.Join(st.IgnoreIP, " "))
	fmt.Printf("Actions: %s\n", strings.Join(st.Actions, ", "))
}

func printBanned(bans []api.BanInfo) {
	if len(bans) == 0 {
		fmt.Println("No banned IPs")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tBANNED AT\tEXPIRES\tBANTIME\tFAILURES\tCOUNT")
	for _, b := range bans {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\n",
			b.IP, formatTime(b.Start), formatUntil(b), banTimeString(b.Duration), b.Failures, b.BanCount)
	}
	_ = w.Flush()
}

func printFailures(fs []api.FailureInfo) {
	if len(fs) == 0 {
		fmt.Println("No failures")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tFAILURES\tFIRST SEEN\tLAST SEEN")
	for _, f := range fs {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", f.IP, f.Count, formatTime(f.FirstSeen), formatTime(f.LastSeen))
	}
	_ = w.Flush()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func formatUntil(b api.BanInfo) string {
	if b.Until.IsZero() || b.Duration < 0 {
		return "permanent"
	}
	return formatTime(b.Until)
}

func banTimeString(seconds int64) string {
	if seconds < 0 {
		return "permanent"
	}
	return (time.Duration(seconds) * time.Second).String()
}
