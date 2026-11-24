package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mengzhuo/autoban/internal/config"
	"github.com/mengzhuo/autoban/internal/engine"
	"github.com/mengzhuo/autoban/internal/logging"
)

func main() {
	var (
		configFlag = flag.String("config", "", "comma-separated configuration directories (default: ./config or /etc/autoban)")
		socket     = flag.String("socket", "", "override control socket path")
		pidfile    = flag.String("pidfile", "", "override pidfile path")
		dbfile     = flag.String("dbfile", "", "override database path (empty disables persistence)")
		logtarget  = flag.String("logtarget", "", "override log target: STDOUT, STDERR, SYSLOG or a file path")
		loglevel   = flag.String("loglevel", "", "override log level: DEBUG, INFO, WARN, ERROR")
		validate   = flag.Bool("test", false, "validate configuration and exit")
		version    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Printf("autoban %s\n", engine.Version)
		return
	}
	dirs := resolveConfigDirs(*configFlag)
	for _, dir := range dirs {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			fmt.Fprintf(os.Stderr, "autoban: configuration directory %q is not accessible\n", dir)
			os.Exit(1)
		}
	}
	global, err := config.LoadGlobal(dirs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "autoban: %v\n", err)
		os.Exit(1)
	}
	if *socket != "" {
		global.Socket = *socket
	}
	if *pidfile != "" {
		global.PIDFile = *pidfile
	}
	if *dbfile != "" {
		global.DBFile = *dbfile
	}
	if *logtarget != "" {
		global.LogTarget = *logtarget
	}
	if *loglevel != "" {
		global.LogLevel = *loglevel
	}

	logger, cleanup, err := logging.Setup(global.LogLevel, global.LogTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "autoban: logging setup failed: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()

	e := engine.New(dirs, global, logger)
	if err := e.Build(); err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}
	if *validate {
		fmt.Println("configuration OK")
		return
	}
	if err := e.Start(); err != nil {
		logger.Error("startup failed", "error", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	done := make(chan struct{})
	go func() {
		e.Wait()
		close(done)
	}()

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				logger.Info("reload requested")
				if err := e.Reload(); err != nil {
					logger.Error("reload failed", "error", err)
				}
			default:
				logger.Info("signal received, shutting down", "signal", sig.String())
				e.Stop()
				<-done
				return
			}
		case <-done:
			return
		}
	}
}

func resolveConfigDirs(flagValue string) []string {
	if strings.TrimSpace(flagValue) != "" {
		var out []string
		for _, p := range strings.Split(flagValue, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return config.DefaultConfigDirs()
}
