// Command smtp-auth-proxy accepts SMTP-AUTH submissions from LAN services and
// relays them through Microsoft 365 using OAuth 2.0 (XOAUTH2 or Graph).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/version"
)

func main() {
	// os.Exit skips deferred calls, so the real work lives in a function that
	// returns a status code and can unwind its signal handler cleanly.
	os.Exit(realMain())
}

func realMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "smtp-auth-proxy: %v\n", err)
		return 1
	}
	return 0
}

// command is one CLI subcommand. Keeping them in a table means `usage` and the
// dispatch below can never drift apart.
type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdout, stderr *os.File) error
}

func commands() []command {
	return []command{
		{"serve", "Run the SMTP proxy and admin API", runServe},
		{"adduser", "Create an administrator for the management interface", runAddUser},
		{"genkey", "Generate an encryption key for secrets at rest", runGenkey},
		{"passwd", "Hash an SMTP account password (generates one if omitted)", runPasswd},
		{"healthcheck", "Probe the running proxy's readiness endpoint", runHealthcheck},
		{"version", "Print build information", runVersion},
	}
}

func run(ctx context.Context, args []string, stdout, stderr *os.File) error {
	if len(args) == 0 {
		usage(stderr)
		return errors.New("no subcommand given")
	}

	name := args[0]
	if name == "-h" || name == "--help" || name == "help" {
		usage(stdout)
		return nil
	}

	for _, c := range commands() {
		if c.name == name {
			return c.run(ctx, args[1:], stdout, stderr)
		}
	}

	usage(stderr)
	return fmt.Errorf("unknown subcommand %q", name)
}

func usage(w *os.File) {
	fmt.Fprintf(w, "smtp-auth-proxy %s\n\n", version.Get().Version)
	fmt.Fprint(w, "Usage:\n  smtp-auth-proxy <command> [flags]\n\nCommands:\n")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, "\nRun 'smtp-auth-proxy <command> -h' for command flags.\n")
}

func runVersion(_ context.Context, args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Fprintln(stdout, version.Get())
	return nil
}
