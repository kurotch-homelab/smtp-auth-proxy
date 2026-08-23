package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/app"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
)

func runServe(ctx context.Context, args []string, _, stderr *os.File) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "config.yaml", "path to the configuration file")
	checkOnly := fs.Bool("check", false, "validate the configuration and exit without starting")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	log := newLogger(cfg.Log, stderr)

	if *checkOnly {
		fmt.Fprintf(stderr, "configuration at %s is valid\n", *configPath)
		for _, w := range cfg.Warnings() {
			fmt.Fprintf(stderr, "warning: %s\n", w)
		}
		return nil
	}

	a, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := a.Close(); err != nil {
			log.Error("could not close the database cleanly", "reason", err)
		}
	}()

	return a.Run(ctx)
}

// newLogger builds the structured logger the whole process shares.
func newLogger(cfg config.Log, out *os.File) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(cfg.Level)}

	var handler slog.Handler
	if strings.EqualFold(cfg.Format, "text") {
		handler = slog.NewTextHandler(out, opts)
	} else {
		handler = slog.NewJSONHandler(out, opts)
	}
	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
