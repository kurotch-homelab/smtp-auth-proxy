package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/legal"
)

func runLicenses(_ context.Context, args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("licenses", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("licenses takes no arguments")
	}
	_, err := stdout.WriteString(legal.Notices)
	return err
}
