package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// runHealthcheck probes the proxy's own readiness endpoint.
//
// It exists because the runtime image is distroless: there is no shell and no
// curl, so the container's HEALTHCHECK has to be the binary itself.
func runHealthcheck(ctx context.Context, args []string, _, stderr *os.File) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", "http://127.0.0.1:8080/readyz", "readiness endpoint to probe")
	timeout := fs.Duration("timeout", 5*time.Second, "how long to wait")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, http.NoBody)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("the proxy is not answering: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the proxy reports %s", resp.Status)
	}
	return nil
}
