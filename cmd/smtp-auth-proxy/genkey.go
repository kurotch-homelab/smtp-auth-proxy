package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
)

func runGenkey(_ context.Context, args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("genkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "k1", "identifier for the key, recorded in every value it seals")
	quiet := fs.Bool("quiet", false, "print only the key specification")
	if err := fs.Parse(args); err != nil {
		return err
	}

	spec, err := appcrypto.GenerateKey(*id)
	if err != nil {
		return err
	}

	if *quiet {
		fmt.Fprintln(stdout, spec)
		return nil
	}

	fmt.Fprintf(stdout, `%s

Store this where the proxy can read it, and nowhere else — it decrypts every
OAuth client secret, certificate key and TOTP seed in the database. Losing it
means those values cannot be recovered; leaking it means they are not protected.

Docker Compose (.env):
  SMTP_AUTH_PROXY_ENCRYPTION_KEY=%s

Kubernetes:
  kubectl create secret generic smtp-auth-proxy-encryption \
    --from-literal=key='%s'

To rotate, generate a new key and list it first in encryption.keys, keeping the
old one after it so values sealed with it stay readable.
`, spec, spec, spec)
	return nil
}
