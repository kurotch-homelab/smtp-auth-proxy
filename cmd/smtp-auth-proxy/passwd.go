package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
)

func runPasswd(_ context.Context, args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	password := fs.String("password", "", "password to hash; generated when omitted")
	if err := fs.Parse(args); err != nil {
		return err
	}

	value := *password
	generated := value == ""
	if generated {
		var err error
		// Devices vary in what they accept in a password field, so a generated
		// one sticks to the base64url alphabet.
		if value, err = appcrypto.GeneratePassword(); err != nil {
			return err
		}
	}

	hash, err := appcrypto.HashPassword(value)
	if err != nil {
		return err
	}

	if generated {
		fmt.Fprintf(stdout, "password: %s\n", value)
	}
	fmt.Fprintf(stdout, "hash:     %s\n", hash)
	return nil
}
