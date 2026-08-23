package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// runAddUser creates an administrator directly in the database.
//
// A fresh deployment has nobody who can sign in, and there is deliberately no
// default account with a known password — that is how appliances end up on the
// internet with admin/admin.
func runAddUser(ctx context.Context, args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("adduser", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "config.yaml", "path to the configuration file")
	username := fs.String("username", "", "username to create")
	email := fs.String("email", "", "email address, for display only")
	role := fs.String("role", "admin", "role: admin, operator or viewer")
	password := fs.String("password", "", "password; one is generated when omitted")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *username == "" {
		return errors.New("--username is required")
	}
	parsedRole, err := adminauth.ParseRole(*role)
	if err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	chosen := *password
	generated := chosen == ""
	if generated {
		if chosen, err = appcrypto.GeneratePassword(); err != nil {
			return err
		}
	}
	hash, err := appcrypto.HashPassword(chosen)
	if err != nil {
		return err
	}

	db, err := store.Open(ctx, store.Options{
		Driver:       cfg.Database.Driver,
		DSN:          cfg.Database.DSN,
		MaxOpenConns: cfg.Database.MaxOpenConns,
	})
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	// The schema has to exist before a user can be inserted into it, and this
	// command is usually the very first thing run against a new database.
	if _, err := db.Migrate(ctx); err != nil {
		return err
	}

	user := &store.AdminUser{
		Username:     *username,
		Email:        *email,
		PasswordHash: store.NullString(hash),
		Role:         parsedRole,
		Source:       store.SourceLocal,
	}
	if err := db.Users().Create(ctx, user); err != nil {
		return err
	}

	if err := db.Audit().Append(ctx, &store.AuditEntry{
		ActorType:  store.ActorSystem,
		ActorName:  "smtp-auth-proxy adduser",
		Action:     "user.create",
		TargetType: "user",
		TargetID:   user.ID,
		TargetName: user.Username,
		Details:    store.MaskSecrets(map[string]any{"role": string(parsedRole)}),
	}); err != nil {
		fmt.Fprintf(stderr, "warning: the user was created but not recorded in the audit log: %v\n", err)
	}

	fmt.Fprintf(stdout, "created %s with the role %s\n", user.Username, parsedRole)
	if generated {
		fmt.Fprintf(stdout, "password: %s\n\nThis is the only time it is shown.\n", chosen)
	}
	return nil
}
