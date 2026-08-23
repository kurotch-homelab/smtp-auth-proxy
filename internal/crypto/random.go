package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// passwordEntropyBytes is the entropy behind a generated SMTP password. 24
// bytes is 192 bits, which is far beyond brute-forceable and still short
// enough to paste into a printer's web form.
const passwordEntropyBytes = 24

// tokenEntropyBytes backs session identifiers and CSRF tokens.
const tokenEntropyBytes = 32

// GeneratePassword returns a URL-safe random password for a new SMTP account.
// Devices vary wildly in what characters they accept in a password field, so
// this deliberately sticks to the base64url alphabet rather than mixing in
// punctuation.
func GeneratePassword() (string, error) {
	return randomString(passwordEntropyBytes)
}

// GenerateToken returns a random opaque token for a session or CSRF cookie.
func GenerateToken() (string, error) {
	return randomString(tokenEntropyBytes)
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto: read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ConstantTimeEqual compares two secrets without leaking their contents through
// timing. Use it for session tokens and CSRF tokens, never `==`.
//
// It compares lengths in variable time, which is intentional and harmless: the
// values it guards are fixed-length.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
