package crypto

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// testKey builds a valid key spec with a deterministic key body.
func testKey(t *testing.T, id string, fill byte) string {
	t.Helper()
	key := make([]byte, keyLen)
	for i := range key {
		key[i] = fill
	}
	return id + ":" + base64.RawURLEncoding.EncodeToString(key)
}

func newTestKeyring(t *testing.T, specs ...string) *Keyring {
	t.Helper()
	kr, err := NewKeyring(specs...)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

func TestNewKeyringRejectsBadSpecs(t *testing.T) {
	t.Parallel()

	short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	good := base64.RawURLEncoding.EncodeToString(make([]byte, keyLen))

	tests := []struct {
		name  string
		specs []string
		want  string
	}{
		{"no keys at all", nil, "no encryption keys"},
		{"missing separator", []string{"justakey"}, "expected <id>:<base64-key>"},
		{"empty id", []string{":" + good}, "key id must be"},
		{"id contains a dot", []string{"a.b:" + good}, "must not contain"},
		{"id contains a colon is read as key", []string{"a:b:" + good}, "not valid base64"},
		{"key too short", []string{"k1:" + short}, "must decode to 32 bytes"},
		{"key not base64", []string{"k1:!!!not-base64!!!"}, "not valid base64"},
		{"duplicate id", []string{testKey(t, "k1", 1), testKey(t, "k1", 2)}, "duplicate key id"},
		{"overlong id", []string{strings.Repeat("x", maxKeyIDLen+1) + ":" + good}, "key id must be"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewKeyring(tt.specs...)
			if err == nil {
				t.Fatalf("NewKeyring(%v) = nil error, want error", tt.specs)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestNewKeyringAcceptsStandardBase64WithPadding(t *testing.T) {
	t.Parallel()

	// `openssl rand -base64 32` emits the standard alphabet with padding; an
	// operator pasting that in should not have to know about base64 variants.
	key := make([]byte, keyLen)
	for i := range key {
		key[i] = byte(i) | 0xC0 // force bytes that encode to '+' and '/'
	}
	spec := "k1:" + base64.StdEncoding.EncodeToString(key)

	if _, err := NewKeyring(spec); err != nil {
		t.Fatalf("NewKeyring with padded standard base64: %v", err)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	kr := newTestKeyring(t, testKey(t, "k1", 1))
	const ctx = "oauth_credentials/client_secret/abc"

	for _, plaintext := range []string{"", "s3cret", strings.Repeat("long", 1000)} {
		sealed, err := kr.EncryptString(plaintext, ctx)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if strings.Contains(sealed, plaintext) && plaintext != "" {
			t.Fatal("sealed value contains the plaintext")
		}

		got, err := kr.DecryptString(sealed, ctx)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if got != plaintext {
			t.Errorf("round trip = %q, want %q", got, plaintext)
		}
	}
}

func TestEncryptIsNonDeterministic(t *testing.T) {
	t.Parallel()

	kr := newTestKeyring(t, testKey(t, "k1", 1))
	a, err := kr.EncryptString("same", "ctx")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := kr.EncryptString("same", "ctx")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// A fresh nonce each time means an observer cannot tell that two rows hold
	// the same secret.
	if a == b {
		t.Error("encrypting the same plaintext twice produced identical ciphertext")
	}
}

func TestDecryptRejectsWrongContext(t *testing.T) {
	t.Parallel()

	kr := newTestKeyring(t, testKey(t, "k1", 1))
	sealed, err := kr.EncryptString("s3cret", "oauth_credentials/client_secret/row-1")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Moving a ciphertext to another row must not decrypt: this is what stops
	// an attacker with UPDATE access from promoting one mailbox's secret onto
	// another mailbox.
	if _, err := kr.Decrypt(sealed, "oauth_credentials/client_secret/row-2"); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("Decrypt with wrong context = %v, want ErrDecryptFailed", err)
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()

	kr := newTestKeyring(t, testKey(t, "k1", 1))
	sealed, err := kr.EncryptString("s3cret", "ctx")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Every byte of the payload must be covered: flipping any one of them has to
	// be caught, whether it lands in the nonce, the ciphertext, the GCM tag, or
	// the unused bits of the final base64 character.
	prefixLen := len(sealedVersion + ".k1.")
	for i := prefixLen; i < len(sealed); i++ {
		b := []byte(sealed)
		orig := b[i]
		// Move to a different character within the base64url alphabet.
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		for _, c := range []byte(alphabet) {
			if c != orig {
				b[i] = c
				break
			}
		}

		if _, err := kr.Decrypt(string(b), "ctx"); err == nil {
			t.Fatalf("Decrypt accepted a ciphertext tampered at index %d (%q -> %q)", i, orig, b[i])
		}
	}
}

func TestDecryptRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	kr := newTestKeyring(t, testKey(t, "k1", 1))
	valid, err := kr.EncryptString("s3cret", "ctx")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, payload, _ := strings.Cut(strings.TrimPrefix(valid, sealedVersion+"."), ".")

	tests := []struct {
		name   string
		sealed string
		want   error
	}{
		{"empty", "", ErrMalformed},
		{"no version", "k1." + payload, ErrMalformed},
		{"wrong version", "v9.k1." + payload, ErrMalformed},
		{"missing payload", "v1.k1", ErrMalformed},
		{"empty payload", "v1.k1.", ErrMalformed},
		{"empty key id", "v1..payload", ErrMalformed},
		{"payload not base64", "v1.k1.!!!", ErrMalformed},
		{"payload shorter than nonce", "v1.k1." + base64.RawURLEncoding.EncodeToString([]byte("ab")), ErrMalformed},
		{"unknown key id", "v1.k9." + payload, ErrUnknownKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := kr.Decrypt(tt.sealed, "ctx")
			if !errors.Is(err, tt.want) {
				t.Errorf("Decrypt(%q) = %v, want %v", tt.sealed, err, tt.want)
			}
		})
	}
}

func TestKeyRotation(t *testing.T) {
	t.Parallel()

	old := newTestKeyring(t, testKey(t, "k1", 1))
	sealed, err := old.EncryptString("s3cret", "ctx")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// After rotation the new key is primary and the old one is kept for reads.
	rotated := newTestKeyring(t, testKey(t, "k2", 2), testKey(t, "k1", 1))

	if got := rotated.PrimaryKeyID(); got != "k2" {
		t.Errorf("PrimaryKeyID() = %q, want k2", got)
	}
	if !rotated.NeedsRotation(sealed) {
		t.Error("NeedsRotation() = false for a value sealed with the old key")
	}

	plaintext, err := rotated.DecryptString(sealed, "ctx")
	if err != nil {
		t.Fatalf("Decrypt with retired key: %v", err)
	}
	if plaintext != "s3cret" {
		t.Errorf("Decrypt = %q, want s3cret", plaintext)
	}

	resealed, err := rotated.EncryptString(plaintext, "ctx")
	if err != nil {
		t.Fatalf("re-Encrypt: %v", err)
	}
	if rotated.NeedsRotation(resealed) {
		t.Error("NeedsRotation() = true for a freshly sealed value")
	}

	// Dropping the retired key must make old rows unreadable, not silently
	// return garbage.
	onlyNew := newTestKeyring(t, testKey(t, "k2", 2))
	if _, err := onlyNew.Decrypt(sealed, "ctx"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Decrypt after dropping the old key = %v, want ErrUnknownKey", err)
	}
}

func TestKeyIDOf(t *testing.T) {
	t.Parallel()

	kr := newTestKeyring(t, testKey(t, "primary", 7))
	sealed, err := kr.EncryptString("x", "ctx")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := KeyIDOf(sealed)
	if err != nil {
		t.Fatalf("KeyIDOf: %v", err)
	}
	if got != "primary" {
		t.Errorf("KeyIDOf = %q, want primary", got)
	}

	if _, err := KeyIDOf("nonsense"); !errors.Is(err, ErrMalformed) {
		t.Errorf("KeyIDOf(nonsense) = %v, want ErrMalformed", err)
	}
	if _, err := KeyIDOf("v1.k1"); !errors.Is(err, ErrMalformed) {
		t.Errorf("KeyIDOf(truncated) = %v, want ErrMalformed", err)
	}
	if NeedsRotationOfInvalid(kr) {
		t.Error("NeedsRotation should be false for an unparseable value")
	}
}

// NeedsRotationOfInvalid keeps the assertion above readable.
func NeedsRotationOfInvalid(kr *Keyring) bool { return kr.NeedsRotation("not-a-sealed-value") }

func TestGenerateKey(t *testing.T) {
	t.Parallel()

	spec, err := GenerateKey("k1")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := NewKeyring(spec)
	if err != nil {
		t.Fatalf("generated key was not accepted by NewKeyring: %v", err)
	}
	if kr.PrimaryKeyID() != "k1" {
		t.Errorf("PrimaryKeyID = %q, want k1", kr.PrimaryKeyID())
	}

	other, err := GenerateKey("k1")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if spec == other {
		t.Error("GenerateKey returned the same key twice")
	}

	for _, bad := range []string{"", "a.b", "a:b", strings.Repeat("x", maxKeyIDLen+1)} {
		if _, err := GenerateKey(bad); err == nil {
			t.Errorf("GenerateKey(%q) = nil error, want error", bad)
		}
	}
}
