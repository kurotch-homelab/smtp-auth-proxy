package crypto

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// cheapParams keep the test suite fast; production uses DefaultArgon2Params.
func cheapParams() Argon2Params {
	return Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

func TestHashPasswordRoundTrip(t *testing.T) {
	t.Parallel()

	passwords := []string{
		"",
		"correct horse battery staple",
		"パスワード", // multi-byte input must survive verbatim
		strings.Repeat("x", MaxPasswordLen),
	}

	for _, pw := range passwords {
		hash, err := HashPasswordWith(pw, cheapParams())
		if err != nil {
			t.Fatalf("HashPasswordWith(%q): %v", pw, err)
		}
		if strings.Contains(hash, pw) && pw != "" {
			t.Fatalf("hash leaks the password: %q", hash)
		}

		match, _, err := VerifyPassword(hash, pw)
		if err != nil {
			t.Fatalf("VerifyPassword: %v", err)
		}
		if !match {
			t.Errorf("VerifyPassword(%q) = false, want true", pw)
		}
	}
}

func TestHashPasswordUsesRandomSalt(t *testing.T) {
	t.Parallel()

	a, err := HashPasswordWith("same", cheapParams())
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	b, err := HashPasswordWith("same", cheapParams())
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	if a == b {
		t.Error("two hashes of the same password are identical; the salt is not random")
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	t.Parallel()

	hash, err := HashPasswordWith("s3cret", cheapParams())
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}

	for _, wrong := range []string{"", "s3cre", "s3crets", "S3cret", "wrong"} {
		match, _, err := VerifyPassword(hash, wrong)
		if err != nil {
			t.Fatalf("VerifyPassword(%q): %v", wrong, err)
		}
		if match {
			t.Errorf("VerifyPassword accepted %q", wrong)
		}
	}
}

func TestVerifyPasswordReportsRehashNeeded(t *testing.T) {
	t.Parallel()

	weak, err := HashPasswordWith("s3cret", cheapParams())
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	match, needsRehash, err := VerifyPassword(weak, "s3cret")
	if err != nil || !match {
		t.Fatalf("VerifyPassword = (%v, %v)", match, err)
	}
	if !needsRehash {
		t.Error("a hash weaker than the defaults should report needsRehash")
	}

	// A hash at the current defaults must not ask to be rehashed on every login.
	strong, err := HashPassword("s3cret")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	match, needsRehash, err = VerifyPassword(strong, "s3cret")
	if err != nil || !match {
		t.Fatalf("VerifyPassword = (%v, %v)", match, err)
	}
	if needsRehash {
		t.Error("a hash at the current defaults should not report needsRehash")
	}
}

func TestVerifyPasswordRejectsMalformedHashes(t *testing.T) {
	t.Parallel()

	valid, err := HashPasswordWith("s3cret", cheapParams())
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	parts := strings.Split(valid, "$")

	tests := []struct {
		name string
		hash string
		want error
	}{
		{"empty", "", ErrInvalidHash},
		{"not a PHC string", "just-a-string", ErrInvalidHash},
		{"too few fields", "$argon2id$v=19$m=8192,t=1,p=1", ErrInvalidHash},
		{"leading field not empty", "x$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA", ErrInvalidHash},
		{"bcrypt hash", "$2a$10$abcdefghijklmnopqrstuv", ErrInvalidHash},
		{"argon2i instead of argon2id", "$argon2i$v=19$m=8192,t=1,p=1$" + parts[4] + "$" + parts[5], ErrIncompatible},
		{"unknown version", "$argon2id$v=16$m=8192,t=1,p=1$" + parts[4] + "$" + parts[5], ErrIncompatible},
		{"unparseable version", "$argon2id$vNaN$m=8192,t=1,p=1$" + parts[4] + "$" + parts[5], ErrInvalidHash},
		{"missing t parameter", "$argon2id$v=19$m=8192,p=1$" + parts[4] + "$" + parts[5], ErrInvalidHash},
		{"unknown parameter", "$argon2id$v=19$m=8192,t=1,p=1,z=9$" + parts[4] + "$" + parts[5], ErrInvalidHash},
		{"zero parameter", "$argon2id$v=19$m=0,t=1,p=1$" + parts[4] + "$" + parts[5], ErrInvalidHash},
		{"parallelism above uint8", "$argon2id$v=19$m=8192,t=1,p=300$" + parts[4] + "$" + parts[5], ErrInvalidHash},
		{"parameter without '='", "$argon2id$v=19$m8192,t=1,p=1$" + parts[4] + "$" + parts[5], ErrInvalidHash},
		{"salt not base64", "$argon2id$v=19$m=8192,t=1,p=1$!!!$" + parts[5], ErrInvalidHash},
		{"key not base64", "$argon2id$v=19$m=8192,t=1,p=1$" + parts[4] + "$!!!", ErrInvalidHash},
		{"empty salt", "$argon2id$v=19$m=8192,t=1,p=1$$" + parts[5], ErrInvalidHash},
		{"empty key", "$argon2id$v=19$m=8192,t=1,p=1$" + parts[4] + "$", ErrInvalidHash},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			match, _, err := VerifyPassword(tt.hash, "s3cret")
			if match {
				t.Fatalf("VerifyPassword(%q) matched a malformed hash", tt.hash)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("VerifyPassword(%q) = %v, want %v", tt.hash, err, tt.want)
			}
		})
	}
}

func TestPasswordLengthIsBounded(t *testing.T) {
	t.Parallel()

	// An unauthenticated SMTP client must not be able to make us hash an
	// arbitrarily large buffer.
	huge := strings.Repeat("x", MaxPasswordLen+1)

	if _, err := HashPassword(huge); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("HashPassword(huge) = %v, want ErrPasswordTooLong", err)
	}

	hash, err := HashPasswordWith("s3cret", cheapParams())
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	if _, _, err := VerifyPassword(hash, huge); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("VerifyPassword(huge) = %v, want ErrPasswordTooLong", err)
	}
}

func TestDefaultParamsAreAtLeastOWASPRecommendation(t *testing.T) {
	t.Parallel()

	p := DefaultArgon2Params()
	if p.Memory < 46*1024 {
		t.Errorf("Memory = %d KiB, want at least 46 MiB", p.Memory)
	}
	if p.Iterations < 1 {
		t.Errorf("Iterations = %d, want at least 1", p.Iterations)
	}
	if p.SaltLength < 16 {
		t.Errorf("SaltLength = %d, want at least 16", p.SaltLength)
	}
	if p.KeyLength < 32 {
		t.Errorf("KeyLength = %d, want at least 32", p.KeyLength)
	}
	if p.Parallelism < 1 {
		t.Errorf("Parallelism = %d, want at least 1", p.Parallelism)
	}
}

func TestHashFormatIsPHC(t *testing.T) {
	t.Parallel()

	hash, err := HashPasswordWith("s3cret", cheapParams())
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	// Other tooling (and a future migration to a different KDF) relies on the
	// stored hash being a standard PHC string.
	if !strings.HasPrefix(hash, "$argon2id$v=") {
		t.Errorf("hash = %q, want a $argon2id$ PHC string", hash)
	}
	if !strings.Contains(hash, "v=19") || argon2.Version != 19 {
		t.Errorf("hash = %q, want argon2 version 19", hash)
	}
}
