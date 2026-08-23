package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password hashing errors.
var (
	ErrInvalidHash     = errors.New("crypto: password hash is malformed")
	ErrIncompatible    = errors.New("crypto: password hash uses an unsupported algorithm or version")
	ErrPasswordTooLong = errors.New("crypto: password exceeds the maximum length")
)

// MaxPasswordLen bounds work an unauthenticated caller can force us to do. An
// SMTP client that sends a megabyte-long password should be rejected before it
// reaches Argon2, not after.
const MaxPasswordLen = 1024

// Argon2Params are the cost parameters baked into each hash, so raising them
// later does not invalidate existing passwords: VerifyPassword reads the
// parameters out of the stored hash and reports when a rehash is due.
type Argon2Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params follows the OWASP recommendation for Argon2id
// (46 MiB, t=1, p=1) rounded up to 64 MiB, which a homelab-sized host can
// absorb while staying expensive for an attacker with a stolen database.
func DefaultArgon2Params() Argon2Params {
	p := Argon2Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	if n := runtime.NumCPU(); n < int(p.Parallelism) {
		p.Parallelism = uint8(n)
	}
	return p
}

// HashPassword returns a PHC-formatted Argon2id hash:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
//
// The format is self-describing, so the parameters can be raised over time
// without a migration.
func HashPassword(password string) (string, error) {
	return HashPasswordWith(password, DefaultArgon2Params())
}

// HashPasswordWith is HashPassword with explicit cost parameters. Tests use it
// to keep hashing cheap; production code should use HashPassword.
func HashPasswordWith(password string, p Argon2Params) (string, error) {
	if len(password) > MaxPasswordLen {
		return "", ErrPasswordTooLong
	}

	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("crypto: read random salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether password matches encoded.
//
// needsRehash is true when the stored hash used weaker parameters than the
// current defaults, so callers can transparently upgrade it on a successful
// login. It is only meaningful when match is true.
func VerifyPassword(encoded, password string) (match, needsRehash bool, err error) {
	if len(password) > MaxPasswordLen {
		return false, false, ErrPasswordTooLong
	}

	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}

	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	return true, weakerThanDefault(p), nil
}

func weakerThanDefault(p Argon2Params) bool {
	d := DefaultArgon2Params()
	return p.Memory < d.Memory ||
		p.Iterations < d.Iterations ||
		p.KeyLength < d.KeyLength ||
		p.SaltLength < d.SaltLength
}

func decodeHash(encoded string) (p Argon2Params, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	// A well-formed PHC string starts with an empty field: "", "argon2id", ...
	if len(parts) != 6 || parts[0] != "" {
		return p, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return p, nil, nil, fmt.Errorf("%w: algorithm %q", ErrIncompatible, parts[1])
	}

	var version int
	if _, scanErr := fmt.Sscanf(parts[2], "v=%d", &version); scanErr != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("%w: version %d", ErrIncompatible, version)
	}

	if p, err = parseParams(parts[3]); err != nil {
		return p, nil, nil, err
	}

	if salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if key, err = base64.RawStdEncoding.Strict().DecodeString(parts[5]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if len(salt) == 0 || len(key) == 0 {
		return p, nil, nil, ErrInvalidHash
	}

	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	return p, salt, key, nil
}

func parseParams(s string) (Argon2Params, error) {
	var p Argon2Params
	var seenM, seenT, seenP bool

	for _, field := range strings.Split(s, ",") {
		name, value, ok := strings.Cut(field, "=")
		if !ok {
			return p, ErrInvalidHash
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil || n == 0 {
			return p, ErrInvalidHash
		}
		switch name {
		case "m":
			p.Memory, seenM = uint32(n), true
		case "t":
			p.Iterations, seenT = uint32(n), true
		case "p":
			if n > 255 {
				return p, ErrInvalidHash
			}
			p.Parallelism, seenP = uint8(n), true
		default:
			return p, ErrInvalidHash
		}
	}
	if !seenM || !seenT || !seenP {
		return p, ErrInvalidHash
	}
	return p, nil
}
