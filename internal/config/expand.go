package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrUnsetVariable is returned when a referenced variable has no value and no
// default. Failing loudly beats starting with an empty client secret and
// discovering it when the first message cannot be sent.
var ErrUnsetVariable = errors.New("config: referenced variable is unset")

// maxFileSecretSize bounds what a ${file:...} reference may pull in. Secrets
// are small; anything larger is a misconfigured path.
const maxFileSecretSize = 1 << 20 // 1 MiB

// Lookup resolves an environment variable. Tests substitute their own.
type Lookup func(key string) (string, bool)

// expander resolves ${...} references in a raw config document.
type expander struct {
	lookup   Lookup
	readFile func(string) ([]byte, error)
}

// Expand substitutes ${...} references in raw and returns the result.
//
// Supported forms:
//
//	${VAR}              environment variable; an error if unset
//	${VAR:-default}     environment variable, or the literal default if unset or empty
//	${file:/path}       the contents of a file, with surrounding whitespace trimmed
//	$${literal}         an escaped '$', producing a literal "${literal}"
//
// The file form exists for Docker secrets and Kubernetes projected volumes,
// where the secret is mounted rather than injected into the environment.
func Expand(raw string) (string, error) {
	return (&expander{lookup: os.LookupEnv, readFile: os.ReadFile}).expand(raw)
}

func (e *expander) expand(raw string) (string, error) {
	var out strings.Builder
	out.Grow(len(raw))

	// Track YAML lexical state so that ${...} inside a comment is left alone.
	// Operators document their config with examples like "# use ${VAR}", and
	// failing to start because of a comment would be indefensible.
	var (
		inComment bool
		quote     byte // 0, '\'' or '"'
	)

	for i := 0; i < len(raw); {
		c := raw[i]

		switch {
		case c == '\n':
			inComment = false
			quote = 0
		case inComment:
			// Nothing to do; the byte is copied below.
		case quote != 0:
			// A doubled '' inside a single-quoted scalar is an escaped quote.
			if c == quote && quote == '\'' && i+1 < len(raw) && raw[i+1] == '\'' {
				out.WriteString("''")
				i += 2
				continue
			}
			// A backslash escape inside a double-quoted scalar.
			if c == '\\' && quote == '"' && i+1 < len(raw) {
				out.WriteByte(c)
				out.WriteByte(raw[i+1])
				i += 2
				continue
			}
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || raw[i-1] == ' ' || raw[i-1] == '\t' || raw[i-1] == '\n'):
			// YAML only starts a comment at the beginning of a line or after
			// whitespace, so "a#b" is a plain scalar rather than a comment.
			inComment = true
		}

		if inComment {
			out.WriteByte(c)
			i++
			continue
		}

		// Anything that is not the start of a reference is copied verbatim.
		if c != '$' {
			out.WriteByte(c)
			i++
			continue
		}
		// "$$" escapes a literal dollar sign.
		if i+1 < len(raw) && raw[i+1] == '$' {
			out.WriteByte('$')
			i += 2
			continue
		}
		if i+1 >= len(raw) || raw[i+1] != '{' {
			out.WriteByte('$')
			i++
			continue
		}

		end := strings.IndexByte(raw[i:], '}')
		if end < 0 {
			return "", fmt.Errorf("config: unterminated ${...} reference at offset %d", i)
		}
		ref := raw[i+2 : i+end]

		value, err := e.resolve(ref)
		if err != nil {
			return "", err
		}
		out.WriteString(value)
		i += end + 1
	}
	return out.String(), nil
}

func (e *expander) resolve(ref string) (string, error) {
	if ref == "" {
		return "", errors.New("config: empty ${} reference")
	}

	if path, ok := strings.CutPrefix(ref, "file:"); ok {
		return e.resolveFile(path)
	}

	name, fallback, hasFallback := strings.Cut(ref, ":-")
	value, found := e.lookup(name)
	if found && value != "" {
		return value, nil
	}
	if hasFallback {
		return fallback, nil
	}
	return "", fmt.Errorf("%w: %s", ErrUnsetVariable, name)
}

func (e *expander) resolveFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("config: ${file:} reference has an empty path")
	}
	if !filepath.IsAbs(path) {
		// A relative path would resolve against whatever directory the process
		// happens to be started in, which is not something an operator can
		// reason about from the config file alone.
		return "", fmt.Errorf("config: ${file:%s} must be an absolute path", path)
	}

	//nolint:gosec // The path is written by the operator in their own config
	// file. Treating that as untrusted input would mean the feature cannot
	// exist; the trust boundary is the config file itself.
	info, err := os.Stat(path)
	if err == nil && info.Size() > maxFileSecretSize {
		return "", fmt.Errorf("config: ${file:%s} is %d bytes, larger than the %d byte limit",
			path, info.Size(), maxFileSecretSize)
	}

	b, err := e.readFile(path)
	if err != nil {
		return "", fmt.Errorf("config: reading ${file:%s}: %w", path, err)
	}
	// Mounted secrets routinely carry a trailing newline that would otherwise
	// end up inside a client secret or a DSN.
	return strings.TrimSpace(string(b)), nil
}
