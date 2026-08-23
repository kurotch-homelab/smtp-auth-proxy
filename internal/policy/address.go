// Package policy decides, for one submission, whether the authenticated
// account may send it and which shared mailbox it goes out as.
//
// This is the security boundary between LAN services: an account that can send
// as a mailbox it was never granted is the failure this package exists to
// prevent.
package policy

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// Address errors.
var (
	// ErrNoAddress means the field was empty or contained no address at all.
	ErrNoAddress = errors.New("policy: no address")
	// ErrMalformedAddress means the address could not be parsed.
	ErrMalformedAddress = errors.New("policy: malformed address")
)

// maxAddressLen bounds an address before it is parsed. RFC 5321 caps a path at
// 256 octets; anything longer is malicious or broken.
const maxAddressLen = 320

// Address is one parsed email address.
type Address struct {
	// Display is the friendly name, if the header carried one.
	Display string
	// Original is the address exactly as it appeared, for headers we pass on.
	Original string
	// Normalized is lowercased, for comparison. Localparts are technically
	// case-sensitive in SMTP, but Exchange Online treats them as equal, and an
	// operator who writes Sales@ in the allow-list means sales@ as well.
	Normalized string
	// Domain is the normalized domain part, without the '@'.
	Domain string
}

// ParseAddress parses a single address, with or without a display name.
//
// It accepts the empty envelope sender "<>" as an empty Address with no error,
// because that is how a bounce announces itself; callers that need a real
// sender must check IsEmpty.
func ParseAddress(raw string) (Address, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "<>" {
		return Address{}, nil
	}
	if len(trimmed) > maxAddressLen {
		return Address{}, fmt.Errorf("%w: longer than %d characters", ErrMalformedAddress, maxAddressLen)
	}

	parsed, err := mail.ParseAddress(trimmed)
	if err != nil {
		// An envelope path arrives wrapped in angle brackets, which
		// mail.ParseAddress accepts, but a bare localpart@domain is also
		// common from simple clients; both are handled by the retry below.
		bare := strings.Trim(trimmed, "<>")
		parsed, err = mail.ParseAddress(bare)
		if err != nil {
			return Address{}, fmt.Errorf("%w: %q", ErrMalformedAddress, raw)
		}
	}

	at := strings.LastIndex(parsed.Address, "@")
	if at <= 0 || at == len(parsed.Address)-1 {
		return Address{}, fmt.Errorf("%w: %q has no domain", ErrMalformedAddress, raw)
	}

	return Address{
		Display:    parsed.Name,
		Original:   parsed.Address,
		Normalized: strings.ToLower(parsed.Address),
		Domain:     strings.ToLower(parsed.Address[at+1:]),
	}, nil
}

// MustParseAddress is ParseAddress for addresses that come from the database
// and have already been validated. It panics on a malformed value, which would
// mean the database holds something the API should have rejected.
func MustParseAddress(raw string) Address {
	a, err := ParseAddress(raw)
	if err != nil {
		panic(fmt.Sprintf("policy: %v", err))
	}
	return a
}

// IsEmpty reports whether this is the null sender.
func (a Address) IsEmpty() bool { return a.Normalized == "" }

// String renders the address for a header, keeping the display name if there
// was one.
func (a Address) String() string {
	if a.IsEmpty() {
		return ""
	}
	if a.Display == "" {
		return a.Original
	}
	return (&mail.Address{Name: a.Display, Address: a.Original}).String()
}

// ParseHeaderFrom extracts the first address from a From header.
//
// RFC 5322 allows several addresses in From, but a message with more than one
// has no single identity to check, so it is rejected rather than guessed at.
func ParseHeaderFrom(header string) (Address, error) {
	trimmed := strings.TrimSpace(header)
	if trimmed == "" {
		return Address{}, ErrNoAddress
	}

	list, err := mail.ParseAddressList(trimmed)
	if err != nil {
		// Fall back to the single-address parser, which is more forgiving about
		// the unquoted display names some devices emit.
		return ParseAddress(trimmed)
	}
	switch len(list) {
	case 0:
		return Address{}, ErrNoAddress
	case 1:
		// Rebuild from the parsed pair rather than the bare address: the
		// display name has to survive, or a rewritten message loses who
		// actually sent it when the original goes into Reply-To.
		addr, err := ParseAddress(list[0].Address)
		if err != nil {
			return Address{}, err
		}
		addr.Display = list[0].Name
		return addr, nil
	default:
		return Address{}, fmt.Errorf("%w: From lists %d addresses, which has no single sender identity",
			ErrMalformedAddress, len(list))
	}
}

// MatchesPattern reports whether a normalized address matches an allow-list
// pattern. A pattern is either an exact address or "*@domain" for a whole
// domain. Matching is case-insensitive.
//
// There is deliberately no support for "*" on its own, or for patterns like
// "*foo*": an allow-list entry that matches everything is indistinguishable
// from having no policy at all, and would be an easy configuration mistake to
// make and a hard one to notice.
func MatchesPattern(normalized, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" || normalized == "" {
		return false
	}

	if domain, ok := strings.CutPrefix(pattern, "*@"); ok {
		if domain == "" {
			return false
		}
		at := strings.LastIndex(normalized, "@")
		return at >= 0 && normalized[at+1:] == domain
	}
	return normalized == pattern
}

// ValidatePattern reports whether a pattern is one the allow-list accepts, so
// the admin API can reject a bad entry at write time rather than silently never
// matching.
func ValidatePattern(pattern string) error {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return errors.New("policy: pattern must not be empty")
	}
	if trimmed == "*" || trimmed == "*@*" {
		return errors.New(`policy: "*" would allow sending as any address; grant the specific addresses or domains instead`)
	}

	if domain, ok := strings.CutPrefix(trimmed, "*@"); ok {
		if domain == "" || strings.ContainsAny(domain, "*@ ") {
			return fmt.Errorf("policy: %q is not a valid domain pattern; use *@example.com", pattern)
		}
		return nil
	}
	if strings.Contains(trimmed, "*") {
		return fmt.Errorf("policy: %q is not supported; use an exact address or *@example.com", pattern)
	}
	if _, err := ParseAddress(trimmed); err != nil {
		return fmt.Errorf("policy: %q is not a valid address or domain pattern", pattern)
	}
	return nil
}
