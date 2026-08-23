package policy

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		in             string
		wantNormalized string
		wantDisplay    string
		wantDomain     string
		wantEmpty      bool
		wantErr        error
	}{
		{name: "plain", in: "user@example.com", wantNormalized: "user@example.com", wantDomain: "example.com"},
		{name: "angle brackets", in: "<user@example.com>", wantNormalized: "user@example.com", wantDomain: "example.com"},
		{
			name: "display name", in: `"Some Service" <user@example.com>`,
			wantNormalized: "user@example.com", wantDisplay: "Some Service", wantDomain: "example.com",
		},
		{
			name: "unquoted display name", in: "Some Service <user@example.com>",
			wantNormalized: "user@example.com", wantDisplay: "Some Service", wantDomain: "example.com",
		},
		{
			// The allow-list is written by a human who may not match the case
			// the device sends, and Exchange treats them as equal anyway.
			name: "case is normalized", in: "User@Example.COM",
			wantNormalized: "user@example.com", wantDomain: "example.com",
		},
		{name: "surrounding whitespace", in: "  user@example.com  ", wantNormalized: "user@example.com", wantDomain: "example.com"},
		{name: "plus addressing", in: "user+tag@example.com", wantNormalized: "user+tag@example.com", wantDomain: "example.com"},
		{name: "subdomain", in: "user@mail.example.co.uk", wantNormalized: "user@mail.example.co.uk", wantDomain: "mail.example.co.uk"},

		// The null sender is how a bounce identifies itself; it is not an error.
		{name: "empty", in: "", wantEmpty: true},
		{name: "null sender", in: "<>", wantEmpty: true},
		{name: "whitespace only", in: "   ", wantEmpty: true},

		{name: "no domain", in: "user", wantErr: ErrMalformedAddress},
		{name: "no localpart", in: "@example.com", wantErr: ErrMalformedAddress},
		{name: "trailing at", in: "user@", wantErr: ErrMalformedAddress},
		{name: "two addresses", in: "a@example.com, b@example.com", wantErr: ErrMalformedAddress},
		{name: "not an address", in: "not an address", wantErr: ErrMalformedAddress},
		{name: "overlong", in: strings.Repeat("a", 320) + "@example.com", wantErr: ErrMalformedAddress},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseAddress(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseAddress(%q) = (%+v, %v), want %v", tt.in, got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAddress(%q): %v", tt.in, err)
			}
			if tt.wantEmpty {
				if !got.IsEmpty() {
					t.Errorf("ParseAddress(%q) = %+v, want the empty address", tt.in, got)
				}
				return
			}
			if got.Normalized != tt.wantNormalized {
				t.Errorf("Normalized = %q, want %q", got.Normalized, tt.wantNormalized)
			}
			if got.Display != tt.wantDisplay {
				t.Errorf("Display = %q, want %q", got.Display, tt.wantDisplay)
			}
			if got.Domain != tt.wantDomain {
				t.Errorf("Domain = %q, want %q", got.Domain, tt.wantDomain)
			}
		})
	}
}

func TestAddressStringKeepsTheDisplayName(t *testing.T) {
	t.Parallel()

	withName, err := ParseAddress(`"Some Service" <user@example.com>`)
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if got := withName.String(); !strings.Contains(got, "Some Service") || !strings.Contains(got, "user@example.com") {
		t.Errorf("String() = %q, want it to keep both parts", got)
	}

	plain, err := ParseAddress("user@example.com")
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if got := plain.String(); got != "user@example.com" {
		t.Errorf("String() = %q, want the bare address", got)
	}

	if got := (Address{}).String(); got != "" {
		t.Errorf("empty String() = %q, want empty", got)
	}
}

func TestParseHeaderFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{name: "single", in: "user@example.com", want: "user@example.com"},
		{name: "with display name", in: `Printer <printer@example.com>`, want: "printer@example.com"},
		{name: "empty", in: "", wantErr: ErrNoAddress},
		{name: "whitespace", in: "  ", wantErr: ErrNoAddress},
		// Two senders means no single identity to enforce a policy against,
		// so it is refused rather than resolved to whichever came first.
		{name: "two addresses", in: "a@example.com, b@example.com", wantErr: ErrMalformedAddress},
		{name: "garbage", in: "this is not a header", wantErr: ErrMalformedAddress},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseHeaderFrom(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseHeaderFrom(%q) = (%+v, %v), want %v", tt.in, got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseHeaderFrom(%q): %v", tt.in, err)
			}
			if got.Normalized != tt.want {
				t.Errorf("= %q, want %q", got.Normalized, tt.want)
			}
		})
	}
}

func TestMatchesPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		address string
		pattern string
		want    bool
	}{
		{"user@example.com", "user@example.com", true},
		{"user@example.com", "User@Example.com", true},
		{"user@example.com", " user@example.com ", true},
		{"user@example.com", "other@example.com", false},

		{"user@example.com", "*@example.com", true},
		{"user@example.com", "*@EXAMPLE.COM", true},
		{"user@example.com", "*@example.org", false},
		// A subdomain is a different domain; matching it would let anyone who
		// controls mail.example.com send as example.com.
		{"user@mail.example.com", "*@example.com", false},

		// A bare wildcard would allow everything, which is the same as having
		// no policy; it must never match.
		{"user@example.com", "*", false},
		{"user@example.com", "*@", false},
		{"user@example.com", "", false},
		{"", "user@example.com", false},
		{"", "*@example.com", false},
	}

	for _, tt := range tests {
		if got := MatchesPattern(tt.address, tt.pattern); got != tt.want {
			t.Errorf("MatchesPattern(%q, %q) = %v, want %v", tt.address, tt.pattern, got, tt.want)
		}
	}
}

func TestValidatePattern(t *testing.T) {
	t.Parallel()

	valid := []string{"user@example.com", "*@example.com", "  user@example.com  "}
	for _, p := range valid {
		if err := ValidatePattern(p); err != nil {
			t.Errorf("ValidatePattern(%q) = %v, want nil", p, err)
		}
	}

	invalid := map[string]string{
		"":               "must not be empty",
		"*":              "allow sending as any address",
		"*@*":            "allow sending as any address",
		"*@":             "not a valid domain pattern",
		"user*@x.com":    "not supported",
		"*@ex ample.com": "not a valid domain pattern",
		"not-an-address": "not a valid address",
	}
	for p, want := range invalid {
		err := ValidatePattern(p)
		if err == nil {
			t.Errorf("ValidatePattern(%q) = nil, want an error", p)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidatePattern(%q) = %q, want it to mention %q", p, err, want)
		}
	}
}

func TestMustParseAddressPanicsOnGarbage(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("MustParseAddress did not panic on a malformed address")
		}
	}()
	MustParseAddress("not an address")
}
