package oauth

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestBuildXOAuth2Bytes(t *testing.T) {
	t.Parallel()

	got, err := BuildXOAuth2("shared@example.com", "T0K3N")
	if err != nil {
		t.Fatalf("BuildXOAuth2: %v", err)
	}

	// The separators are literal 0x01 bytes. Microsoft's documentation renders
	// them as "^A", and sending those two characters is the classic cause of a
	// 535 with an otherwise correct tenant setup — so assert on the exact bytes.
	want := []byte("user=shared@example.com\x01auth=Bearer T0K3N\x01\x01")
	if !bytes.Equal(got, want) {
		t.Errorf("BuildXOAuth2 =\n %q\nwant\n %q", got, want)
	}
	if strings.Contains(string(got), "^A") {
		t.Error("the separator was written as the text \"^A\" instead of 0x01")
	}
}

func TestBuildXOAuth2MatchesTheDocumentedEncoding(t *testing.T) {
	t.Parallel()

	// The worked example from Microsoft's own documentation.
	got, err := BuildXOAuth2("test@contoso.onmicrosoft.com", "EwBAAl3BAAUFFpUAo7J3Ve0bjLBWZWCclRC3EoAA")
	if err != nil {
		t.Fatalf("BuildXOAuth2: %v", err)
	}
	const want = "dXNlcj10ZXN0QGNvbnRvc28ub25taWNyb3NvZnQuY29tAWF1dGg9QmVhcmVy" +
		"IEV3QkFBbDNCQUFVRkZwVUFvN0ozVmUwYmpMQldaV0NjbFJDM0VvQUEBAQ=="

	if encoded := base64.StdEncoding.EncodeToString(got); encoded != want {
		t.Errorf("base64 =\n %s\nwant\n %s", encoded, want)
	}
}

func TestBuildXOAuth2Rejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mailbox string
		token   string
	}{
		{name: "no mailbox", mailbox: "", token: "T0K3N"},
		{name: "no token", mailbox: "a@example.com", token: ""},
		// A separator inside a field would let a caller forge the structure of
		// the string.
		{name: "separator in the mailbox", mailbox: "a@example.com\x01auth=Bearer x", token: "T0K3N"},
		{name: "newline in the mailbox", mailbox: "a@example.com\r\n", token: "T0K3N"},
		{name: "separator in the token", mailbox: "a@example.com", token: "T0\x01K3N"},
		{name: "newline in the token", mailbox: "a@example.com", token: "T0K3N\r\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := BuildXOAuth2(tt.mailbox, tt.token); err == nil {
				t.Error("BuildXOAuth2 accepted an unsafe input")
			}
		})
	}
}
