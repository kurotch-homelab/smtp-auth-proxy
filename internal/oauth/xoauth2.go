package oauth

import (
	"errors"
	"fmt"
	"strings"
)

// XOAuth2 is the SASL mechanism name Exchange Online advertises for OAuth.
const XOAuth2 = "XOAUTH2"

// separator is the byte that delimits the fields of an XOAUTH2 string. It is a
// literal 0x01, not the two characters "^A" that Microsoft's documentation
// prints — writing it as text is the single most common way to get a
// "535 5.7.3 Authentication unsuccessful" with an otherwise correct setup.
const separator = "\x01"

// BuildXOAuth2 returns the SASL initial response for SMTP AUTH XOAUTH2:
//
//	user=<mailbox>^Aauth=Bearer <token>^A^A
//
// The mailbox is the address the message will be sent as. For a shared mailbox
// this is the shared mailbox's own address, not the identity that owns the
// token — that substitution is what lets one application registration send as
// every mailbox the tenant has granted it.
//
// The result is returned unencoded; go-smtp base64-encodes the SASL response
// itself.
func BuildXOAuth2(mailbox, accessToken string) ([]byte, error) {
	if mailbox == "" {
		return nil, errors.New("oauth: XOAUTH2 needs a mailbox address")
	}
	if accessToken == "" {
		return nil, errors.New("oauth: XOAUTH2 needs an access token")
	}
	// A separator inside either field would let a caller forge the structure of
	// the string, and neither an address nor a token can legitimately contain
	// a control character.
	if strings.ContainsAny(mailbox, separator+"\r\n") {
		return nil, fmt.Errorf("oauth: mailbox %q contains a control character", mailbox)
	}
	if strings.ContainsAny(accessToken, separator+"\r\n") {
		return nil, errors.New("oauth: the access token contains a control character")
	}

	return []byte("user=" + mailbox + separator + "auth=Bearer " + accessToken + separator + separator), nil
}
