package adminapi

import "encoding/base64"

// The pending single sign-on request is base64-encoded rather than stored
// server-side, so a deployment with several replicas does not need the callback
// to land on the one that started the flow. It is not encrypted because it
// holds nothing secret: the state, nonce and PKCE verifier are only meaningful
// alongside the browser's own cookie.

func encodeState(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decodeState(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
