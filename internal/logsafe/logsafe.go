// Package logsafe neutralizes user-provided values before they reach a log.
//
// The attack it closes is log forging: a username of
// "alice\n2026-01-01 level=INFO msg=admin sign-in succeeded" would otherwise
// write a convincing fake entry into a text-format log, and corrupt
// line-oriented log shippers either way. Values are also bounded, so an
// unauthenticated client cannot choose how much log storage a single request
// consumes.
package logsafe

import "strings"

// maxLen bounds a single logged value. Long enough for any legitimate
// username, path or upstream error; short enough that a hostile value cannot
// bloat the log.
const maxLen = 512

// String makes a user-provided value safe to log.
//
// Newlines are made visible as literal \n and \r rather than dropped — an
// operator investigating an attack wants to see that they were there — and
// every other control character is removed.
func String(s string) string {
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)

	if len(s) > maxLen {
		return s[:maxLen] + "…(truncated)"
	}
	return s
}

// Error is String for an error's message, tolerating nil.
//
// Error text routinely embeds user input — "no account named %q" — so it needs
// the same treatment as the input itself.
func Error(err error) string {
	if err == nil {
		return ""
	}
	return String(err.Error())
}
