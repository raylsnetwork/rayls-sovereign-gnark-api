// Package logsafe neutralises untrusted text before it is written to logs.
package logsafe

import "strings"

// String escapes CR and LF so untrusted input cannot forge extra log lines.
func String(s string) string {
	s = strings.ReplaceAll(s, "\r", `\r`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

// Err returns err's message made safe for logging, or "<nil>" for a nil error.
func Err(err error) string {
	if err == nil {
		return "<nil>"
	}
	return String(err.Error())
}
