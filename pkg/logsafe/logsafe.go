// Package logsafe neutralises untrusted text before it is written to logs.
package logsafe

import (
	"fmt"
	"strings"
	"unicode"
)

// String escapes control characters so untrusted input cannot forge extra log
// lines (CR, LF) or corrupt log viewers and parsers (NUL, ANSI escapes). CR and
// LF become \r and \n, every other control character \xNN or \uNNNN; tabs are
// kept.
func String(s string) string {
	if strings.IndexFunc(s, needsEscape) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\n':
			b.WriteString(`\n`)
		case needsEscape(r) && r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case needsEscape(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func needsEscape(r rune) bool {
	return r != '\t' && (unicode.IsControl(r) || r == ' ' || r == ' ')
}

// Err returns err's message made safe for logging, or "<nil>" for a nil error.
func Err(err error) string {
	if err == nil {
		return "<nil>"
	}
	return String(err.Error())
}
