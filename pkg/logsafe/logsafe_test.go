package logsafe

import (
	"errors"
	"testing"
)

func TestString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"plain", "bad field", "bad field"},
		{"newline", "a\nINFO forged", `a\nINFO forged`},
		{"crlf", "a\r\nb", `a\r\nb`},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := String(tt.in); got != tt.want {
				t.Errorf("String(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestErr(t *testing.T) {
	t.Parallel()
	if got := Err(nil); got != "<nil>" {
		t.Errorf("Err(nil) = %q, want <nil>", got)
	}
	if got, want := Err(errors.New("x\ny")), `x\ny`; got != want {
		t.Errorf("Err = %q, want %q", got, want)
	}
}
