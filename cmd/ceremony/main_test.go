package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsBadInvocations(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "none")
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no subcommand", nil, "usage"},
		{"unknown subcommand", []string{"launch"}, "unknown subcommand"},
		{"unknown flag", []string{"status", "--nope"}, "flag provided but not defined"},
		{"status without ceremony", []string{"status", "--dir", missing}, "run init first"},
		{"contribute without ceremony", []string{"contribute", "--dir", missing, "--name", "alice", "--beacon-source", "x"}, "run init first"},
		{"init without ptau", []string{"init", "--dir", missing}, "powers-of-tau"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out, errOut bytes.Buffer
			err := run(tc.args, &out, &errOut)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
