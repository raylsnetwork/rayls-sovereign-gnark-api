package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckNoRelease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		manifest string // "" means no manifest file
		wantErr  bool
	}{
		{name: "no ceremony", manifest: "", wantErr: false},
		{name: "no release yet", manifest: `{"version":2,"phase2":{"contributions":[],"releases":[]}}`, wantErr: false},
		{name: "released", manifest: `{"version":2,"phase2":{"contributions":[],"releases":[{"version":1,"contributions":1}]}}`, wantErr: true},
		{name: "unreadable manifest", manifest: `{not json`, wantErr: true},
		{name: "unknown manifest version", manifest: `{"version":99}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if tt.manifest != "" {
				if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(tt.manifest), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			err := checkNoRelease(dir)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkNoRelease() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckNoReleaseRepoCeremony(t *testing.T) {
	t.Parallel()
	// The committed ceremony has released keys, so the guard must hold.
	if err := checkNoRelease(filepath.Join("..", "..", "..", "ceremony")); err == nil {
		t.Fatal("checkNoRelease(ceremony/) = nil, want an error: the repository's ceremony has a release")
	}
}
