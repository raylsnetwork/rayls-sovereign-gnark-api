package ceremony

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ManifestFile is the manifest's file name inside the ceremony directory.
const ManifestFile = "manifest.json"

const manifestVersion = 2

// Manifest records everything needed to replay and check the ceremony. It is
// committed alongside the transcript files, and every path in it is relative
// to the ceremony directory.
//
// Phase 1 is imported once from a public powers-of-tau file. Phase 2 is a
// single chain of contributions that never closes: each release applies a
// beacon to the chain as it stood at that point, so every release includes
// every earlier contribution.
type Manifest struct {
	Version  int             `json:"version"`
	Curve    string          `json:"curve"`
	Gnark    string          `json:"gnark"`
	Circuits []CircuitRecord `json:"circuits"`
	Phase1   Phase1Record    `json:"phase1"`
	Phase2   Phase2Record    `json:"phase2"`
}

// CircuitRecord pins a circuit's constraint system.
type CircuitRecord struct {
	Name        string `json:"name"`
	Verifier    string `json:"verifier"`
	Constraints int    `json:"constraints"`
	Power       int    `json:"power"`
	R1CSSHA256  string `json:"r1cs_sha256"`
}

// Phase1Record describes the imported powers of tau.
type Phase1Record struct {
	// Source is where the powers-of-tau file came from (a URL), or
	// DemoPhase1Source for a rehearsal.
	Source string `json:"source"`
	// PtauSHA256 and PtauBLAKE2b identify the imported file.
	PtauSHA256  string `json:"ptau_sha256,omitempty"`
	PtauBLAKE2b string `json:"ptau_blake2b,omitempty"`
	Power       int    `json:"power"`
	// SRS holds the imported parameters truncated to each circuit domain size.
	SRS []SRSRecord `json:"srs"`
}

// DemoPhase1Source marks a phase 1 generated locally for a rehearsal. Its
// generator knows the toxic waste, so its keys are insecure.
const DemoPhase1Source = "insecure-demo"

// Phase2Record is the perpetual per-circuit phase.
type Phase2Record struct {
	Contributions []Contribution `json:"contributions"`
	Releases      []Release      `json:"releases"`
}

// Contribution is one participant's addition to phase 2.
type Contribution struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	// Path is the contribution directory, one file per circuit.
	Path string `json:"path"`
	// SHA256 is the hash over the per-circuit file hashes (see bundleHash),
	// which the contributor publishes.
	SHA256 string `json:"sha256"`
	// Files maps circuit name to file hash.
	Files map[string]string `json:"files"`
	// Beacon is the public beacon the contributor announced for the next
	// release, which must not be known when the contribution is made, e.g.
	// "drand quicknet round 12345678".
	Beacon string `json:"beacon"`
}

// Release is a set of keys derived from the first Contributions contributions.
type Release struct {
	Version       int    `json:"version"`
	Contributions int    `json:"contributions"`
	Beacon        Beacon `json:"beacon"`
	// Outputs maps last_build-relative paths to their SHA-256.
	Outputs map[string]string `json:"outputs"`
}

// Beacon is a public random value: its source was announced in advance and
// its value revealed later.
type Beacon struct {
	Source string `json:"source"`
	Value  string `json:"value"`
}

// SRSRecord is phase 1 output truncated to one domain size.
type SRSRecord struct {
	Power  int    `json:"power"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// LatestRelease returns the newest release, or nil if there is none.
func (m *Manifest) LatestRelease() *Release {
	if len(m.Phase2.Releases) == 0 {
		return nil
	}
	return &m.Phase2.Releases[len(m.Phase2.Releases)-1]
}

// Pending reports whether there are contributions not yet in any release.
func (m *Manifest) Pending() bool {
	released := 0
	if r := m.LatestRelease(); r != nil {
		released = r.Contributions
	}
	return len(m.Phase2.Contributions) > released
}

// PendingBeacon is the beacon source the next release must use: the one
// announced by the latest contribution.
func (m *Manifest) PendingBeacon() string {
	if !m.Pending() {
		return ""
	}
	return m.Phase2.Contributions[len(m.Phase2.Contributions)-1].Beacon
}

func (m *Manifest) srs(power int) (SRSRecord, error) {
	for _, s := range m.Phase1.SRS {
		if s.Power == power {
			return s, nil
		}
	}
	return SRSRecord{}, fmt.Errorf("no phase 1 parameters for domain 2^%d", power)
}

// Load reads the manifest of the ceremony in dir.
func Load(dir string) (*Manifest, error) { return loadManifest(dir) }

func loadManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no ceremony in %s: run init first", dir)
	}
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Version != manifestVersion {
		return nil, fmt.Errorf("manifest version %d, this tool supports %d", m.Version, manifestVersion)
	}
	return &m, nil
}

// save writes the manifest atomically so an interrupted run never leaves a
// half-written file.
func (m *Manifest) save(dir string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	b = append(b, '\n')
	tmp := filepath.Join(dir, ManifestFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, ManifestFile)); err != nil {
		return fmt.Errorf("replace manifest: %w", err)
	}
	return nil
}
