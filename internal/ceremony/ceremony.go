// Package ceremony runs a Groth16 trusted setup (gnark's mpcsetup) whose
// transcript is a directory of files plus a manifest, so it can be committed
// to git and replayed by anyone.
//
// Phase 1 is imported once from a public powers-of-tau file (Init). Phase 2 is
// perpetual: anyone can Contribute at any time, announcing a future public
// beacon, and Finalize turns every contribution so far into a new release of
// keys once that beacon is published. Every release includes every earlier
// contribution, so a participant who contributed can trust every later release.
// Verify replays the whole transcript and every release.
package ceremony

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"golang.org/x/crypto/blake2b"
)

// Ceremony operates on the transcript in Dir for the given circuits.
type Ceremony struct {
	Dir      string
	Circuits []Circuit
	// Log receives progress messages; nil discards them.
	Log io.Writer
	// Jobs is how many circuits are processed at once; 0 means AutoJobs().
	// Each job needs about 2 GB of memory for the largest circuits.
	Jobs int

	logMu sync.Mutex
	// lag shares Lagrange-form phase 1 parameters across circuits.
	lag lagrangeCache
}

// InitOptions selects the phase 1 parameters.
type InitOptions struct {
	// PtauPath is a snarkjs powers-of-tau file to import.
	PtauPath string
	// PtauSource records where the file came from, e.g. its download URL.
	PtauSource string
	// Demo generates an insecure phase 1 locally instead, for rehearsals.
	Demo bool
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// minBeaconBytes is the minimum beacon length accepted.
const minBeaconBytes = 16

// Init compiles the circuits, imports phase 1 and writes a new manifest. It
// refuses to overwrite an existing ceremony.
func (c *Ceremony) Init(opts InitOptions) (*Manifest, error) {
	if _, err := os.Stat(filepath.Join(c.Dir, ManifestFile)); err == nil {
		return nil, fmt.Errorf("a ceremony already exists in %s", c.Dir)
	}
	if !opts.Demo && (opts.PtauPath == "" || opts.PtauSource == "") {
		return nil, errors.New("init needs a powers-of-tau file and its source")
	}
	circuits, err := c.compileAll()
	if err != nil {
		return nil, err
	}
	m := &Manifest{
		Version: manifestVersion,
		Curve:   "bn254",
		Gnark:   gnarkVersion(),
		Phase2:  Phase2Record{Contributions: []Contribution{}, Releases: []Release{}},
	}
	maxPower := 0
	for _, cc := range circuits {
		m.Circuits = append(m.Circuits, CircuitRecord{
			Name:        cc.Name,
			Verifier:    cc.Verifier,
			Constraints: cc.R1CS.GetNbConstraints(),
			Power:       cc.Power,
			R1CSSHA256:  cc.Hash,
		})
		maxPower = max(maxPower, cc.Power)
	}

	var srs *mpcsetup.SrsCommons
	if opts.Demo {
		c.logf("generating an INSECURE demo phase 1 (2^%d)", maxPower)
		srs = demoPhase1(maxPower)
		m.Phase1.Source, m.Phase1.Power = DemoPhase1Source, maxPower
	} else {
		c.logf("importing phase 1 from %s", opts.PtauPath)
		if srs, m.Phase1.Power, err = ImportPtau(opts.PtauPath); err != nil {
			return nil, err
		}
		if m.Phase1.PtauSHA256, m.Phase1.PtauBLAKE2b, err = ptauHashes(opts.PtauPath); err != nil {
			return nil, err
		}
		m.Phase1.Source = opts.PtauSource
	}
	if m.Phase1.Power < maxPower {
		return nil, fmt.Errorf("phase 1 supports 2^%d constraints, the largest circuit needs 2^%d", m.Phase1.Power, maxPower)
	}

	for _, p := range circuitPowers(m) {
		t, err := truncateSRS(srs, uint64(1)<<p)
		if err != nil {
			return nil, err
		}
		rel := fmt.Sprintf("phase1/srs-%02d.bin", p)
		sha, err := writeObject(filepath.Join(c.Dir, rel), t)
		if err != nil {
			return nil, err
		}
		m.Phase1.SRS = append(m.Phase1.SRS, SRSRecord{Power: p, Path: rel, SHA256: sha})
	}
	if err := m.save(c.Dir); err != nil {
		return nil, err
	}
	c.logf("initialised ceremony for %d circuits", len(m.Circuits))
	return m, nil
}

// Contribute adds fresh randomness to every circuit's phase 2 and announces
// beacon, a future public random value, for the next release. It first
// verifies every earlier contribution, then builds on the latest one. The
// randomness exists only in memory.
func (c *Ceremony) Contribute(name, beacon string) (Contribution, error) {
	if !namePattern.MatchString(name) {
		return Contribution{}, fmt.Errorf("invalid contributor name %q: use lowercase letters, digits and dashes", name)
	}
	if strings.TrimSpace(beacon) == "" {
		return Contribution{}, errors.New("announce the beacon for the next release")
	}
	m, err := loadManifest(c.Dir)
	if err != nil {
		return Contribution{}, err
	}
	for _, prev := range m.Phase2.Contributions {
		if prev.Name == name {
			return Contribution{}, fmt.Errorf("%s has already contributed", name)
		}
	}
	circuits, err := c.checkCircuits(m)
	if err != nil {
		return Contribution{}, err
	}

	srs, err := c.loadSRS(m)
	if err != nil {
		return Contribution{}, err
	}
	idx := len(m.Phase2.Contributions) + 1
	relDir := fmt.Sprintf("phase2/%04d-%s", idx, name)
	hashes := make([]string, len(circuits))
	err = c.forEach(circuits, func(i int, cc *compiled) error {
		latest, _, err := c.replayPhase2(m, cc, srs[cc.Power])
		if err != nil {
			return err
		}
		start := time.Now()
		latest.Contribute()
		if hashes[i], err = writeObject(filepath.Join(c.Dir, relDir, cc.Name+".bin"), latest); err != nil {
			return err
		}
		c.logf("%s: contributed in %s", cc.Name, since(start))
		return nil
	})
	if err != nil {
		_ = os.RemoveAll(filepath.Join(c.Dir, relDir))
		return Contribution{}, err
	}
	files := make(map[string]string, len(circuits))
	for i, cc := range circuits {
		files[cc.Name] = hashes[i]
	}

	contrib := Contribution{
		Index:  idx,
		Name:   name,
		Path:   relDir,
		SHA256: bundleHash(m.Circuits, files),
		Files:  files,
		Beacon: beacon,
	}
	m.Phase2.Contributions = append(m.Phase2.Contributions, contrib)
	if err := m.save(c.Dir); err != nil {
		return Contribution{}, err
	}
	c.logf("contribution %d by %s: %s", idx, name, contrib.SHA256)
	return contrib, nil
}

// Finalize makes a new release from every contribution so far: it verifies
// the phase 2 transcripts, applies beaconHex (the value of the beacon the
// latest contribution announced), and writes the keys, R1CS and raw Solidity
// verifiers to outDir (normally last_build).
func (c *Ceremony) Finalize(beaconHex, outDir string) (*Release, error) {
	m, err := loadManifest(c.Dir)
	if err != nil {
		return nil, err
	}
	if !m.Pending() {
		return nil, errors.New("no contributions since the last release")
	}
	beacon, err := decodeBeacon(beaconHex)
	if err != nil {
		return nil, err
	}
	circuits, err := c.checkCircuits(m)
	if err != nil {
		return nil, err
	}
	srs, err := c.loadSRS(m)
	if err != nil {
		return nil, err
	}
	n := len(m.Phase2.Contributions)
	written := make([]map[string]string, len(circuits))
	err = c.forEach(circuits, func(i int, cc *compiled) error {
		latest, evals, err := c.replayPhase2(m, cc, srs[cc.Power])
		if err != nil {
			return err
		}
		start := time.Now()
		pk, vk := latest.Seal(srs[cc.Power], evals, beacon)
		if written[i], err = writeOutputs(outDir, cc, pk, vk); err != nil {
			return err
		}
		c.logf("%s: keys sealed and written in %s", cc.Name, since(start))
		return nil
	})
	if err != nil {
		return nil, err
	}
	outputs := make(map[string]string)
	for _, w := range written {
		for k, v := range w {
			outputs[k] = v
		}
	}
	release := Release{
		Version:       len(m.Phase2.Releases) + 1,
		Contributions: n,
		Beacon:        Beacon{Source: m.PendingBeacon(), Value: beaconHex},
		Outputs:       outputs,
	}
	m.Phase2.Releases = append(m.Phase2.Releases, release)
	if err := m.save(c.Dir); err != nil {
		return nil, err
	}
	c.logf("release v%d: %d contribution(s), beacon %s", release.Version, n, release.Beacon.Source)
	return &release, nil
}

// Verify replays the whole transcript: circuit hashes, the phase 1
// parameters, every phase 2 contribution and every release. If ptauPath is set
// the phase 1 parameters must derive from that file. If outDir is set its
// files must match the latest release.
func (c *Ceremony) Verify(outDir, ptauPath string) error {
	m, err := loadManifest(c.Dir)
	if err != nil {
		return err
	}
	circuits, err := c.checkCircuits(m)
	if err != nil {
		return err
	}
	if err := c.checkPhase1(m, ptauPath); err != nil {
		return err
	}
	if err := checkReleases(m); err != nil {
		return err
	}
	if len(m.Phase2.Contributions) == 0 {
		if outDir != "" {
			return errors.New("there is no release to compare with " + outDir)
		}
		c.logf("no phase 2 contributions yet")
		return nil
	}
	srs, err := c.loadSRS(m)
	if err != nil {
		return err
	}
	err = c.forEach(circuits, func(_ int, cc *compiled) error {
		_, evals, err := c.replayPhase2(m, cc, srs[cc.Power])
		if err != nil {
			return err
		}
		for i := range m.Phase2.Releases {
			rel := &m.Phase2.Releases[i]
			beacon, err := decodeBeacon(rel.Beacon.Value)
			if err != nil {
				return fmt.Errorf("release v%d beacon: %w", rel.Version, err)
			}
			pk, vk, err := c.sealAt(m, cc, srs[cc.Power], evals, rel.Contributions, beacon)
			if err != nil {
				return err
			}
			dir := ""
			if i == len(m.Phase2.Releases)-1 {
				dir = outDir
			}
			if err := checkOutputs(rel, cc, pk, vk, dir); err != nil {
				return fmt.Errorf("release v%d: %w", rel.Version, err)
			}
		}
		c.logf("%s: %d contribution(s) and %d release(s) verify", cc.Name, len(m.Phase2.Contributions), len(m.Phase2.Releases))
		return nil
	})
	if err != nil {
		return err
	}
	if outDir != "" && len(m.Phase2.Releases) == 0 {
		return errors.New("there is no release to compare with " + outDir)
	}
	return nil
}

// checkPhase1 checks the phase 1 parameter files: their hashes, their
// structure and, given the powers-of-tau file, that they derive from it.
func (c *Ceremony) checkPhase1(m *Manifest, ptauPath string) error {
	powers := circuitPowers(m)
	if len(m.Phase1.SRS) != len(powers) {
		return fmt.Errorf("manifest records %d phase 1 parameter sets, circuits need %d", len(m.Phase1.SRS), len(powers))
	}
	if m.Phase1.Source == DemoPhase1Source {
		c.logf("WARNING: phase 1 is an insecure demo; these keys must never be used")
	}
	var imported *mpcsetup.SrsCommons
	if ptauPath != "" {
		sha, b2, err := ptauHashes(ptauPath)
		if err != nil {
			return err
		}
		if sha != m.Phase1.PtauSHA256 || b2 != m.Phase1.PtauBLAKE2b {
			return fmt.Errorf("%s is not the powers-of-tau file the ceremony imported", ptauPath)
		}
		if imported, _, err = ImportPtau(ptauPath); err != nil {
			return err
		}
	}
	all, err := c.loadSRS(m)
	if err != nil {
		return err
	}
	for _, p := range powers {
		srs := all[p]
		if len(srs.G1.AlphaTau) != 1<<p {
			return fmt.Errorf("phase 1 parameters for 2^%d have the wrong size", p)
		}
		if err := checkSRS(srs); err != nil {
			return fmt.Errorf("phase 1 parameters for 2^%d: %w", p, err)
		}
		if imported != nil {
			want, err := truncateSRS(imported, uint64(1)<<p)
			if err != nil {
				return err
			}
			sha, err := hashOf(want)
			if err != nil {
				return err
			}
			rec, _ := m.srs(p)
			if sha != rec.SHA256 {
				return fmt.Errorf("phase 1 parameters for 2^%d do not derive from the powers-of-tau file", p)
			}
		}
	}
	c.logf("phase 1 parameters verify (source: %s)", m.Phase1.Source)
	return nil
}

// checkReleases checks the release list is well formed: consecutive
// versions, each covering more contributions than the last and using the
// beacon announced by its last contribution.
func checkReleases(m *Manifest) error {
	for i, c := range m.Phase2.Contributions {
		if c.Index != i+1 {
			return fmt.Errorf("contribution %d has index %d", i+1, c.Index)
		}
	}
	prev := 0
	for i, r := range m.Phase2.Releases {
		if r.Version != i+1 {
			return fmt.Errorf("release %d has version %d", i+1, r.Version)
		}
		if r.Contributions <= prev || r.Contributions > len(m.Phase2.Contributions) {
			return fmt.Errorf("release v%d covers %d contributions", r.Version, r.Contributions)
		}
		if want := m.Phase2.Contributions[r.Contributions-1].Beacon; r.Beacon.Source != want {
			return fmt.Errorf("release v%d uses beacon %q, but its last contribution announced %q", r.Version, r.Beacon.Source, want)
		}
		prev = r.Contributions
	}
	return nil
}

// replayPhase2 verifies every phase 2 contribution for one circuit, in order.
// It returns the latest state (the initial one if nobody has contributed) and
// the circuit's evaluations, which sealing needs. Initialising is the
// expensive step, so it happens once per circuit.
func (c *Ceremony) replayPhase2(m *Manifest, cc *compiled, srs *mpcsetup.SrsCommons) (*mpcsetup.Phase2, *mpcsetup.Phase2Evaluations, error) {
	start := time.Now()
	lag, err := c.lag.get(srs)
	if err != nil {
		return nil, nil, err
	}
	prev, evals, err := initializePhase2(cc.R1CS, srs, lag)
	if err != nil {
		return nil, nil, err
	}
	c.logf("%s (2^%d): prepared in %s", cc.Name, cc.Power, since(start))
	start = time.Now()
	for _, contrib := range m.Phase2.Contributions {
		next, err := c.readPhase2(contrib, cc.Name)
		if err != nil {
			return nil, nil, err
		}
		if err := prev.Verify(next); err != nil {
			return nil, nil, fmt.Errorf("contribution %d by %s for %s does not verify: %w", contrib.Index, contrib.Name, cc.Name, err)
		}
		prev = next
	}
	if n := len(m.Phase2.Contributions); n > 0 {
		c.logf("%s: %d contribution(s) checked in %s", cc.Name, n, since(start))
	}
	return prev, evals, nil
}

// sealAt derives the keys for one circuit from the first n contributions and
// a beacon, using evals from replayPhase2. Seal only reads evals, so they can
// be shared across releases. The caller must have verified the transcript.
func (c *Ceremony) sealAt(m *Manifest, cc *compiled, srs *mpcsetup.SrsCommons, evals *mpcsetup.Phase2Evaluations, n int, beacon []byte) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	last, err := c.readPhase2(m.Phase2.Contributions[n-1], cc.Name)
	if err != nil {
		return nil, nil, err
	}
	pk, vk := last.Seal(srs, evals, beacon)
	return pk, vk, nil
}

func (c *Ceremony) readPhase2(contrib Contribution, circuit string) (*mpcsetup.Phase2, error) {
	want, ok := contrib.Files[circuit]
	if !ok {
		return nil, fmt.Errorf("contribution %d by %s has no file for %s", contrib.Index, contrib.Name, circuit)
	}
	p := new(mpcsetup.Phase2)
	if err := readObject(filepath.Join(c.Dir, contrib.Path, circuit+".bin"), want, p); err != nil {
		return nil, err
	}
	return p, nil
}

// compileAll compiles the configured circuits in order.
func (c *Ceremony) compileAll() ([]*compiled, error) {
	if len(c.Circuits) == 0 {
		return nil, errors.New("no circuits configured")
	}
	start := time.Now()
	out := make([]*compiled, len(c.Circuits))
	errs := make([]error, len(c.Circuits))
	sem := make(chan struct{}, c.jobs())
	var wg sync.WaitGroup
	for i, circ := range c.Circuits {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i], errs[i] = compile(circ)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	c.logf("compiled %d circuits in %s", len(out), since(start))
	return out, nil
}

// checkCircuits compiles the circuits and requires them to match the manifest
// exactly, so nobody contributes to or releases keys for a different circuit.
func (c *Ceremony) checkCircuits(m *Manifest) ([]*compiled, error) {
	circuits, err := c.compileAll()
	if err != nil {
		return nil, err
	}
	if len(circuits) != len(m.Circuits) {
		return nil, fmt.Errorf("the code has %d circuits, the manifest records %d", len(circuits), len(m.Circuits))
	}
	for i, cc := range circuits {
		rec := m.Circuits[i]
		if cc.Name != rec.Name || cc.Verifier != rec.Verifier {
			return nil, fmt.Errorf("circuit %d is %s/%s, the manifest records %s/%s", i, cc.Name, cc.Verifier, rec.Name, rec.Verifier)
		}
		if cc.Hash != rec.R1CSSHA256 {
			return nil, fmt.Errorf("circuit %s compiles to R1CS %s, the manifest records %s: the circuit code differs from the ceremony's", cc.Name, cc.Hash, rec.R1CSSHA256)
		}
		if cc.Power > m.Phase1.Power {
			return nil, fmt.Errorf("circuit %s needs 2^%d, phase 1 is 2^%d", cc.Name, cc.Power, m.Phase1.Power)
		}
	}
	return circuits, nil
}

func (c *Ceremony) logf(format string, args ...any) {
	if c.Log == nil {
		return
	}
	c.logMu.Lock()
	defer c.logMu.Unlock()
	fmt.Fprintf(c.Log, format+"\n", args...)
}

func (c *Ceremony) jobs() int {
	if c.Jobs > 0 {
		return c.Jobs
	}
	return AutoJobs()
}

// forEach runs fn for every circuit, at most jobs() at a time, and returns the
// first error in circuit order.
func (c *Ceremony) forEach(circuits []*compiled, fn func(i int, cc *compiled) error) error {
	c.logf("processing %d circuits, %d at a time", len(circuits), c.jobs())
	errs := make([]error, len(circuits))
	sem := make(chan struct{}, c.jobs())
	var wg sync.WaitGroup
	for i, cc := range circuits {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			errs[i] = fn(i, cc)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// loadSRS reads every phase 1 parameter set the circuits need, keyed by
// power. The sets are only read afterwards, so workers can share them.
func (c *Ceremony) loadSRS(m *Manifest) (map[int]*mpcsetup.SrsCommons, error) {
	out := make(map[int]*mpcsetup.SrsCommons, len(m.Phase1.SRS))
	for _, p := range circuitPowers(m) {
		rec, err := m.srs(p)
		if err != nil {
			return nil, err
		}
		srs := new(mpcsetup.SrsCommons)
		if err := readObject(filepath.Join(c.Dir, rec.Path), rec.SHA256, srs); err != nil {
			return nil, err
		}
		out[p] = srs
	}
	return out, nil
}

// artifacts returns one circuit's release artifacts keyed by outDir-relative
// path. The raw Solidity verifier is keyed <Verifier>_raw.sol, the name it has
// after convert_verifiers.sh converts it.
func artifacts(cc *compiled, pk groth16.ProvingKey, vk groth16.VerifyingKey) (map[string][]byte, error) {
	out := make(map[string][]byte, 4)
	for rel, obj := range map[string]io.WriterTo{
		"keys/" + cc.Name + "Pk.key":    pk,
		"keys/" + cc.Name + "Vk.key":    vk,
		"circuits/" + cc.Name + ".r1cs": cc.R1CS,
	} {
		var buf bytes.Buffer
		if _, err := obj.WriteTo(&buf); err != nil {
			return nil, fmt.Errorf("serialize %s: %w", rel, err)
		}
		out[rel] = buf.Bytes()
	}
	var sol bytes.Buffer
	if err := vk.ExportSolidity(&sol); err != nil {
		return nil, fmt.Errorf("export verifier for %s: %w", cc.Name, err)
	}
	out[cc.Verifier+"_raw.sol"] = sol.Bytes()
	return out, nil
}

// writeOutputs writes one circuit's artifacts under outDir and returns their
// hashes. The raw verifier is written as <Verifier>.sol, for conversion.
func writeOutputs(outDir string, cc *compiled, pk groth16.ProvingKey, vk groth16.VerifyingKey) (map[string]string, error) {
	files, err := artifacts(cc, pk, vk)
	if err != nil {
		return nil, err
	}
	hashes := make(map[string]string, len(files))
	for rel, b := range files {
		path := filepath.Join(outDir, rel)
		if strings.HasSuffix(rel, "_raw.sol") {
			path = filepath.Join(outDir, cc.Verifier+".sol")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create %s: %w", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
		hashes[rel] = sha256Hex(b)
	}
	return hashes, nil
}

// checkOutputs compares re-derived artifacts with the release record and, if
// outDir is set, with the files there.
func checkOutputs(rel *Release, cc *compiled, pk groth16.ProvingKey, vk groth16.VerifyingKey, outDir string) error {
	files, err := artifacts(cc, pk, vk)
	if err != nil {
		return err
	}
	for name, b := range files {
		sha := sha256Hex(b)
		if rel.Outputs[name] != sha {
			return fmt.Errorf("%s: re-derived %s, manifest records %s", name, sha, rel.Outputs[name])
		}
		if outDir == "" {
			continue
		}
		if strings.HasSuffix(name, "_raw.sol") {
			if err := checkVerifiers(outDir, cc.Verifier, b); err != nil {
				return err
			}
			continue
		}
		path := filepath.Join(outDir, name)
		got, err := fileSHA256(path)
		if err != nil {
			return err
		}
		if got != sha {
			return fmt.Errorf("%s: sha256 %s, but the ceremony derives %s", path, got, sha)
		}
	}
	return nil
}

// solidityConstant matches a constant declaration in a generated verifier.
var solidityConstant = regexp.MustCompile(`(?m)^\s*uint256\s+constant\s+([A-Za-z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*;`)

// solidityConstants returns a verifier's constant declarations, which hold
// its verifying key, in order.
func solidityConstants(src []byte) []string {
	var out []string
	for _, m := range solidityConstant.FindAllSubmatch(src, -1) {
		out = append(out, string(m[1])+"="+string(m[2]))
	}
	return out
}

// checkVerifiers checks that <Verifier>.sol and, if present,
// <Verifier>_raw.sol in outDir embed the same verifying key as raw, the
// verifier exported from the release. convert_verifiers.sh rewrites
// both files (contract name, wrapper function), so only their constants are
// compared, not their bytes.
func checkVerifiers(outDir, verifier string, raw []byte) error {
	want := solidityConstants(raw)
	if len(want) == 0 {
		return fmt.Errorf("%s: exported verifier has no constants", verifier)
	}
	for _, name := range []string{verifier + ".sol", verifier + "_raw.sol"} {
		path := filepath.Join(outDir, name)
		src, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) && name != verifier+".sol" {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if got := solidityConstants(src); !slices.Equal(got, want) {
			return fmt.Errorf("%s: its verifying-key constants differ from the verifier the ceremony derives", path)
		}
	}
	return nil
}

// demoPhase1 generates phase 1 parameters with one local contribution. Whoever
// runs it could keep the toxic waste, so it is only for rehearsals.
func demoPhase1(power int) *mpcsetup.SrsCommons {
	p := mpcsetup.NewPhase1(uint64(1) << power)
	p.Contribute()
	s := p.Seal([]byte("insecure demo phase 1 beacon"))
	return &s
}

// ptauHashes returns the SHA-256 and BLAKE2b-512 of a powers-of-tau file; the
// Perpetual Powers of Tau publishes BLAKE2b hashes.
func ptauHashes(path string) (sha, b2 string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h2, err := blake2b.New512(nil)
	if err != nil {
		return "", "", err
	}
	h1 := sha256.New()
	if _, err := io.Copy(io.MultiWriter(h1, h2), f); err != nil {
		return "", "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h1.Sum(nil)), hex.EncodeToString(h2.Sum(nil)), nil
}

// bundleHash is the published hash of a contribution: SHA-256 over
// "<circuit> <file sha256>\n" lines in manifest order.
func bundleHash(circuits []CircuitRecord, files map[string]string) string {
	var b strings.Builder
	for _, rec := range circuits {
		fmt.Fprintf(&b, "%s %s\n", rec.Name, files[rec.Name])
	}
	return sha256Hex([]byte(b.String()))
}

// circuitPowers returns the distinct circuit domain sizes, largest first.
func circuitPowers(m *Manifest) []int {
	seen := map[int]bool{}
	var out []int
	for _, rec := range m.Circuits {
		if !seen[rec.Power] {
			seen[rec.Power] = true
			out = append(out, rec.Power)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

func decodeBeacon(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, fmt.Errorf("beacon must be hex: %w", err)
	}
	if len(b) < minBeaconBytes {
		return nil, fmt.Errorf("beacon must be at least %d bytes, got %d", minBeaconBytes, len(b))
	}
	return b, nil
}

func gnarkVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/consensys/gnark" {
			return dep.Version
		}
	}
	return "unknown"
}

// since formats the time elapsed since start for progress messages.
func since(start time.Time) string {
	return time.Since(start).Round(time.Second).String()
}
