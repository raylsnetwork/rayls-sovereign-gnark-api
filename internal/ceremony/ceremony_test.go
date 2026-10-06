package ceremony

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/frontend"
)

// Two circuits needing different domain sizes, so phase 1 is truncated.
func testCircuits() []Circuit { return DemoCircuits() }

const (
	beacon1 = "00112233445566778899aabbccddeeff"
	beacon2 = "ffeeddccbbaa99887766554433221100"
	source1 = "drand quicknet round 100"
	source2 = "drand quicknet round 200"
)

// testPtau writes a snarkjs-format powers-of-tau file of the given power.
func testPtau(t *testing.T, power int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.ptau")
	writePtau(t, path, demoPhase1(power), power)
	return path
}

func newCeremony(t *testing.T) (*Ceremony, string) {
	t.Helper()
	ptau := testPtau(t, 8)
	c := &Ceremony{Dir: filepath.Join(t.TempDir(), "ceremony"), Circuits: testCircuits()}
	if _, err := c.Init(InitOptions{PtauPath: ptau, PtauSource: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	return c, ptau
}

// twoReleases runs contribute+finalize twice and returns the output dir.
func twoReleases(t *testing.T, c *Ceremony) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "last_build")
	if _, err := c.Contribute("alice", source1); err != nil {
		t.Fatalf("contribute alice: %v", err)
	}
	if _, err := c.Finalize(beacon1, out); err != nil {
		t.Fatalf("release v1: %v", err)
	}
	if _, err := c.Contribute("bob", source2); err != nil {
		t.Fatalf("contribute bob: %v", err)
	}
	if _, err := c.Finalize(beacon2, out); err != nil {
		t.Fatalf("release v2: %v", err)
	}
	return out
}

func TestPtauImportRoundTrip(t *testing.T) {
	t.Parallel()
	srs := demoPhase1(6)
	path := filepath.Join(t.TempDir(), "x.ptau")
	writePtau(t, path, srs, 6)
	got, power, err := ImportPtau(path)
	if err != nil {
		t.Fatal(err)
	}
	if power != 6 {
		t.Fatalf("power %d, want 6", power)
	}
	a, _ := hashOf(srs)
	b, _ := hashOf(got)
	if a != b {
		t.Fatal("imported parameters differ from the written ones")
	}
}

func TestPtauImportRejectsBadFiles(t *testing.T) {
	t.Parallel()
	srs := demoPhase1(5)
	tests := []struct {
		name   string
		mutate func(b []byte) []byte
	}{
		{"wrong magic", func(b []byte) []byte { b[0] = 'x'; return b }},
		{"other curve", func(b []byte) []byte { b[ptauSectionOffset(b, ptauHeader)+4] ^= 1; return b }},
		{"point off the curve", func(b []byte) []byte { b[ptauSectionOffset(b, ptauTauG1)+3*g1Bytes+5] ^= 1; return b }},
		{"truncated", func(b []byte) []byte { return b[:len(b)-10] }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "x.ptau")
			writePtau(t, path, srs, 5)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, tc.mutate(b), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ImportPtau(path); err == nil {
				t.Fatal("bad ptau file imported")
			}
		})
	}

	t.Run("valid points but not powers of one tau", func(t *testing.T) {
		t.Parallel()
		bad := demoPhase1(5)
		bad.G1.Tau[3], bad.G1.Tau[4] = bad.G1.Tau[4], bad.G1.Tau[3]
		path := filepath.Join(t.TempDir(), "x.ptau")
		writePtau(t, path, bad, 5)
		if _, _, err := ImportPtau(path); err == nil || !strings.Contains(err.Error(), "powers of tau") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestCeremonyReleases(t *testing.T) {
	t.Parallel()
	c, ptau := newCeremony(t)
	out := filepath.Join(t.TempDir(), "last_build")

	if _, err := c.Contribute("alice", source1); err != nil {
		t.Fatal(err)
	}
	v1, err := c.Finalize(beacon1, out)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(out, ptau); err != nil {
		t.Fatalf("verify after v1: %v", err)
	}
	proveWithRelease(t, c, out)

	if _, err := c.Contribute("bob", source2); err != nil {
		t.Fatal(err)
	}
	v2, err := c.Finalize(beacon2, out)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(out, ptau); err != nil {
		t.Fatalf("verify after v2: %v", err)
	}
	proveWithRelease(t, c, out)

	if v1.Version != 1 || v2.Version != 2 || v1.Contributions != 1 || v2.Contributions != 2 {
		t.Fatalf("unexpected releases %+v %+v", v1, v2)
	}
	if v2.Beacon.Source != source2 {
		t.Fatalf("v2 beacon %q, want %q", v2.Beacon.Source, source2)
	}
	for k := range v1.Outputs {
		if strings.Contains(k, "Pk.key") && v1.Outputs[k] == v2.Outputs[k] {
			t.Errorf("%s did not change between releases", k)
		}
	}
}

func TestCeremonyFinalizeIsDeterministic(t *testing.T) {
	t.Parallel()
	c, _ := newCeremony(t)
	if _, err := c.Contribute("alice", source1); err != nil {
		t.Fatal(err)
	}
	copyDir := filepath.Join(t.TempDir(), "copy")
	copyTree(t, c.Dir, copyDir)
	c2 := &Ceremony{Dir: copyDir, Circuits: testCircuits()}
	out1, out2 := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	r1, err := c.Finalize(beacon1, out1)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := c2.Finalize(beacon1, out2)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range r1.Outputs {
		if r2.Outputs[k] != v {
			t.Errorf("%s differs between two finalizations of the same transcript", k)
		}
	}
}

func TestCeremonyVerifyRejectsTampering(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		tamper func(t *testing.T, c *Ceremony, out string) (ptau string)
	}{
		{"contribution file edited", func(t *testing.T, c *Ceremony, _ string) string {
			flipByte(t, filepath.Join(c.Dir, loadManifestT(t, c).Phase2.Contributions[0].Path, "DemoLarge.bin"))
			return ""
		}},
		{"contribution file edited and manifest hash updated", func(t *testing.T, c *Ceremony, _ string) string {
			m := loadManifestT(t, c)
			contrib := m.Phase2.Contributions[1]
			path := filepath.Join(c.Dir, contrib.Path, "DemoLarge.bin")
			flipByte(t, path)
			contrib.Files["DemoLarge"] = mustFileSHA(t, path)
			saveManifestT(t, c, m)
			return ""
		}},
		{"first contribution removed from the chain", func(t *testing.T, c *Ceremony, _ string) string {
			m := loadManifestT(t, c)
			m.Phase2.Contributions = m.Phase2.Contributions[1:]
			m.Phase2.Contributions[0].Index = 1
			m.Phase2.Releases = m.Phase2.Releases[1:]
			m.Phase2.Releases[0].Version, m.Phase2.Releases[0].Contributions = 1, 1
			saveManifestT(t, c, m)
			return ""
		}},
		{"release beacon value changed", func(t *testing.T, c *Ceremony, _ string) string {
			m := loadManifestT(t, c)
			m.Phase2.Releases[0].Beacon.Value = beacon2
			saveManifestT(t, c, m)
			return ""
		}},
		{"release uses a beacon nobody announced", func(t *testing.T, c *Ceremony, _ string) string {
			m := loadManifestT(t, c)
			m.Phase2.Releases[1].Beacon.Source = "drand quicknet round 1"
			saveManifestT(t, c, m)
			return ""
		}},
		{"release claims fewer contributions", func(t *testing.T, c *Ceremony, _ string) string {
			m := loadManifestT(t, c)
			m.Phase2.Releases[1].Contributions = 1
			saveManifestT(t, c, m)
			return ""
		}},
		{"output key replaced", func(t *testing.T, _ *Ceremony, out string) string {
			flipByte(t, filepath.Join(out, "keys", "DemoSmallVk.key"))
			return ""
		}},
		{"verifier constant changed", func(t *testing.T, _ *Ceremony, out string) string {
			editVerifier(t, filepath.Join(out, "DemoSmallVerifier.sol"), changeFirstConstant)
			return ""
		}},
		{"converted raw verifier constant changed", func(t *testing.T, _ *Ceremony, out string) string {
			convertVerifier(t, out, "DemoSmallVerifier")
			editVerifier(t, filepath.Join(out, "DemoSmallVerifier_raw.sol"), changeFirstConstant)
			return ""
		}},
		{"phase 1 parameters edited and hash updated", func(t *testing.T, c *Ceremony, _ string) string {
			m := loadManifestT(t, c)
			rec := &m.Phase1.SRS[0]
			path := filepath.Join(c.Dir, rec.Path)
			flipByte(t, path)
			rec.SHA256 = mustFileSHA(t, path)
			saveManifestT(t, c, m)
			return ""
		}},
		{"a different powers-of-tau file", func(t *testing.T, _ *Ceremony, _ string) string {
			return testPtau(t, 8)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newCeremony(t)
			out := twoReleases(t, c)
			ptau := tc.tamper(t, c, out)
			err := c.Verify(out, ptau)
			if err == nil {
				t.Fatal("tampered ceremony verified")
			}
			if os.Getenv("SHOWERR") != "" {
				t.Logf("REASON: %v", err)
			}
		})
	}
}

func TestCeremonyRejectsChangedCircuits(t *testing.T) {
	t.Parallel()
	c, _ := newCeremony(t)
	changed := testCircuits()
	changed[1].New = func() frontend.Circuit { return &squareChain{n: 101} }
	c.Circuits = changed
	if _, err := c.Contribute("alice", source1); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("contribution against changed circuits: err = %v", err)
	}
	if err := c.Verify("", ""); err == nil {
		t.Fatal("verify accepted changed circuits")
	}
}

func TestCeremonyStateErrors(t *testing.T) {
	t.Parallel()
	c, ptau := newCeremony(t)
	out := t.TempDir()

	if _, err := c.Init(InitOptions{PtauPath: ptau, PtauSource: "test"}); err == nil {
		t.Error("init over an existing ceremony succeeded")
	}
	fresh := &Ceremony{Dir: filepath.Join(t.TempDir(), "x"), Circuits: testCircuits()}
	if _, err := fresh.Init(InitOptions{}); err == nil {
		t.Error("init without a powers-of-tau file succeeded")
	}
	small := &Ceremony{Dir: filepath.Join(t.TempDir(), "y"), Circuits: testCircuits()}
	if _, err := small.Init(InitOptions{PtauPath: testPtau(t, 5), PtauSource: "test"}); err == nil {
		t.Error("init with a too-small powers-of-tau file succeeded")
	}
	if _, err := c.Finalize(beacon1, out); err == nil {
		t.Error("finalize without contributions succeeded")
	}
	for _, name := range []string{"", "Alice", "a b", "../x", strings.Repeat("a", 41)} {
		if _, err := c.Contribute(name, source1); err == nil {
			t.Errorf("contributor name %q was accepted", name)
		}
	}
	if _, err := c.Contribute("alice", " "); err == nil {
		t.Error("a contribution without an announced beacon was accepted")
	}
	if _, err := c.Contribute("alice", source1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Contribute("alice", source2); err == nil {
		t.Error("the same contributor contributed twice")
	}
	if _, err := c.Finalize("abcd", out); err == nil {
		t.Error("a 2-byte beacon was accepted")
	}
	if _, err := c.Finalize(beacon1, out); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Finalize(beacon1, out); err == nil {
		t.Error("a second release without new contributions succeeded")
	}
}

func TestCeremonyDemoPhase1(t *testing.T) {
	t.Parallel()
	c := &Ceremony{Dir: filepath.Join(t.TempDir(), "demo"), Circuits: testCircuits()}
	m, err := c.Init(InitOptions{Demo: true})
	if err != nil {
		t.Fatal(err)
	}
	if m.Phase1.Source != DemoPhase1Source {
		t.Fatalf("phase 1 source %q", m.Phase1.Source)
	}
	if _, err := c.Contribute("alice", source1); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if _, err := c.Finalize(beacon1, out); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	c.Log = &log
	if err := c.Verify(out, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "insecure demo") {
		t.Error("verify did not warn about the demo phase 1")
	}
}

func TestManifestIsStableJSON(t *testing.T) {
	t.Parallel()
	c, _ := newCeremony(t)
	b, err := os.ReadFile(filepath.Join(c.Dir, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Circuits) != 2 || m.Phase1.Power != 8 || len(m.Phase1.SRS) != 2 || !bytes.HasSuffix(b, []byte("\n")) {
		t.Fatalf("unexpected manifest: %s", b)
	}
}

// --- helpers ---

// proveWithRelease proves and verifies each circuit with the keys in out, and
// checks each proving key uses its circuit's own domain size.
func proveWithRelease(t *testing.T, c *Ceremony, out string) {
	t.Helper()
	m := loadManifestT(t, c)
	for i, rec := range m.Circuits {
		pk, vk := loadKeys(t, out, rec.Name)
		if got, want := pk.(*groth16bn254.ProvingKey).Domain.Cardinality, uint64(1)<<rec.Power; got != want {
			t.Errorf("%s: proving key domain %d, want %d", rec.Name, got, want)
		}
		n := testCircuits()[i].New().(*squareChain).n
		cc, err := compile(testCircuits()[i])
		if err != nil {
			t.Fatal(err)
		}
		w, err := frontend.NewWitness(&squareChain{X: 3, Y: squareChainOutput(3, n)}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		proof, err := groth16.Prove(cc.R1CS, pk, w)
		if err != nil {
			t.Fatalf("%s: prove: %v", rec.Name, err)
		}
		pub, err := w.Public()
		if err != nil {
			t.Fatal(err)
		}
		if err := groth16.Verify(proof, vk, pub); err != nil {
			t.Fatalf("%s: verify: %v", rec.Name, err)
		}
	}
}

func loadKeys(t *testing.T, out, name string) (groth16.ProvingKey, groth16.VerifyingKey) {
	t.Helper()
	pk := groth16.NewProvingKey(ecc.BN254)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	readInto(t, filepath.Join(out, "keys", name+"Pk.key"), pk)
	readInto(t, filepath.Join(out, "keys", name+"Vk.key"), vk)
	return pk, vk
}

func readInto(t *testing.T, path string, obj io.ReaderFrom) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := obj.ReadFrom(f); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
}

func squareChainOutput(x int64, n int) *big.Int {
	mod := ecc.BN254.ScalarField()
	y := big.NewInt(x)
	for i := 0; i < n; i++ {
		y.Mul(y, y).Mod(y, mod)
	}
	return y
}

// writePtau writes srs in the snarkjs .ptau layout (sections 1 to 6).
func writePtau(t *testing.T, path string, srs *mpcsetup.SrsCommons, power int) {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("ptau")
	writeLE(&buf, uint32(1))
	writeLE(&buf, uint32(6))

	section := func(typ uint32, body []byte) {
		writeLE(&buf, typ)
		writeLE(&buf, uint64(len(body)))
		buf.Write(body)
	}
	var header bytes.Buffer
	writeLE(&header, uint32(fp.Bytes))
	header.Write(reverse(fp.Modulus().FillBytes(make([]byte, fp.Bytes))))
	writeLE(&header, uint32(power))
	writeLE(&header, uint32(power))
	section(ptauHeader, header.Bytes())
	section(ptauTauG1, encodeG1(srs.G1.Tau))
	section(ptauTauG2, encodeG2(srs.G2.Tau))
	section(ptauAlphaTau1, encodeG1(srs.G1.AlphaTau))
	section(ptauBetaTau1, encodeG1(srs.G1.BetaTau))
	section(ptauBetaG2, encodeG2([]curve.G2Affine{srs.G2.Beta}))
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeLE(buf *bytes.Buffer, v any) {
	if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
		panic(err)
	}
}

func encodeFp(buf *bytes.Buffer, e *fp.Element) {
	for _, limb := range e {
		writeLE(buf, limb)
	}
}

func encodeG1(points []curve.G1Affine) []byte {
	var buf bytes.Buffer
	for i := range points {
		encodeFp(&buf, &points[i].X)
		encodeFp(&buf, &points[i].Y)
	}
	return buf.Bytes()
}

func encodeG2(points []curve.G2Affine) []byte {
	var buf bytes.Buffer
	for i := range points {
		encodeFp(&buf, &points[i].X.A0)
		encodeFp(&buf, &points[i].X.A1)
		encodeFp(&buf, &points[i].Y.A0)
		encodeFp(&buf, &points[i].Y.A1)
	}
	return buf.Bytes()
}

// ptauSectionOffset returns the data offset of a section in an encoded file.
func ptauSectionOffset(b []byte, typ uint32) int {
	pos := 12
	for pos < len(b) {
		t := binary.LittleEndian.Uint32(b[pos:])
		size := int(binary.LittleEndian.Uint64(b[pos+4:]))
		if t == typ {
			return pos + 12
		}
		pos += 12 + size
	}
	return -1
}

func loadManifestT(t *testing.T, c *Ceremony) *Manifest {
	t.Helper()
	m, err := loadManifest(c.Dir)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	return m
}

func saveManifestT(t *testing.T, c *Ceremony, m *Manifest) {
	t.Helper()
	if err := m.save(c.Dir); err != nil {
		t.Fatalf("save manifest: %v", err)
	}
}

func flipByte(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0x01
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustFileSHA(t *testing.T, path string) string {
	t.Helper()
	s, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCeremonyParallelismDoesNotChangeOutputs(t *testing.T) {
	t.Parallel()
	c, _ := newCeremony(t)
	c.Jobs = 4
	if _, err := c.Contribute("alice", source1); err != nil {
		t.Fatal(err)
	}
	copyDir := filepath.Join(t.TempDir(), "copy")
	copyTree(t, c.Dir, copyDir)
	serial := &Ceremony{Dir: copyDir, Circuits: testCircuits(), Jobs: 1}
	r1, err := c.Finalize(beacon1, filepath.Join(t.TempDir(), "a"))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := serial.Finalize(beacon1, filepath.Join(t.TempDir(), "b"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r1.Outputs) == 0 || len(r1.Outputs) != len(r2.Outputs) {
		t.Fatalf("output sets differ: %d vs %d", len(r1.Outputs), len(r2.Outputs))
	}
	for k, v := range r1.Outputs {
		if r2.Outputs[k] != v {
			t.Errorf("%s differs between 4 jobs and 1 job", k)
		}
	}
}

// convertVerifier mimics convert_verifiers.sh: <Verifier>_raw.sol gets a
// renamed contract and a wrapper function, and <Verifier>.sol changes too.
func convertVerifier(t *testing.T, out, verifier string) {
	t.Helper()
	path := filepath.Join(out, verifier+".sol")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Replace(string(src), "contract Verifier", "contract "+verifier+"_raw", 1) +
		"\n// wrapper\nfunction verifyProof() {}\n"
	if err := os.WriteFile(filepath.Join(out, verifier+"_raw.sol"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	editVerifier(t, path, func(s string) string { return "// converted\n" + s })
}

func editVerifier(t *testing.T, path string, edit func(string) string) {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(edit(string(src))), 0o644); err != nil {
		t.Fatal(err)
	}
}

// changeFirstConstant alters the value of the verifier's first verifying-key
// constant (the precompile addresses come first and are skipped).
func changeFirstConstant(s string) string {
	loc := solidityConstant.FindAllStringSubmatchIndex(s, -1)
	for _, m := range loc {
		if strings.HasPrefix(s[m[2]:m[3]], "PRECOMPILE") || s[m[2]:m[3]] == "P" || s[m[2]:m[3]] == "R" {
			continue
		}
		digit := "1"
		if s[m[5]-1] == '1' {
			digit = "2"
		}
		return s[:m[5]-1] + digit + s[m[5]:]
	}
	panic("no verifying-key constant")
}

func TestCeremonyVerifyAcceptsConvertedVerifiers(t *testing.T) {
	t.Parallel()
	c, ptau := newCeremony(t)
	out := twoReleases(t, c)
	for _, v := range []string{"DemoSmallVerifier", "DemoLargeVerifier"} {
		convertVerifier(t, out, v)
	}
	if err := c.Verify(out, ptau); err != nil {
		t.Fatalf("verify with converted verifiers: %v", err)
	}
}
