package ceremony

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
)

// encodePhase2 serializes a starting state and its evaluations for comparison.
func encodePhase2(t *testing.T, p *mpcsetup.Phase2, e *mpcsetup.Phase2Evaluations) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := p.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	enc := curve.NewEncoder(&buf, curve.RawEncoding())
	for _, v := range []any{e.G1.A, e.G1.B, e.G1.VKK, e.G2.B} {
		if err := enc.Encode(v); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Fprintf(&buf, "%d %v", len(e.G1.CKK), e.PublicAndCommitmentCommitted)
	return buf.Bytes()
}

// checkInitializeMatchesGnark compares initializePhase2 with gnark's
// Phase2.Initialize for one circuit, byte for byte, and returns both timings.
func checkInitializeMatchesGnark(t *testing.T, circ Circuit) (gnark, ours time.Duration) {
	t.Helper()
	cc, err := compile(circ)
	if err != nil {
		t.Fatal(err)
	}
	srs := demoPhase1(cc.Power)

	start := time.Now()
	want := new(mpcsetup.Phase2)
	wantEvals := want.Initialize(cc.R1CS, srs)
	gnark = time.Since(start)

	start = time.Now()
	lag, err := computeLagrange(srs)
	if err != nil {
		t.Fatal(err)
	}
	got, gotEvals, err := initializePhase2(cc.R1CS, srs, lag)
	if err != nil {
		t.Fatal(err)
	}
	ours = time.Since(start)

	if !bytes.Equal(encodePhase2(t, want, &wantEvals), encodePhase2(t, got, gotEvals)) {
		t.Fatalf("%s: initializePhase2 differs from gnark's Phase2.Initialize", circ.Name)
	}
	// The states must also behave the same: a contribution on top of ours
	// verifies against gnark's starting state.
	next := new(mpcsetup.Phase2)
	if _, err := next.ReadFrom(bytes.NewReader(encodeOnly(t, got))); err != nil {
		t.Fatal(err)
	}
	next.Contribute()
	if err := want.Verify(next); err != nil {
		t.Fatalf("%s: contribution on the fast state does not verify against gnark's: %v", circ.Name, err)
	}
	return gnark, ours
}

func encodeOnly(t *testing.T, p *mpcsetup.Phase2) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := p.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestInitializeMatchesGnark(t *testing.T) {
	t.Parallel()
	circuits := DemoCircuits()
	if !testing.Short() {
		for _, c := range ProductionCircuits() {
			if c.Name == "Erc721Ownership" {
				circuits = append(circuits, c)
			}
		}
	}
	for _, c := range circuits {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			gnark, ours := checkInitializeMatchesGnark(t, c)
			t.Logf("gnark %v, ours %v", gnark.Round(time.Millisecond), ours.Round(time.Millisecond))
		})
	}
}

// TestInitializeMatchesGnarkLarge checks a 2^16 production circuit. It takes
// minutes (gnark's side is the slow one), so it only runs with CEREMONY_LONG=1.
func TestInitializeMatchesGnarkLarge(t *testing.T) {
	if os.Getenv("CEREMONY_LONG") != "1" {
		t.Skip("set CEREMONY_LONG=1 to run")
	}
	for _, c := range ProductionCircuits() {
		if c.Name == "Enygmak2" {
			gnark, ours := checkInitializeMatchesGnark(t, c)
			t.Logf("Enygmak2 (2^16): gnark %v, ours %v", gnark.Round(time.Second), ours.Round(time.Second))
		}
	}
}
