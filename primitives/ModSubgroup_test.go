package primitives

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var bn254Modulus = ecc.BN254.ScalarField()

// solve compiles circuit to R1CS and runs the real solver on assignment, the
// same path the prover takes, so hint overrides behave as a dishonest prover's.
func solve(t *testing.T, circuit, assignment frontend.Circuit, opts ...solver.Option) error {
	t.Helper()
	ccs, err := frontend.Compile(bn254Modulus, r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	w, err := frontend.NewWitness(assignment, bn254Modulus)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	return ccs.IsSolved(w, opts...)
}

// forgeModHint replaces ModHintBabyJubJub with f, as a dishonest prover can.
func forgeModHint(f func(x *big.Int) (r, q *big.Int)) solver.Option {
	return solver.OverrideHint(solver.GetHintID(ModHintBabyJubJub), func(_ *big.Int, in, out []*big.Int) error {
		r, q := f(in[0])
		out[0].Set(r)
		out[1].Set(q)
		return nil
	})
}

type modSubgroupCircuit struct {
	X, Want frontend.Variable `gnark:",public"`
}

func (c *modSubgroupCircuit) Define(api frontend.API) error {
	r, err := ModSubgroup(api, c.X)
	if err != nil {
		return err
	}
	api.AssertIsEqual(r, c.Want)
	return nil
}

func bi(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad big int: " + s)
	}
	return v
}

func TestModSubgroupHonest(t *testing.T) {
	t.Parallel()
	l := JubJubPrimeSubGroup
	pMinus1 := new(big.Int).Sub(bn254Modulus, big.NewInt(1))
	tests := []struct {
		name string
		x    *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"one", big.NewInt(1)},
		{"l-1", new(big.Int).Sub(l, big.NewInt(1))},
		{"l", new(big.Int).Set(l)},
		{"2l+5", new(big.Int).Add(new(big.Int).Mul(l, big.NewInt(2)), big.NewInt(5))},
		{"7l", new(big.Int).Mul(l, big.NewInt(7))},
		{"p-1 (q=7, max remainder)", pMinus1},
		{"poseidon-sized", bi("19014214495641488759237505126948346942972912379615652741039992445865937985820")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want := new(big.Int).Mod(tc.x, l)
			if err := solve(t, &modSubgroupCircuit{}, &modSubgroupCircuit{X: tc.x, Want: want}); err != nil {
				t.Fatalf("honest reduction rejected: %v", err)
			}
		})
	}
}

func TestModSubgroupRejectsForgedRemainder(t *testing.T) {
	t.Parallel()
	l := JubJubPrimeSubGroup
	lInv := new(big.Int).ModInverse(l, bn254Modulus)
	target := big.NewInt(1337)

	tests := []struct {
		name string
		x    *big.Int
		want *big.Int // the forged remainder the prover claims
		hint func(x *big.Int) (r, q *big.Int)
	}{
		{
			// q = (x - r') / l in the field satisfies q*l + r' == x for any r' < l.
			name: "unbounded quotient",
			x:    bi("19014214495641488759237505126948346942972912379615652741039992445865937985820"),
			want: target,
			hint: func(x *big.Int) (*big.Int, *big.Int) {
				q := new(big.Int).Sub(x, target)
				q.Mul(q, lInv).Mod(q, bn254Modulus)
				return target, q
			},
		},
		{
			// For x < 8l - p, q = 7 and r' = x + p - 7l < l also give 7l + r' == x mod p.
			name: "quotient 7 wraps past the field",
			x:    big.NewInt(5),
			want: new(big.Int).Sub(new(big.Int).Add(big.NewInt(5), bn254Modulus), new(big.Int).Mul(l, big.NewInt(7))),
			hint: func(x *big.Int) (*big.Int, *big.Int) {
				r := new(big.Int).Add(x, bn254Modulus)
				r.Sub(r, new(big.Int).Mul(l, big.NewInt(7)))
				return r, big.NewInt(7)
			},
		},
		{
			name: "remainder not reduced",
			x:    new(big.Int).Add(l, big.NewInt(9)),
			want: new(big.Int).Add(l, big.NewInt(9)),
			hint: func(x *big.Int) (*big.Int, *big.Int) { return new(big.Int).Set(x), big.NewInt(0) },
		},
		{
			name: "arbitrary output",
			x:    big.NewInt(42),
			want: target,
			hint: func(*big.Int) (*big.Int, *big.Int) { return target, big.NewInt(0) },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := solve(t, &modSubgroupCircuit{}, &modSubgroupCircuit{X: tc.x, Want: tc.want}, forgeModHint(tc.hint))
			if err == nil {
				t.Fatalf("forged remainder %s for x=%s was accepted", tc.want, tc.x)
			}
		})
	}
}

func TestForgedPairsAreFieldValid(t *testing.T) {
	t.Parallel()
	// Guards the attack table above: the "unbounded quotient" and "wraps" pairs
	// satisfy the old checks (q*l + r == x mod p and r < l), so they are real attacks.
	l := JubJubPrimeSubGroup
	lInv := new(big.Int).ModInverse(l, bn254Modulus)
	x := bi("19014214495641488759237505126948346942972912379615652741039992445865937985820")
	r := big.NewInt(1337)
	q := new(big.Int).Sub(x, r)
	q.Mul(q, lInv).Mod(q, bn254Modulus)
	if got := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(q, l), r), bn254Modulus); got.Cmp(x) != 0 {
		t.Fatalf("unbounded-quotient pair does not satisfy q*l + r == x")
	}

	x = big.NewInt(5)
	r = new(big.Int).Sub(new(big.Int).Add(x, bn254Modulus), new(big.Int).Mul(l, big.NewInt(7)))
	if r.Cmp(l) >= 0 {
		t.Fatalf("wrap remainder %s is not below l", r)
	}
	if got := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(big.NewInt(7), l), r), bn254Modulus); got.Cmp(x) != 0 {
		t.Fatalf("wrap pair does not satisfy 7*l + r == x mod p")
	}
}
