package common

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

const k = 3

var (
	field = ecc.BN254.ScalarField()
	l     = primitives.JubJubPrimeSubGroup
)

func solve(t *testing.T, circuit, assignment frontend.Circuit, opts ...solver.Option) error {
	t.Helper()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	w, err := frontend.NewWitness(assignment, field)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	return ccs.IsSolved(w, opts...)
}

func hash(t *testing.T, in ...*big.Int) *big.Int {
	t.Helper()
	h, err := poseidon.Hash(in)
	if err != nil {
		t.Fatalf("poseidon: %v", err)
	}
	return h
}

func hashModL(t *testing.T, in ...*big.Int) *big.Int {
	return new(big.Int).Mod(hash(t, in...), l)
}

// forgeRemainders is a dishonest ModHintBabyJubJub. For each input listed in
// claims it returns the claimed remainder, with the field quotient that
// satisfies q*l + r == x; every other input is reduced honestly.
func forgeRemainders(claims map[string]*big.Int) solver.Option {
	lInv := new(big.Int).ModInverse(l, field)
	return solver.OverrideHint(solver.GetHintID(primitives.ModHintBabyJubJub), func(_ *big.Int, in, out []*big.Int) error {
		r, ok := claims[in[0].String()]
		if !ok {
			out[1].DivMod(in[0], l, out[0])
			return nil
		}
		q := new(big.Int).Sub(in[0], r)
		q.Mul(q, lInv).Mod(q, field)
		out[0].Set(r)
		out[1].Set(q)
		return nil
	})
}

// fixture is an honest k=3 anonymity set where participant 1 is the sender.
type fixture struct {
	senderID, secretKey, previousR, blockNumber *big.Int
	anonymitySet, sharedSecrets, publicKeys     [k]*big.Int
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{
		senderID:    big.NewInt(20),
		secretKey:   big.NewInt(123456789),
		previousR:   big.NewInt(4242),
		blockNumber: big.NewInt(1000),
	}
	for i := 0; i < k; i++ {
		f.anonymitySet[i] = big.NewInt(int64(10 * (i + 1)))
		f.sharedSecrets[i] = big.NewInt(int64(900 + i))
		f.publicKeys[i] = big.NewInt(int64(5000 + i))
	}
	f.sharedSecrets[1] = hashModL(t, f.previousR, f.secretKey)
	f.publicKeys[1] = hashModL(t, f.secretKey, f.secretKey)
	return f
}

type checksCircuit struct {
	SenderID, SecretKey, PreviousR, BlockNumber frontend.Variable
	AnonymitySet, SharedSecrets, PublicKeys     [k]frontend.Variable
	HashSecrets, MessageTags, TxRandom          [k]frontend.Variable
}

func (c *checksCircuit) Define(api frontend.API) error {
	if err := CheckSecretKnowledge(api, k, c.SenderID, c.AnonymitySet[:], c.SharedSecrets[:], c.PreviousR, c.SecretKey); err != nil {
		return err
	}
	if err := CheckHashArrayOfSecrets(api, k, c.SharedSecrets[:], c.HashSecrets[:]); err != nil {
		return err
	}
	if err := CheckPublicKeyKnowledge(api, k, c.SenderID, c.AnonymitySet[:], c.PublicKeys[:], c.SecretKey); err != nil {
		return err
	}
	if err := CheckMessageTags(api, k, c.SharedSecrets[:], c.BlockNumber, c.MessageTags[:]); err != nil {
		return err
	}
	return CheckRandomFactors(api, k, c.SenderID, c.AnonymitySet[:], c.SharedSecrets[:], c.BlockNumber, c.TxRandom[:])
}

// honestAssignment computes every checked value off-circuit.
func honestAssignment(t *testing.T, f fixture) *checksCircuit {
	t.Helper()
	a := &checksCircuit{SenderID: f.senderID, SecretKey: f.secretKey, PreviousR: f.previousR, BlockNumber: f.blockNumber}
	hashTag := hash(t, big.NewInt(12))
	hashRandom := hash(t, big.NewInt(21))
	sum := new(big.Int)
	for i := 0; i < k; i++ {
		a.AnonymitySet[i] = f.anonymitySet[i]
		a.SharedSecrets[i] = f.sharedSecrets[i]
		a.PublicKeys[i] = f.publicKeys[i]
		a.HashSecrets[i] = hashModL(t, f.sharedSecrets[i], f.sharedSecrets[i])
		a.MessageTags[i] = hashModL(t, hashTag, f.sharedSecrets[i], f.blockNumber)

		h := hashModL(t, hashRandom, f.sharedSecrets[i], f.blockNumber)
		if f.anonymitySet[i].Cmp(f.senderID) != 0 {
			a.TxRandom[i] = new(big.Int).Sub(l, h)
			sum.Add(sum, h)
		}
	}
	for i := 0; i < k; i++ {
		if f.anonymitySet[i].Cmp(f.senderID) == 0 {
			a.TxRandom[i] = new(big.Int).Mod(sum, l)
		}
	}
	return a
}

func TestPaymentChecksHonest(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if err := solve(t, &checksCircuit{}, honestAssignment(t, f)); err != nil {
		t.Fatalf("honest witness rejected: %v", err)
	}
}

func TestPaymentChecksRejectForgedHints(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	forged := big.NewInt(1337)
	hashRandom := hash(t, big.NewInt(21))

	// Each case changes one witness value and forges only the reductions that
	// value depends on, so every other check stays honest. On the old code
	// (unbounded quotient, or no constraint at all) each of these was accepted.
	tests := []struct {
		name   string
		mutate func(t *testing.T, a *checksCircuit) map[string]*big.Int
	}{
		{
			name: "spend without the sender's secret key",
			mutate: func(t *testing.T, a *checksCircuit) map[string]*big.Int {
				wrongSk := big.NewInt(999)
				a.SecretKey = wrongSk
				return map[string]*big.Int{
					hash(t, f.previousR, wrongSk).String(): f.sharedSecrets[1],
					hash(t, wrongSk, wrongSk).String():     f.publicKeys[1],
				}
			},
		},
		{
			name: "forged hash of secrets (nullifier preimage)",
			mutate: func(t *testing.T, a *checksCircuit) map[string]*big.Int {
				a.HashSecrets[0] = forged
				return map[string]*big.Int{hash(t, f.sharedSecrets[0], f.sharedSecrets[0]).String(): forged}
			},
		},
		{
			name: "forged message tag",
			mutate: func(t *testing.T, a *checksCircuit) map[string]*big.Int {
				a.MessageTags[2] = forged
				x := hash(t, hash(t, big.NewInt(12)), f.sharedSecrets[2], f.blockNumber)
				return map[string]*big.Int{x.String(): forged}
			},
		},
		{
			name: "forged random factor",
			mutate: func(t *testing.T, a *checksCircuit) map[string]*big.Int {
				// Receiver 0 gets a forged factor; the sender's is rebalanced to match.
				h2 := hashModL(t, hashRandom, f.sharedSecrets[2], f.blockNumber)
				a.TxRandom[0] = new(big.Int).Sub(l, forged)
				a.TxRandom[1] = new(big.Int).Mod(new(big.Int).Add(forged, h2), l)
				x := hash(t, hashRandom, f.sharedSecrets[0], f.blockNumber)
				return map[string]*big.Int{x.String(): forged}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := honestAssignment(t, f)
			claims := tc.mutate(t, a)
			if err := solve(t, &checksCircuit{}, a, forgeRemainders(claims)); err == nil {
				t.Fatal("forged witness was accepted")
			}
		})
	}
}
