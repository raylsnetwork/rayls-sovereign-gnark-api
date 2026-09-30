package erc721_ownership

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/internal/dvptest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

const (
	ownerSk    = "123456789012345678901234567890"
	attackerSk = "555555555555555555555555555555"
	uid        = "42"
	saltIn     = "1001"
	saltOut    = "2002"
	revertSalt = "3003"
	leafIndex  = 5
)

func compile(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Erc721OwnershipCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return ccs
}

// honestWitness builds a valid transfer of the NFT held by ownerSk, using the
// same off-circuit helpers the relayer uses.
func honestWitness(t *testing.T) *Erc721OwnershipCircuit {
	t.Helper()
	recipientPK := primitives.DerivePublicKeyBN254("777")

	w := &Erc721OwnershipCircuit{PaymentCommitment: 111, TreeNumber: 1}
	setInput(t, w, ownerSk, leafIndex)
	w.RecipientPK[0] = recipientPK
	w.SaltsOut[0] = saltOut
	w.UIdOut[0] = uid
	w.CommitmentsOut[0] = primitives.ComputeCommitmentV2ERC721BN254(recipientPK, saltOut, uid)
	return w
}

// setInput makes the input the NFT note held by sk at index, in a tree whose
// root is computed off-circuit, and sets the matching revert commitment.
func setInput(t *testing.T, w *Erc721OwnershipCircuit, sk string, index uint) {
	t.Helper()
	pk := primitives.DerivePublicKeyBN254(sk)
	leaf := primitives.ParseBigInt(primitives.ComputeCommitmentV2ERC721BN254(pk, saltIn, uid))
	path, root := dvptest.MerklePath(t, leaf, index, merkleTreeDepth)
	for j := range path {
		w.PathElements[0][j] = path[j]
	}
	w.MerkleRoot = root
	w.PrivateKeys[0] = sk
	w.SaltsIn[0] = saltIn
	w.UIdIn[0] = uid
	w.PathIndices[0] = index
	w.Nullifiers[0] = primitives.ComputeNullifierBN254(sk, fmt.Sprint(index))
	w.RevertSalt = revertSalt
	w.RevertCommitment = primitives.ComputeCommitmentV2ERC721BN254(pk, revertSalt, uid)
}

func isSolved(t *testing.T, ccs constraint.ConstraintSystem, a *Erc721OwnershipCircuit, opts ...solver.Option) error {
	t.Helper()
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	return ccs.IsSolved(w, opts...)
}

func TestErc721OwnershipProofVerifiesAndBindsPublicInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("groth16 setup and prove")
	}
	ccs := compile(t)
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	w, err := frontend.NewWitness(honestWitness(t), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	pub, err := w.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// The proof must not verify once a public input is changed.
	tests := []struct {
		name   string
		mutate func(w *Erc721OwnershipCircuit)
	}{
		{"other PaymentCommitment (message)", func(w *Erc721OwnershipCircuit) { w.PaymentCommitment = 112 }},
		{"other TreeNumber", func(w *Erc721OwnershipCircuit) { w.TreeNumber = 2 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := honestWitness(t)
			tc.mutate(a)
			pub, err := frontend.NewWitness(a, ecc.BN254.ScalarField(), frontend.PublicOnly())
			if err != nil {
				t.Fatalf("public witness: %v", err)
			}
			if err := groth16.Verify(proof, vk, pub); err == nil {
				t.Fatal("proof verified with a changed public input")
			}
		})
	}
}

func TestErc721OwnershipRejectsAttacks(t *testing.T) {
	t.Parallel()
	ccs := compile(t)
	ownerPK := primitives.ParseBigInt(primitives.DerivePublicKeyBN254(ownerSk))
	l := primitives.JubJubPrimeSubGroup
	lInv := new(big.Int).ModInverse(l, ecc.BN254.ScalarField())

	// A dishonest prover's ModHintBabyJubJub: always claims the owner's public key,
	// with the quotient that makes q*l + r == x hold in the field.
	claimOwnerPK := solver.OverrideHint(solver.GetHintID(primitives.ModHintBabyJubJub),
		func(_ *big.Int, in, out []*big.Int) error {
			q := new(big.Int).Sub(in[0], ownerPK)
			q.Mul(q, lInv).Mod(q, ecc.BN254.ScalarField())
			out[0].Set(ownerPK)
			out[1].Set(q)
			return nil
		})

	tests := []struct {
		name   string
		mutate func(w *Erc721OwnershipCircuit)
		opts   []solver.Option
	}{
		{
			// sk = 0, pathIndex = 0 gives the dummy nullifier, which makes the vault
			// skip its root check, so an NFT note in a made-up tree would be accepted.
			name:   "real NFT behind the dummy nullifier",
			mutate: func(w *Erc721OwnershipCircuit) { setInput(t, w, "0", 0) },
		},
		{
			name:   "forged nullifier (double spend)",
			mutate: func(w *Erc721OwnershipCircuit) { w.Nullifiers[0] = 1337 },
		},
		{
			name:   "forged merkle root (fake membership)",
			mutate: func(w *Erc721OwnershipCircuit) { w.MerkleRoot = 1337 },
		},
		{
			name:   "forged output commitment",
			mutate: func(w *Erc721OwnershipCircuit) { w.CommitmentsOut[0] = 1337 },
		},
		{
			name: "stolen note: attacker key, owner's public key via forged hint",
			mutate: func(w *Erc721OwnershipCircuit) {
				w.PrivateKeys[0] = attackerSk
				w.Nullifiers[0] = primitives.ComputeNullifierBN254(attackerSk, "5")
			},
			opts: []solver.Option{claimOwnerPK},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := honestWitness(t)
			tc.mutate(w)
			if err := isSolved(t, ccs, w, tc.opts...); err == nil {
				t.Fatal("attack witness was accepted")
			}
		})
	}
}

func TestErc721OwnershipHonestWitnessSolves(t *testing.T) {
	t.Parallel()
	if err := isSolved(t, compile(t), honestWitness(t)); err != nil {
		t.Fatalf("honest witness rejected: %v", err)
	}
}
