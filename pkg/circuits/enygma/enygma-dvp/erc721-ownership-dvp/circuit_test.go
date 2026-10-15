package erc721_ownership

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/internal/dvptest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/internal/circuittest"
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

// honestWitness builds a valid transfer of the NFT held by ownerSk, using the
// same off-circuit helpers the relayer uses.
func honestWitness(t testing.TB) *Erc721OwnershipCircuit {
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
func setInput(t testing.TB, w *Erc721OwnershipCircuit, sk string, index uint) {
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

func TestErc721OwnershipProofVerifiesAndBindsPublicInputs(t *testing.T) {
	ccs := circuittest.Compile(t, &Erc721OwnershipCircuit{})
	circuittest.ProofBindsPublicInputs(t, ccs, honestWitness, []circuittest.PublicInputChange[*Erc721OwnershipCircuit]{
		{Name: "unchanged", Mutate: func(testing.TB, *Erc721OwnershipCircuit) {}},
		{Name: "other PaymentCommitment (message)", Mutate: func(_ testing.TB, w *Erc721OwnershipCircuit) { w.PaymentCommitment = 112 }, WantErr: true},
		{Name: "other TreeNumber", Mutate: func(_ testing.TB, w *Erc721OwnershipCircuit) { w.TreeNumber = 2 }, WantErr: true},
	})
}

func TestErc721OwnershipRejectsAttacks(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &Erc721OwnershipCircuit{})
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

	mutate := func(m func(t *testing.T, w *Erc721OwnershipCircuit)) func(*testing.T) *Erc721OwnershipCircuit {
		return circuittest.Mutate(honestWitness, m)
	}
	circuittest.RejectsAttacks(t, ccs, []circuittest.Attack[*Erc721OwnershipCircuit]{
		{
			// sk = 0, pathIndex = 0 gives the dummy nullifier, which makes the vault
			// skip its root check, so an NFT note in a made-up tree would be accepted.
			Name:  "real NFT behind the dummy nullifier",
			Build: mutate(func(t *testing.T, w *Erc721OwnershipCircuit) { setInput(t, w, "0", 0) }),
		},
		{
			Name:  "forged nullifier (double spend)",
			Build: mutate(func(t *testing.T, w *Erc721OwnershipCircuit) { w.Nullifiers[0] = 1337 }),
		},
		{
			Name:  "forged merkle root (fake membership)",
			Build: mutate(func(t *testing.T, w *Erc721OwnershipCircuit) { w.MerkleRoot = 1337 }),
		},
		{
			Name:  "forged output commitment",
			Build: mutate(func(t *testing.T, w *Erc721OwnershipCircuit) { w.CommitmentsOut[0] = 1337 }),
		},
		{
			Name: "stolen note: attacker key, owner's public key via forged hint",
			Build: mutate(func(t *testing.T, w *Erc721OwnershipCircuit) {
				w.PrivateKeys[0] = attackerSk
				w.Nullifiers[0] = primitives.ComputeNullifierBN254(attackerSk, "5")
			}),
			Opts: []solver.Option{claimOwnerPK},
		},
	})
}

func TestErc721OwnershipHonestWitnessSolves(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &Erc721OwnershipCircuit{})
	if err := circuittest.IsSolved(t, ccs, honestWitness(t)); err != nil {
		t.Fatalf("honest witness rejected: %v", err)
	}
}
