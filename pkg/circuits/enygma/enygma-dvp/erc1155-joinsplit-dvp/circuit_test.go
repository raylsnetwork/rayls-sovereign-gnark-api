package erc1155_joinsplit

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/internal/dvptest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

const (
	ownerSk = "123456789012345678901234567890"
	token   = "1234567890123456789012345678901234567890"
	tokenID = "7"
)

func compile(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Erc1155JoinSplitCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return ccs
}

// setInput fills input i with a note of value held by sk at leafIndex, in a
// tree whose root is computed off-circuit.
func setInput(t *testing.T, w *Erc1155JoinSplitCircuit, i int, sk string, value int64, leafIndex uint, treeNumber int) {
	t.Helper()
	pk := primitives.DerivePublicKeyBN254(sk)
	salt := fmt.Sprint(100 + i)
	leaf := primitives.ParseBigInt(primitives.ComputeCommitmentV2ERC1155BN254(pk, salt, token, tokenID, fmt.Sprint(value)))
	path, root := dvptest.MerklePath(t, leaf, leafIndex, merkleTreeDepth)

	w.PrivateKeys[i] = sk
	w.SaltsIn[i] = salt
	w.ValuesIn[i] = value
	w.PathIndices[i] = leafIndex
	for j := range path {
		w.PathElements[i][j] = path[j]
	}
	w.MerkleRoots[i] = root
	w.Nullifiers[i] = primitives.ComputeNullifierBN254(sk, fmt.Sprint(leafIndex))
	w.TreeNumbers[i] = treeNumber
}

// setDummy fills input i the way the relayer pads unused inputs: all zeros.
func setDummy(t *testing.T, w *Erc1155JoinSplitCircuit, i int) {
	t.Helper()
	w.PrivateKeys[i], w.SaltsIn[i], w.ValuesIn[i], w.PathIndices[i] = 0, 0, 0, 0
	for j := 0; j < merkleTreeDepth; j++ {
		w.PathElements[i][j] = 0
	}
	w.MerkleRoots[i], w.TreeNumbers[i] = 0, 0
	w.Nullifiers[i] = dvptest.DummyNullifier(t)
}

// honestWitness spends two notes (60 + 40) into two outputs (70 + 30).
func honestWitness(t *testing.T) *Erc1155JoinSplitCircuit {
	t.Helper()
	w := &Erc1155JoinSplitCircuit{NftCommitment: 777, Erc1155ContractAddress: token, Erc1155TokenId: tokenID, RevertSalt: 5}
	setInput(t, w, 0, ownerSk, 60, 3, 1)
	setInput(t, w, 1, ownerSk, 40, 9, 1)
	for i := 2; i < nInputs; i++ {
		setDummy(t, w, i)
	}
	setOutputs(t, w, 70, 30)
	return w
}

func setOutputs(t *testing.T, w *Erc1155JoinSplitCircuit, values ...int64) {
	t.Helper()
	total := int64(0)
	for i, v := range values {
		rpk := primitives.DerivePublicKeyBN254(fmt.Sprint(900 + i))
		salt := fmt.Sprint(200 + i)
		w.RecipientPK[i] = rpk
		w.SaltsOut[i] = salt
		w.ValuesOut[i] = v
		w.CommitmentsOut[i] = primitives.ComputeCommitmentV2ERC1155BN254(rpk, salt, token, tokenID, fmt.Sprint(v))
		total += v
	}
	senderPK := primitives.DerivePublicKeyBN254(fmt.Sprint(w.PrivateKeys[0]))
	w.RevertCommitment = primitives.ComputeCommitmentV2ERC1155BN254(senderPK, fmt.Sprint(w.RevertSalt), token, tokenID, fmt.Sprint(total))
}

func isSolved(t *testing.T, ccs constraint.ConstraintSystem, a *Erc1155JoinSplitCircuit) error {
	t.Helper()
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	return ccs.IsSolved(w)
}

func TestJoinSplitHonestWitnessSolves(t *testing.T) {
	t.Parallel()
	if err := isSolved(t, compile(t), honestWitness(t)); err != nil {
		t.Fatalf("honest witness rejected: %v", err)
	}
}

func TestJoinSplitRejectsAttacks(t *testing.T) {
	t.Parallel()
	ccs := compile(t)
	tests := []struct {
		name   string
		mutate func(w *Erc1155JoinSplitCircuit)
	}{
		{
			// sk = 0, pathIndex = 0 gives the dummy nullifier, which makes the vault
			// skip its root check, so a note in a made-up tree would be accepted.
			name: "real value behind the dummy nullifier (mint)",
			mutate: func(w *Erc1155JoinSplitCircuit) {
				setInput(t, w, 1, "0", 1_000_000, 0, 1)
				setOutputs(t, w, 1_000_030, 30)
			},
		},
		{
			name:   "outputs exceed inputs",
			mutate: func(w *Erc1155JoinSplitCircuit) { setOutputs(t, w, 80, 30) },
		},
		{
			name:   "forged nullifier",
			mutate: func(w *Erc1155JoinSplitCircuit) { w.Nullifiers[0] = 1337 },
		},
		{
			name:   "forged merkle root",
			mutate: func(w *Erc1155JoinSplitCircuit) { w.MerkleRoots[1] = 1337 },
		},
		{
			name: "amount above range",
			mutate: func(w *Erc1155JoinSplitCircuit) {
				big := "1000000000000000000000000000000000000"
				w.ValuesIn[0] = big
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := honestWitness(t)
			tc.mutate(w)
			if err := isSolved(t, ccs, w); err == nil {
				t.Fatal("attack witness was accepted")
			}
		})
	}
}

func TestJoinSplitProofBindsPublicInputs(t *testing.T) {
	t.Parallel()
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

	tests := []struct {
		name    string
		mutate  func(w *Erc1155JoinSplitCircuit)
		wantErr bool
	}{
		{"unchanged", func(*Erc1155JoinSplitCircuit) {}, false},
		{"other NftCommitment (message)", func(w *Erc1155JoinSplitCircuit) { w.NftCommitment = 778 }, true},
		{"other TreeNumber", func(w *Erc1155JoinSplitCircuit) { w.TreeNumbers[0] = 2 }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := honestWitness(t)
			tc.mutate(a)
			pub, err := frontend.NewWitness(a, ecc.BN254.ScalarField(), frontend.PublicOnly())
			if err != nil {
				t.Fatalf("public witness: %v", err)
			}
			if err := groth16.Verify(proof, vk, pub); (err != nil) != tc.wantErr {
				t.Fatalf("verify err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
