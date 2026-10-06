package dvptest

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/internal/circuittest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

// JoinSplit fills the witness fields shared by the DvP join-split circuits
// (ERC20 and ERC1155), which differ only in how a note commitment is computed.
type JoinSplit struct {
	// Commit is the commitment of a note of value held by pk with salt.
	Commit func(pk, salt, value string) string
}

// Note is an input note of Value held by Sk at LeafIndex of tree TreeNumber.
type Note struct {
	Sk         string
	Value      int64
	LeafIndex  uint
	TreeNumber int
}

// SetInput fills input i of w with note n, in a tree whose root is computed
// off-circuit.
func (js JoinSplit) SetInput(t testing.TB, w frontend.Circuit, i int, n Note) {
	t.Helper()
	pk := primitives.DerivePublicKeyBN254(n.Sk)
	salt := fmt.Sprint(100 + i)
	leaf := primitives.ParseBigInt(js.Commit(pk, salt, fmt.Sprint(n.Value)))
	path, root := MerklePath(t, leaf, n.LeafIndex, circuittest.Len(t, w, "PathElements", i))
	for j := range path {
		circuittest.Set(t, w, "PathElements", path[j], i, j)
	}
	circuittest.Set(t, w, "PrivateKeys", n.Sk, i)
	circuittest.Set(t, w, "SaltsIn", salt, i)
	circuittest.Set(t, w, "ValuesIn", n.Value, i)
	circuittest.Set(t, w, "PathIndices", n.LeafIndex, i)
	circuittest.Set(t, w, "MerkleRoots", root, i)
	circuittest.Set(t, w, "Nullifiers", primitives.ComputeNullifierBN254(n.Sk, fmt.Sprint(n.LeafIndex)), i)
	circuittest.Set(t, w, "TreeNumbers", n.TreeNumber, i)
}

// SetDummy fills input i of w the way the relayer pads unused inputs: all zeros.
func SetDummy(t testing.TB, w frontend.Circuit, i int) {
	t.Helper()
	for _, name := range []string{"PrivateKeys", "SaltsIn", "ValuesIn", "PathIndices", "MerkleRoots", "TreeNumbers"} {
		circuittest.Set(t, w, name, 0, i)
	}
	for j := 0; j < circuittest.Len(t, w, "PathElements", i); j++ {
		circuittest.Set(t, w, "PathElements", 0, i, j)
	}
	circuittest.Set(t, w, "Nullifiers", DummyNullifier(t), i)
}

// SetOutputs fills the outputs of w with values and sets the revert commitment
// for their total, owned by input 0's key.
func (js JoinSplit) SetOutputs(t testing.TB, w frontend.Circuit, values ...int64) {
	t.Helper()
	total := int64(0)
	for i, v := range values {
		rpk := primitives.DerivePublicKeyBN254(fmt.Sprint(900 + i))
		salt := fmt.Sprint(200 + i)
		circuittest.Set(t, w, "RecipientPK", rpk, i)
		circuittest.Set(t, w, "SaltsOut", salt, i)
		circuittest.Set(t, w, "ValuesOut", v, i)
		circuittest.Set(t, w, "CommitmentsOut", js.Commit(rpk, salt, fmt.Sprint(v)), i)
		total += v
	}
	senderPK := primitives.DerivePublicKeyBN254(fmt.Sprint(circuittest.Get(t, w, "PrivateKeys", 0)))
	revertSalt := fmt.Sprint(circuittest.Get(t, w, "RevertSalt"))
	circuittest.Set(t, w, "RevertCommitment", js.Commit(senderPK, revertSalt, fmt.Sprint(total)))
}

// FillHonest makes w spend two notes of sk (60 + 40) into two outputs (70 + 30),
// padding the other inputs with dummies. The caller sets the circuit's own fields.
func (js JoinSplit) FillHonest(t testing.TB, w frontend.Circuit, sk string) {
	t.Helper()
	js.SetInput(t, w, 0, Note{Sk: sk, Value: 60, LeafIndex: 3, TreeNumber: 1})
	js.SetInput(t, w, 1, Note{Sk: sk, Value: 40, LeafIndex: 9, TreeNumber: 1})
	for i := 2; i < circuittest.Len(t, w, "PrivateKeys"); i++ {
		SetDummy(t, w, i)
	}
	js.SetOutputs(t, w, 70, 30)
}

// JoinSplitAttacks are the forged witnesses every DvP join-split circuit must
// reject, each built from honest.
func JoinSplitAttacks[C frontend.Circuit](js JoinSplit, honest func(testing.TB) C) []circuittest.Attack[C] {
	mutate := func(m func(t *testing.T, w C)) func(*testing.T) C { return circuittest.Mutate(honest, m) }
	return []circuittest.Attack[C]{
		{
			// sk = 0, pathIndex = 0 gives the dummy nullifier, which makes the vault
			// skip its root check, so a note in a made-up tree would be accepted.
			Name: "real value behind the dummy nullifier (mint)",
			Build: mutate(func(t *testing.T, w C) {
				js.SetInput(t, w, 1, Note{Sk: "0", Value: 1_000_000, TreeNumber: 1})
				js.SetOutputs(t, w, 1_000_030, 30)
			}),
		},
		{
			Name:  "outputs exceed inputs",
			Build: mutate(func(t *testing.T, w C) { js.SetOutputs(t, w, 80, 30) }),
		},
		{
			Name:  "forged nullifier",
			Build: mutate(func(t *testing.T, w C) { circuittest.Set(t, w, "Nullifiers", 1337, 0) }),
		},
		{
			Name:  "forged merkle root",
			Build: mutate(func(t *testing.T, w C) { circuittest.Set(t, w, "MerkleRoots", 1337, 1) }),
		},
		{
			Name: "amount above range",
			Build: mutate(func(t *testing.T, w C) {
				circuittest.Set(t, w, "ValuesIn", "1000000000000000000000000000000000000", 0)
			}),
		},
	}
}

// JoinSplitPublicInputChanges are the public input edits a DvP join-split
// proof must not survive, plus the unchanged control.
func JoinSplitPublicInputChanges[C frontend.Circuit]() []circuittest.PublicInputChange[C] {
	return []circuittest.PublicInputChange[C]{
		{Name: "unchanged", Mutate: func(testing.TB, C) {}},
		{Name: "other NftCommitment (message)", Mutate: func(t testing.TB, w C) { circuittest.Set(t, w, "NftCommitment", 778) }, WantErr: true},
		{Name: "other TreeNumber", Mutate: func(t testing.TB, w C) { circuittest.Set(t, w, "TreeNumbers", 2, 0) }, WantErr: true},
	}
}
