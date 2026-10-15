// Package dvptest builds honest witness data for the DvP circuit tests, using
// the same off-circuit helpers the relayer uses.
package dvptest

import (
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

// MerklePath returns sibling elements for a leaf at index in a tree of the
// given depth, and the resulting root, hashed exactly as primitives.MerkleProof.
func MerklePath(t testing.TB, leaf *big.Int, index uint, depth int) (path []*big.Int, root *big.Int) {
	t.Helper()
	cur := leaf
	for j := 0; j < depth; j++ {
		sib := big.NewInt(int64(1000*(j+1) + int(index)))
		path = append(path, sib)
		left, right := cur, sib
		if index>>uint(j)&1 == 1 {
			left, right = sib, cur
		}
		h, err := poseidon.Hash([]*big.Int{left, right})
		if err != nil {
			t.Fatalf("poseidon: %v", err)
		}
		cur = h
	}
	return path, cur
}

// DummyNullifier is Poseidon(0, 0), the nullifier of an all-zero dummy input and
// the value the vault contracts skip.
func DummyNullifier(t testing.TB) *big.Int {
	t.Helper()
	h, err := poseidon.Hash([]*big.Int{big.NewInt(0), big.NewInt(0)})
	if err != nil {
		t.Fatalf("poseidon: %v", err)
	}
	return h
}
