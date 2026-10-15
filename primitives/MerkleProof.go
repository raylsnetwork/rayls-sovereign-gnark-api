package primitives

import (
	pos "github.com/raylsnetwork/rayls-sovereign-gnark-api/poseidon"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// MerkleProof recomputes the Merkle root for leaf along pathElements, using the
// bits of pathIndices (LSB first) to choose the left/right order at each level.
func MerkleProof(api frontend.API, leaf frontend.Variable, pathIndices frontend.Variable, pathElements []frontend.Variable) frontend.Variable {
	levels := len(pathElements)
	idxBits := bits.ToBinary(api, pathIndices, bits.WithNbDigits(levels))

	currentHash := leaf
	for i := 0; i < levels; i++ {
		bit := idxBits[i]
		sibling := pathElements[i]

		left := api.Select(bit, sibling, currentHash)
		right := api.Select(bit, currentHash, sibling)

		currentHash = pos.Poseidon(api, []frontend.Variable{left, right})
	}

	return currentHash
}
