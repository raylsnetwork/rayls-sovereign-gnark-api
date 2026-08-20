package primitives

import (
	pos "enygma-gnark-server/poseidon"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

func MerkleProof(api frontend.API, leaf frontend.Variable, pathIndices frontend.Variable, pathElements []frontend.Variable) frontend.Variable {
	levels := len(pathElements)
	idxBits := bits.ToBinary(api, pathIndices, bits.WithNbDigits(levels))

	// Debug: Print initial values
	//api.Println("=== MerkleProof Debug ===")
	//api.Println("Initial leaf:", leaf)
	//api.Println("Path indices:", pathIndices)
	//api.Println("Number of levels:", levels)

	currentHash := leaf

	for i := 0; i < levels; i++ {
		bit := idxBits[i]
		sibling := pathElements[i]

		// Debug: Print values at each level
		//api.Println("--- Level", i, "---")
		//api.Println("  Bit:", bit)
		//api.Println("  Current hash:", currentHash)
		//api.Println("  Sibling:", sibling)

		left := api.Select(bit, sibling, currentHash)
		right := api.Select(bit, currentHash, sibling)

		//api.Println("  Left:", left)
		//api.Println("  Right:", right)

		// Poseidon([left, right])
		hash := pos.Poseidon(api, []frontend.Variable{left, right})

		// Apply ModHint after Poseidon
		modHash, _ := api.NewHint(ModHintBN254, 2, hash)
		currentHash = modHash[0]

		//api.Println("  New hash:", currentHash)
	}

	//api.Println("Final root:", currentHash)
	//api.Println("=== End MerkleProof ===")

	return currentHash
}

func MerkleProofNative(api frontend.API, leaf frontend.Variable, pathIndices frontend.Variable, pathElements []frontend.Variable) frontend.Variable {

	levels := len(pathElements)
	idxBits := bits.ToBinary(api, pathIndices, bits.WithNbDigits(levels))

	currentHash := leaf
	for i := 0; i < levels; i++ {

		bit := idxBits[i]
		sibling := pathElements[i]

		left := api.Select(bit, sibling, currentHash)
		right := api.Select(bit, currentHash, sibling)

		hash, _ := api.NewHint(PoseidonNative, 1, left, right)
		// //api.Println("hashApi", hash, "i",i, "left", left, "right", right)
		currentHash = hash[0]
	}

	return currentHash

}
