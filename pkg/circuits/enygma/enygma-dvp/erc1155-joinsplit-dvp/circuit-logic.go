package erc1155_joinsplit

import (
	"enygma-gnark-server/primitives"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

func circuitLogic(
	api frontend.API,
	message frontend.Variable,
	merkleRoots []frontend.Variable,
	nullifiers []frontend.Variable,
	commitmentsOut []frontend.Variable,
	privateKeys []frontend.Variable,
	saltsIn []frontend.Variable,
	valuesIn []frontend.Variable,
	pathElements [][]frontend.Variable,
	pathIndices []frontend.Variable,
	erc1155ContractAddress frontend.Variable,
	erc1155TokenId frontend.Variable,
	recipientPK []frontend.Variable,
	saltsOut []frontend.Variable,
	valuesOut []frontend.Variable,
	revertCommitment frontend.Variable,
	revertSalt frontend.Variable,
) error {
	inputsTotals := frontend.Variable(0)
	outputsTotals := frontend.Variable(0)

	// Verify input notes
	//api.Println("\n=== VERIFYING INPUT NOTES ===")
	for i := 0; i < nInputs; i++ {
		//api.Println("\n--- Input", i, "---")
		//api.Println("ValueIn[", i, "]:", valuesIn[i])
		//api.Println("PrivateKey[", i, "]:", privateKeys[i])
		//api.Println("PathIndex[", i, "]:", pathIndices[i])
		//api.Println("MerkleRoot[", i, "]:", merkleRoots[i])
		//api.Println("Expected Nullifier[", i, "]:", nullifiers[i])

		// Range checks for amounts
		isValid0 := cmp.IsLess(api, valuesIn[i], rangeCircuit)
		//api.Println("IsLess than rangeCircuit:", isValid0)
		api.AssertIsEqual(isValid0, 1)

		isValid1 := cmp.IsLessOrEqual(api, 0, valuesIn[i])
		//api.Println("IsGreaterOrEqual to 0:", isValid1)
		api.AssertIsEqual(isValid1, 1)

		// Compute public key from private key
		publicKey := primitives.PublicKey(api, privateKeys[i])

		// Compute and verify nullifier
		nullifier := primitives.Nullifier(api, privateKeys[i], pathIndices[i])
		api.AssertIsEqual(nullifier, nullifiers[i])

		// Compute V2 input commitment: H(H(H(H(spendPK, salt), tokenAddress), tokenID), amount)
		commitment := primitives.CommitmentV2ERC1155(api, publicKey, saltsIn[i], erc1155ContractAddress, erc1155TokenId, valuesIn[i])

		// Prepare path elements for merkle proof
		pathElement := make([]frontend.Variable, merkleTreeDepth)
		//api.Println("Path elements for merkle proof:")
		for j := 0; j < merkleTreeDepth; j++ {
			pathElement[j] = pathElements[i][j]
			//api.Println("  PathElement[", j, "]:", pathElement[j])
		}

		// Compute and verify merkle root
		//api.Println("Computing merkle proof...")
		root := primitives.MerkleProof(api, commitment, pathIndices[i], pathElement)
		//api.Println("Computed root:", root)
		//api.Println("Expected root:", merkleRoots[i])

		// Check if this is a dummy input (value = 0, isZero = 1)
		isZero := api.IsZero(valuesIn[i])
		//api.Println("IsZero(valueIn):", isZero)

		// Enable = 1 - isZero (1 if value != 0, 0 if value == 0)
		// This enables the merkle root check only for non-dummy inputs
		Enable := api.Sub(1, isZero)
		//api.Println("Enable flag (1 for real input, 0 for dummy):", Enable)

		// Diff = merkleRoots[i] - root
		Diff := api.Sub(merkleRoots[i], root)
		//api.Println("Diff (expected - computed root):", Diff)

		// If Enable == 1 (real input), then Diff must be 0
		// If Enable == 0 (dummy input), then this check is bypassed
		DiffTimesEnable := api.Mul(Diff, Enable)
		//api.Println("Diff * Enable:", DiffTimesEnable)
		//api.Println("Asserting Diff * Enable == 0")
		api.AssertIsEqual(DiffTimesEnable, 0)
		//api.Println("Merkle root check passed for input", i)

		// Add to input total
		inputsTotals = api.Add(inputsTotals, valuesIn[i])
		//api.Println("Running input total:", inputsTotals)
	}

	//api.Println("\n=== Input totals:", inputsTotals, "===")

	// Verify output notes
	//api.Println("\n=== VERIFYING OUTPUT NOTES ===")
	for i := 0; i < mOutputs; i++ {
		//api.Println("\n--- Output", i, "---")
		//api.Println("ValueOut[", i, "]:", valuesOut[i])
		//api.Println("RecipientPK[", i, "]:", recipientPK[i])
		//api.Println("Expected CommitmentOut[", i, "]:", commitmentsOut[i])

		// Range checks for amounts
		isValid0 := cmp.IsLess(api, valuesOut[i], rangeCircuit)
		//api.Println("IsLess than rangeCircuit:", isValid0)
		api.AssertIsEqual(isValid0, 1)

		isValid1 := cmp.IsLessOrEqual(api, 0, valuesOut[i])
		//api.Println("IsGreaterOrEqual to 0:", isValid1)
		api.AssertIsEqual(isValid1, 1)

		// Compute V2 output commitment: H(H(H(H(recipientPK, salt), tokenAddress), tokenID), amount)
		commitment := primitives.CommitmentV2ERC1155(api, recipientPK[i], saltsOut[i], erc1155ContractAddress, erc1155TokenId, valuesOut[i])
		api.AssertIsEqual(commitment, commitmentsOut[i])

		// Add to output total
		outputsTotals = api.Add(outputsTotals, valuesOut[i])
		//api.Println("Running output total:", outputsTotals)
	}

	//api.Println("\n=== Output totals:", outputsTotals, "===")

	// Verify revert commitment
	// Derive sender's public key from private key — no need to pass it explicitly
	senderPK := primitives.PublicKey(api, privateKeys[0])

	// Revert uses the SAME contractAddr, tokenId, inputsTotals — guarantees same token type and amount
	revertCommit := primitives.CommitmentV2ERC1155(api, senderPK, revertSalt, erc1155ContractAddress, erc1155TokenId, inputsTotals)
	api.AssertIsEqual(revertCommit, revertCommitment)

	// Check that input and output amounts balance
	api.AssertIsEqual(inputsTotals, outputsTotals)
	//api.Println("Balance check passed - inputs equal outputs!")

	//api.Println("\n=== Erc1155 JOINSPLIT CIRCUIT COMPLETED SUCCESSFULLY ===")
	return nil
}
