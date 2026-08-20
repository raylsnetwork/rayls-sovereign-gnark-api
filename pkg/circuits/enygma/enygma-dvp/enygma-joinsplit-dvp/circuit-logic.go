package enygma_joinsplit

import (
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

func circuitLogic(
	api frontend.API,
	nftCommitment frontend.Variable,
	merkleRoots []frontend.Variable,
	nullifiers []frontend.Variable,
	commitmentsOut []frontend.Variable,
	privateKeys []frontend.Variable,
	saltsIn []frontend.Variable,
	valuesIn []frontend.Variable,
	pathElements [][]frontend.Variable,
	pathIndices []frontend.Variable,
	erc20ContractAddress frontend.Variable,
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

		// Range checks
		isValid0 := cmp.IsLess(api, valuesIn[i], rangeCircuit)
		//api.Println("IsLess than rangeCircuit:", isValid0)
		api.AssertIsEqual(isValid0, 1)

		isValid1 := cmp.IsLessOrEqual(api, 0, valuesIn[i])
		//api.Println("IsGreaterOrEqual to 0:", isValid1)
		api.AssertIsEqual(isValid1, 1)

		// Compute public key
		publicKey := primitives.PublicKey(api, privateKeys[i])

		// Compute nullifier
		nullifier := primitives.Nullifier(api, privateKeys[i], pathIndices[i])
		api.AssertIsEqual(nullifier, nullifiers[i])

		// Compute V2 commitment: H(H(H(spendPK, salt), amount), tokenAddress)
		commitment := primitives.CommitmentV2ERC20(api, publicKey, saltsIn[i], valuesIn[i], erc20ContractAddress)

		// Prepare path elements
		pathElement := make([]frontend.Variable, merkleTreeDepth)
		//api.Println("Path elements for merkle proof:")
		for j := 0; j < merkleTreeDepth; j++ {
			pathElement[j] = pathElements[i][j]
			//api.Println("  PathElement[", j, "]:", pathElement[j])
		}

		// Compute merkle root
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

		// Add to total
		inputsTotals = api.Add(inputsTotals, valuesIn[i])
		//api.Println("Running input total:", inputsTotals)
	}

	//api.Println("\n=== Input totals:", inputsTotals, "===")

	// Verifying Outputs
	//api.Println("\n=== VERIFYING OUTPUT NOTES ===")
	for i := 0; i < mOutputs; i++ {
		//api.Println("\n--- Output", i, "---")
		//api.Println("ValueOut[", i, "]:", valuesOut[i])
		//api.Println("RecipientPK[", i, "]:", recipientPK[i])
		//api.Println("Expected CommitmentOut[", i, "]:", commitmentsOut[i])

		// Range checks
		isValid0 := cmp.IsLess(api, valuesOut[i], rangeCircuit)
		//api.Println("IsLess than rangeCircuit:", isValid0)
		api.AssertIsEqual(isValid0, 1)

		isValid1 := cmp.IsLessOrEqual(api, 0, valuesOut[i])
		//api.Println("IsGreaterOrEqual to 0:", isValid1)
		api.AssertIsEqual(isValid1, 1)

		// Compute V2 output commitment: H(H(H(recipientPK, salt), amount), tokenAddress)
		commitment := primitives.CommitmentV2ERC20(api, recipientPK[i], saltsOut[i], valuesOut[i], erc20ContractAddress)
		api.AssertIsEqual(commitment, commitmentsOut[i])

		// Add to output total
		outputsTotals = api.Add(outputsTotals, valuesOut[i])
		//api.Println("Running output total:", outputsTotals)
	}

	//api.Println("\n=== Output totals:", outputsTotals, "===")

	// Verify revert commitment
	// Derive sender's public key from private key — no need to pass it explicitly
	senderPK := primitives.PublicKey(api, privateKeys[0])

	// Compute revert commitment using the SAME token data from inputs:
	// - inputsTotals: same total amount being spent (constrained by balance check)
	// - erc20ContractAddress: same contract used for input commitments
	revertCommit := primitives.CommitmentV2ERC20(api, senderPK, revertSalt, inputsTotals, erc20ContractAddress)
	api.AssertIsEqual(revertCommit, revertCommitment)

	// Check input/output balance
	api.AssertIsEqual(outputsTotals, inputsTotals)
	//api.Println("Balance check passed!")

	//api.Println("\n=== CIRCUIT LOGIC COMPLETED SUCCESSFULLY ===")
	return nil
}
