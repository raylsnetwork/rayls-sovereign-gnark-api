package enygma_joinsplit

import (
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"

	"github.com/consensys/gnark/frontend"
)

func circuitLogic(
	api frontend.API,
	nftCommitment frontend.Variable,
	merkleRoots []frontend.Variable,
	nullifiers []frontend.Variable,
	treeNumbers []frontend.Variable,
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
	// The message links this proof to the other leg of the DvP, and the vault
	// records nullifiers per tree number; neither is otherwise constrained.
	primitives.BindPublicInputs(api, nftCommitment)
	primitives.BindPublicInputs(api, treeNumbers...)

	inputsTotals := frontend.Variable(0)
	outputsTotals := frontend.Variable(0)

	// Verify input notes
	var senderPK frontend.Variable
	for i := 0; i < nInputs; i++ {
		primitives.AssertIsAmount(api, valuesIn[i])

		// Compute public key
		publicKey, err := primitives.PublicKey(api, privateKeys[i])
		if err != nil {
			return err
		}
		if i == 0 {
			senderPK = publicKey
		}

		// Compute nullifier
		nullifier := primitives.Nullifier(api, privateKeys[i], pathIndices[i])
		api.AssertIsEqual(nullifier, nullifiers[i])

		// Compute V2 commitment: H(H(H(spendPK, salt), amount), tokenAddress)
		commitment := primitives.CommitmentV2ERC20(api, publicKey, saltsIn[i], valuesIn[i], erc20ContractAddress)

		// Prepare path elements
		pathElement := make([]frontend.Variable, merkleTreeDepth)
		for j := 0; j < merkleTreeDepth; j++ {
			pathElement[j] = pathElements[i][j]
		}

		// Compute merkle root
		root := primitives.MerkleProof(api, commitment, pathIndices[i], pathElement)

		// Check if this is a dummy input (value = 0, isZero = 1)
		isZero := api.IsZero(valuesIn[i])

		// Enable = 1 - isZero (1 if value != 0, 0 if value == 0)
		// This enables the merkle root check only for non-dummy inputs
		Enable := api.Sub(1, isZero)

		// Diff = merkleRoots[i] - root
		Diff := api.Sub(merkleRoots[i], root)

		// If Enable == 1 (real input), then Diff must be 0
		// If Enable == 0 (dummy input), then this check is bypassed
		// A real input must not use the dummy nullifier, or the vault skips its root check
		primitives.AssertRealInputNotDummy(api, Enable, nullifier)

		DiffTimesEnable := api.Mul(Diff, Enable)
		api.AssertIsEqual(DiffTimesEnable, 0)

		// Add to total
		inputsTotals = api.Add(inputsTotals, valuesIn[i])
	}

	// Verifying Outputs
	for i := 0; i < mOutputs; i++ {
		primitives.AssertIsAmount(api, valuesOut[i])

		// Compute V2 output commitment: H(H(H(recipientPK, salt), amount), tokenAddress)
		commitment := primitives.CommitmentV2ERC20(api, recipientPK[i], saltsOut[i], valuesOut[i], erc20ContractAddress)
		api.AssertIsEqual(commitment, commitmentsOut[i])

		// Add to output total
		outputsTotals = api.Add(outputsTotals, valuesOut[i])
	}

	// Verify revert commitment, owned by the first input's key.
	// Compute revert commitment using the SAME token data from inputs:
	// - inputsTotals: same total amount being spent (constrained by balance check)
	// - erc20ContractAddress: same contract used for input commitments
	revertCommit := primitives.CommitmentV2ERC20(api, senderPK, revertSalt, inputsTotals, erc20ContractAddress)
	api.AssertIsEqual(revertCommit, revertCommitment)

	// Check input/output balance
	api.AssertIsEqual(outputsTotals, inputsTotals)

	return nil
}
