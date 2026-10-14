package erc1155_joinsplit

import (
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"

	"github.com/consensys/gnark/frontend"
)

func circuitLogic(
	api frontend.API,
	message frontend.Variable,
	merkleRoots []frontend.Variable,
	nullifiers []frontend.Variable,
	treeNumbers []frontend.Variable,
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
	// The message links this proof to the other leg of the DvP, and the vault
	// records nullifiers per tree number; neither is otherwise constrained.
	primitives.BindPublicInputs(api, message)
	primitives.BindPublicInputs(api, treeNumbers...)

	inputsTotals := frontend.Variable(0)
	outputsTotals := frontend.Variable(0)

	// Verify input notes
	var senderPK frontend.Variable
	for i := 0; i < nInputs; i++ {
		primitives.AssertIsAmount(api, valuesIn[i])

		// Compute public key from private key
		publicKey, err := primitives.PublicKey(api, privateKeys[i])
		if err != nil {
			return err
		}
		if i == 0 {
			senderPK = publicKey
		}

		// Compute and verify nullifier
		nullifier := primitives.Nullifier(api, privateKeys[i], pathIndices[i])
		api.AssertIsEqual(nullifier, nullifiers[i])

		// Compute V2 input commitment: H(H(H(H(spendPK, salt), tokenAddress), tokenID), amount)
		commitment := primitives.CommitmentV2ERC1155(api, publicKey, saltsIn[i], erc1155ContractAddress, erc1155TokenId, valuesIn[i])

		// Prepare path elements for merkle proof
		pathElement := make([]frontend.Variable, merkleTreeDepth)
		for j := 0; j < merkleTreeDepth; j++ {
			pathElement[j] = pathElements[i][j]
		}

		// Compute and verify merkle root
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

		// Add to input total
		inputsTotals = api.Add(inputsTotals, valuesIn[i])
	}

	// Verify output notes
	for i := 0; i < mOutputs; i++ {
		primitives.AssertIsAmount(api, valuesOut[i])

		// Compute V2 output commitment: H(H(H(H(recipientPK, salt), tokenAddress), tokenID), amount)
		commitment := primitives.CommitmentV2ERC1155(api, recipientPK[i], saltsOut[i], erc1155ContractAddress, erc1155TokenId, valuesOut[i])
		api.AssertIsEqual(commitment, commitmentsOut[i])

		// Add to output total
		outputsTotals = api.Add(outputsTotals, valuesOut[i])
	}

	// Verify revert commitment, owned by the first input's key.
	// Revert uses the SAME contractAddr, tokenId, inputsTotals — guarantees same token type and amount
	revertCommit := primitives.CommitmentV2ERC1155(api, senderPK, revertSalt, erc1155ContractAddress, erc1155TokenId, inputsTotals)
	api.AssertIsEqual(revertCommit, revertCommitment)

	// Check that input and output amounts balance
	api.AssertIsEqual(inputsTotals, outputsTotals)

	return nil
}
