package erc721_ownership

import (
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"

	"github.com/consensys/gnark/frontend"
)

func circuitLogic(
	api frontend.API,
	paymentCommitment frontend.Variable,
	merkleRoot frontend.Variable,
	nullifiers []frontend.Variable,
	treeNumber frontend.Variable,
	commitmentsOut []frontend.Variable,
	privateKeys []frontend.Variable,
	saltsIn []frontend.Variable,
	uIdIn []frontend.Variable,
	pathElements [][]frontend.Variable,
	pathIndices []frontend.Variable,
	recipientPK []frontend.Variable,
	saltsOut []frontend.Variable,
	uIdOut []frontend.Variable,
	revertCommitment frontend.Variable,
	revertSalt frontend.Variable,
) error {

	// The message is the DvP payment link or the ownership challenge, and the vault
	// records nullifiers per tree number; neither is otherwise constrained.
	primitives.BindPublicInputs(api, paymentCommitment, treeNumber)

	// Verify input notes
	var senderPK frontend.Variable
	for i := 0; i < nInputs; i++ {
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

		// Compute V2 input commitment: H(H(spendPK, salt), uId)
		commitment := primitives.CommitmentV2ERC721(api, publicKey, saltsIn[i], uIdIn[i])

		// Prepare path elements for merkle proof
		pathElement := make([]frontend.Variable, merkleTreeDepth)
		for j := 0; j < merkleTreeDepth; j++ {
			pathElement[j] = pathElements[i][j]
		}

		// Compute and verify merkle root
		root := primitives.MerkleProof(api, commitment, pathIndices[i], pathElement)

		// Check if this is a dummy input (value = 0, isZero = 1)
		isZero := api.IsZero(uIdIn[i])

		// Enable = 1 - isZero (1 if value != 0, 0 if value == 0)
		// This enables the merkle root check only for non-dummy inputs
		Enable := api.Sub(1, isZero)

		// A real input must not use the dummy nullifier, or the vault skips its root check
		primitives.AssertRealInputNotDummy(api, Enable, nullifier)

		// Diff = merkleRoots[i] - root
		Diff := api.Sub(merkleRoot, root)

		// If Enable == 1 (real input), then Diff must be 0
		// If Enable == 0 (dummy input), then this check is bypassed
		DiffTimesEnable := api.Mul(Diff, Enable)
		api.AssertIsEqual(DiffTimesEnable, 0)
	}

	//Verifying Outputs
	for i := 0; i < mOutputs; i++ {
		api.AssertIsEqual(uIdOut[i], uIdIn[i])
		// Compute V2 output commitment: H(H(recipientPK, salt), uId)
		commitmentOut := primitives.CommitmentV2ERC721(api, recipientPK[i], saltsOut[i], uIdOut[i])
		api.AssertIsEqual(commitmentOut, commitmentsOut[i])

	}

	// Verify revert commitment, owned by the first input's key.
	// Revert uses the SAME uIdIn[0] — guarantees the revert locks the same NFT
	revertCommit := primitives.CommitmentV2ERC721(api, senderPK, revertSalt, uIdIn[0])
	api.AssertIsEqual(revertCommit, revertCommitment)

	return nil
}
