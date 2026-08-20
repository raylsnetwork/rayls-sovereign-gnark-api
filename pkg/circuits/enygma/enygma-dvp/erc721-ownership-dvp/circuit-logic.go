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

	//verify input notes
	for i := 0; i < nInputs; i++ {

		// Compute public key from private key
		publicKey := primitives.PublicKey(api, privateKeys[i])
		//api.Println("PublicKey computed from private key")

		// Compute and verify nullifier
		nullifier := primitives.Nullifier(api, privateKeys[i], pathIndices[i])
		//api.Println("Computed nullifier:", nullifier)
		//api.Println("Comparing with expected:", nullifiers[i])
		api.AssertIsEqual(nullifier, nullifiers[i])
		//api.Println("Nullifier check passed")

		// Compute V2 input commitment: H(H(spendPK, salt), uId)
		commitment := primitives.CommitmentV2ERC721(api, publicKey, saltsIn[i], uIdIn[i])
		//api.Println("Commitment computed:", commitment)

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
		isZero := api.IsZero(uIdIn[i])
		//api.Println("IsZero(valueIn):", isZero)

		// Enable = 1 - isZero (1 if value != 0, 0 if value == 0)
		// This enables the merkle root check only for non-dummy inputs
		Enable := api.Sub(1, isZero)
		//api.Println("Enable flag (1 for real input, 0 for dummy):", Enable)

		// Diff = merkleRoots[i] - root
		Diff := api.Sub(merkleRoot, root)
		//api.Println("Diff (expected - computed root):", Diff)

		// If Enable == 1 (real input), then Diff must be 0
		// If Enable == 0 (dummy input), then this check is bypassed
		DiffTimesEnable := api.Mul(Diff, Enable)
		//api.Println("Diff * Enable:", DiffTimesEnable)
		//api.Println("Asserting Diff * Enable == 0")
		api.AssertIsEqual(DiffTimesEnable, 0)
		//api.Println("Merkle root check passed for input", i)
	}

	//Verifying Outputs
	for i := 0; i < mOutputs; i++ {

		api.AssertIsEqual(uIdOut[i], uIdIn[i])
		// Compute V2 output commitment: H(H(recipientPK, salt), uId)
		commitmentOut := primitives.CommitmentV2ERC721(api, recipientPK[i], saltsOut[i], uIdOut[i])
		api.AssertIsEqual(commitmentOut, commitmentsOut[i])

	}

	// Verify revert commitment
	// Derive sender's public key from private key — no need to pass it explicitly
	senderPK := primitives.PublicKey(api, privateKeys[0])

	// Revert uses the SAME uIdIn[0] — guarantees the revert locks the same NFT
	revertCommit := primitives.CommitmentV2ERC721(api, senderPK, revertSalt, uIdIn[0])
	api.AssertIsEqual(revertCommit, revertCommitment)

	return nil
}
