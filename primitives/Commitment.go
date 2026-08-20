package primitives

import (
	pos "github.com/raylsnetwork/rayls-sovereign-gnark-api/poseidon"

	"github.com/consensys/gnark/frontend"
)

func Commitment(api frontend.API, uniqueId frontend.Variable, publicKey frontend.Variable) frontend.Variable {

	commit := pos.Poseidon(api, []frontend.Variable{uniqueId, publicKey})

	commitout, _ := api.NewHint(ModHintBN254, 2, commit)

	commitmentVar := commitout[0]
	return commitmentVar

}

func CommitmentNative(api frontend.API, uniqueId frontend.Variable, publicKey frontend.Variable) frontend.Variable {

	commit, _ := api.NewHint(PoseidonNative, 1, uniqueId, publicKey)

	return commit[0]

}

// CommitmentV2ERC20 computes H(H(H(spendPK, salt), amount), tokenAddress) mod BN254
// using chained 2-input Poseidon hashes.
func CommitmentV2ERC20(api frontend.API, spendPK, salt, amount, tokenAddress frontend.Variable) frontend.Variable {
	h1 := pos.Poseidon(api, []frontend.Variable{spendPK, salt})
	h1out, _ := api.NewHint(ModHintBN254, 2, h1)

	h2 := pos.Poseidon(api, []frontend.Variable{h1out[0], amount})
	h2out, _ := api.NewHint(ModHintBN254, 2, h2)

	h3 := pos.Poseidon(api, []frontend.Variable{h2out[0], tokenAddress})
	h3out, _ := api.NewHint(ModHintBN254, 2, h3)

	return h3out[0]
}

// CommitmentV2ERC721 computes H(H(spendPK, salt), uId) mod BN254
// using chained 2-input Poseidon hashes.
func CommitmentV2ERC721(api frontend.API, spendPK, salt, uId frontend.Variable) frontend.Variable {
	h1 := pos.Poseidon(api, []frontend.Variable{spendPK, salt})
	h1out, _ := api.NewHint(ModHintBN254, 2, h1)

	h2 := pos.Poseidon(api, []frontend.Variable{h1out[0], uId})
	h2out, _ := api.NewHint(ModHintBN254, 2, h2)

	return h2out[0]
}

// CommitmentV2ERC1155 computes H(H(H(H(spendPK, salt), tokenAddress), tokenID), tokenAmount) mod BN254
// using chained 2-input Poseidon hashes.
func CommitmentV2ERC1155(api frontend.API, spendPK, salt, tokenAddress, tokenID, tokenAmount frontend.Variable) frontend.Variable {
	h1 := pos.Poseidon(api, []frontend.Variable{spendPK, salt})
	h1out, _ := api.NewHint(ModHintBN254, 2, h1)

	h2 := pos.Poseidon(api, []frontend.Variable{h1out[0], tokenAddress})
	h2out, _ := api.NewHint(ModHintBN254, 2, h2)

	h3 := pos.Poseidon(api, []frontend.Variable{h2out[0], tokenID})
	h3out, _ := api.NewHint(ModHintBN254, 2, h3)

	h4 := pos.Poseidon(api, []frontend.Variable{h3out[0], tokenAmount})
	h4out, _ := api.NewHint(ModHintBN254, 2, h4)

	return h4out[0]
}
