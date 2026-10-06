package primitives

import (
	pos "github.com/raylsnetwork/rayls-sovereign-gnark-api/poseidon"

	"github.com/consensys/gnark/frontend"
)

// CommitmentV2ERC20 computes H(H(H(spendPK, salt), amount), tokenAddress)
// using chained 2-input Poseidon hashes.
func CommitmentV2ERC20(api frontend.API, spendPK, salt, amount, tokenAddress frontend.Variable) frontend.Variable {
	h1 := pos.Poseidon(api, []frontend.Variable{spendPK, salt})
	h2 := pos.Poseidon(api, []frontend.Variable{h1, amount})
	return pos.Poseidon(api, []frontend.Variable{h2, tokenAddress})
}

// CommitmentV2ERC721 computes H(H(spendPK, salt), uId)
// using chained 2-input Poseidon hashes.
func CommitmentV2ERC721(api frontend.API, spendPK, salt, uId frontend.Variable) frontend.Variable {
	h1 := pos.Poseidon(api, []frontend.Variable{spendPK, salt})
	return pos.Poseidon(api, []frontend.Variable{h1, uId})
}

// CommitmentV2ERC1155 computes H(H(H(H(spendPK, salt), tokenAddress), tokenID), tokenAmount)
// using chained 2-input Poseidon hashes.
func CommitmentV2ERC1155(api frontend.API, spendPK, salt, tokenAddress, tokenID, tokenAmount frontend.Variable) frontend.Variable {
	h1 := pos.Poseidon(api, []frontend.Variable{spendPK, salt})
	h2 := pos.Poseidon(api, []frontend.Variable{h1, tokenAddress})
	h3 := pos.Poseidon(api, []frontend.Variable{h2, tokenID})
	return pos.Poseidon(api, []frontend.Variable{h3, tokenAmount})
}
