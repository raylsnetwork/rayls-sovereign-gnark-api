package primitives

import (
	pos "github.com/raylsnetwork/rayls-sovereign-gnark-api/poseidon"

	"github.com/consensys/gnark/frontend"
)

func AuctionId(api frontend.API, commitment frontend.Variable) frontend.Variable {

	idInter := pos.Poseidon(api, []frontend.Variable{commitment})
	id, _ := api.NewHint(ModHintBN254, 2, idInter)
	return id[0]

}
