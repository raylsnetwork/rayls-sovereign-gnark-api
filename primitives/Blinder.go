package primitives

import (
	pos "github.com/raylsnetwork/rayls-sovereign-gnark-api/poseidon"

	"github.com/consensys/gnark/frontend"
)

func Blinder(api frontend.API, in frontend.Variable) frontend.Variable {

	hasherInter := pos.Poseidon(api, []frontend.Variable{in})

	hash, _ := api.NewHint(ModHintBN254, 2, hasherInter)

	return hash[0]

}
