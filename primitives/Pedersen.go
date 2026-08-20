package primitives

import (
	pos "enygma-gnark-server/poseidon"

	"github.com/consensys/gnark/frontend"
)

func Pedersen(api frontend.API, amount frontend.Variable, random frontend.Variable) frontend.Variable {

	commitment := pos.Poseidon(api, []frontend.Variable{amount, random})
	pedersenOut, _ := api.NewHint(ModHintBN254, 2, commitment)
	return pedersenOut[0]

}
