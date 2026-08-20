package primitives

import (
	pos "enygma-gnark-server/poseidon"

	"github.com/consensys/gnark/frontend"
)

func Nullifier(api frontend.API, privateKey frontend.Variable, pathIndex frontend.Variable) frontend.Variable {

	hasher := pos.Poseidon(api, []frontend.Variable{privateKey, pathIndex})
	nullifier, _ := api.NewHint(ModHintBN254, 2, hasher)
	return nullifier[0]

}
