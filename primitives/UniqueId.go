package primitives

import (
	pos "enygma-gnark-server/poseidon"

	"github.com/consensys/gnark/frontend"
)

func UniqueId(api frontend.API, contractAddress frontend.Variable, amount frontend.Variable) frontend.Variable {

	hasher := pos.Poseidon(api, []frontend.Variable{contractAddress, amount})

	hasherOut, _ := api.NewHint(ModHintBN254, 2, hasher)

	return hasherOut[0]

}
