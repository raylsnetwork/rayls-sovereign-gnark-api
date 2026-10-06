package primitives

import (
	pos "github.com/raylsnetwork/rayls-sovereign-gnark-api/poseidon"

	"github.com/consensys/gnark/frontend"
)

// Nullifier computes Poseidon(privateKey, pathIndex). The output is already a
// BN254 field element, so it matches ComputeNullifierBN254 without reduction.
func Nullifier(api frontend.API, privateKey frontend.Variable, pathIndex frontend.Variable) frontend.Variable {
	return pos.Poseidon(api, []frontend.Variable{privateKey, pathIndex})
}
