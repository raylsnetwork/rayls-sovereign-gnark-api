package primitives

import (
	pos "github.com/raylsnetwork/rayls-sovereign-gnark-api/poseidon"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

// PublicKey derives the in-circuit public key as
// Poseidon(sk, sk) mod JubJubPrimeSubGroup, matching the relayer's
// GetPoseidonHashModNumber([]*big.Int{sk, sk}, JubJubPrimeSubGroup).
func PublicKey(api frontend.API, privateKey frontend.Variable) frontend.Variable {
	hash := pos.Poseidon(api, []frontend.Variable{privateKey, privateKey})

	out, _ := api.NewHint(ModHintBabyJubJub, 2, hash)
	r := out[0]
	q := out[1]

	p := frontend.Variable(JubJubPrimeSubGroup)
	api.AssertIsEqual(api.Add(api.Mul(q, p), r), hash)
	isValid := cmp.IsLess(api, r, p)
	api.AssertIsEqual(isValid, 1)

	return r
}
