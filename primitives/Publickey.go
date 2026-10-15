package primitives

import (
	"fmt"

	pos "github.com/raylsnetwork/rayls-sovereign-gnark-api/poseidon"

	"github.com/consensys/gnark/frontend"
)

// PublicKey derives the in-circuit public key as
// Poseidon(sk, sk) mod JubJubPrimeSubGroup, matching the relayer's
// GetPoseidonHashModNumber([]*big.Int{sk, sk}, JubJubPrimeSubGroup).
func PublicKey(api frontend.API, privateKey frontend.Variable) (frontend.Variable, error) {
	hash := pos.Poseidon(api, []frontend.Variable{privateKey, privateKey})

	pk, err := ModSubgroup(api, hash)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	return pk, nil
}
