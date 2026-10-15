package primitives

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// remainderBits is the bit length of l.
const remainderBits = 251

// maxRemainderWhenQuotientIsSeven is p_BN254 - 7*l. When the quotient is 7 the
// remainder must stay below it, otherwise 7*l + r would wrap past the field
// modulus and a second (q, r) pair would satisfy x = q*l + r in the field.
var maxRemainderWhenQuotientIsSeven = new(big.Int).Sub(
	ecc.BN254.ScalarField(),
	new(big.Int).Mul(big.NewInt(7), JubJubPrimeSubGroup),
)

// ModSubgroup returns x mod l, where l is the BabyJubJub prime subgroup order.
//
// The quotient and remainder come from ModHintBabyJubJub and are fully
// constrained: x = q*l + r as integers, with 0 <= q <= 7 and 0 <= r < l.
// Since every field element is below 8*l, this pins down a unique r.
func ModSubgroup(api frontend.API, x frontend.Variable) (frontend.Variable, error) {
	out, err := api.NewHint(ModHintBabyJubJub, 2, x)
	if err != nil {
		return nil, fmt.Errorf("mod subgroup hint: %w", err)
	}
	r, q := out[0], out[1]

	api.ToBinary(q, 3) // q in [0, 7]
	api.AssertIsEqual(api.Add(api.Mul(q, JubJubPrimeSubGroup), r), x)

	// 0 <= r < bound, where bound <= l < 2^251:
	//   ToBinary(r, 251)           gives 0 <= r < 2^251;
	//   ToBinary(bound-1-r, 251)   gives r <= bound-1, because for r >= bound
	//   the difference is negative and wraps to p - (r - bound + 1), which is
	//   above p - 2^251 > 2^251 because p > 2^253 (BN254).
	isSeven := api.IsZero(api.Sub(q, 7))
	bound := api.Select(isSeven, maxRemainderWhenQuotientIsSeven, JubJubPrimeSubGroup)
	api.ToBinary(r, remainderBits)
	api.ToBinary(api.Sub(bound, 1, r), remainderBits)

	return r, nil
}
