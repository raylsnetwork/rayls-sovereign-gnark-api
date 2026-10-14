package primitives

import "github.com/consensys/gnark/frontend"

// MaxAmountBits bounds every balance and amount. Values are only defined mod
// the subgroup order l (~2^251) in Pedersen commitments and mod p in Poseidon
// commitments, so without a bound far below both a balance B can be opened as
// B + l, and a "negative" amount l - x or p - x passes as positive. With at
// most 12 values below 2^128, no sum can wrap.
const MaxAmountBits = 128

// AssertIsAmount constrains 0 <= v < 2^MaxAmountBits.
func AssertIsAmount(api frontend.API, v frontend.Variable) {
	api.ToBinary(v, MaxAmountBits)
}
