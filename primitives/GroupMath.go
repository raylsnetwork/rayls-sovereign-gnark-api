package primitives

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

var (
	// Curve parameters for BabyJubJub
	A = big.NewInt(168700)
	D = big.NewInt(168696)

	// Generator point G coordinates
	Gx = "16540640123574156134436876038791482806971768689494387082833631921987005038935"
	Gy = "20819045374670962167435360035096875258406992893633759881276124905556507972311"

	// Generator point H coordinates
	Hx = "10100005861917718053548237064487763771145251762383025193119768015180892676690"
	Hy = "7512830269827713629724023825249861327768672768516116945507944076335453576011"

	// Circuit version (twistededwards.Point)
	G = twistededwards.Point{X: Gx, Y: Gy}
	H = twistededwards.Point{X: Hx, Y: Hy}

	// Standalone version (babyjub.Point) - used by validation and non-circuit code
	gxBig    = mustBigInt(Gx)
	gyBig    = mustBigInt(Gy)
	GBabyJub = &babyjub.Point{X: gxBig, Y: gyBig}

	hxBig    = mustBigInt(Hx)
	hyBig    = mustBigInt(Hy)
	HBabyJub = &babyjub.Point{X: hxBig, Y: hyBig}

	// Prime moduli
	JubJubPrimeGroup    = mustBigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617") //group prime in babyjubjub is 21888242871839275222246405745257275088548364400416034343698204186575808495617, a 254 bit number, BN254 prime
	JubJubPrimeSubGroup = mustBigInt("2736030358979909402780800718157159386076813972158567259200215660948447373041")  //sub group prime in babyjubjub is 2736030358979909402780800718157159386076813972158567259200215660948447373041, a 251 bit number
)

// PointAdd adds two points with the complete twisted Edwards law. Both inputs
// MUST be on the BabyJubJub curve: fixed generator multiples, PedersenCommitment
// outputs, or points checked with AssertPointsIsOnCurve. For curve points the
// denominators 1 +- d*v0*v1 never vanish, because a is a square and d is not, so
// api.DivUnchecked is safe; off-curve inputs could give a zero denominator and an
// unconstrained result.
func PointAdd(api frontend.API, p1, p2 twistededwards.Point) twistededwards.Point {
	v0 := api.Mul(p1.X, p2.Y)
	v1 := api.Mul(p2.X, p1.Y)
	u := api.Mul(api.Sub(p1.Y, api.Mul(A, p1.X)), api.Add(p2.X, p2.Y))
	v2 := api.Mul(D, v0, v1)

	return twistededwards.Point{
		X: api.DivUnchecked(api.Add(v0, v1), api.Add(1, v2)),
		Y: api.DivUnchecked(api.Sub(api.Add(u, api.Mul(A, v0)), v1), api.Sub(1, v2)),
	}
}

func AssertPointsIsOnCurve(api frontend.API, X, Y frontend.Variable) {
	x2 := api.Mul(X, X)
	y2 := api.Mul(Y, Y)
	lhs := api.Add(api.Mul(A, x2), y2)
	rhs := api.Add(1, api.Mul(D, x2, y2))
	api.AssertIsEqual(lhs, rhs)
}

// PedersenCommitment returns X*G + Y*H for any field elements X and Y.
func PedersenCommitment(api frontend.API, X, Y frontend.Variable) twistededwards.Point {
	xBits := bits.ToBinary(api, X) // canonical: a non-reduced decomposition would commit to X + p
	yBits := bits.ToBinary(api, Y)

	// acc starts from window 0 of X*G rather than the identity; every window of
	// X*G and Y*H is still added below (a 00 window is the identity point).
	acc := gTable.lookup(api, 0, xBits)
	acc = PointAdd(api, acc, hTable.lookup(api, 0, yBits))
	for w := 1; w < nbWindows; w++ {
		acc = PointAdd(api, acc, gTable.lookup(api, w, xBits))
		acc = PointAdd(api, acc, hTable.lookup(api, w, yBits))
	}
	return acc
}

// nbWindows 2-bit windows cover a canonical BN254 scalar (254 bits).
const nbWindows = 127

// fixedBaseTable holds m * 4^w * P for every window w and digit m in [0, 3].
type fixedBaseTable [nbWindows][4][2]*big.Int

var gTable, hTable = newFixedBaseTable(GBabyJub), newFixedBaseTable(HBabyJub)

func newFixedBaseTable(p *babyjub.Point) *fixedBaseTable {
	t := new(fixedBaseTable)
	base := p
	for w := range t {
		double := AddPks(base, base)
		for m, q := range []*babyjub.Point{{X: big.NewInt(0), Y: big.NewInt(1)}, base, double, AddPks(double, base)} {
			t[w][m] = [2]*big.Int{q.X, q.Y}
		}
		base = AddPks(double, double)
	}
	return t
}

// lookup returns the table entry for window w of the scalar bits. The entries
// are constants, so the selection costs one constraint (the bit product). The
// interpolation c0 + b0(c1-c0) + b1(c2-c0) + b0b1(c3-c2-c1+c0) is exact for any
// four constants, including when the cross coefficient is zero.
func (t *fixedBaseTable) lookup(api frontend.API, w int, bits []frontend.Variable) twistededwards.Point {
	b0, b1 := bits[2*w], bits[2*w+1]
	b01 := api.Mul(b0, b1)
	coord := func(i int) frontend.Variable {
		c0, c1, c2, c3 := t[w][0][i], t[w][1][i], t[w][2][i], t[w][3][i]
		res := api.Add(c0, api.Mul(b0, new(big.Int).Sub(c1, c0)), api.Mul(b1, new(big.Int).Sub(c2, c0)))
		cross := new(big.Int).Sub(c3, c2)
		cross.Sub(cross, c1).Add(cross, c0)
		return api.Add(res, api.Mul(b01, cross))
	}
	return twistededwards.Point{X: coord(0), Y: coord(1)}
}
