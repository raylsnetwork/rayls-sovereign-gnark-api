package primitives

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
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
	gxBig, _ = new(big.Int).SetString(Gx, 10)
	gyBig, _ = new(big.Int).SetString(Gy, 10)
	GBabyJub = &babyjub.Point{X: gxBig, Y: gyBig}

	hxBig, _ = new(big.Int).SetString(Hx, 10)
	hyBig, _ = new(big.Int).SetString(Hy, 10)
	HBabyJub = &babyjub.Point{X: hxBig, Y: hyBig}

	// Prime moduli
	JubJubPrimeGroup, _    = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10) //group prime in babyjubjub is 21888242871839275222246405745257275088548364400416034343698204186575808495617, a 254 bit number, BN254 prime
	JubJubPrimeSubGroup, _ = new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)  //sub group prime in babyjubjub is 2736030358979909402780800718157159386076813972158567259200215660948447373041, a 251 bit number
)

func PointAdd(api frontend.API, p1, p2 twistededwards.Point) twistededwards.Point {
	x1y2 := api.Mul(p1.X, p2.Y)
	y1x2 := api.Mul(p1.Y, p2.X)
	x1x2 := api.Mul(p1.X, p2.X)
	y1y2 := api.Mul(p1.Y, p2.Y)

	denomX := api.Add(api.Mul(D, api.Mul(x1x2, y1y2)), frontend.Variable(1))
	denomY := api.Sub(frontend.Variable(1), api.Mul(D, api.Mul(x1x2, y1y2)))

	// Ensure denominators are non-zero.
	api.AssertIsDifferent(denomX, frontend.Variable(0))
	api.AssertIsDifferent(denomY, frontend.Variable(0))

	numerX := api.Add(x1y2, y1x2)
	numerY := api.Sub(y1y2, api.Mul(A, x1x2))

	invDenomX := api.Inverse(denomX)
	invDenomY := api.Inverse(denomY)

	x := api.Mul(numerX, invDenomX)
	y := api.Mul(numerY, invDenomY)

	return twistededwards.Point{X: x, Y: y}
}

// pointDouble doubles a point by simply adding it to itself.
func PointDouble(api frontend.API, p twistededwards.Point) twistededwards.Point {
	return PointAdd(api, p, p)
}

// pointSelect conditionally selects one of two points based on a boolean condition.
func PointSelect(api frontend.API, cond frontend.Variable, p0, p1 twistededwards.Point) twistededwards.Point {
	return twistededwards.Point{
		X: api.Select(cond, p1.X, p0.X),
		Y: api.Select(cond, p1.Y, p0.Y),
	}
}

// scalarMul multiplies a point by a scalar using the double and add algorithm.
// It uses api.ToBinary to decompose the scalar (assumed 256 bits, little-endian).
func ScalarMul(api frontend.API, p twistededwards.Point, scalar frontend.Variable) twistededwards.Point {
	// Convert scalar to its 256-bit binary representation.
	bits := api.ToBinary(scalar, 256)
	// Initialize result to the identity point: (0,1)
	result := twistededwards.Point{
		X: frontend.Variable(0),
		Y: frontend.Variable(1),
	}
	// Use a temporary variable for the point to add.
	temp := p
	for i := 0; i < 256; i++ {
		// If the i-th bit is 1, then add temp to result.
		// Here we compute add := pointAdd(result, temp) and conditionally update result.
		add := PointAdd(api, result, temp)
		result = PointSelect(api, bits[i], result, add)
		// Double the temp point for the next bit.
		temp = PointDouble(api, temp)
	}
	return result
}

func AssertPointsIsOnCurve(api frontend.API, X, Y frontend.Variable) {
	// Compute X² and Y²
	x2 := api.Mul(X, X)
	y2 := api.Mul(Y, Y)

	// Compute X²Y²
	x2y2 := api.Mul(x2, y2)

	// Compute left-hand side (A*X² + Y²)
	lhs := api.Add(api.Mul(A, x2), y2)

	// Compute right-hand side (1 + D*X²Y²)
	rhs := api.Add(1, api.Mul(D, x2y2))

	// Assert equality of both sides
	api.AssertIsEqual(lhs, rhs)
}

func PedersenCommitment(api frontend.API, X, Y frontend.Variable) twistededwards.Point {

	vG := ScalarMul(api, G, X)
	rH := ScalarMul(api, H, Y)

	commitOutput := PointAdd(api, vG, rH)

	return commitOutput

}
