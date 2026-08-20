package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// BabyJubJub curve parameters
var (
	a   = mustParseBigInt("168700")
	d   = mustParseBigInt("168696")
	p   = mustParseBigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617")
	one = big.NewInt(1)
	two = big.NewInt(2)
)

// Point represents a point on the Baby Jubjub curve
type Point struct {
	X, Y *big.Int
}

// HSetupCircuit is a simple circuit to verify a point is on the Baby Jubjub curve
type HSetupCircuit struct {
	X frontend.Variable
	Y frontend.Variable
}

// Define implements the circuit logic
func (circuit *HSetupCircuit) Define(api frontend.API) error {
	// Baby Jubjub curve equation: a*x² + y² = 1 + d*x²*y²
	x2 := api.Mul(circuit.X, circuit.X)
	y2 := api.Mul(circuit.Y, circuit.Y)
	x2y2 := api.Mul(x2, y2)

	// Left side: a*x² + y²
	ax2 := api.Mul(a.String(), x2)
	leftSide := api.Add(ax2, y2)

	// Right side: 1 + d*x²*y²
	dx2y2 := api.Mul(d.String(), x2y2)
	rightSide := api.Add(1, dx2y2)

	// Assert curve equation holds
	api.AssertIsEqual(leftSide, rightSide)

	return nil
}

func main() {
	fmt.Println("=====================================")
	fmt.Println("Baby Jubjub H Parameter Generator")
	fmt.Println("=====================================\n")

	// Generate H point
	fmt.Println("🔍 Searching for valid H point...")
	H := generateHPoint()
	fmt.Printf("✅ Found valid point H:\n")
	fmt.Printf("   Hx = %s\n", H.X.String())
	fmt.Printf("   Hy = %s\n", H.Y.String())

	// Apply cofactor clearing
	fmt.Println("\n🔄 Clearing cofactor (multiplying by 8)...")
	HCofactorCleared := clearCofactor(H)
	fmt.Printf("✅ Cofactor-cleared H:\n")
	fmt.Printf("   Hx = %s\n", HCofactorCleared.X.String())
	fmt.Printf("   Hy = %s\n", HCofactorCleared.Y.String())

	// Verify using gnark circuit
	fmt.Println("\n🔐 Verifying point using gnark circuit...")
	if err := verifyPointWithCircuit(HCofactorCleared); err != nil {
		fmt.Printf("❌ Circuit verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Circuit verification successful!")

	// Print final output
	fmt.Println("\n=====================================")
	fmt.Println("Final H Parameter (Cofactor-Cleared)")
	fmt.Println("=====================================")
	fmt.Printf("Hx = \"%s\"\n", HCofactorCleared.X.String())
	fmt.Printf("Hy = \"%s\"\n", HCofactorCleared.Y.String())
	fmt.Println("\n✅ H parameter generation complete!")
	fmt.Println("\n💡 You can use these values in primitives/GroupMath.go")
}

// generateHPoint generates a valid Baby Jubjub point using the Nothing Up My Sleeve (NUMS)
// methodology. This ensures nobody knows the discrete log relationship between G and H,
// which is critical for Pedersen commitment security. The deterministic SHA256 hash chain
// starting from seed=1 makes the process publicly verifiable and prevents trapdoor selection.
// See README.md for full security rationale.
func generateHPoint() Point {
	seed := big.NewInt(1)

	for {
		// Hash the seed
		hash := sha256hash(seed)

		// Check if hash is a valid x-coordinate on Baby Jubjub
		if y, valid := babyJubYFromX(hash); valid {
			return Point{X: hash, Y: y}
		}

		// Use hash as next seed
		seed = hash
	}
}

// sha256hash computes SHA256 of a big.Int
func sha256hash(number *big.Int) *big.Int {
	buf := number.Bytes()
	hash := sha256.Sum256(buf)
	result := new(big.Int)
	result.SetBytes(hash[:])
	return result
}

// babyJubYFromX computes the y-coordinate from x on Baby Jubjub curve
func babyJubYFromX(xIn *big.Int) (*big.Int, bool) {
	x := mod(new(big.Int).Set(xIn))

	// x² = x²
	x2 := new(big.Int).Exp(x, two, p)

	// num = 1 - a*x²
	ax2 := new(big.Int).Mul(a, x2)
	num := new(big.Int).Sub(one, ax2)
	mod(num)

	// den = 1 - d*x²
	dx2 := new(big.Int).Mul(d, x2)
	den := new(big.Int).Sub(one, dx2)
	mod(den)

	// Check if denominator is zero
	if den.Sign() == 0 {
		return nil, false
	}

	// y² = num / den
	invDen := modInverse(den)
	if invDen == nil {
		return nil, false
	}
	y2 := new(big.Int).Mul(num, invDen)
	y2.Mod(y2, p)

	// Compute square root using Tonelli-Shanks
	y, ok := tonelliShanks(y2)
	if !ok {
		return nil, false
	}

	// Canonicalize: choose even y
	if y.Bit(0) == 1 {
		y.Sub(p, y)
	}

	return y, true
}

// clearCofactor multiplies point by cofactor h=8 (2³)
func clearCofactor(P Point) Point {
	Q := double(P) // [2]P
	Q = double(Q)  // [4]P
	Q = double(Q)  // [8]P
	return Q
}

// add adds two points on Baby Jubjub curve
func add(P, Q Point) Point {
	// x1*x2 and y1*y2
	x1x2 := new(big.Int).Mul(P.X, Q.X)
	x1x2.Mod(x1x2, p)
	y1y2 := new(big.Int).Mul(P.Y, Q.Y)
	y1y2.Mod(y1y2, p)

	// t = d*x1*x2*y1*y2
	t := new(big.Int).Mul(d, new(big.Int).Mul(x1x2, y1y2))
	t.Mod(t, p)

	// x numerator: x1*y2 + y1*x2
	xnum := new(big.Int).Add(new(big.Int).Mul(P.X, Q.Y), new(big.Int).Mul(P.Y, Q.X))
	xnum.Mod(xnum, p)

	// x denominator: 1 + t
	xden := new(big.Int).Add(one, t)
	xden.Mod(xden, p)

	// y numerator: y1*y2 - a*x1*x2
	ayx := new(big.Int).Mul(a, x1x2)
	ayx.Mod(ayx, p)
	ynum := new(big.Int).Sub(y1y2, ayx)
	mod(ynum)

	// y denominator: 1 - t
	yden := new(big.Int).Sub(one, t)
	mod(yden)

	// x3 = xnum / xden
	ixd := modInverse(xden)
	iyd := modInverse(yden)
	x3 := new(big.Int).Mul(xnum, ixd)
	x3.Mod(x3, p)
	y3 := new(big.Int).Mul(ynum, iyd)
	y3.Mod(y3, p)

	return Point{X: x3, Y: y3}
}

// double doubles a point
func double(P Point) Point {
	return add(P, P)
}

// verifyPointWithCircuit verifies the point using gnark
func verifyPointWithCircuit(P Point) error {
	var circuit HSetupCircuit

	// Compile circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}

	// Generate proving and verifying keys
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("failed to setup keys: %w", err)
	}

	// Create witness
	witness := HSetupCircuit{
		X: frontend.Variable(P.X.String()),
		Y: frontend.Variable(P.Y.String()),
	}

	// Generate full witness
	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to create witness: %w", err)
	}

	// Generate proof
	proof, err := groth16.Prove(ccs, pk, witnessFull)
	if err != nil {
		return fmt.Errorf("failed to generate proof: %w", err)
	}

	// Create public witness
	witnessPublic, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	// Verify proof
	err = groth16.Verify(proof, vk, witnessPublic)
	if err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// Utility functions

func mod(x *big.Int) *big.Int {
	x.Mod(x, p)
	if x.Sign() < 0 {
		x.Add(x, p)
	}
	return x
}

func modInverse(x *big.Int) *big.Int {
	return new(big.Int).ModInverse(mod(new(big.Int).Set(x)), p)
}

func legendreSymbol(x *big.Int) *big.Int {
	e := new(big.Int).Sub(p, one)
	e.Rsh(e, 1) // (p-1)/2
	return new(big.Int).Exp(mod(new(big.Int).Set(x)), e, p)
}

func tonelliShanks(n *big.Int) (*big.Int, bool) {
	n = mod(new(big.Int).Set(n))
	if n.Sign() == 0 {
		return big.NewInt(0), true
	}

	// Check quadratic residue
	ls := legendreSymbol(n)
	if ls.Cmp(one) != 0 {
		return nil, false
	}

	// Factor p-1 = q * 2^s with q odd
	q := new(big.Int).Sub(p, one)
	s := 0
	for q.Bit(0) == 0 {
		q.Rsh(q, 1)
		s++
	}

	// Find quadratic non-residue z
	z := big.NewInt(2)
	for {
		if legendreSymbol(z).Cmp(new(big.Int).Sub(p, one)) == 0 {
			break
		}
		z.Add(z, one)
	}

	// Initialize
	c := new(big.Int).Exp(z, q, p)
	t := new(big.Int).Exp(n, q, p)
	r := new(big.Int).Exp(n, new(big.Int).Rsh(new(big.Int).Add(q, one), 1), p)

	for {
		if t.Cmp(one) == 0 {
			return r, true
		}

		// Find least i with t^(2^i) ≡ 1
		i := 1
		t2i := new(big.Int).Exp(t, two, p)
		for i < s {
			if t2i.Cmp(one) == 0 {
				break
			}
			t2i.Exp(t2i, two, p)
			i++
		}

		// b = c^(2^(s-i-1))
		e := s - i - 1
		b := new(big.Int).Set(c)
		for j := 0; j < e; j++ {
			b.Exp(b, two, p)
		}

		// Update
		r.Mul(r, b).Mod(r, p)
		t.Mul(t, new(big.Int).Exp(b, two, p)).Mod(t, p)
		c.Exp(b, two, p)
		s = i
	}
}

func mustParseBigInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(fmt.Sprintf("failed to parse big int: %s", s))
	}
	return n
}
