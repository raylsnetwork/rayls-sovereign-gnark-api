package ceremony

import "github.com/consensys/gnark/frontend"

// squareChain proves knowledge of X with X^(2^n) = Y; n sets its size.
type squareChain struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
	n int
}

// Define implements frontend.Circuit.
func (c *squareChain) Define(api frontend.API) error {
	acc := c.X
	for i := 0; i < c.n; i++ {
		acc = api.Mul(acc, acc)
	}
	api.AssertIsEqual(acc, c.Y)
	return nil
}

// DemoCircuits returns two tiny circuits of different sizes for rehearsing a
// ceremony in minutes. Their keys are useless for production, and verify
// rejects a demo transcript run against the production circuits.
func DemoCircuits() []Circuit {
	return []Circuit{
		{Name: "DemoSmall", Verifier: "DemoSmallVerifier", New: func() frontend.Circuit { return &squareChain{n: 20} }},
		{Name: "DemoLarge", Verifier: "DemoLargeVerifier", New: func() frontend.Circuit { return &squareChain{n: 100} }},
	}
}
