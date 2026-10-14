package primitives

import "github.com/consensys/gnark/frontend"

// DummyNullifier is Poseidon(0, 0): the nullifier of an all-zero padding input.
// The vault contracts (AbstractCoinVault.dummyNullifier) skip the Merkle root and
// double-spend checks for any input carrying it.
var DummyNullifier = mustBigInt("14744269619966411208579211824598458697587494354926760081771325075741142829156")

// AssertRealInputNotDummy requires that an enabled (non-zero value) input does not
// use DummyNullifier. Without it, sk = 0 and pathIndex = 0 give a real-value input
// the dummy nullifier, so the contract never checks its (prover-chosen) root.
func AssertRealInputNotDummy(api frontend.API, enabled, nullifier frontend.Variable) {
	isDummy := api.IsZero(api.Sub(nullifier, DummyNullifier))
	api.AssertIsEqual(api.Mul(enabled, isDummy), 0)
}

// BindPublicInputs adds a constraint on each variable. Groth16 only binds a proof
// to public inputs that appear in a constraint; one that appears in none can be
// changed after proving and the proof still verifies.
//
// v == v is always true; the assertion is there only to put v in the constraint
// system (one R1CS constraint per input). The DvP circuit tests
// (circuittest.ProofBindsPublicInputs) prove, then change each bound input and
// require Verify to fail, so a gnark change that drops the constraint fails them.
// Checked with gnark v0.14.0; rerun those tests after any upgrade.
func BindPublicInputs(api frontend.API, vars ...frontend.Variable) {
	for _, v := range vars {
		api.AssertIsEqual(v, v)
	}
}
