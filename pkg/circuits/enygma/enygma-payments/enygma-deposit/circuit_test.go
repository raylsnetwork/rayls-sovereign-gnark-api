package deposit

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/internal/paytest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

const (
	senderIdx = 1
	dvpPK     = "31337"
	saltOut   = "555"
	token     = "1234567890123456789012345678901234567890"
)

func compile(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &DepositEnygmak3Circuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return ccs
}

// deposit builds a fixture where the sender, holding balance, moves v into a DvP note.
func deposit(t *testing.T, balance, v int64) *paytest.Fixture {
	t.Helper()
	f := paytest.New(t, k3, senderIdx, balance, v)
	values := make([]*big.Int, k3)
	values[senderIdx] = paytest.Neg(big.NewInt(v))
	f.SetTxValues(values...)
	return f
}

func assign(f *paytest.Fixture) *DepositEnygmak3Circuit {
	a := &DepositEnygmak3Circuit{
		SenderId:                  f.SenderID,
		SecretKey:                 f.SecretKey,
		PreviousSenderBalance:     f.PreviousV,
		PreviousSenderRandomValue: f.PreviousR,
		SenderTxValue:             f.SenderTxValue,
		Nullifier:                 f.Nullifier,
		BlockNumber:               f.BlockNumber,
		Hash:                      primitives.ComputeCommitmentV2ERC20BN254(dvpPK, saltOut, f.SenderTxValue.String(), token),
		Pk:                        dvpPK,
		Address:                   token,
		SaltOut:                   saltOut,
	}
	for i := 0; i < k3; i++ {
		a.SharedSecrets[i] = f.SharedSecrets[i]
		a.HashedSharedSecrets[i] = f.HashedSharedSecrets[i]
		a.PublicKey[i] = f.PublicKeys[i]
		a.PreviousCommits[i] = [2]frontend.Variable{f.PreviousCommits[i][0], f.PreviousCommits[i][1]}
		a.TxCommits[i] = [2]frontend.Variable{f.TxCommits[i][0], f.TxCommits[i][1]}
		a.TxValues[i] = f.TxValues[i]
		a.TxRandomValues[i] = f.TxRandom[i]
		a.AnonymitySet[i] = f.AnonymitySet[i]
		a.MessageTags[i] = f.MessageTags[i]
	}
	return a
}

func isSolved(t *testing.T, ccs constraint.ConstraintSystem, a *DepositEnygmak3Circuit) error {
	t.Helper()
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	return ccs.IsSolved(w)
}

func TestDepositHonest(t *testing.T) {
	t.Parallel()
	ccs := compile(t)
	for _, v := range []int64{30, 100} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			t.Parallel()
			if err := isSolved(t, ccs, assign(deposit(t, 100, v))); err != nil {
				t.Fatalf("honest deposit rejected: %v", err)
			}
		})
	}
}

func TestDepositRejectsAttacks(t *testing.T) {
	t.Parallel()
	ccs := compile(t)
	tests := []struct {
		name  string
		build func(t *testing.T) *DepositEnygmak3Circuit
	}{
		{
			name:  "amount above balance",
			build: func(t *testing.T) *DepositEnygmak3Circuit { return assign(deposit(t, 100, 101)) },
		},
		{
			name: "balance opened as balance + L",
			build: func(t *testing.T) *DepositEnygmak3Circuit {
				a := assign(deposit(t, 100, 150))
				a.PreviousSenderBalance = new(big.Int).Add(big.NewInt(100), paytest.L)
				return a
			},
		},
		{
			// Moves 1000 from one decoy to another: +1000 and L - 1000 sum to 0 mod L.
			name: "value shifted between other members",
			build: func(t *testing.T) *DepositEnygmak3Circuit {
				f := deposit(t, 100, 30)
				values := make([]*big.Int, k3)
				values[senderIdx] = paytest.Neg(big.NewInt(30))
				values[0] = big.NewInt(1000)
				values[2] = paytest.Neg(big.NewInt(1000))
				f.SetTxValues(values...)
				return assign(f)
			},
		},
		{
			name: "DvP note for more than was debited",
			build: func(t *testing.T) *DepositEnygmak3Circuit {
				a := assign(deposit(t, 100, 30))
				a.Hash = primitives.ComputeCommitmentV2ERC20BN254(dvpPK, saltOut, "31", token)
				return a
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := isSolved(t, ccs, tc.build(t)); err == nil {
				t.Fatal("attack witness was accepted")
			}
		})
	}
}
