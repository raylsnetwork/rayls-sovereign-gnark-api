package deposit

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/internal/paytest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/internal/circuittest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

const (
	senderIdx = 1
	dvpPK     = "31337"
	saltOut   = "555"
	token     = "1234567890123456789012345678901234567890"
)

// deposit builds a fixture where the sender, holding balance, moves v into a DvP note.
func deposit(t *testing.T, balance, v int64) *paytest.Fixture {
	t.Helper()
	f := paytest.New(t, k3, senderIdx, balance, v)
	values := make([]*big.Int, k3)
	values[senderIdx] = paytest.Neg(big.NewInt(v))
	f.SetTxValues(values...)
	return f
}

func assign(t testing.TB, f *paytest.Fixture) *DepositEnygmak3Circuit {
	t.Helper()
	a := &DepositEnygmak3Circuit{
		Hash:    primitives.ComputeCommitmentV2ERC20BN254(dvpPK, saltOut, f.SenderTxValue.String(), token),
		Pk:      dvpPK,
		Address: token,
		SaltOut: saltOut,
	}
	f.Assign(t, a)
	return a
}

func TestDepositHonest(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &DepositEnygmak3Circuit{})
	for _, v := range []int64{30, 100} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			t.Parallel()
			if err := circuittest.IsSolved(t, ccs, assign(t, deposit(t, 100, v))); err != nil {
				t.Fatalf("honest deposit rejected: %v", err)
			}
		})
	}
}

func TestDepositRejectsAttacks(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &DepositEnygmak3Circuit{})
	circuittest.RejectsAttacks(t, ccs, []circuittest.Attack[*DepositEnygmak3Circuit]{
		{
			Name:  "amount above balance",
			Build: func(t *testing.T) *DepositEnygmak3Circuit { return assign(t, deposit(t, 100, 101)) },
		},
		{
			Name: "balance opened as balance + L",
			Build: func(t *testing.T) *DepositEnygmak3Circuit {
				a := assign(t, deposit(t, 100, 150))
				a.PreviousSenderBalance = new(big.Int).Add(big.NewInt(100), paytest.L)
				return a
			},
		},
		{
			// Moves 1000 from one decoy to another: +1000 and L - 1000 sum to 0 mod L.
			Name: "value shifted between other members",
			Build: func(t *testing.T) *DepositEnygmak3Circuit {
				f := deposit(t, 100, 30)
				values := make([]*big.Int, k3)
				values[senderIdx] = paytest.Neg(big.NewInt(30))
				values[0] = big.NewInt(1000)
				values[2] = paytest.Neg(big.NewInt(1000))
				f.SetTxValues(values...)
				return assign(t, f)
			},
		},
		{
			Name: "DvP note for more than was debited",
			Build: func(t *testing.T) *DepositEnygmak3Circuit {
				a := assign(t, deposit(t, 100, 30))
				a.Hash = primitives.ComputeCommitmentV2ERC20BN254(dvpPK, saltOut, "31", token)
				return a
			},
		},
	})
}
