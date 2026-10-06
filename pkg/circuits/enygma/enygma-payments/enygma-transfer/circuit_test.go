package enygma

import (
	"math/big"
	"testing"

	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/internal/paytest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/internal/circuittest"
)

const (
	senderIdx   = 1
	receiverIdx = 2
	decoyIdx    = 0
)

func assign(t testing.TB, f *paytest.Fixture) *Enygmak3Circuit {
	t.Helper()
	a := &Enygmak3Circuit{}
	f.Assign(t, a)
	return a
}

// transfer builds a fixture where the sender, holding balance, sends v to the receiver.
func transfer(t testing.TB, balance, v int64) *paytest.Fixture {
	t.Helper()
	f := paytest.New(t, k3, senderIdx, balance, v)
	values := make([]*big.Int, k3)
	values[senderIdx] = paytest.Neg(big.NewInt(v))
	values[receiverIdx] = big.NewInt(v)
	f.SetTxValues(values...)
	return f
}

func TestTransferHonest(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &Enygmak3Circuit{})
	tests := []struct {
		name       string
		balance, v int64
	}{
		{"partial balance", 100, 30},
		{"whole balance", 100, 100},
		{"zero amount", 100, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := circuittest.IsSolved(t, ccs, assign(t, transfer(t, tc.balance, tc.v))); err != nil {
				t.Fatalf("honest transfer rejected: %v", err)
			}
		})
	}
}

func TestTransferRejectsAttacks(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &Enygmak3Circuit{})
	circuittest.RejectsAttacks(t, ccs, []circuittest.Attack[*Enygmak3Circuit]{
		{
			Name:  "amount above balance",
			Build: func(t *testing.T) *Enygmak3Circuit { return assign(t, transfer(t, 100, 101)) },
		},
		{
			// Pays the receiver 1000 extra and takes it from a decoy with a
			// "negative" amount L - 1000; the values still sum to 0 mod L.
			Name: "negative amount to another member",
			Build: func(t *testing.T) *Enygmak3Circuit {
				f := transfer(t, 100, 30)
				values := make([]*big.Int, k3)
				values[senderIdx] = paytest.Neg(big.NewInt(30))
				values[receiverIdx] = big.NewInt(1030)
				values[decoyIdx] = paytest.Neg(big.NewInt(1000))
				f.SetTxValues(values...)
				return assign(t, f)
			},
		},
		{
			// Opens the balance commitment of 100 as 100 + L (same point) to pass
			// the balance check while spending 150.
			Name: "balance opened as balance + L",
			Build: func(t *testing.T) *Enygmak3Circuit {
				a := assign(t, transfer(t, 100, 150))
				a.PreviousSenderBalance = new(big.Int).Add(big.NewInt(100), paytest.L)
				return a
			},
		},
		{
			Name: "debit does not match amount",
			Build: func(t *testing.T) *Enygmak3Circuit {
				a := assign(t, transfer(t, 100, 30))
				a.SenderTxValue = 10
				return a
			},
		},
	})
}

func BenchmarkTransferK3Prove(b *testing.B) {
	circuittest.BenchmarkProve(b, circuittest.Compile(b, &Enygmak3Circuit{}), assign(b, transfer(b, 100, 30)))
}
