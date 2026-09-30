package enygma

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/internal/paytest"
)

const (
	senderIdx   = 1
	receiverIdx = 2
	decoyIdx    = 0
)

func compile(t testing.TB) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Enygmak3Circuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return ccs
}

func assign(f *paytest.Fixture) *Enygmak3Circuit {
	a := &Enygmak3Circuit{
		SenderId:                  f.SenderID,
		SecretKey:                 f.SecretKey,
		PreviousSenderBalance:     f.PreviousV,
		PreviousSenderRandomValue: f.PreviousR,
		SenderTxValue:             f.SenderTxValue,
		Nullifier:                 f.Nullifier,
		BlockNumber:               f.BlockNumber,
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

func isSolved(t *testing.T, ccs constraint.ConstraintSystem, a *Enygmak3Circuit) error {
	t.Helper()
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	return ccs.IsSolved(w)
}

func TestTransferHonest(t *testing.T) {
	t.Parallel()
	ccs := compile(t)
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
			if err := isSolved(t, ccs, assign(transfer(t, tc.balance, tc.v))); err != nil {
				t.Fatalf("honest transfer rejected: %v", err)
			}
		})
	}
}

func TestTransferRejectsAttacks(t *testing.T) {
	t.Parallel()
	ccs := compile(t)
	tests := []struct {
		name  string
		build func(t *testing.T) *Enygmak3Circuit
	}{
		{
			name:  "amount above balance",
			build: func(t *testing.T) *Enygmak3Circuit { return assign(transfer(t, 100, 101)) },
		},
		{
			// Pays the receiver 1000 extra and takes it from a decoy with a
			// "negative" amount L - 1000; the values still sum to 0 mod L.
			name: "negative amount to another member",
			build: func(t *testing.T) *Enygmak3Circuit {
				f := transfer(t, 100, 30)
				values := make([]*big.Int, k3)
				values[senderIdx] = paytest.Neg(big.NewInt(30))
				values[receiverIdx] = big.NewInt(1030)
				values[decoyIdx] = paytest.Neg(big.NewInt(1000))
				f.SetTxValues(values...)
				return assign(f)
			},
		},
		{
			// Opens the balance commitment of 100 as 100 + L (same point) to pass
			// the balance check while spending 150.
			name: "balance opened as balance + L",
			build: func(t *testing.T) *Enygmak3Circuit {
				a := assign(transfer(t, 100, 150))
				a.PreviousSenderBalance = new(big.Int).Add(big.NewInt(100), paytest.L)
				return a
			},
		},
		{
			name: "debit does not match amount",
			build: func(t *testing.T) *Enygmak3Circuit {
				a := assign(transfer(t, 100, 30))
				a.SenderTxValue = 10
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

func BenchmarkTransferK3Prove(b *testing.B) {
	ccs := compile(b)
	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatalf("setup: %v", err)
	}
	w, err := frontend.NewWitness(assign(transfer(b, 100, 30)), ecc.BN254.ScalarField())
	if err != nil {
		b.Fatalf("witness: %v", err)
	}
	b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := groth16.Prove(ccs, pk, w); err != nil {
			b.Fatalf("prove: %v", err)
		}
	}
}
