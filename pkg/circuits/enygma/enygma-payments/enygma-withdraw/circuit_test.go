package withdraw

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
	senderIdx  = 1
	paymentSk  = "777777"
	paymentSlt = "42"
	token      = "1234567890123456789012345678901234567890"
)

func compile(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &WithdrawEnygmak3Circuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return ccs
}

// withdraw builds a fixture where the sender is credited v, backed by a DvP
// join-split payment output worth paymentValue under the payment key.
func withdraw(t *testing.T, v, paymentValue int64) *WithdrawEnygmak3Circuit {
	t.Helper()
	f := paytest.New(t, k3, senderIdx, 0, v)
	values := make([]*big.Int, k3)
	values[senderIdx] = big.NewInt(v)
	f.SetTxValues(values...)
	a := assign(f)
	setPayment(a, paymentValue)
	return a
}

// setPayment sets the join-split payment output the contract will compare against.
func setPayment(a *WithdrawEnygmak3Circuit, paymentValue int64) {
	pk := primitives.DerivePublicKeyBN254(paymentSk)
	a.PaymentCommitment = primitives.ComputeCommitmentV2ERC20BN254(pk, paymentSlt, fmt.Sprint(paymentValue), token)
	a.PaymentSecretKey = paymentSk
	a.PaymentSalt = paymentSlt
	a.Address = token
}

func assign(f *paytest.Fixture) *WithdrawEnygmak3Circuit {
	a := &WithdrawEnygmak3Circuit{
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

func isSolved(t *testing.T, ccs constraint.ConstraintSystem, a *WithdrawEnygmak3Circuit) error {
	t.Helper()
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	return ccs.IsSolved(w)
}

func TestWithdrawHonest(t *testing.T) {
	t.Parallel()
	if err := isSolved(t, compile(t), withdraw(t, 30, 30)); err != nil {
		t.Fatalf("honest withdraw rejected: %v", err)
	}
}

func TestWithdrawRejectsAttacks(t *testing.T) {
	t.Parallel()
	ccs := compile(t)
	tests := []struct {
		name  string
		build func(t *testing.T) *WithdrawEnygmak3Circuit
	}{
		{
			// Moves 1000 from one decoy to another: +1000 and L - 1000 sum to 0 mod L.
			name: "value shifted between other members",
			build: func(t *testing.T) *WithdrawEnygmak3Circuit {
				f := paytest.New(t, k3, senderIdx, 0, 30)
				values := make([]*big.Int, k3)
				values[senderIdx] = big.NewInt(30)
				values[0] = big.NewInt(1000)
				values[2] = paytest.Neg(big.NewInt(1000))
				f.SetTxValues(values...)
				b := assign(f)
				setPayment(b, 30)
				return b
			},
		},
		{
			name: "credit above the amount range",
			build: func(t *testing.T) *WithdrawEnygmak3Circuit {
				// A witness crediting 2^128, consistent except for the range bound.
				f := paytest.New(t, k3, senderIdx, 0, 0)
				credit := new(big.Int).Lsh(big.NewInt(1), 128)
				f.SenderTxValue = credit
				values := make([]*big.Int, k3)
				values[senderIdx] = credit
				f.SetTxValues(values...)
				b := assign(f)
				pk := primitives.DerivePublicKeyBN254(paymentSk)
				b.PaymentCommitment = primitives.ComputeCommitmentV2ERC20BN254(pk, paymentSlt, credit.String(), token)
				b.PaymentSecretKey, b.PaymentSalt, b.Address = paymentSk, paymentSlt, token
				return b
			},
		},
		{
			// The join-split paid out 30; the proof tries to credit 31.
			name:  "credit above the burned payment",
			build: func(t *testing.T) *WithdrawEnygmak3Circuit { return withdraw(t, 31, 30) },
		},
		{
			name: "payment opened with another key",
			build: func(t *testing.T) *WithdrawEnygmak3Circuit {
				a := withdraw(t, 30, 30)
				a.PaymentSecretKey = "888888"
				return a
			},
		},
		{
			name: "payment opened with another salt",
			build: func(t *testing.T) *WithdrawEnygmak3Circuit {
				a := withdraw(t, 30, 30)
				a.PaymentSalt = 43
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
