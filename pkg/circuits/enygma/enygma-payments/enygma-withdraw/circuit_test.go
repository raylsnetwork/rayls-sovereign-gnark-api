package withdraw

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/internal/paytest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/internal/circuittest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

const (
	senderIdx  = 1
	paymentSk  = "777777"
	paymentSlt = "42"
	token      = "1234567890123456789012345678901234567890"
)

// withdraw builds a fixture where the sender is credited v, backed by a DvP
// join-split payment output worth paymentValue under the payment key.
func withdraw(t *testing.T, v, paymentValue int64) *WithdrawEnygmak3Circuit {
	t.Helper()
	f := paytest.New(t, k3, senderIdx, 0, v)
	values := make([]*big.Int, k3)
	values[senderIdx] = big.NewInt(v)
	f.SetTxValues(values...)
	a := assign(t, f)
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

func assign(t testing.TB, f *paytest.Fixture) *WithdrawEnygmak3Circuit {
	t.Helper()
	a := &WithdrawEnygmak3Circuit{}
	f.Assign(t, a)
	return a
}

func TestWithdrawHonest(t *testing.T) {
	t.Parallel()
	if err := circuittest.IsSolved(t, circuittest.Compile(t, &WithdrawEnygmak3Circuit{}), withdraw(t, 30, 30)); err != nil {
		t.Fatalf("honest withdraw rejected: %v", err)
	}
}

func TestWithdrawRejectsAttacks(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &WithdrawEnygmak3Circuit{})
	circuittest.RejectsAttacks(t, ccs, []circuittest.Attack[*WithdrawEnygmak3Circuit]{
		{
			// Moves 1000 from one decoy to another: +1000 and L - 1000 sum to 0 mod L.
			Name: "value shifted between other members",
			Build: func(t *testing.T) *WithdrawEnygmak3Circuit {
				f := paytest.New(t, k3, senderIdx, 0, 30)
				values := make([]*big.Int, k3)
				values[senderIdx] = big.NewInt(30)
				values[0] = big.NewInt(1000)
				values[2] = paytest.Neg(big.NewInt(1000))
				f.SetTxValues(values...)
				b := assign(t, f)
				setPayment(b, 30)
				return b
			},
		},
		{
			Name: "credit above the amount range",
			Build: func(t *testing.T) *WithdrawEnygmak3Circuit {
				// A witness crediting 2^128, consistent except for the range bound.
				f := paytest.New(t, k3, senderIdx, 0, 0)
				credit := new(big.Int).Lsh(big.NewInt(1), 128)
				f.SenderTxValue = credit
				values := make([]*big.Int, k3)
				values[senderIdx] = credit
				f.SetTxValues(values...)
				b := assign(t, f)
				pk := primitives.DerivePublicKeyBN254(paymentSk)
				b.PaymentCommitment = primitives.ComputeCommitmentV2ERC20BN254(pk, paymentSlt, credit.String(), token)
				b.PaymentSecretKey, b.PaymentSalt, b.Address = paymentSk, paymentSlt, token
				return b
			},
		},
		{
			// The join-split paid out 30; the proof tries to credit 31.
			Name:  "credit above the burned payment",
			Build: func(t *testing.T) *WithdrawEnygmak3Circuit { return withdraw(t, 31, 30) },
		},
		{
			Name: "payment opened with another key",
			Build: func(t *testing.T) *WithdrawEnygmak3Circuit {
				a := withdraw(t, 30, 30)
				a.PaymentSecretKey = "888888"
				return a
			},
		},
		{
			Name: "payment opened with another salt",
			Build: func(t *testing.T) *WithdrawEnygmak3Circuit {
				a := withdraw(t, 30, 30)
				a.PaymentSalt = 43
				return a
			},
		},
	})
}
