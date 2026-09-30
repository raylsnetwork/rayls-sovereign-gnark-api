package withdraw

import (
	"testing"

	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

func TestValidatePaymentCommitment(t *testing.T) {
	t.Parallel()
	pk := primitives.DerivePublicKeyBN254(paymentSk)
	commitment := primitives.ComputeCommitmentV2ERC20BN254(pk, paymentSlt, "30", token)

	tests := []struct {
		name             string
		sk, salt, amount string
		wantErr          bool
	}{
		{"matches", paymentSk, paymentSlt, "30", false},
		{"other amount", paymentSk, paymentSlt, "31", true},
		{"other key", "888888", paymentSlt, "30", true},
		{"other salt", paymentSk, "43", "30", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validatePaymentCommitment(commitment, tc.sk, tc.salt, tc.amount, token)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
