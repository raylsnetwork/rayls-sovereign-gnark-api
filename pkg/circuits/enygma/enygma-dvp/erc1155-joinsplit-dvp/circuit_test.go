package erc1155_joinsplit

import (
	"testing"

	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/internal/dvptest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/internal/circuittest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

const (
	ownerSk = "123456789012345678901234567890"
	token   = "1234567890123456789012345678901234567890"
	tokenID = "7"
)

var joinSplit = dvptest.JoinSplit{
	Commit: func(pk, salt, value string) string {
		return primitives.ComputeCommitmentV2ERC1155BN254(pk, salt, token, tokenID, value)
	},
}

// honestWitness spends two notes (60 + 40) into two outputs (70 + 30).
func honestWitness(t testing.TB) *Erc1155JoinSplitCircuit {
	t.Helper()
	w := &Erc1155JoinSplitCircuit{NftCommitment: 777, Erc1155ContractAddress: token, Erc1155TokenId: tokenID, RevertSalt: 5}
	joinSplit.FillHonest(t, w, ownerSk)
	return w
}

func TestJoinSplitHonestWitnessSolves(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &Erc1155JoinSplitCircuit{})
	if err := circuittest.IsSolved(t, ccs, honestWitness(t)); err != nil {
		t.Fatalf("honest witness rejected: %v", err)
	}
}

func TestJoinSplitRejectsAttacks(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &Erc1155JoinSplitCircuit{})
	circuittest.RejectsAttacks(t, ccs, dvptest.JoinSplitAttacks(joinSplit, honestWitness))
}

func TestJoinSplitProofBindsPublicInputs(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &Erc1155JoinSplitCircuit{})
	circuittest.ProofBindsPublicInputs(t, ccs, honestWitness, dvptest.JoinSplitPublicInputChanges[*Erc1155JoinSplitCircuit]())
}
