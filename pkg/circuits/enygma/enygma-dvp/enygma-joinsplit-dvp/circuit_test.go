package enygma_joinsplit

import (
	"math/big"
	"testing"

	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/internal/dvptest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/internal/circuittest"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

const (
	ownerSk = "123456789012345678901234567890"
	token   = "1234567890123456789012345678901234567890"
)

var joinSplit = dvptest.JoinSplit{
	Commit: func(pk, salt, value string) string {
		return primitives.ComputeCommitmentV2ERC20BN254(pk, salt, value, token)
	},
}

// honestWitness spends two notes (60 + 40) into two outputs (70 + 30).
func honestWitness(t testing.TB) *EnygmaJoinSplitCircuit {
	t.Helper()
	w := &EnygmaJoinSplitCircuit{NftCommitment: 777, EnygmaContractAddress: token, RevertSalt: 5}
	joinSplit.FillHonest(t, w, ownerSk)
	return w
}

func TestJoinSplitHonestWitnessSolves(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &EnygmaJoinSplitCircuit{})
	if err := circuittest.IsSolved(t, ccs, honestWitness(t)); err != nil {
		t.Fatalf("honest witness rejected: %v", err)
	}
}

func TestJoinSplitRejectsAttacks(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &EnygmaJoinSplitCircuit{})
	circuittest.RejectsAttacks(t, ccs, dvptest.JoinSplitAttacks(joinSplit, honestWitness))
}

func TestJoinSplitProofBindsPublicInputs(t *testing.T) {
	t.Parallel()
	ccs := circuittest.Compile(t, &EnygmaJoinSplitCircuit{})
	circuittest.ProofBindsPublicInputs(t, ccs, honestWitness, dvptest.JoinSplitPublicInputChanges[*EnygmaJoinSplitCircuit]())
}

func TestDummyNullifierMatchesContract(t *testing.T) {
	t.Parallel()
	// AbstractCoinVault.dummyNullifier in rayls-privacy-contracts.
	want, _ := new(big.Int).SetString("14744269619966411208579211824598458697587494354926760081771325075741142829156", 10)
	if got := dvptest.DummyNullifier(t); got.Cmp(want) != 0 {
		t.Fatalf("Poseidon(0,0) = %s, contract dummyNullifier = %s", got, want)
	}
}

func BenchmarkJoinSplitProve(b *testing.B) {
	circuittest.BenchmarkProve(b, circuittest.Compile(b, &EnygmaJoinSplitCircuit{}), honestWitness(b))
}
