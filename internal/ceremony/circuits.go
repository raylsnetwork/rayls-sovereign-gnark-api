package ceremony

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	enygma_joinsplit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/enygma-joinsplit-dvp"
	erc1155_joinsplit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/erc1155-joinsplit-dvp"
	erc721_ownership "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/erc721-ownership-dvp"
	deposit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-deposit"
	enygma "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-transfer"
	withdraw "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-withdraw"
)

// Circuit is one circuit in the ceremony and the artifact names it produces.
type Circuit struct {
	// Name is the base name of the keys and R1CS in last_build, e.g. "Enygmak2"
	// gives keys/Enygmak2Pk.key, keys/Enygmak2Vk.key and circuits/Enygmak2.r1cs.
	Name string
	// Verifier is the base name of the Solidity verifier, e.g. "EnygmaVerifierk2".
	Verifier string
	// New returns an empty circuit definition to compile.
	New func() frontend.Circuit
}

// ProductionCircuits returns the 18 circuits served by the API, named as in
// config/config.go and cmd/setup/setup_keys_verifiers.
func ProductionCircuits() []Circuit {
	return []Circuit{
		{"Enygmak2", "EnygmaVerifierk2", func() frontend.Circuit { return &enygma.Enygmak2Circuit{} }},
		{"Enygmak3", "EnygmaVerifierk3", func() frontend.Circuit { return &enygma.Enygmak3Circuit{} }},
		{"Enygmak4", "EnygmaVerifierk4", func() frontend.Circuit { return &enygma.Enygmak4Circuit{} }},
		{"Enygmak5", "EnygmaVerifierk5", func() frontend.Circuit { return &enygma.Enygmak5Circuit{} }},
		{"Enygmak6", "EnygmaVerifierk6", func() frontend.Circuit { return &enygma.Enygmak6Circuit{} }},
		{"Withdrawk2", "EnygmaWithdrawFromDvpVerifierk2", func() frontend.Circuit { return &withdraw.WithdrawEnygmak2Circuit{} }},
		{"Withdrawk3", "EnygmaWithdrawFromDvpVerifierk3", func() frontend.Circuit { return &withdraw.WithdrawEnygmak3Circuit{} }},
		{"Withdrawk4", "EnygmaWithdrawFromDvpVerifierk4", func() frontend.Circuit { return &withdraw.WithdrawEnygmak4Circuit{} }},
		{"Withdrawk5", "EnygmaWithdrawFromDvpVerifierk5", func() frontend.Circuit { return &withdraw.WithdrawEnygmak5Circuit{} }},
		{"Withdrawk6", "EnygmaWithdrawFromDvpVerifierk6", func() frontend.Circuit { return &withdraw.WithdrawEnygmak6Circuit{} }},
		{"Depositk2", "EnygmaDepositToDvpVerifierk2", func() frontend.Circuit { return &deposit.DepositEnygmak2Circuit{} }},
		{"Depositk3", "EnygmaDepositToDvpVerifierk3", func() frontend.Circuit { return &deposit.DepositEnygmak3Circuit{} }},
		{"Depositk4", "EnygmaDepositToDvpVerifierk4", func() frontend.Circuit { return &deposit.DepositEnygmak4Circuit{} }},
		{"Depositk5", "EnygmaDepositToDvpVerifierk5", func() frontend.Circuit { return &deposit.DepositEnygmak5Circuit{} }},
		{"Depositk6", "EnygmaDepositToDvpVerifierk6", func() frontend.Circuit { return &deposit.DepositEnygmak6Circuit{} }},
		{"EnygmaJoinSplit", "EnygmaJoinSplitVerifier", func() frontend.Circuit { return &enygma_joinsplit.EnygmaJoinSplitCircuit{} }},
		{"Erc721Ownership", "Erc721OwnershipVerifier", func() frontend.Circuit { return &erc721_ownership.Erc721OwnershipCircuit{} }},
		{"Erc1155JoinSplit", "Erc1155JoinSplitVerifier", func() frontend.Circuit { return &erc1155_joinsplit.Erc1155JoinSplitCircuit{} }},
	}
}

// compiled is a circuit together with its constraint system.
type compiled struct {
	Circuit
	R1CS *cs.R1CS
	// Hash is the hex SHA-256 of the serialized constraint system.
	Hash string
	// Power is log2 of the evaluation domain the circuit needs.
	Power int
}

// compile builds the R1CS for c over BN254 and hashes it.
func compile(c Circuit) (*compiled, error) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c.New())
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", c.Name, err)
	}
	r, ok := ccs.(*cs.R1CS)
	if !ok {
		return nil, fmt.Errorf("compile %s: unexpected constraint system type %T", c.Name, ccs)
	}
	h := sha256.New()
	if _, err := r.WriteTo(h); err != nil {
		return nil, fmt.Errorf("hash %s: %w", c.Name, err)
	}
	return &compiled{
		Circuit: c,
		R1CS:    r,
		Hash:    hex.EncodeToString(h.Sum(nil)),
		Power:   domainPower(r.GetNbConstraints()),
	}, nil
}

// domainPower returns log2 of the smallest power of two >= n.
func domainPower(n int) int {
	return bits.Len64(ecc.NextPowerOfTwo(uint64(n)) - 1)
}
