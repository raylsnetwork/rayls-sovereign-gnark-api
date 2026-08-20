package enygma_joinsplit

import (
	"github.com/consensys/gnark/frontend"
)

const nInputs = 10
const mOutputs = 2
const merkleTreeDepth = 8

var rangeCircuit = frontend.Variable("1000000000000000000000000000000000000")

type EnygmaJoinSplitCircuit struct {
	// Public signals
	NftCommitment  frontend.Variable           `gnark:",public"`
	MerkleRoots    [nInputs]frontend.Variable  `gnark:",public"`
	Nullifiers     [nInputs]frontend.Variable  `gnark:",public"`
	TreeNumbers    [nInputs]frontend.Variable  `gnark:",public"`
	CommitmentsOut   [mOutputs]frontend.Variable `gnark:",public"`
	RevertCommitment frontend.Variable          `gnark:",public"`

	// Private signals
	PrivateKeys           [nInputs]frontend.Variable
	SaltsIn               [nInputs]frontend.Variable
	ValuesIn              [nInputs]frontend.Variable
	PathElements          [nInputs][merkleTreeDepth]frontend.Variable
	PathIndices           [nInputs]frontend.Variable
	EnygmaContractAddress frontend.Variable
	RecipientPK           [mOutputs]frontend.Variable
	SaltsOut              [mOutputs]frontend.Variable
	ValuesOut             [mOutputs]frontend.Variable
	RevertSalt            frontend.Variable
}

type KeyPairIn struct {
	PublicKey  string `json:"publicKey" binding:"required"`
	PrivateKey string `json:"privateKey" binding:"required"`
}

type PubKeyOut struct {
	PublicKey  string `json:"publicKey" binding:"required"`
	PrivateKey string `json:"privateKey"` // Optional for outputs
}

type MerkleProof struct {
	Indices  string   `json:"indices" binding:"required"`
	Elements []string `json:"elements" binding:"required"`
}

type EnygmaJoinSplitRequest struct {
	NftCommitment         string        `json:"nftCommitment" binding:"required"`
	ValuesIn              []string      `json:"valuesIn"` // binding:"required"` removed to allow 0 enygma swap
	ValuesOut             []string      `json:"valuesOut" binding:"required,len=2"`
	KeyPairsIn            []KeyPairIn   `json:"keyPairsIn"` // binding:"required"` removed to allow 0 enygma swap
	PubKeysOut            []PubKeyOut   `json:"pubKeysOut" binding:"required,len=2"`
	MerkleDepth           int           `json:"merkleDepth"`
	MerkleProofs          []MerkleProof `json:"merkleProofs"` // binding:"required"` removed to allow 0 enygma swap
	MerkleRoots           []string      `json:"merkleRoots"`  // binding:"required"` removed to allow 0 enygma swap
	TreeNumbers           []int         `json:"treeNumbers"`  // binding:"required"` removed to allow 0 enygma swap
	EnygmaContractAddress string        `json:"erc20Address" binding:"required"`
	SaltsIn               []string      `json:"saltsIn"`
	SaltsOut              []string      `json:"saltsOut" binding:"required,len=2"`
	RevertSalt            string        `json:"revertSalt" binding:"required"`
}

type EnygmaJoinSplitResponseAPI struct {
	Pi_A          []string   `json:"pi_a"`
	Pi_B          [][]string `json:"pi_b"`
	Pi_C          []string   `json:"pi_c"`
	Public_Signal []string   `json:"public_signal"`
}

func (circuit *EnygmaJoinSplitCircuit) Define(api frontend.API) error {
	return circuitLogic(api,
		circuit.NftCommitment,
		circuit.MerkleRoots[:],
		circuit.Nullifiers[:],
		circuit.CommitmentsOut[:],
		circuit.PrivateKeys[:],
		circuit.SaltsIn[:],
		circuit.ValuesIn[:],
		convertPathElementsToSlice(circuit.PathElements),
		circuit.PathIndices[:],
		circuit.EnygmaContractAddress,
		circuit.RecipientPK[:],
		circuit.SaltsOut[:],
		circuit.ValuesOut[:],
		circuit.RevertCommitment,
		circuit.RevertSalt)
}

func convertPathElementsToSlice(arr [nInputs][merkleTreeDepth]frontend.Variable) [][]frontend.Variable {
	slice := make([][]frontend.Variable, nInputs)
	for i := 0; i < nInputs; i++ {
		slice[i] = make([]frontend.Variable, merkleTreeDepth)
		for j := 0; j < merkleTreeDepth; j++ {
			slice[i][j] = arr[i][j]
		}
	}
	return slice
}
