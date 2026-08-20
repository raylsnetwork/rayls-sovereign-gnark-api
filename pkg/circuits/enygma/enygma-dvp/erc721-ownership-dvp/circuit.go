package erc721_ownership

import (
	"github.com/consensys/gnark/frontend"
)

const nInputs = 1
const mOutputs = 1
const merkleTreeDepth = 8

type Erc721OwnershipCircuit struct {
	// Public signals
	PaymentCommitment frontend.Variable           `gnark:",public"`
	MerkleRoot        frontend.Variable           `gnark:",public"`
	Nullifiers        [nInputs]frontend.Variable  `gnark:",public"`
	TreeNumber        frontend.Variable           `gnark:",public"`
	CommitmentsOut    [mOutputs]frontend.Variable `gnark:",public"`
	RevertCommitment  frontend.Variable          `gnark:",public"`

	// Private signals
	PrivateKeys  [nInputs]frontend.Variable
	SaltsIn      [nInputs]frontend.Variable
	UIdIn        [nInputs]frontend.Variable
	PathElements [nInputs][merkleTreeDepth]frontend.Variable
	PathIndices  [nInputs]frontend.Variable
	RecipientPK  [mOutputs]frontend.Variable
	SaltsOut      [mOutputs]frontend.Variable
	UIdOut        [mOutputs]frontend.Variable
	RevertSalt    frontend.Variable
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

type Erc721OwnershipRequest struct {
	PaymentCommitment string      `json:"paymentCommitment" binding:"required"`
	UId               string      `json:"uid" binding:"required"`
	SaltIn            string      `json:"saltIn" binding:"required"`
	SaltOut           string      `json:"saltOut" binding:"required"`
	RevertSalt        string      `json:"revertSalt" binding:"required"`
	KeyPairsIn        KeyPairIn   `json:"keyPairIn" binding:"required"`
	PubKeysOut        PubKeyOut   `json:"pubKeyOut" binding:"required"`
	MerkleDepth       int         `json:"merkleDepth"`
	MerkleProofs      MerkleProof `json:"merkleProof" binding:"required"`
	MerkleRoot        string      `json:"merkleRoot" binding:"required"`
	TreeNumber        int         `json:"treeNumber"`
}

type Erc721OwnershipResponseAPI struct {
	Pi_A          []string   `json:"pi_a"`
	Pi_B          [][]string `json:"pi_b"`
	Pi_C          []string   `json:"pi_c"`
	Public_Signal []string   `json:"public_signal"`
}

func (circuit *Erc721OwnershipCircuit) Define(api frontend.API) error {
	return circuitLogic(api,
		circuit.PaymentCommitment,
		circuit.MerkleRoot,
		circuit.Nullifiers[:],
		circuit.CommitmentsOut[:],
		circuit.PrivateKeys[:],
		circuit.SaltsIn[:],
		circuit.UIdIn[:],
		convertPathElementsToSlice(circuit.PathElements),
		circuit.PathIndices[:],
		circuit.RecipientPK[:],
		circuit.SaltsOut[:],
		circuit.UIdOut[:],
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
