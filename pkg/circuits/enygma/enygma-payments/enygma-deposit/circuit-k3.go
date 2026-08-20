package deposit

import (
	"github.com/consensys/gnark/frontend"
)

const k3 = 3

type DepositEnygmak3Circuit struct {
	SenderId                  frontend.Variable
	SharedSecrets             [k3]frontend.Variable
	HashedSharedSecrets       [k3]frontend.Variable `gnark:",public"`
	PublicKey                 [k3]frontend.Variable `gnark:",public"`
	SecretKey                 frontend.Variable
	PreviousSenderBalance     frontend.Variable
	PreviousSenderRandomValue frontend.Variable
	PreviousCommits           [k3][2]frontend.Variable `gnark:",public"`
	TxCommits                 [k3][2]frontend.Variable `gnark:",public"`
	TxValues                  [k3]frontend.Variable
	TxRandomValues            [k3]frontend.Variable
	SenderTxValue             frontend.Variable
	Nullifier                 frontend.Variable     `gnark:",public"`
	BlockNumber               frontend.Variable     `gnark:",public"`
	AnonymitySet              [k3]frontend.Variable `gnark:",public"`
	MessageTags               [k3]frontend.Variable `gnark:",public"`
	Hash                      frontend.Variable     `gnark:",public"`
	Pk                        frontend.Variable
	Address                   frontend.Variable
	SaltOut                   frontend.Variable
}

type DepositEnygmak3Request struct {
	SenderID                  string        `json:"sender_id" binding:"required"`
	SharedSecrets             [k3]string    `json:"shared_secrets" binding:"required,len=3,dive,required"`
	HashedSharedSecrets       [k3]string    `json:"hashed_shared_secrets" binding:"required,len=3"`
	PublicKey                 [k3]string    `json:"public_keys" binding:"required,len=3"`
	SecretKey                 string        `json:"secret_key" binding:"required"`
	PreviousSenderBalance     string        `json:"previous_sender_balance" binding:"required"`
	PreviousSenderRandomValue string        `json:"previous_sender_random_value" binding:"required"`
	PreviousCommits           [k3][2]string `json:"previous_commits" binding:"required,len=3,dive,len=2"`
	TxCommits                 [k3][2]string `json:"tx_commits" binding:"required,len=3,dive,len=2"`
	TxValues                  [k3]string    `json:"tx_values" binding:"required,len=3"`
	TxRandomValues            [k3]string    `json:"tx_random_values" binding:"required,len=3"`
	SenderTxValue             string        `json:"sender_tx_value" binding:"required"`
	Nullifier                 string        `json:"nullifier" binding:"required"`
	BlockNumber               string        `json:"block_number" binding:"required"`
	AnonymitySet              [k3]string    `json:"anonymity_set" binding:"required,len=3"`
	MessageTags               [k3]string    `json:"message_tags" binding:"required,len=3"`
	Hash                      string        `json:"hash" binding:"required"`
	Pk                        string        `json:"pk" binding:"required"`
	Address                   string        `json:"address" binding:"required"`
	SaltOut                   string        `json:"saltOut" binding:"required"`
}

func (circuit *DepositEnygmak3Circuit) Define(api frontend.API) error {
	return circuitLogic(api, k3,
		circuit.SenderId,
		circuit.SharedSecrets[:],
		circuit.HashedSharedSecrets[:],
		circuit.PublicKey[:],
		circuit.SecretKey,
		circuit.PreviousSenderBalance,
		circuit.PreviousSenderRandomValue,
		convertArrayToSlice3(circuit.PreviousCommits),
		convertArrayToSlice3(circuit.TxCommits),
		circuit.TxValues[:],
		circuit.TxRandomValues[:],
		circuit.SenderTxValue,
		circuit.Nullifier,
		circuit.BlockNumber,
		circuit.AnonymitySet[:],
		circuit.MessageTags[:],
		circuit.Hash,
		circuit.Pk,
		circuit.Address,
		circuit.SaltOut)
}

func convertArrayToSlice3(arr [3][2]frontend.Variable) [][2]frontend.Variable {
	slice := make([][2]frontend.Variable, 3)
	for i := 0; i < 3; i++ {
		slice[i] = arr[i]
	}
	return slice
}
