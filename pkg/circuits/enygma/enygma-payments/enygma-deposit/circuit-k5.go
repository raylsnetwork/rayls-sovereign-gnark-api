package deposit

import (
	"github.com/consensys/gnark/frontend"
)

const k5 = 5

type DepositEnygmak5Circuit struct {
	SenderId                  frontend.Variable
	SharedSecrets             [k5]frontend.Variable
	HashedSharedSecrets       [k5]frontend.Variable `gnark:",public"`
	PublicKey                 [k5]frontend.Variable `gnark:",public"`
	SecretKey                 frontend.Variable
	PreviousSenderBalance     frontend.Variable
	PreviousSenderRandomValue frontend.Variable
	PreviousCommits           [k5][2]frontend.Variable `gnark:",public"`
	TxCommits                 [k5][2]frontend.Variable `gnark:",public"`
	TxValues                  [k5]frontend.Variable
	TxRandomValues            [k5]frontend.Variable
	SenderTxValue             frontend.Variable
	Nullifier                 frontend.Variable     `gnark:",public"`
	BlockNumber               frontend.Variable     `gnark:",public"`
	AnonymitySet              [k5]frontend.Variable `gnark:",public"`
	MessageTags               [k5]frontend.Variable `gnark:",public"`
	Hash                      frontend.Variable     `gnark:",public"`
	Pk                        frontend.Variable
	Address                   frontend.Variable
	SaltOut                   frontend.Variable
}

type DepositEnygmak5Request struct {
	SenderID                  string        `json:"sender_id" binding:"required"`
	SharedSecrets             [k5]string    `json:"shared_secrets" binding:"required,len=5,dive,required"`
	HashedSharedSecrets       [k5]string    `json:"hashed_shared_secrets" binding:"required,len=5"`
	PublicKey                 [k5]string    `json:"public_keys" binding:"required,len=5"`
	SecretKey                 string        `json:"secret_key" binding:"required"`
	PreviousSenderBalance     string        `json:"previous_sender_balance" binding:"required"`
	PreviousSenderRandomValue string        `json:"previous_sender_random_value" binding:"required"`
	PreviousCommits           [k5][2]string `json:"previous_commits" binding:"required,len=5,dive,len=2"`
	TxCommits                 [k5][2]string `json:"tx_commits" binding:"required,len=5,dive,len=2"`
	TxValues                  [k5]string    `json:"tx_values" binding:"required,len=5"`
	TxRandomValues            [k5]string    `json:"tx_random_values" binding:"required,len=5"`
	SenderTxValue             string        `json:"sender_tx_value" binding:"required"`
	Nullifier                 string        `json:"nullifier" binding:"required"`
	BlockNumber               string        `json:"block_number" binding:"required"`
	AnonymitySet              [k5]string    `json:"anonymity_set" binding:"required,len=5"`
	MessageTags               [k5]string    `json:"message_tags" binding:"required,len=5"`
	Hash                      string        `json:"hash" binding:"required"`
	Pk                        string        `json:"pk" binding:"required"`
	Address                   string        `json:"address" binding:"required"`
	SaltOut                   string        `json:"saltOut" binding:"required"`
}

func (circuit *DepositEnygmak5Circuit) Define(api frontend.API) error {
	return circuitLogic(api, k5,
		circuit.SenderId,
		circuit.SharedSecrets[:],
		circuit.HashedSharedSecrets[:],
		circuit.PublicKey[:],
		circuit.SecretKey,
		circuit.PreviousSenderBalance,
		circuit.PreviousSenderRandomValue,
		convertArrayToSlice5(circuit.PreviousCommits),
		convertArrayToSlice5(circuit.TxCommits),
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

func convertArrayToSlice5(arr [5][2]frontend.Variable) [][2]frontend.Variable {
	slice := make([][2]frontend.Variable, 5)
	for i := 0; i < 5; i++ {
		slice[i] = arr[i]
	}
	return slice
}
