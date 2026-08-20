package deposit

import (
	"github.com/consensys/gnark/frontend"
)

const k2 = 2

type DepositEnygmak2Circuit struct {
	SenderId                  frontend.Variable
	SharedSecrets             [k2]frontend.Variable
	HashedSharedSecrets       [k2]frontend.Variable `gnark:",public"`
	PublicKey                 [k2]frontend.Variable `gnark:",public"`
	SecretKey                 frontend.Variable
	PreviousSenderBalance     frontend.Variable
	PreviousSenderRandomValue frontend.Variable
	PreviousCommits           [k2][2]frontend.Variable `gnark:",public"`
	TxCommits                 [k2][2]frontend.Variable `gnark:",public"`
	TxValues                  [k2]frontend.Variable
	TxRandomValues            [k2]frontend.Variable
	SenderTxValue             frontend.Variable
	Nullifier                 frontend.Variable     `gnark:",public"`
	BlockNumber               frontend.Variable     `gnark:",public"`
	AnonymitySet              [k2]frontend.Variable `gnark:",public"`
	MessageTags               [k2]frontend.Variable `gnark:",public"`
	Hash                      frontend.Variable     `gnark:",public"`
	Pk                        frontend.Variable
	Address                   frontend.Variable
	SaltOut                   frontend.Variable
}

type DepositEnygmak2Request struct {
	SenderID                  string        `json:"sender_id" binding:"required"`
	SharedSecrets             [k2]string    `json:"shared_secrets" binding:"required,len=2,dive,required"`
	HashedSharedSecrets       [k2]string    `json:"hashed_shared_secrets" binding:"required,len=2"`
	PublicKey                 [k2]string    `json:"public_keys" binding:"required,len=2"`
	SecretKey                 string        `json:"secret_key" binding:"required"`
	PreviousSenderBalance     string        `json:"previous_sender_balance" binding:"required"`
	PreviousSenderRandomValue string        `json:"previous_sender_random_value" binding:"required"`
	PreviousCommits           [k2][2]string `json:"previous_commits" binding:"required,len=2,dive,len=2"`
	TxCommits                 [k2][2]string `json:"tx_commits" binding:"required,len=2,dive,len=2"`
	TxValues                  [k2]string    `json:"tx_values" binding:"required,len=2"`
	TxRandomValues            [k2]string    `json:"tx_random_values" binding:"required,len=2"`
	SenderTxValue             string        `json:"sender_tx_value" binding:"required"`
	Nullifier                 string        `json:"nullifier" binding:"required"`
	BlockNumber               string        `json:"block_number" binding:"required"`
	AnonymitySet              [k2]string    `json:"anonymity_set" binding:"required,len=2"`
	MessageTags               [k2]string    `json:"message_tags" binding:"required,len=2"`
	Hash                      string        `json:"hash" binding:"required"`
	Pk                        string        `json:"pk" binding:"required"`
	Address                   string        `json:"address" binding:"required"`
	SaltOut                   string        `json:"saltOut" binding:"required"`
}

func (circuit *DepositEnygmak2Circuit) Define(api frontend.API) error {
	return circuitLogic(api, k2,
		circuit.SenderId,
		circuit.SharedSecrets[:],
		circuit.HashedSharedSecrets[:],
		circuit.PublicKey[:],
		circuit.SecretKey,
		circuit.PreviousSenderBalance,
		circuit.PreviousSenderRandomValue,
		convertArrayToSlice2(circuit.PreviousCommits),
		convertArrayToSlice2(circuit.TxCommits),
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

func convertArrayToSlice2(arr [2][2]frontend.Variable) [][2]frontend.Variable {
	slice := make([][2]frontend.Variable, 2)
	for i := 0; i < 2; i++ {
		slice[i] = arr[i]
	}
	return slice
}
