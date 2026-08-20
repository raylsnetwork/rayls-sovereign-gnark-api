package enygma

import (
	"github.com/consensys/gnark/frontend"
)

const k6 = 6

type Enygmak6Circuit struct {
	SenderId                  frontend.Variable
	SharedSecrets             [k6]frontend.Variable
	HashedSharedSecrets       [k6]frontend.Variable `gnark:",public"`
	PublicKey                 [k6]frontend.Variable `gnark:",public"`
	SecretKey                 frontend.Variable
	PreviousSenderBalance     frontend.Variable
	PreviousSenderRandomValue frontend.Variable
	PreviousCommits           [k6][2]frontend.Variable `gnark:",public"`
	TxCommits                 [k6][2]frontend.Variable `gnark:",public"`
	TxValues                  [k6]frontend.Variable
	TxRandomValues            [k6]frontend.Variable
	SenderTxValue             frontend.Variable
	Nullifier                 frontend.Variable     `gnark:",public"`
	BlockNumber               frontend.Variable     `gnark:",public"`
	AnonymitySet              [k6]frontend.Variable `gnark:",public"`
	MessageTags               [k6]frontend.Variable `gnark:",public"`
}

type Enygmak6Request struct {
	SenderID                  string        `json:"sender_id" binding:"required"`
	SharedSecrets             [k6]string    `json:"shared_secrets" binding:"required,len=6,dive,required"`
	HashedSharedSecrets       [k6]string    `json:"hashed_shared_secrets" binding:"required,len=6"`
	PublicKey                 [k6]string    `json:"public_keys" binding:"required,len=6"`
	SecretKey                 string        `json:"secret_key" binding:"required"`
	PreviousSenderBalance     string        `json:"previous_sender_balance" binding:"required"`
	PreviousSenderRandomValue string        `json:"previous_sender_random_value" binding:"required"`
	PreviousCommits           [k6][2]string `json:"previous_commits" binding:"required,len=6,dive,len=2"`
	TxCommits                 [k6][2]string `json:"tx_commits" binding:"required,len=6,dive,len=2"`
	TxValues                  [k6]string    `json:"tx_values" binding:"required,len=6"`
	TxRandomValues            [k6]string    `json:"tx_random_values" binding:"required,len=6"`
	SenderTxValue             string        `json:"sender_tx_value" binding:"required"`
	Nullifier                 string        `json:"nullifier" binding:"required"`
	BlockNumber               string        `json:"block_number" binding:"required"`
	AnonymitySet              [k6]string    `json:"anonymity_set" binding:"required,len=6"`
	MessageTags               [k6]string    `json:"message_tags" binding:"required,len=6"`
}

type EnygmaResponseAPI struct {
	Pi_A          []string   `json:"pi_a"`
	Pi_B          [][]string `json:"pi_b"`
	Pi_C          []string   `json:"pi_c"`
	Public_Signal []string   `json:"public_signal"`
}

func (circuit *Enygmak6Circuit) Define(api frontend.API) error {
	return circuitLogic(api, k6,
		circuit.SenderId,
		circuit.SharedSecrets[:],
		circuit.HashedSharedSecrets[:],
		circuit.PublicKey[:],
		circuit.SecretKey,
		circuit.PreviousSenderBalance,
		circuit.PreviousSenderRandomValue,
		convertArrayToSlice6(circuit.PreviousCommits),
		convertArrayToSlice6(circuit.TxCommits),
		circuit.TxValues[:],
		circuit.TxRandomValues[:],
		circuit.SenderTxValue,
		circuit.Nullifier,
		circuit.BlockNumber,
		circuit.AnonymitySet[:],
		circuit.MessageTags[:])
}

func convertArrayToSlice6(arr [6][2]frontend.Variable) [][2]frontend.Variable {
	slice := make([][2]frontend.Variable, 6)
	for i := 0; i < 6; i++ {
		slice[i] = arr[i]
	}
	return slice
}
