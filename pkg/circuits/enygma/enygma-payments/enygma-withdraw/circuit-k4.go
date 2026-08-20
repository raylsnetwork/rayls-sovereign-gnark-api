package withdraw

import (
	"github.com/consensys/gnark/frontend"
)

const k4 = 4

type WithdrawEnygmak4Circuit struct {
	SenderId                  frontend.Variable
	SharedSecrets             [k4]frontend.Variable
	HashedSharedSecrets       [k4]frontend.Variable `gnark:",public"`
	PublicKey                 [k4]frontend.Variable `gnark:",public"`
	SecretKey                 frontend.Variable
	PreviousSenderBalance     frontend.Variable
	PreviousSenderRandomValue frontend.Variable
	PreviousCommits           [k4][2]frontend.Variable `gnark:",public"`
	TxCommits                 [k4][2]frontend.Variable `gnark:",public"`
	TxValues                  [k4]frontend.Variable
	TxRandomValues            [k4]frontend.Variable
	SenderTxValue             frontend.Variable
	Nullifier                 frontend.Variable     `gnark:",public"`
	BlockNumber               frontend.Variable     `gnark:",public"`
	AnonymitySet              [k4]frontend.Variable `gnark:",public"`
	MessageTags               [k4]frontend.Variable `gnark:",public"`
	Hashes                    [10]frontend.Variable `gnark:",public"`
	SkDeposits                [10]frontend.Variable
	VPerDeposit               [10]frontend.Variable
	Address                   frontend.Variable
	SaltsIn                   [10]frontend.Variable
}

type WithdrawEnygmak4Request struct {
	SenderID                  string        `json:"sender_id" binding:"required"`
	SharedSecrets             [k4]string    `json:"shared_secrets" binding:"required,len=4,dive,required"`
	HashedSharedSecrets       [k4]string    `json:"hashed_shared_secrets" binding:"required,len=4"`
	PublicKey                 [k4]string    `json:"public_keys" binding:"required,len=4"`
	SecretKey                 string        `json:"secret_key" binding:"required"`
	PreviousSenderBalance     string        `json:"previous_sender_balance" binding:"required"`
	PreviousSenderRandomValue string        `json:"previous_sender_random_value" binding:"required"`
	PreviousCommits           [k4][2]string `json:"previous_commits" binding:"required,len=4,dive,len=2"`
	TxCommits                 [k4][2]string `json:"tx_commits" binding:"required,len=4,dive,len=2"`
	TxValues                  [k4]string    `json:"tx_values" binding:"required,len=4"`
	TxRandomValues            [k4]string    `json:"tx_random_values" binding:"required,len=4"`
	SenderTxValue             string        `json:"sender_tx_value" binding:"required"`
	Nullifier                 string        `json:"nullifier" binding:"required"`
	BlockNumber               string        `json:"block_number" binding:"required"`
	AnonymitySet              [k4]string    `json:"anonymity_set" binding:"required,len=4"`
	MessageTags               [k4]string    `json:"message_tags" binding:"required,len=4"`
	Hashes                    [10]string    `json:"hashes" binding:"required"`
	SkDeposits                [10]string    `json:"sk_deposits" binding:"required"`
	VPerDeposit               [10]string    `json:"v_per_deposit" binding:"required"`
	Address                   string        `json:"address" binding:"required"`
	SaltsIn                   [10]string    `json:"saltsIn" binding:"required"`
}

func (circuit *WithdrawEnygmak4Circuit) Define(api frontend.API) error {
	return circuitLogic(api, k4,
		circuit.SenderId,
		circuit.SharedSecrets[:],
		circuit.HashedSharedSecrets[:],
		circuit.PublicKey[:],
		circuit.SecretKey,
		circuit.PreviousSenderBalance,
		circuit.PreviousSenderRandomValue,
		convertArrayToSlice4(circuit.PreviousCommits),
		convertArrayToSlice4(circuit.TxCommits),
		circuit.TxValues[:],
		circuit.TxRandomValues[:],
		circuit.SenderTxValue,
		circuit.Nullifier,
		circuit.BlockNumber,
		circuit.AnonymitySet[:],
		circuit.MessageTags[:],
		circuit.Hashes[:],
		circuit.SkDeposits[:],
		circuit.VPerDeposit[:],
		circuit.Address,
		circuit.SaltsIn[:])
}

func convertArrayToSlice4(arr [4][2]frontend.Variable) [][2]frontend.Variable {
	slice := make([][2]frontend.Variable, 4)
	for i := 0; i < 4; i++ {
		slice[i] = arr[i]
	}
	return slice
}
