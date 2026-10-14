package enygma

import (
	common "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/common"

	"github.com/consensys/gnark/frontend"
)

// Shared circuit logic that works for any k
func circuitLogic(
	api frontend.API,
	k int,
	senderId frontend.Variable,
	shared_secrets []frontend.Variable,
	arrayHashSecret []frontend.Variable,
	publicKey []frontend.Variable,
	secret_key frontend.Variable,
	previousV frontend.Variable,
	previousR frontend.Variable,
	previousCommit [][2]frontend.Variable,
	txCommit [][2]frontend.Variable,
	txValue []frontend.Variable,
	txRandom []frontend.Variable,
	sender_tx_value frontend.Variable,
	nullifier frontend.Variable,
	blockNumber frontend.Variable,
	anonymity_set []frontend.Variable,
	message_tags []frontend.Variable,
) error {

	//////////////////////////////////**///////////////////////////////////
	// Check if SenderId is in K
	common.CheckSenderIdIsInK(api, k, senderId, anonymity_set)

	///////////////////////////////////**///////////////////////////////////
	// Check if Amount To Transfer Corresponds To Sender TxValues
	selected_v := frontend.Variable(0)
	for i := 0; i < k; i++ {
		eq := api.IsZero(api.Sub(senderId, anonymity_set[i]))
		selected_v = api.Add(selected_v, api.Mul(eq, txValue[i]))
	}
	common.CheckNegatedSenderValue(api, selected_v, sender_tx_value)

	///////////////////////////////////**///////////////////////////////////
	// Check if previous commits and tx commits are on Curve
	common.CheckCurvePoints(api, k, previousCommit, txCommit)

	///////////////////////////////////**///////////////////////////////////
	// Check knowledge of secret of sender
	if err := common.CheckSecretKnowledge(api, k, senderId, anonymity_set, shared_secrets, previousR, secret_key); err != nil {
		return err
	}

	///////////////////////////////////**///////////////////////////////////
	// Check if Hash Array of Secret is well formed
	if err := common.CheckHashArrayOfSecrets(api, k, shared_secrets, arrayHashSecret); err != nil {
		return err
	}

	///////////////////////////////////**///////////////////////////////////
	// Knowledge of SecretKey - Perform public key generation and check if SecretKey generate senderId's PublicKey
	if err := common.CheckPublicKeyKnowledge(api, k, senderId, anonymity_set, publicKey, secret_key); err != nil {
		return err
	}

	///////////////////////////////////**///////////////////////////////////
	// Check Knowledge of Previous Commitment
	common.CheckPreviousCommitmentKnowledge(api, k, senderId, anonymity_set, previousCommit, previousV, previousR)

	///////////////////////////////////**///////////////////////////////////
	// Knowledge of Message Tag - Perform verification is message tag is well formed
	if err := common.CheckMessageTags(api, k, shared_secrets, blockNumber, message_tags); err != nil {
		return err
	}

	///////////////////////////////////**///////////////////////////////////
	// Check Sum TxCommits = (0,1)
	sum := common.SumTxCommits(api, txCommit)
	api.AssertIsEqual(sum.X, 0)
	api.AssertIsEqual(sum.Y, 1)

	///////////////////////////////////**///////////////////////////////////
	// Range Proof: previousV >= sender_tx_value and sender_tx_value >= 0
	common.CheckRangeProofWithPreviousV(api, previousV, sender_tx_value)
	common.CheckReceiverAmounts(api, k, senderId, anonymity_set, txValue)

	///////////////////////////////////**//////////////////////////////////////
	// Knowledge of Nullifier
	common.CheckNullifierKnowledge(api, k, senderId, anonymity_set, arrayHashSecret, blockNumber, nullifier)

	///////////////////////////////////**//////////////////////////////////////
	// Check if Tx Commitment is well formed
	common.CheckTxCommitmentsWellFormed(api, k, txValue, txRandom, txCommit)

	// ///////////////////////////////////**//////////////////////////////////////
	// Check if random factors R are well formed
	if err := common.CheckRandomFactors(api, k, senderId, anonymity_set, shared_secrets, blockNumber, txRandom); err != nil {
		return err
	}

	return nil

}
