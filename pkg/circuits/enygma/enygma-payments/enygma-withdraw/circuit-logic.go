package withdraw

import (
	common "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/common"
	primitives "github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"

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
	paymentCommitment frontend.Variable,
	paymentSecretKey frontend.Variable,
	paymentSalt frontend.Variable,
	address frontend.Variable,
) error {

	//////////////////////////////////**///////////////////////////////////
	// Check if SenderId is in K
	common.CheckSenderIdIsInK(api, k, senderId, anonymity_set)

	///////////////////////////////////**///////////////////////////////////
	// Check if Amount To Withdraw Corresponds To Sender TxValues
	selected_v := frontend.Variable(0)
	for i := 0; i < k; i++ {
		eq := api.IsZero(api.Sub(senderId, anonymity_set[i]))
		selected_v = api.Add(selected_v, api.Mul(eq, txValue[i]))
	}
	api.AssertIsEqual(selected_v, sender_tx_value)

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
	// Check if previous commits and tx commits are on Curve
	common.CheckCurvePoints(api, k, previousCommit, txCommit)

	///////////////////////////////////**///////////////////////////////////
	// Check Knowledge of Previous Commitment
	common.CheckPreviousCommitmentKnowledge(api, k, senderId, anonymity_set, previousCommit, previousV, previousR)

	///////////////////////////////////**///////////////////////////////////
	// Check Sum TxCommits = Pedersen(sender_tx_value, 0)
	sum := common.SumTxCommits(api, txCommit)
	expected := primitives.PedersenCommitment(api, sender_tx_value, 0)
	api.AssertIsEqual(sum.X, expected.X)
	api.AssertIsEqual(sum.Y, expected.Y)

	///////////////////////////////////**///////////////////////////////////
	// Range Proof: sender_tx_value >= 0
	common.CheckRangeProofVOnly(api, sender_tx_value)
	common.CheckReceiverAmounts(api, k, senderId, anonymity_set, txValue)

	///////////////////////////////////**//////////////////////////////////////
	// Knowledge of Nullifier
	common.CheckNullifierKnowledge(api, k, senderId, anonymity_set, arrayHashSecret, blockNumber, nullifier)

	///////////////////////////////////**//////////////////////////////////////
	// Check if Tx Commitment is well formed
	common.CheckTxCommitmentsWellFormed(api, k, txValue, txRandom, txCommit)

	///////////////////////////////////**//////////////////////////////////////
	// Knowledge of Message Tag - Perform verification is message tag is well formed
	if err := common.CheckMessageTags(api, k, shared_secrets, blockNumber, message_tags); err != nil {
		return err
	}

	// ///////////////////////////////////**//////////////////////////////////////
	// Check if random factors R are well formed
	if err := common.CheckRandomFactors(api, k, senderId, anonymity_set, shared_secrets, blockNumber, txRandom); err != nil {
		return err
	}

	///////////////////////////////////**//////////////////////////////////////
	// Bind the credit to the DvP join-split that burned the notes.
	// paymentCommitment is the join-split receipt's payment output; the contract
	// requires the two to be equal, and the join-split circuit guarantees that
	// output holds exactly what its nullified inputs held (minus change).
	// Opening it here with sender_tx_value proves the credit equals that value.
	paymentPK, err := primitives.PublicKey(api, paymentSecretKey)
	if err != nil {
		return err
	}
	computedPayment := primitives.CommitmentV2ERC20(api, paymentPK, paymentSalt, sender_tx_value, address)
	api.AssertIsEqual(computedPayment, paymentCommitment)

	return nil
}
