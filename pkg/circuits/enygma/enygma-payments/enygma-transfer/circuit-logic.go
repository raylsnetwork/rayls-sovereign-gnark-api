package enygma

import (
	"fmt"

	common "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/common"
	primitives "github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
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

	// Subgroup order
	JubJubPrimeSubGroup := frontend.Variable(primitives.JubJubPrimeSubGroup)

	//////////////////////////////////**///////////////////////////////////
	// Check if SenderId is in K
	common.CheckSenderIdIsInK(api, k, senderId, anonymity_set)

	///////////////////////////////////**///////////////////////////////////
	// Check if Amount To Transfer Corresponds To Sender TxValues
	selected_v := frontend.Variable(0)

	for i := 0; i < k; i++ {
		diff := api.Sub(senderId, anonymity_set[i])
		eq := api.IsZero(diff)

		selected_v = api.Add(selected_v, api.Mul(eq, txValue[i]))
	}
	selectedVBits := api.ToBinary(selected_v, 252)
	vBits := api.ToBinary(sender_tx_value, 252)
	pDiffBits := api.ToBinary(JubJubPrimeSubGroup, 252)

	selectedVConstrained := api.FromBinary(selectedVBits...)
	vConstrained := api.FromBinary(vBits...)
	pDiffConstrained := api.FromBinary(pDiffBits...)

	// Compute (p - sender_tx_value) mod p
	expectedTxValue := api.Sub(pDiffConstrained, vConstrained)
	expectedTxValueMod, err := primitives.ModSubgroup(api, expectedTxValue)
	if err != nil {
		return fmt.Errorf("sender tx value: %w", err)
	}

	api.AssertIsEqual(selectedVConstrained, expectedTxValueMod)

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

	// ///////////////////////////////////**///////////////////////////////////
	// Check Pedersen (Sum SenderTxValue, SumR) = Pedersen (0, 0) = (0,1)

	sumX := frontend.Variable(0)
	sumY := frontend.Variable(0)

	for i := 0; i < k; i++ {

		sumX = api.Add(sumX, txValue[i])
		sumY = api.Add(sumY, txRandom[i])

	}
	PedersenZero := primitives.PedersenCommitment(api, sumX, sumY)

	api.AssertIsEqual(PedersenZero.X, frontend.Variable(0))
	api.AssertIsEqual(PedersenZero.Y, frontend.Variable(1))

	// Check Sum TxCommits = (0,1)
	sum := twistededwards.Point{
		X: txCommit[0][0],
		Y: txCommit[0][1],
	}

	for i := 1; i < k; i++ {
		point := twistededwards.Point{
			X: txCommit[i][0],
			Y: txCommit[i][1],
		}
		sum = primitives.PointAdd(api, sum, point)
	}

	api.AssertIsEqual(sum.X, frontend.Variable(0))
	api.AssertIsEqual(sum.Y, frontend.Variable(1))

	///////////////////////////////////**///////////////////////////////////
	// Range Proof: previousV >= sender_tx_value and sender_tx_value >= 0
	common.CheckRangeProofWithPreviousV(api, previousV, sender_tx_value)
	common.CheckReceiverAmounts(api, k, senderId, anonymity_set, txValue)

	///////////////////////////////////**//////////////////////////////////////
	// Knowledge of Nullifier
	common.CheckNullifierKnowledge(api, k, senderId, anonymity_set, arrayHashSecret, blockNumber, nullifier)

	///////////////////////////////////**//////////////////////////////////////
	// Check if Tx Commitment is well formed

	for i := 0; i < k; i++ {

		computedPedersenCommitment := primitives.PedersenCommitment(api, txValue[i], txRandom[i])

		api.AssertIsEqual(txCommit[i][0], computedPedersenCommitment.X)
		api.AssertIsEqual(txCommit[i][1], computedPedersenCommitment.Y)
	}

	// ///////////////////////////////////**//////////////////////////////////////
	// Check if random factors R are well formed
	if err := common.CheckRandomFactors(api, k, senderId, anonymity_set, shared_secrets, blockNumber, txRandom); err != nil {
		return err
	}

	return nil

}
