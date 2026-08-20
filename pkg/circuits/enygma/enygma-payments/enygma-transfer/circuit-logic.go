package enygma

import (
	common "enygma-gnark-server/pkg/circuits/enygma/enygma-payments/common"
	primitives "enygma-gnark-server/primitives"

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
	JubJubPrimeSubGroup := frontend.Variable(common.JubJubPrimeSubGroupStr)

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
	expectedTxValueInter, _ := api.NewHint(primitives.ModHintBabyJubJub, 2, expectedTxValue)
	expectedTxValueMod := expectedTxValueInter[0] // remainder (mod p)

	api.AssertIsEqual(selectedVConstrained, expectedTxValueMod)

	///////////////////////////////////**///////////////////////////////////
	// Check if previous commits and tx commits are on Curve
	common.CheckCurvePoints(api, k, previousCommit, txCommit)

	///////////////////////////////////**///////////////////////////////////
	// Check knowledge of secret of sender
	common.CheckSecretKnowledge(api, k, senderId, anonymity_set, shared_secrets, previousR, secret_key)

	///////////////////////////////////**///////////////////////////////////
	// Check if Hash Array of Secret is well formed
	common.CheckHashArrayOfSecrets(api, k, shared_secrets, arrayHashSecret)

	///////////////////////////////////**///////////////////////////////////
	// Knowledge of SecretKey - Perform public key generation and check if SecretKey generate senderId's PublicKey
	common.CheckPublicKeyKnowledge(api, k, senderId, anonymity_set, publicKey, secret_key)

	///////////////////////////////////**///////////////////////////////////
	// Check Knowledge of Previous Commitment
	common.CheckPreviousCommitmentKnowledge(api, k, senderId, anonymity_set, previousCommit, previousV, previousR)

	///////////////////////////////////**///////////////////////////////////
	// Knowledge of Message Tag - Perform verification is message tag is well formed
	common.CheckMessageTags(api, k, shared_secrets, blockNumber, message_tags)

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
	common.CheckRandomFactors(api, k, senderId, anonymity_set, shared_secrets, blockNumber, txRandom)

	return nil

}
