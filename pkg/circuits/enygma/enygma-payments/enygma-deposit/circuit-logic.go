package deposit

import (
	common "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/common"
	pos "github.com/raylsnetwork/rayls-sovereign-gnark-api/poseidon"
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
	hash frontend.Variable,
	pkDeposit frontend.Variable,
	address frontend.Variable,
	saltOut frontend.Variable,
) error {

	// Subgroup order
	JubJubPrimeSubGroup := frontend.Variable(common.JubJubPrimeSubGroupStr)

	//////////////////////////////////**///////////////////////////////////
	// Check if SenderId is in K
	common.CheckSenderIdIsInK(api, k, senderId, anonymity_set)

	///////////////////////////////////**///////////////////////////////////
	// Check if Negative of Amount To Deposit Corresponds To Sender TxValues
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

	// Compute (p - sender_tx_value) mod p to handle sender_tx_value=0 case correctly
	expectedTxValue := api.Sub(pDiffConstrained, vConstrained)
	expectedTxValueInter, _ := api.NewHint(primitives.ModHintBabyJubJub, 2, expectedTxValue)
	expectedTxValueMod := expectedTxValueInter[0]

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
	// Check Pedersen (Sum SenderTxValue, SumR) = Pedersen (Sender TxValues, 0)
	sumX := frontend.Variable(0)
	sumY := frontend.Variable(0)
	senderV := frontend.Variable(0)

	for i := 0; i < k; i++ {
		sumX = api.Add(sumX, txValue[i])
		sumY = api.Add(sumY, txRandom[i])
		senderV = selected_v
	}
	PedersenObtained := primitives.PedersenCommitment(api, sumX, sumY)
	PedersenExpected := primitives.PedersenCommitment(api, senderV, frontend.Variable(0))
	api.AssertIsEqual(PedersenObtained.X, PedersenExpected.X)
	api.AssertIsEqual(PedersenObtained.Y, PedersenExpected.Y)

	///////////////////////////////////**///////////////////////////////////
	// Range Proof: previousV >= sender_tx_value and sender_tx_value >= 0
	common.CheckRangeProofWithPreviousV(api, previousV, sender_tx_value)

	///////////////////////////////////**//////////////////////////////////////
	// Knowledge of Nullifier
	common.CheckNullifierKnowledge(api, k, senderId, anonymity_set, arrayHashSecret, blockNumber, nullifier)

	///////////////////////////////////**//////////////////////////////////////
	// Check if Tx Commitment is well formed
	common.CheckTxCommitmentsWellFormed(api, k, txValue, txRandom, txCommit)

	///////////////////////////////////**//////////////////////////////////////
	// Knowledge of Message Tag - Perform verification is message tag is well formed
	common.CheckMessageTags(api, k, shared_secrets, blockNumber, message_tags)

	// ///////////////////////////////////**//////////////////////////////////////
	// Check if random factors R are well formed
	common.CheckRandomFactors(api, k, senderId, anonymity_set, shared_secrets, blockNumber, txRandom)

	///////////////////////////////////**//////////////////////////////////////
	// Check if Hash(commitment in Dvp - MerkleTree) is well formed (V2)
	// V2 formula: H(H(H(pkDeposit, saltOut), sender_tx_value), address)
	h1 := pos.Poseidon(api, []frontend.Variable{pkDeposit, saltOut})
	h2 := pos.Poseidon(api, []frontend.Variable{h1, sender_tx_value})
	CalculatedHash := pos.Poseidon(api, []frontend.Variable{h2, address})
	api.AssertIsEqual(CalculatedHash, hash)

	return nil
}
