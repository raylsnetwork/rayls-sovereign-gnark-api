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

	// Debug: Log input parameters
	//api.Println("=== CIRCUIT DEBUG START ===")
	//api.Println("k value:", k)
	//api.Println("senderId:", senderId)
	//api.Println("secret_key:", secret_key)
	//api.Println("previousV:", previousV)
	//api.Println("previousR:", previousR)
	//api.Println("sender_tx_value (amount to withdraw):", sender_tx_value)
	//api.Println("nullifier:", nullifier)
	//api.Println("blockNumber:", blockNumber)

	// Log arrays
	for i := 0; i < k; i++ {
		//api.Println(fmt.Sprintf("anonymity_set[%d]:", i), anonymity_set[i])
		//api.Println(fmt.Sprintf("shared_secrets[%d]:", i), shared_secrets[i])
		//api.Println(fmt.Sprintf("publicKey[%d]:", i), publicKey[i][0], publicKey[i][1])
		//api.Println(fmt.Sprintf("previousCommit[%d]:", i), previousCommit[i][0], previousCommit[i][1])
		//api.Println(fmt.Sprintf("txCommit[%d]:", i), txCommit[i][0], txCommit[i][1])
		//api.Println(fmt.Sprintf("txValue[%d]:", i), txValue[i])
		//api.Println(fmt.Sprintf("txRandom[%d]:", i), txRandom[i])
	}

	//////////////////////////////////**///////////////////////////////////
	// Check if SenderId is in K
	//api.Println("\n--- Checking if SenderId is in K ---")
	common.CheckSenderIdIsInK(api, k, senderId, anonymity_set)

	///////////////////////////////////**///////////////////////////////////
	// Check if Amount To Withdraw Corresponds To Sender TxValues
	//api.Println("\n--- Checking Amount To Withdraw ---")
	selected_v := frontend.Variable(0)
	for i := 0; i < k; i++ {
		diff := api.Sub(senderId, anonymity_set[i])
		eq := api.IsZero(diff)
		//api.Println(fmt.Sprintf("Is sender at index %d?", i), eq)
		contribution := api.Mul(eq, txValue[i])
		//api.Println(fmt.Sprintf("Contribution from index %d:", i), contribution)
		selected_v = api.Add(selected_v, contribution)
	}
	//api.Println("selected_v (should match sender_tx_value):", selected_v)
	//api.Println("sender_tx_value (expected):", sender_tx_value)
	selectedVBits := api.ToBinary(selected_v, 252)
	vBits := api.ToBinary(sender_tx_value, 252)

	selectedVConstrained := api.FromBinary(selectedVBits...)
	vConstrained := api.FromBinary(vBits...)

	api.AssertIsEqual(selectedVConstrained, vConstrained)

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
	//api.Println("\n--- Checking Points on Curve ---")
	common.CheckCurvePoints(api, k, previousCommit, txCommit)

	///////////////////////////////////**///////////////////////////////////
	// Check Knowledge of Previous Commitment
	//api.Println("\n--- Verifying Previous Commitment ---")
	common.CheckPreviousCommitmentKnowledge(api, k, senderId, anonymity_set, previousCommit, previousV, previousR)

	///////////////////////////////////**///////////////////////////////////
	// Check Pedersen (Sum SenderTxValue, SumR) = Pedersen (Sender TxValues, 0)
	//api.Println("\n--- Verifying Pedersen Commitment Sum ---")
	sumX := frontend.Variable(0)
	sumY := frontend.Variable(0)
	senderV := frontend.Variable(0)

	for i := 0; i < k; i++ {
		sumX = api.Add(sumX, txValue[i])
		sumY = api.Add(sumY, txRandom[i])
		//api.Println(fmt.Sprintf("After index %d - sumX:", i), sumX, "sumY:", sumY)
		senderV = selected_v
	}
	//api.Println("Final sums - sumX:", sumX, "sumY:", sumY, "senderV:", senderV)

	PedersenObtained := primitives.PedersenCommitment(api, sumX, sumY)
	//api.Println("PedersenObtained:", PedersenObtained.X, PedersenObtained.Y)

	PedersenExpected := primitives.PedersenCommitment(api, senderV, frontend.Variable(0))
	//api.Println("PedersenExpected:", PedersenExpected.X, PedersenExpected.Y)

	api.AssertIsEqual(PedersenObtained.X, PedersenExpected.X)
	api.AssertIsEqual(PedersenObtained.Y, PedersenExpected.Y)

	///////////////////////////////////**///////////////////////////////////
	// Range Proof: sender_tx_value >= 0
	//api.Println("\n--- Range Proof ---")
	common.CheckRangeProofVOnly(api, sender_tx_value)
	common.CheckReceiverAmounts(api, k, senderId, anonymity_set, txValue)

	///////////////////////////////////**//////////////////////////////////////
	// Knowledge of Nullifier
	//api.Println("\n--- Verifying Nullifier ---")
	common.CheckNullifierKnowledge(api, k, senderId, anonymity_set, arrayHashSecret, blockNumber, nullifier)

	///////////////////////////////////**//////////////////////////////////////
	// Check if Tx Commitment is well formed
	//api.Println("\n--- Verifying Transaction Commitments ---")
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

	//api.Println("\n=== CIRCUIT DEBUG END ===")
	return nil
}
