package withdraw

import (
	common "enygma-gnark-server/pkg/circuits/enygma/enygma-payments/common"
	pos "enygma-gnark-server/poseidon"
	primitives "enygma-gnark-server/primitives"

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
	hashes []frontend.Variable,
	sk_deposits []frontend.Variable,
	v_per_deposit []frontend.Variable,
	address frontend.Variable,
	saltsIn []frontend.Variable,
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
	//api.Println("address:", address)

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

	for i := 0; i < len(hashes); i++ {
		//api.Println(fmt.Sprintf("hashes[%d]:", i), hashes[i])
	}

	for i := 0; i < len(sk_deposits); i++ {
		//api.Println(fmt.Sprintf("sk_deposits[%d]:", i), sk_deposits[i])
		//api.Println(fmt.Sprintf("v_per_deposit[%d]:", i), v_per_deposit[i])
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
	common.CheckSecretKnowledge(api, k, senderId, anonymity_set, shared_secrets, previousR, secret_key)

	///////////////////////////////////**///////////////////////////////////
	// Check if Hash Array of Secret is well formed
	common.CheckHashArrayOfSecrets(api, k, shared_secrets, arrayHashSecret)

	///////////////////////////////////**///////////////////////////////////
	// Knowledge of SecretKey - Perform public key generation and check if SecretKey generate senderId's PublicKey
	common.CheckPublicKeyKnowledge(api, k, senderId, anonymity_set, publicKey, secret_key)

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
	common.CheckMessageTags(api, k, shared_secrets, blockNumber, message_tags)

	// ///////////////////////////////////**//////////////////////////////////////
	// Check if random factors R are well formed
	common.CheckRandomFactors(api, k, senderId, anonymity_set, shared_secrets, blockNumber, txRandom)

	///////////////////////////////////**//////////////////////////////////////
	// Components for processing multiple commitment withdraw
	// Always process exactly 10 deposits
	//api.Println("\n--- Processing 10 Deposits ---")

	// Process each potential deposit
	for i := 0; i < 10; i++ {
		//api.Println(fmt.Sprintf("\nProcessing deposit %d:", i))
		//api.Println(fmt.Sprintf("v_per_deposit[%d]:", i), v_per_deposit[i])
		//api.Println(fmt.Sprintf("sk_deposits[%d]:", i), sk_deposits[i])

		// Check if deposit value is zero
		isDepositZero := api.IsZero(v_per_deposit[i])
		//api.Println(fmt.Sprintf("isDepositZero[%d]:", i), isDepositZero)

		publicKeyFromSk := primitives.PublicKey(api, sk_deposits[i])

		// Check if Hash(commitment in Dvp - MerkleTree) is well formed (V2)
		// V2 formula: H(H(H(publicKeyFromSk, saltsIn[i]), v_per_deposit[i]), address)
		h1 := pos.Poseidon(api, []frontend.Variable{publicKeyFromSk, saltsIn[i]})
		h2 := pos.Poseidon(api, []frontend.Variable{h1, v_per_deposit[i]})
		secondHash := pos.Poseidon(api, []frontend.Variable{h2, address})

		// Conditional check: if v_per_deposit[i] is zero, we skip the equality check
		// enabled = 1 - isZero = 1 if value is NOT zero, 0 if value is zero
		enabled := api.Sub(frontend.Variable(1), isDepositZero)
		//api.Println(fmt.Sprintf("enabled[%d] (should check?):", i), enabled)

		// ForceEqualIfEnabled equivalent:
		// If enabled == 1, assert equality; if enabled == 0, skip assertion
		// This can be implemented as: enabled * (hashes[i] - computedHash) == 0
		difference := api.Sub(hashes[i], secondHash)
		//api.Println(fmt.Sprintf("difference[%d] (hashes - secondHash):", i), difference)

		conditionalDifference := api.Mul(enabled, difference)
		//api.Println(fmt.Sprintf("conditionalDifference[%d] (should be 0):", i), conditionalDifference)

		api.AssertIsEqual(conditionalDifference, frontend.Variable(0))
	}

	//api.Println("\n=== CIRCUIT DEBUG END ===")
	return nil
}
