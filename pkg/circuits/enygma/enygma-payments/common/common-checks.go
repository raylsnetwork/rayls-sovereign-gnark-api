package common

import (
	pos "github.com/raylsnetwork/rayls-sovereign-gnark-api/poseidon"
	primitives "github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

// JubJubPrimeSubGroup constant used across all circuits
const JubJubPrimeSubGroupStr = "2736030358979909402780800718157159386076813972158567259200215660948447373041"

// CheckSenderIdIsInK verifies that the sender ID is present in the k-anonymity set
func CheckSenderIdIsInK(api frontend.API, k int, senderId frontend.Variable, anonymity_set []frontend.Variable) {
	sumIsInK := frontend.Variable(0)
	for i := 0; i < k; i++ {
		isEqual := api.IsZero(api.Sub(anonymity_set[i], senderId))
		sumIsInK = api.Add(isEqual, sumIsInK)
	}
	api.AssertIsEqual(sumIsInK, 1)
}

// CheckCurvePoints verifies that all previous commits and tx commits are valid curve points
func CheckCurvePoints(api frontend.API, k int, previousCommit [][2]frontend.Variable, txCommit [][2]frontend.Variable) {
	for i := 0; i < k; i++ {
		X := previousCommit[i][0]
		Y := previousCommit[i][1]
		primitives.AssertPointsIsOnCurve(api, X, Y)

		X2 := txCommit[i][0]
		Y2 := txCommit[i][1]
		primitives.AssertPointsIsOnCurve(api, X2, Y2)
	}
}

// CheckSecretKnowledge verifies the sender knows the secret via Poseidon(previousR, secret_key) == shared_secrets[senderIdx]
func CheckSecretKnowledge(api frontend.API, k int, senderId frontend.Variable, anonymity_set []frontend.Variable, shared_secrets []frontend.Variable, previousR frontend.Variable, secret_key frontend.Variable) {
	// Select shared_secrets[senderIdx] where anonymity_set[senderIdx] == senderId
	selectedSecret := frontend.Variable(0)
	for i := 0; i < k; i++ {
		eq := api.IsZero(api.Sub(senderId, anonymity_set[i]))
		selectedSecret = api.Add(selectedSecret, api.Mul(eq, shared_secrets[i]))
	}

	secretSenderCalculated := pos.Poseidon(api, []frontend.Variable{previousR, secret_key})
	secretInter, _ := api.NewHint(primitives.ModHintBabyJubJub, 2, secretSenderCalculated)
	secretRemain := secretInter[0] // remainder

	api.AssertIsEqual(secretRemain, selectedSecret)
}

// CheckHashArrayOfSecrets verifies that arrayHashSecret[i] = Poseidon(shared_secrets[i], shared_secrets[i])
func CheckHashArrayOfSecrets(api frontend.API, k int, shared_secrets []frontend.Variable, arrayHashSecret []frontend.Variable) {
	for i := 0; i < k; i++ {
		calculatedHash := pos.Poseidon(api, []frontend.Variable{shared_secrets[i], shared_secrets[i]})
		hashInter, _ := api.NewHint(primitives.ModHintBabyJubJub, 2, calculatedHash)
		hashMod := hashInter[0] // remainder

		api.AssertIsEqual(hashMod, arrayHashSecret[i])
	}
}

// CheckPublicKeyKnowledge verifies the sender knows the secret key that generates their public key
func CheckPublicKeyKnowledge(api frontend.API, k int, senderId frontend.Variable, anonymity_set []frontend.Variable, publicKey []frontend.Variable, secret_key frontend.Variable) {
	selectedPK := frontend.Variable(0)

	for i := 0; i < k; i++ {
		diff := api.Sub(senderId, anonymity_set[i])
		eq := api.IsZero(diff)
		selectedPK = api.Add(selectedPK, api.Mul(eq, publicKey[i]))
	}
	pk := pos.Poseidon(api, []frontend.Variable{secret_key, secret_key}) // Pk = PoseidonHash (secret_key , secret_key)
	pkInter, _ := api.NewHint(primitives.ModHintBabyJubJub, 2, pk)
	pkMod := pkInter[0] // remainder

	api.AssertIsEqual(selectedPK, pkMod)
}

// CheckPreviousCommitmentKnowledge verifies the sender knows the previous commitment
func CheckPreviousCommitmentKnowledge(api frontend.API, k int, senderId frontend.Variable, anonymity_set []frontend.Variable, previousCommit [][2]frontend.Variable, previousV frontend.Variable, previousR frontend.Variable) {
	selectedPreviousCommitmentX := frontend.Variable(0)
	selectedPreviousCommitmentY := frontend.Variable(0)
	for i := 0; i < k; i++ {
		diff := api.Sub(senderId, anonymity_set[i])
		eq := api.IsZero(diff)
		selectedPreviousCommitmentX = api.Add(selectedPreviousCommitmentX, api.Mul(eq, previousCommit[i][0]))
		selectedPreviousCommitmentY = api.Add(selectedPreviousCommitmentY, api.Mul(eq, previousCommit[i][1]))
	}

	computedPreviousCommitment := primitives.PedersenCommitment(api, previousV, previousR)

	api.AssertIsEqual(selectedPreviousCommitmentX, computedPreviousCommitment.X)
	api.AssertIsEqual(selectedPreviousCommitmentY, computedPreviousCommitment.Y)
}

// CheckRangeProofWithPreviousV verifies previousV >= sender_tx_value and sender_tx_value >= 0
func CheckRangeProofWithPreviousV(api frontend.API, previousV frontend.Variable, sender_tx_value frontend.Variable) {

	previousVBits := api.ToBinary(previousV, 252)
	vBits := api.ToBinary(sender_tx_value, 252)

	previousVConstrained := api.FromBinary(previousVBits...)
	vConstrained := api.FromBinary(vBits...)

	// previousV >= sender_tx_value means previousV - sender_tx_value >= 0, which means Cmp(previousV, sender_tx_value) != -1
	prevVGreaterEqualV := api.Cmp(previousVConstrained, vConstrained)
	api.AssertIsEqual(api.IsZero(api.Add(prevVGreaterEqualV, frontend.Variable(1))), frontend.Variable(0))

	// sender_tx_value >= 0 means Cmp(sender_tx_value, 0) != -1
	vGreaterEqualZero := api.Cmp(vConstrained, frontend.Variable(0))
	api.AssertIsEqual(api.IsZero(api.Add(vGreaterEqualZero, frontend.Variable(1))), frontend.Variable(0))
}

// CheckRangeProofVOnly verifies sender_tx_value >= 0 (for withdraw)
func CheckRangeProofVOnly(api frontend.API, sender_tx_value frontend.Variable) {
	vBits := api.ToBinary(sender_tx_value, 252)
	vConstrained := api.FromBinary(vBits...)

	// sender_tx_value >= 0 means Cmp(sender_tx_value, 0) != -1
	vGreaterEqualZero := api.Cmp(vConstrained, frontend.Variable(0))
	api.AssertIsEqual(api.IsZero(api.Add(vGreaterEqualZero, frontend.Variable(1))), frontend.Variable(0))
}

// CheckNullifierKnowledge verifies knowledge of nullifier = Poseidon(selectedPreImage, blockNumber)
// where selectedPreImage is selected from arrayHashSecret based on senderId
func CheckNullifierKnowledge(api frontend.API, k int, senderId frontend.Variable, anonymity_set []frontend.Variable, arrayHashSecret []frontend.Variable, blockNumber frontend.Variable, nullifier frontend.Variable) {
	selectedPreImage := frontend.Variable(0)

	for i := 0; i < k; i++ {
		diff := api.Sub(senderId, anonymity_set[i])
		eq := api.IsZero(diff)

		selectedPreImage = api.Add(selectedPreImage, api.Mul(eq, arrayHashSecret[i]))
	}

	computedNullifier := pos.Poseidon(api, []frontend.Variable{selectedPreImage, blockNumber})
	api.AssertIsEqual(computedNullifier, nullifier)
}

// CheckTxCommitmentsWellFormed verifies all transaction commitments are properly formed
func CheckTxCommitmentsWellFormed(api frontend.API, k int, txValue []frontend.Variable, txRandom []frontend.Variable, txCommit [][2]frontend.Variable) {
	for i := 0; i < k; i++ {
		computedPedersenCommitment := primitives.PedersenCommitment(api, txValue[i], txRandom[i])
		api.AssertIsEqual(txCommit[i][0], computedPedersenCommitment.X)
		api.AssertIsEqual(txCommit[i][1], computedPedersenCommitment.Y)
	}
}

// CheckMessageTags verifies message tags are well formed
// For all participants: MessageTag[i] = Poseidon(HashTag, shared_secrets[i], blockNumber)
// shared_secrets[] is the preselected sender row
func CheckMessageTags(api frontend.API, k int, shared_secrets []frontend.Variable, blockNumber frontend.Variable, message_tags []frontend.Variable) {
	HashTag := pos.Poseidon(api, []frontend.Variable{12})
	for i := 0; i < k; i++ {
		calculatedMessageTag := pos.Poseidon(api, []frontend.Variable{HashTag, shared_secrets[i], blockNumber})
		calculatedMessageTagInter, _ := api.NewHint(primitives.ModHintBabyJubJub, 2, calculatedMessageTag)
		calculatedMessageTagMod := calculatedMessageTagInter[0]

		api.AssertIsEqual(message_tags[i], calculatedMessageTagMod)
	}
}

// CheckRandomFactors verifies all random factors are well formed
// shared_secrets[] is the preselected sender row
func CheckRandomFactors(api frontend.API, k int, senderId frontend.Variable, anonymity_set []frontend.Variable, shared_secrets []frontend.Variable, blockNumber frontend.Variable, txRandom []frontend.Variable) {
	JubJubPrimeSubGroup := frontend.Variable(JubJubPrimeSubGroupStr)
	calculatedRandomFactor := make([]frontend.Variable, k)
	receiverHashesModP := make([]frontend.Variable, k)
	sumOfReceiverHashes := frontend.Variable(0)

	HashRandom := pos.Poseidon(api, []frontend.Variable{21})

	// First pass: compute all hashes using shared_secrets[i], reduce modulo JubJubPrimeSubGroup
	for i := 0; i < k; i++ {
		RandomFactor := pos.Poseidon(api, []frontend.Variable{HashRandom, shared_secrets[i], blockNumber})

		// Reduce RandomFactor modulo JubJubPrimeSubGroup
		randomInter, _ := api.NewHint(primitives.ModHintBabyJubJub, 2, RandomFactor)
		hashModP := randomInter[0]
		q := randomInter[1]

		api.AssertIsEqual(api.Add(api.Mul(q, JubJubPrimeSubGroup), hashModP), RandomFactor)
		isValid := cmp.IsLess(api, hashModP, JubJubPrimeSubGroup)
		api.AssertIsEqual(isValid, 1)

		receiverHashesModP[i] = hashModP

		// Check if this participant is a receiver (not the sender)
		isSender := api.IsZero(api.Sub(anonymity_set[i], senderId))
		isReceiver := api.Sub(1, isSender)

		// Add to sum only if this is a receiver
		sumOfReceiverHashes = api.Add(sumOfReceiverHashes, api.Mul(isReceiver, hashModP))
	}

	// Reduce the sum modulo JubJubPrimeSubGroup
	sumInter, _ := api.NewHint(primitives.ModHintBabyJubJub, 2, sumOfReceiverHashes)
	senderRandomFactor := sumInter[0]
	sumQ := sumInter[1]

	api.AssertIsEqual(api.Add(api.Mul(sumQ, JubJubPrimeSubGroup), senderRandomFactor), sumOfReceiverHashes)
	isSumValid := cmp.IsLess(api, senderRandomFactor, JubJubPrimeSubGroup)
	api.AssertIsEqual(isSumValid, 1)

	// Second pass: assign the correct random factors based on role
	for i := 0; i < k; i++ {
		isSender := api.IsZero(api.Sub(anonymity_set[i], senderId))
		// For receivers: neg(hash mod p) = p - hash
		// For sender: sum of receiver hashes mod p
		receiverRandomFactor := api.Sub(JubJubPrimeSubGroup, receiverHashesModP[i])
		calculatedRandomFactor[i] = api.Select(isSender, senderRandomFactor, receiverRandomFactor)
	}

	// Verification: check that calculated factors match provided TxRandomValues
	for i := 0; i < k; i++ {
		api.AssertIsEqual(calculatedRandomFactor[i], txRandom[i])
	}
}
