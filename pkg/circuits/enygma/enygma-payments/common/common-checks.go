package common

import (
	"fmt"

	pos "github.com/raylsnetwork/rayls-sovereign-gnark-api/poseidon"
	primitives "github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"

	"github.com/consensys/gnark/frontend"
)

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
func CheckSecretKnowledge(api frontend.API, k int, senderId frontend.Variable, anonymity_set []frontend.Variable, shared_secrets []frontend.Variable, previousR frontend.Variable, secret_key frontend.Variable) error {
	// Select shared_secrets[senderIdx] where anonymity_set[senderIdx] == senderId
	selectedSecret := frontend.Variable(0)
	for i := 0; i < k; i++ {
		eq := api.IsZero(api.Sub(senderId, anonymity_set[i]))
		selectedSecret = api.Add(selectedSecret, api.Mul(eq, shared_secrets[i]))
	}

	secretSenderCalculated := pos.Poseidon(api, []frontend.Variable{previousR, secret_key})
	secretRemain, err := primitives.ModSubgroup(api, secretSenderCalculated)
	if err != nil {
		return fmt.Errorf("check secret knowledge: %w", err)
	}

	api.AssertIsEqual(secretRemain, selectedSecret)
	return nil
}

// CheckHashArrayOfSecrets verifies that arrayHashSecret[i] = Poseidon(shared_secrets[i], shared_secrets[i])
func CheckHashArrayOfSecrets(api frontend.API, k int, shared_secrets []frontend.Variable, arrayHashSecret []frontend.Variable) error {
	for i := 0; i < k; i++ {
		calculatedHash := pos.Poseidon(api, []frontend.Variable{shared_secrets[i], shared_secrets[i]})
		hashMod, err := primitives.ModSubgroup(api, calculatedHash)
		if err != nil {
			return fmt.Errorf("check hash array of secrets: %w", err)
		}

		api.AssertIsEqual(hashMod, arrayHashSecret[i])
	}
	return nil
}

// CheckPublicKeyKnowledge verifies the sender knows the secret key that generates their public key
func CheckPublicKeyKnowledge(api frontend.API, k int, senderId frontend.Variable, anonymity_set []frontend.Variable, publicKey []frontend.Variable, secret_key frontend.Variable) error {
	selectedPK := frontend.Variable(0)

	for i := 0; i < k; i++ {
		diff := api.Sub(senderId, anonymity_set[i])
		eq := api.IsZero(diff)
		selectedPK = api.Add(selectedPK, api.Mul(eq, publicKey[i]))
	}
	pkMod, err := primitives.PublicKey(api, secret_key) // Pk = PoseidonHash(secret_key, secret_key) mod l
	if err != nil {
		return fmt.Errorf("check public key knowledge: %w", err)
	}

	api.AssertIsEqual(selectedPK, pkMod)
	return nil
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

// MaxAmountBits bounds every balance and amount. Pedersen values are only
// defined mod the subgroup order l (~2^251), so without a bound well below l a
// balance B can be opened as B + l, and a "negative" amount l - x passes as
// positive. With k <= 6 values below 2^128, no sum can wrap mod l.
const MaxAmountBits = 128

// CheckRangeProofWithPreviousV verifies 0 <= sender_tx_value <= previousV < 2^MaxAmountBits
func CheckRangeProofWithPreviousV(api frontend.API, previousV frontend.Variable, sender_tx_value frontend.Variable) {
	api.ToBinary(previousV, MaxAmountBits)
	api.ToBinary(sender_tx_value, MaxAmountBits)
	api.AssertIsLessOrEqual(sender_tx_value, previousV)
}

// CheckRangeProofVOnly verifies 0 <= sender_tx_value < 2^MaxAmountBits (for withdraw)
func CheckRangeProofVOnly(api frontend.API, sender_tx_value frontend.Variable) {
	api.ToBinary(sender_tx_value, MaxAmountBits)
}

// CheckReceiverAmounts verifies 0 <= txValue[i] < 2^MaxAmountBits for every
// participant other than the sender, whose (possibly negated) value is checked
// by the circuit itself. Without it, one member can be given l - x so that
// another receives x more than the sender paid.
func CheckReceiverAmounts(api frontend.API, k int, senderId frontend.Variable, anonymity_set []frontend.Variable, txValue []frontend.Variable) {
	for i := 0; i < k; i++ {
		isReceiver := api.Sub(1, api.IsZero(api.Sub(anonymity_set[i], senderId)))
		api.ToBinary(api.Mul(isReceiver, txValue[i]), MaxAmountBits)
	}
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
// For all participants: MessageTag[i] = Poseidon(HashTag, sharedSecrets[i], blockNumber)
// sharedSecrets[] is the preselected sender row
func CheckMessageTags(api frontend.API, k int, sharedSecrets []frontend.Variable, blockNumber frontend.Variable, messageTags []frontend.Variable) error {
	HashTag := pos.Poseidon(api, []frontend.Variable{12})
	for i := 0; i < k; i++ {
		calculatedMessageTag := pos.Poseidon(api, []frontend.Variable{HashTag, sharedSecrets[i], blockNumber})
		calculatedMessageTagMod, err := primitives.ModSubgroup(api, calculatedMessageTag)
		if err != nil {
			return fmt.Errorf("check message tags: %w", err)
		}

		api.AssertIsEqual(messageTags[i], calculatedMessageTagMod)
	}
	return nil
}

// CheckRandomFactors verifies all random factors are well formed
// shared_secrets[] is the preselected sender row
func CheckRandomFactors(api frontend.API, k int, senderId frontend.Variable, anonymity_set []frontend.Variable, shared_secrets []frontend.Variable, blockNumber frontend.Variable, txRandom []frontend.Variable) error {
	JubJubPrimeSubGroup := frontend.Variable(primitives.JubJubPrimeSubGroup)
	calculatedRandomFactor := make([]frontend.Variable, k)
	receiverHashesModP := make([]frontend.Variable, k)
	sumOfReceiverHashes := frontend.Variable(0)

	HashRandom := pos.Poseidon(api, []frontend.Variable{21})

	// First pass: compute all hashes using shared_secrets[i], reduce modulo JubJubPrimeSubGroup
	for i := 0; i < k; i++ {
		RandomFactor := pos.Poseidon(api, []frontend.Variable{HashRandom, shared_secrets[i], blockNumber})

		// Reduce RandomFactor modulo JubJubPrimeSubGroup
		hashModP, err := primitives.ModSubgroup(api, RandomFactor)
		if err != nil {
			return fmt.Errorf("check random factors: %w", err)
		}

		receiverHashesModP[i] = hashModP

		// Check if this participant is a receiver (not the sender)
		isSender := api.IsZero(api.Sub(anonymity_set[i], senderId))
		isReceiver := api.Sub(1, isSender)

		// Add to sum only if this is a receiver
		sumOfReceiverHashes = api.Add(sumOfReceiverHashes, api.Mul(isReceiver, hashModP))
	}

	// Reduce the sum modulo JubJubPrimeSubGroup
	senderRandomFactor, err := primitives.ModSubgroup(api, sumOfReceiverHashes)
	if err != nil {
		return fmt.Errorf("check random factors: %w", err)
	}

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
	return nil
}
