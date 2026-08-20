package primitives

import (
	"fmt"
	"math/big"
	"os"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

var hintRegistrationOnce sync.Once

func init() {
	hintRegistrationOnce.Do(func() {
		solver.RegisterHint(ModHintBabyJubJub)
		solver.RegisterHint(ModHintBN254)
		fmt.Println("✓ Hint functions registered")
	})
}

func ModHintBabyJubJub(mod *big.Int, inputs []*big.Int, res []*big.Int) error {
	p := JubJubPrimeSubGroup

	// Debug log
	//fmt.Println("JOINSPLIT: Using BabyJubJub prime:", p.String())

	value := inputs[0]
	q := new(big.Int)
	r := new(big.Int)

	q.DivMod(value, p, r) // q = value / p, r = value % p

	res[0] = r // remainder
	res[1] = q // quotient
	return nil

}

func ModHintBN254(mod *big.Int, inputs []*big.Int, res []*big.Int) error {
	p := JubJubPrimeGroup

	// Debug log
	//fmt.Println("JOINSPLIT: Using BN254 prime:", p.String())

	value := inputs[0]
	q := new(big.Int)
	r := new(big.Int)

	q.DivMod(value, p, r) // q = value / p, r = value % p

	res[0] = r // remainder
	res[1] = q // quotient
	return nil

}

func Erc155UniqueIdNative(mod *big.Int, inputs []*big.Int, res []*big.Int) error {
	p := JubJubPrimeGroup

	address := inputs[0]
	id := inputs[1]
	amount := inputs[2]
	id1, _ := poseidon.Hash([]*big.Int{address, id})
	id1.Mod(id1, p)

	erc1155Id, _ := poseidon.Hash([]*big.Int{id1, amount})
	erc1155Id.Mod(erc1155Id, p)
	res[0] = erc1155Id
	return nil
}

func PoseidonNative(mod *big.Int, inputs []*big.Int, res []*big.Int) error {
	p := JubJubPrimeGroup

	value := inputs[0]
	random := inputs[1]

	hash, _ := poseidon.Hash([]*big.Int{value, random})

	hash.Mod(hash, p)

	res[0] = hash
	return nil
}

func GetPkHash(secret_key *big.Int) *big.Int {
	hash, _ := poseidon.Hash([]*big.Int{secret_key, secret_key})
	hash.Mod(hash, JubJubPrimeSubGroup)
	return hash
}

func GetPK(v *big.Int) *babyjub.Point {
	rG := babyjub.NewPoint().Mul(v, GBabyJub)
	return rG
}

func GetH(v *big.Int) *babyjub.Point {
	rG := babyjub.NewPoint().Mul(v, HBabyJub)
	return rG
}

func PedersenCommitmentBabyJub(v *big.Int, r *big.Int) *babyjub.Point {

	vG := GetPK(v)
	vH := GetH(r)

	return AddPks(vG, vH)
}

func AddPks(pk1 *babyjub.Point, pk2 *babyjub.Point) *babyjub.Point {
	return babyjub.NewPoint().Projective().Add(pk1.Projective(), pk2.Projective()).Affine()
}

func LoadProvingKey(curve ecc.ID, filename string) (groth16.ProvingKey, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pk := groth16.NewProvingKey(curve) // e.g., ecc.BN254
	_, err = pk.ReadFrom(file)
	return pk, err
}

// Load verifying key from file
func LoadVerifyingKey(curve ecc.ID, filename string) (groth16.VerifyingKey, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	vk := groth16.NewVerifyingKey(curve) // e.g., ecc.BN254
	_, err = vk.ReadFrom(file)
	return vk, err
}

// SaveProvingKey saves proving key to file
func SaveProvingKey(curve ecc.ID, pk groth16.ProvingKey, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = pk.WriteTo(file)
	return err
}

// SaveVerifyingKey saves verifying key to file
func SaveVerifyingKey(curve ecc.ID, vk groth16.VerifyingKey, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = vk.WriteTo(file)
	return err
}

// ComputeNullifierBN254 computes Poseidon(privateKey, pathIndex) mod BN254 prime
func ComputeNullifierBN254(privateKeyStr, pathIndexStr string) string {
	privateKey := ParseBigInt(privateKeyStr)
	pathIndex := ParseBigInt(pathIndexStr)

	inputs := []*big.Int{privateKey, pathIndex}
	hash, _ := poseidon.Hash(inputs)

	// Mod by BN254 prime to match what happens in the circuit
	p := JubJubPrimeGroup
	hash.Mod(hash, p)

	return hash.String()
}

// ComputeOutputCommitmentBN254 computes Poseidon(Poseidon(contractAddress, value), recipientPK) mod BN254 prime
func ComputeOutputCommitmentBN254(uniqueIdStr, recipientPKStr string) string {
	uniqueId := ParseBigInt(uniqueIdStr)
	recipientPK := ParseBigInt(recipientPKStr)

	// BN254 prime for modular reduction
	p := JubJubPrimeGroup

	// Step 2: commitment = Poseidon(uniqueId, recipientPK) mod p
	commitmentInputs := []*big.Int{uniqueId, recipientPK}
	commitment, _ := poseidon.Hash(commitmentInputs)
	commitment.Mod(commitment, p)

	return commitment.String()
}

func ComputeOutputCommitmentBN254Uid(Uid, recipientPKStr string) string {
	uniqueId := ParseBigInt(Uid)
	recipientPK := ParseBigInt(recipientPKStr)

	// BN254 prime for modular reduction
	p := JubJubPrimeGroup

	// Step 2: commitment = Poseidon(uniqueId, recipientPK) mod p
	commitmentInputs := []*big.Int{uniqueId, recipientPK}
	commitment, _ := poseidon.Hash(commitmentInputs)
	commitment.Mod(commitment, p)

	return commitment.String()
}

// ComputeUniqueIdBN254 computes Poseidon(contractAddress, value) mod BN254 prime
func ComputeUniqueIdBN254(contractAddressStr, valueStr string) string {
	contractAddress := ConvertAddressToBigInt(contractAddressStr)
	value := ParseBigInt(valueStr)

	p := JubJubPrimeGroup

	inputs := []*big.Int{contractAddress, value}
	hash, _ := poseidon.Hash(inputs)
	hash.Mod(hash, p)

	return hash.String()
}

func ComputeErc1155UniqueIdBN254(contractAddress, tokenId, amount string) string {
	// Parse inputs
	contractAddr := ConvertAddressToBigInt(contractAddress)
	tokenIdBig := ParseBigInt(tokenId)
	amountBig := ParseBigInt(amount)

	// BN254 field modulus
	p := JubJubPrimeGroup

	// First hash: Poseidon(contractAddress, tokenId)
	hash1, err := poseidon.Hash([]*big.Int{contractAddr, tokenIdBig})
	if err != nil {
		panic(err)
	}
	hash1.Mod(hash1, p) // Apply modulus (this is what ModHintBN254 does)

	// Second hash: Poseidon(hash1, amount)
	hash2, err := poseidon.Hash([]*big.Int{hash1, amountBig})
	if err != nil {
		panic(err)
	}
	hash2.Mod(hash2, p) // Apply modulus

	return hash2.String()
}

// ConvertAddressToBigInt converts hex address (with or without 0x prefix) to big.Int
func ConvertAddressToBigInt(address string) *big.Int {
	// Remove "0x" prefix if present
	if len(address) > 2 && address[:2] == "0x" {
		address = address[2:]
	}

	// Convert hex to big integer
	bigInt := new(big.Int)
	bigInt.SetString(address, 16) // base 16 for hex
	return bigInt
}

func ParseBigInt(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

// poseidonHashModBN254 computes Poseidon(a, b) mod BN254 prime.
// Helper used by V2 commitment functions.
func poseidonHashModBN254(a, b *big.Int) *big.Int {
	hash, _ := poseidon.Hash([]*big.Int{a, b})
	hash.Mod(hash, JubJubPrimeGroup)
	return hash
}

// DerivePublicKeyBN254 derives a public key from a private key using Poseidon(sk, sk) mod JubJubPrimeSubGroup.
// This is the plain-Go equivalent of primitives.PublicKey() used inside circuits.
func DerivePublicKeyBN254(privateKeyStr string) string {
	sk := ParseBigInt(privateKeyStr)
	hash, _ := poseidon.Hash([]*big.Int{sk, sk})
	hash.Mod(hash, JubJubPrimeSubGroup)
	return hash.String()
}

// ComputeCommitmentV2ERC20BN254 computes H(H(H(spendPK, salt), amount), tokenAddress) mod BN254
// using chained 2-input Poseidon hashes.
func ComputeCommitmentV2ERC20BN254(spendPKStr, saltStr, amountStr, tokenAddressStr string) string {
	spendPK := ParseBigInt(spendPKStr)
	salt := ParseBigInt(saltStr)
	amount := ParseBigInt(amountStr)
	tokenAddress := ParseBigInt(tokenAddressStr)

	h1 := poseidonHashModBN254(spendPK, salt)
	h2 := poseidonHashModBN254(h1, amount)
	h3 := poseidonHashModBN254(h2, tokenAddress)

	return h3.String()
}

// ComputeCommitmentV2ERC721BN254 computes H(H(spendPK, salt), uId) mod BN254
// using chained 2-input Poseidon hashes.
func ComputeCommitmentV2ERC721BN254(spendPKStr, saltStr, uIdStr string) string {
	spendPK := ParseBigInt(spendPKStr)
	salt := ParseBigInt(saltStr)
	uId := ParseBigInt(uIdStr)

	h1 := poseidonHashModBN254(spendPK, salt)
	h2 := poseidonHashModBN254(h1, uId)

	return h2.String()
}

// ComputeCommitmentV2ERC1155BN254 computes H(H(H(H(spendPK, salt), tokenAddress), tokenID), tokenAmount) mod BN254
// using chained 2-input Poseidon hashes.
func ComputeCommitmentV2ERC1155BN254(spendPKStr, saltStr, tokenAddressStr, tokenIDStr, tokenAmountStr string) string {
	spendPK := ParseBigInt(spendPKStr)
	salt := ParseBigInt(saltStr)
	tokenAddress := ParseBigInt(tokenAddressStr)
	tokenID := ParseBigInt(tokenIDStr)
	tokenAmount := ParseBigInt(tokenAmountStr)

	h1 := poseidonHashModBN254(spendPK, salt)
	h2 := poseidonHashModBN254(h1, tokenAddress)
	h3 := poseidonHashModBN254(h2, tokenID)
	h4 := poseidonHashModBN254(h3, tokenAmount)

	return h4.String()
}
