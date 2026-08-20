package erc1155_joinsplit

import (
	primitives "enygma-gnark-server/primitives"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/gin-gonic/gin"
)

var (
	erc1155CircuitCache     *CompiledCircuit
	erc1155CircuitCacheOnce sync.Once
	bigIntPool              = NewBigIntPool()
)

type CompiledCircuit struct {
	R1CS constraint.ConstraintSystem
	PK   groth16.ProvingKey
}

type BigIntPool struct {
	pool sync.Pool
}

func NewBigIntPool() *BigIntPool {
	return &BigIntPool{
		pool: sync.Pool{
			New: func() interface{} {
				return new(big.Int)
			},
		},
	}
}

func (p *BigIntPool) Get() *big.Int {
	return p.pool.Get().(*big.Int)
}

func (p *BigIntPool) Put(bi *big.Int) {
	bi.SetInt64(0)
	p.pool.Put(bi)
}

// Helper function to load constraint system from file
func loadConstraintSystem(path string) (constraint.ConstraintSystem, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open constraint system file: %v", err)
	}
	defer file.Close()

	cs := groth16.NewCS(ecc.BN254)
	_, err = cs.ReadFrom(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read constraint system: %v", err)
	}

	return cs, nil
}

// Circuit loading function for Erc1155 ownership
func getOrLoadErc1155Circuit(pkPath, r1csPath string) *CompiledCircuit {
	erc1155CircuitCacheOnce.Do(func() {
		fmt.Println("Loading pre-compiled Erc1155 ownership circuit...")
		start := time.Now()

		r1cs, err := loadConstraintSystem(r1csPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load Erc1155 constraint system: %v", err))
		}

		pk, err := primitives.LoadProvingKey(ecc.BN254, pkPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load Erc1155 proving key: %v", err))
		}

		erc1155CircuitCache = &CompiledCircuit{
			R1CS: r1cs,
			PK:   pk,
		}

		fmt.Printf("✓ Erc1155 Circuit loaded and cached in %v\n", time.Since(start))
	})
	return erc1155CircuitCache
}

// Handler function for Erc1155 ownership
func NewHandler(pkPath, vkPath, r1csPath string) gin.HandlerFunc {
	// Pre-load the circuit
	compiled := getOrLoadErc1155Circuit(pkPath, r1csPath)

	return func(c *gin.Context) {
		totalStart := time.Now()

		var request Erc1155JoinSplitRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		bindTime := time.Since(totalStart)

		if err := validateErc1155Inputs(&request); err != nil {
			fmt.Printf("Input validation failed: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Input validation failed: " + err.Error(),
			})
			return
		}

		var witness Erc1155JoinSplitCircuit
		setErc1155WitnessOptimized(&witness, &request)
		parseTime := time.Since(totalStart)

		response, err := generateErc1155Proof(&witness, compiled, &request)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to generate proof: %v", err)
			if containsConstraintError(err.Error()) {
				errorMsg += "\nNote: This constraint error suggests input validation issues. The circuit computed different values than provided."
			}

			c.JSON(http.StatusInternalServerError, gin.H{
				"error":     errorMsg,
				"raw_error": err.Error(),
			})
			return
		}

		proveTime := time.Since(totalStart)

		fmt.Printf("Erc1155 Ownership Timing: Bind=%v, Parse=%v, Prove=%v, Total=%v\n",
			bindTime, parseTime-bindTime, proveTime-parseTime, proveTime)

		c.JSON(http.StatusOK, response)
	}
}

// Input validation for Erc1155 ownership
func validateErc1155Inputs(request *Erc1155JoinSplitRequest) error {
	// Validate that we have the right number of outputs
	if len(request.ValuesOut) != mOutputs {
		return fmt.Errorf("expected %d output values, got %d", mOutputs, len(request.ValuesOut))
	}

	if len(request.PubKeysOut) != mOutputs {
		return fmt.Errorf("expected %d output public keys, got %d", mOutputs, len(request.PubKeysOut))
	}

	// Validate that we have matching key pairs and merkle proofs for inputs
	if len(request.KeyPairsIn) != len(request.ValuesIn) {
		return fmt.Errorf("number of key pairs (%d) must match number of input values (%d)",
			len(request.KeyPairsIn), len(request.ValuesIn))
	}

	if len(request.MerkleProofs) != len(request.ValuesIn) {
		return fmt.Errorf("number of merkle proofs (%d) must match number of input values (%d)",
			len(request.MerkleProofs), len(request.ValuesIn))
	}

	if len(request.MerkleRoots) != len(request.ValuesIn) {
		return fmt.Errorf("number of merkle roots (%d) must match number of input values (%d)",
			len(request.MerkleRoots), len(request.ValuesIn))
	}

	// Validate that total inputs equal total outputs
	inputTotal := new(big.Int)
	for _, valueStr := range request.ValuesIn {
		value := new(big.Int)
		if _, ok := value.SetString(valueStr, 10); !ok {
			return fmt.Errorf("invalid input value: %s", valueStr)
		}
		inputTotal.Add(inputTotal, value)
	}

	outputTotal := new(big.Int)
	for _, valueStr := range request.ValuesOut {
		value := new(big.Int)
		if _, ok := value.SetString(valueStr, 10); !ok {
			return fmt.Errorf("invalid output value: %s", valueStr)
		}
		outputTotal.Add(outputTotal, value)
	}

	if inputTotal.Cmp(outputTotal) != 0 {
		return fmt.Errorf("input total (%s) does not equal output total (%s)", inputTotal.String(), outputTotal.String())
	}

	return nil
}

// Set witness for Erc1155 circuit
func setErc1155WitnessOptimized(witness *Erc1155JoinSplitCircuit, request *Erc1155JoinSplitRequest) {
	witness.NftCommitment = parseBigIntOptimized(request.NftCommitment)
	witness.Erc1155ContractAddress = parseBigIntOptimized(convertAddressToBigInt(request.Erc1155ContractAddress))
	witness.Erc1155TokenId = parseBigIntOptimized(request.Erc1155TokenId)

	// Fill actual inputs
	actualInputs := len(request.ValuesIn)
	for i := 0; i < actualInputs && i < nInputs; i++ {
		witness.ValuesIn[i] = parseBigIntOptimized(request.ValuesIn[i])
		witness.PrivateKeys[i] = parseBigIntOptimized(request.KeyPairsIn[i].PrivateKey)
		witness.SaltsIn[i] = parseBigIntOptimized(request.SaltsIn[i])
		witness.PathIndices[i] = parseBigIntOptimized(request.MerkleProofs[i].Indices)
		witness.MerkleRoots[i] = parseBigIntOptimized(request.MerkleRoots[i])
		witness.TreeNumbers[i] = frontend.Variable(request.TreeNumbers[i])

		// 3. Compute Nullifier
		nullifier := computeNullifier(request.KeyPairsIn[i].PrivateKey, request.MerkleProofs[i].Indices)
		//fmt.Printf("  Computed Nullifier: %s\n", nullifier)
		witness.Nullifiers[i] = parseBigIntOptimized(nullifier)

		// Set path elements
		for j := 0; j < len(request.MerkleProofs[i].Elements) && j < merkleTreeDepth; j++ {
			witness.PathElements[i][j] = parseBigIntOptimized(request.MerkleProofs[i].Elements[j])
		}
		// Fill remaining path elements with zeros
		for j := len(request.MerkleProofs[i].Elements); j < merkleTreeDepth; j++ {
			witness.PathElements[i][j] = frontend.Variable("0")
		}
	}

	// Fill remaining inputs with dummy values (zeros) if needed
	for i := actualInputs; i < nInputs; i++ {
		witness.ValuesIn[i] = frontend.Variable("0")
		witness.PrivateKeys[i] = frontend.Variable("0")
		witness.SaltsIn[i] = frontend.Variable("0")
		witness.PathIndices[i] = frontend.Variable("0")
		witness.MerkleRoots[i] = frontend.Variable("0")
		witness.TreeNumbers[i] = frontend.Variable(0)
		// Use a dummy nullifier for unused inputs
		witness.Nullifiers[i] = frontend.Variable("14744269619966411208579211824598458697587494354926760081771325075741142829156")

		for j := 0; j < merkleTreeDepth; j++ {
			witness.PathElements[i][j] = frontend.Variable("0")
		}
	}

	// Set outputs
	for i := 0; i < mOutputs; i++ {
		witness.ValuesOut[i] = parseBigIntOptimized(request.ValuesOut[i])
		witness.RecipientPK[i] = parseBigIntOptimized(request.PubKeysOut[i].PublicKey)
		witness.SaltsOut[i] = parseBigIntOptimized(request.SaltsOut[i])

		// Generate V2 output commitment: H(H(H(H(recipientPK, salt), tokenAddress), tokenID), amount)
		contractAddrStr := convertAddressToBigInt(request.Erc1155ContractAddress)
		outputCommitment := primitives.ComputeCommitmentV2ERC1155BN254(
			request.PubKeysOut[i].PublicKey, request.SaltsOut[i],
			contractAddrStr, request.Erc1155TokenId, request.ValuesOut[i],
		)
		witness.CommitmentsOut[i] = parseBigIntOptimized(outputCommitment)
	}

	// Set revert commitment witness
	witness.RevertSalt = parseBigIntOptimized(request.RevertSalt)

	// Derive sender's public key from first input's private key (use "0" for 0-swap case)
	senderPrivKey := "0"
	if len(request.KeyPairsIn) > 0 {
		senderPrivKey = request.KeyPairsIn[0].PrivateKey
	}
	senderPK := primitives.DerivePublicKeyBN254(senderPrivKey)

	// Revert commitment uses the same contract address, token ID, and total input amount
	contractAddrStrRevert := convertAddressToBigInt(request.Erc1155ContractAddress)
	inputTotal := new(big.Int)
	for _, v := range request.ValuesIn {
		val, _ := new(big.Int).SetString(v, 10)
		inputTotal.Add(inputTotal, val)
	}
	revertCommitment := primitives.ComputeCommitmentV2ERC1155BN254(
		senderPK, request.RevertSalt,
		contractAddrStrRevert, request.Erc1155TokenId, inputTotal.String(),
	)
	witness.RevertCommitment = parseBigIntOptimized(revertCommitment)
}

// Generate proof for Erc1155 circuit
func generateErc1155Proof(witness frontend.Circuit, compiled *CompiledCircuit, request *Erc1155JoinSplitRequest) (*Erc1155JoinSplitResponseAPI, error) {
	response, _, err := generateProofGeneric(witness, compiled)
	if err != nil {
		return nil, err
	}

	erc1155Response := &Erc1155JoinSplitResponseAPI{
		Pi_A:          response.Pi_A,
		Pi_B:          response.Pi_B,
		Pi_C:          response.Pi_C,
		Public_Signal: generateErc1155PublicSignal(request),
	}

	return erc1155Response, nil
}

// Generate public signals for Erc1155 circuit
func generateErc1155PublicSignal(request *Erc1155JoinSplitRequest) []string {
	// Public signals: paymentCommitment + merkleRoots + nullifiers + +treeNumbers + commitmentsOut
	publicSignal := make([]string, 0, 1+nInputs+nInputs+nInputs+mOutputs)

	// Payment commitment
	publicSignal = append(publicSignal, request.NftCommitment)

	// Merkle roots (padded to nInputs)
	for i := 0; i < len(request.MerkleRoots) && i < nInputs; i++ {
		publicSignal = append(publicSignal, request.MerkleRoots[i])
	}
	for i := len(request.MerkleRoots); i < nInputs; i++ {
		publicSignal = append(publicSignal, "0")
	}

	// Nullifiers (computed/padded to nInputs)
	for i := 0; i < len(request.KeyPairsIn) && i < nInputs; i++ {
		nullifier := computeNullifier(request.KeyPairsIn[i].PrivateKey, request.MerkleProofs[i].Indices)
		publicSignal = append(publicSignal, nullifier)
	}
	for i := len(request.KeyPairsIn); i < nInputs; i++ {
		publicSignal = append(publicSignal, "14744269619966411208579211824598458697587494354926760081771325075741142829156")
	}

	// Tree numbers (padded to nInputs)
	for i := 0; i < len(request.TreeNumbers) && i < nInputs; i++ {
		publicSignal = append(publicSignal, strconv.Itoa(request.TreeNumbers[i]))
	}
	for i := len(request.TreeNumbers); i < nInputs; i++ {
		publicSignal = append(publicSignal, "0")
	}

	// Output commitments (V2)
	for i := 0; i < mOutputs; i++ {
		contractAddrStr := convertAddressToBigInt(request.Erc1155ContractAddress)
		outputCommitment := primitives.ComputeCommitmentV2ERC1155BN254(
			request.PubKeysOut[i].PublicKey, request.SaltsOut[i],
			contractAddrStr, request.Erc1155TokenId, request.ValuesOut[i],
		)
		publicSignal = append(publicSignal, outputCommitment)
	}

	// Revert commitment — derive sender PK from first input's private key (use "0" for 0-swap case)
	senderPrivKeySignal := "0"
	if len(request.KeyPairsIn) > 0 {
		senderPrivKeySignal = request.KeyPairsIn[0].PrivateKey
	}
	senderPKSignal := primitives.DerivePublicKeyBN254(senderPrivKeySignal)
	contractAddrStrRevert := convertAddressToBigInt(request.Erc1155ContractAddress)
	inputTotal := new(big.Int)
	for _, v := range request.ValuesIn {
		val, _ := new(big.Int).SetString(v, 10)
		inputTotal.Add(inputTotal, val)
	}
	revertCommitment := primitives.ComputeCommitmentV2ERC1155BN254(
		senderPKSignal, request.RevertSalt,
		contractAddrStrRevert, request.Erc1155TokenId, inputTotal.String(),
	)
	publicSignal = append(publicSignal, revertCommitment)

	return publicSignal
}

// Generic proof generation function
func generateProofGeneric(witness frontend.Circuit, compiled *CompiledCircuit) (*Erc1155JoinSplitResponseAPI, []string, error) {
	witnessFull, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}

	proof, err := groth16.Prove(compiled.R1CS, compiled.PK, witnessFull)
	if err != nil {
		return nil, nil, err
	}

	p := proof.(*groth16_bn254.Proof)

	A_x1 := new(big.Int)
	p.Ar.X.BigInt(A_x1)
	A_y1 := new(big.Int)
	p.Ar.Y.BigInt(A_y1)
	C_x1 := new(big.Int)
	p.Krs.X.BigInt(C_x1)
	C_y1 := new(big.Int)
	p.Krs.Y.BigInt(C_y1)
	BX01 := new(big.Int)
	p.Bs.X.A0.BigInt(BX01)
	BX11 := new(big.Int)
	p.Bs.X.A1.BigInt(BX11)
	BY01 := new(big.Int)
	p.Bs.Y.A0.BigInt(BY01)
	BY11 := new(big.Int)
	p.Bs.Y.A1.BigInt(BY11)

	response := &Erc1155JoinSplitResponseAPI{
		Pi_A: []string{
			A_x1.String(),
			A_y1.String(),
		},
		Pi_B: [][]string{
			{BX11.String(), BX01.String()},
			{BY11.String(), BY01.String()},
		},
		Pi_C: []string{
			C_x1.String(),
			C_y1.String(),
		},
	}

	return response, nil, nil
}

// Helper function to detect constraint errors
func containsConstraintError(errStr string) bool {
	return strings.Contains(errStr, "constraint") && strings.Contains(errStr, "is not satisfied")
}

func parseBigIntOptimized(s string) frontend.Variable {
	bi := bigIntPool.Get()
	defer bigIntPool.Put(bi)

	if _, ok := bi.SetString(s, 10); !ok {
		panic(fmt.Sprintf("Invalid big int: %s", s))
	}

	return frontend.Variable(bi.String())
}

func computeErc1155UniqueId(contractAddress, tokenId, value string) string {
	return primitives.ComputeErc1155UniqueIdBN254(contractAddress, tokenId, value)
}

// Compute nullifier and commitments using primitives functions
func computeNullifier(privateKey, pathIndex string) string {
	return primitives.ComputeNullifierBN254(privateKey, pathIndex)
}

func computeOutputCommitment(uniqueId, recipientPK string) string {
	return primitives.ComputeOutputCommitmentBN254(uniqueId, recipientPK)
}

// Helper function to convert hex address to big integer string
func convertAddressToBigInt(address string) string {
	bigInt := primitives.ConvertAddressToBigInt(address)
	return bigInt.String()
}
