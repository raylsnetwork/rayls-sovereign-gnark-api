package erc721_ownership

import (
	primitives "github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
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
	erc721CircuitCache     *CompiledCircuit
	erc721CircuitCacheOnce sync.Once
	bigIntPool             = NewBigIntPool()
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

// Circuit loading function for Erc721 ownership
func getOrLoadErc721Circuit(pkPath, r1csPath string) *CompiledCircuit {
	erc721CircuitCacheOnce.Do(func() {
		fmt.Println("Loading pre-compiled Erc721 ownership circuit...")
		start := time.Now()

		r1cs, err := loadConstraintSystem(r1csPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load Erc721 constraint system: %v", err))
		}

		pk, err := primitives.LoadProvingKey(ecc.BN254, pkPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load Erc721 proving key: %v", err))
		}

		erc721CircuitCache = &CompiledCircuit{
			R1CS: r1cs,
			PK:   pk,
		}

		fmt.Printf("✓ Erc721 Circuit loaded and cached in %v\n", time.Since(start))
	})
	return erc721CircuitCache
}

// Handler function for Erc721 ownership
func NewHandler(pkPath, vkPath, r1csPath string) gin.HandlerFunc {
	// Pre-load the circuit
	compiled := getOrLoadErc721Circuit(pkPath, r1csPath)

	return func(c *gin.Context) {
		totalStart := time.Now()

		var request Erc721OwnershipRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		bindTime := time.Since(totalStart)

		if err := validateErc721Inputs(&request); err != nil {
			fmt.Printf("Input validation failed: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Input validation failed: " + err.Error(),
			})
			return
		}

		var witness Erc721OwnershipCircuit
		setErc721WitnessOptimized(&witness, &request)
		parseTime := time.Since(totalStart)

		response, err := generateErc721Proof(&witness, compiled, &request)
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

		fmt.Printf("Erc721 Ownership Timing: Bind=%v, Parse=%v, Prove=%v, Total=%v\n",
			bindTime, parseTime-bindTime, proveTime-parseTime, proveTime)

		c.JSON(http.StatusOK, response)
	}
}

// Input validation for Erc721 ownership
func validateErc721Inputs(request *Erc721OwnershipRequest) error {
	// Validate that we have the right number of outputs

	if nInputs != mOutputs {
		return fmt.Errorf("expected %d output public keys, got %d", mOutputs, nInputs)
	}

	return nil
}

// Set witness for Erc721 circuit
func setErc721WitnessOptimized(witness *Erc721OwnershipCircuit, request *Erc721OwnershipRequest) {
	witness.PaymentCommitment = parseBigIntOptimized(request.PaymentCommitment)

	// Fill actual inputs
	actualInputs := len(request.UId)
	for i := 0; i < actualInputs && i < nInputs; i++ {
		witness.UIdIn[i] = parseBigIntOptimized(request.UId)
		witness.PrivateKeys[i] = parseBigIntOptimized(request.KeyPairsIn.PrivateKey)
		witness.SaltsIn[i] = parseBigIntOptimized(request.SaltIn)
		witness.PathIndices[i] = parseBigIntOptimized(request.MerkleProofs.Indices)
		witness.MerkleRoot = parseBigIntOptimized(request.MerkleRoot)
		witness.TreeNumber = frontend.Variable(request.TreeNumber)

		// 3. Compute Nullifier
		nullifier := computeNullifier(request.KeyPairsIn.PrivateKey, request.MerkleProofs.Indices)
		fmt.Printf("  Computed Nullifier: %s\n", nullifier)
		witness.Nullifiers[i] = parseBigIntOptimized(nullifier)

		// Set path elements
		for j := 0; j < len(request.MerkleProofs.Elements) && j < merkleTreeDepth; j++ {
			witness.PathElements[i][j] = parseBigIntOptimized(request.MerkleProofs.Elements[j])
		}
		// Fill remaining path elements with zeros
		for j := len(request.MerkleProofs.Elements); j < merkleTreeDepth; j++ {
			witness.PathElements[i][j] = frontend.Variable("0")
		}
	}

	// Set outputs
	for i := 0; i < mOutputs; i++ {
		witness.UIdOut[i] = parseBigIntOptimized(request.UId)
		witness.RecipientPK[i] = parseBigIntOptimized(request.PubKeysOut.PublicKey)
		witness.SaltsOut[i] = parseBigIntOptimized(request.SaltOut)

		// Generate V2 output commitment: H(H(recipientPK, salt), uId)
		outputCommitment := primitives.ComputeCommitmentV2ERC721BN254(
			request.PubKeysOut.PublicKey, request.SaltOut, request.UId,
		)
		witness.CommitmentsOut[i] = parseBigIntOptimized(outputCommitment)
	}

	// Set revert commitment witness
	witness.RevertSalt = parseBigIntOptimized(request.RevertSalt)

	// Derive sender's public key from private key
	senderPK := primitives.DerivePublicKeyBN254(request.KeyPairsIn.PrivateKey)

	// Revert commitment uses the same UId as input
	revertCommitment := primitives.ComputeCommitmentV2ERC721BN254(
		senderPK, request.RevertSalt, request.UId,
	)
	witness.RevertCommitment = parseBigIntOptimized(revertCommitment)
}

// Generate proof for Erc721 circuit
func generateErc721Proof(witness frontend.Circuit, compiled *CompiledCircuit, request *Erc721OwnershipRequest) (*Erc721OwnershipResponseAPI, error) {
	response, _, err := generateProofGeneric(witness, compiled)
	if err != nil {
		return nil, err
	}

	erc721Response := &Erc721OwnershipResponseAPI{
		Pi_A:          response.Pi_A,
		Pi_B:          response.Pi_B,
		Pi_C:          response.Pi_C,
		Public_Signal: generateErc721PublicSignal(request),
	}

	return erc721Response, nil
}

// Generate public signals for Erc721 circuit
func generateErc721PublicSignal(request *Erc721OwnershipRequest) []string {
	// Public signals: paymentCommitment + merkleRoots + nullifiers + treeNumber + commitmentsOut
	publicSignal := make([]string, 0, 1+nInputs+nInputs+nInputs+mOutputs)

	// Payment commitment
	publicSignal = append(publicSignal, request.PaymentCommitment)

	publicSignal = append(publicSignal, request.MerkleRoot)

	nullifier := computeNullifier(request.KeyPairsIn.PrivateKey, request.MerkleProofs.Indices)
	publicSignal = append(publicSignal, nullifier)

	publicSignal = append(publicSignal, strconv.Itoa(request.TreeNumber))

	// Output commitments (V2)
	for i := 0; i < mOutputs; i++ {
		outputCommitment := primitives.ComputeCommitmentV2ERC721BN254(
			request.PubKeysOut.PublicKey, request.SaltOut, request.UId,
		)
		publicSignal = append(publicSignal, outputCommitment)
	}

	// Revert commitment — derive sender PK from private key
	senderPKSignal := primitives.DerivePublicKeyBN254(request.KeyPairsIn.PrivateKey)
	revertCommitment := primitives.ComputeCommitmentV2ERC721BN254(
		senderPKSignal, request.RevertSalt, request.UId,
	)
	publicSignal = append(publicSignal, revertCommitment)

	return publicSignal
}

// Generic proof generation function
func generateProofGeneric(witness frontend.Circuit, compiled *CompiledCircuit) (*Erc721OwnershipResponseAPI, []string, error) {
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

	response := &Erc721OwnershipResponseAPI{
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

// Compute nullifier and commitments using primitives functions
func computeNullifier(privateKey, pathIndex string) string {
	return primitives.ComputeNullifierBN254(privateKey, pathIndex)
}

func computeOutputCommitmentUId(Uid, recipientPK string) string {
	return primitives.ComputeOutputCommitmentBN254Uid(Uid, recipientPK)
}
