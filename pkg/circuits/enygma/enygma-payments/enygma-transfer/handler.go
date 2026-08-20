package enygma

import (
	primitives "github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/gin-gonic/gin"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

var (
	circuitCacheK2     *CompiledCircuit
	circuitCacheK3     *CompiledCircuit
	circuitCacheK4     *CompiledCircuit
	circuitCacheK5     *CompiledCircuit
	circuitCacheK6     *CompiledCircuit
	circuitCacheK2Once sync.Once
	circuitCacheK3Once sync.Once
	circuitCacheK4Once sync.Once
	circuitCacheK5Once sync.Once
	circuitCacheK6Once sync.Once
	bigIntPool         = NewBigIntPool()
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

	// "cs implements io.ReaderFrom"
	_, err = cs.ReadFrom(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read constraint system: %v", err)
	}

	return cs, nil
}

// Generic validation function that works for any k value
func validateInputsGeneric(anonymity_set []string, senderID string, previousV string, previousR string, previousCommit [][]string) error {
	// Find sender index
	senderIndex := -1
	for i, kIdx := range anonymity_set {
		if kIdx == senderID {
			senderIndex = i
			break
		}
	}

	if senderIndex == -1 {
		return fmt.Errorf("sender_id %s not found in anonymity_set", senderID)
	}

	// Compute expected previous commitment
	expectedCommit, err := computePedersenCommitment(previousV, previousR)
	if err != nil {
		return fmt.Errorf("failed to compute expected Pedersen commitment: %v", err)
	}

	// Check if provided previous_commit matches expected
	providedCommit := previousCommit[senderIndex]
	if providedCommit[0] != expectedCommit.X || providedCommit[1] != expectedCommit.Y {
		return fmt.Errorf("previous_commits[%d] validation failed: expected PedersenCommitment(%s, %s) = [%s, %s], but got [%s, %s]. Outdated/wrong submitted balance or r",
			senderIndex, previousV, previousR,
			expectedCommit.X, expectedCommit.Y,
			providedCommit[0], providedCommit[1])
	}

	return nil
}

// Helper function to convert 2D array to 2D slice
func convertCommitArray(arr [][2]string) [][]string {
	result := make([][]string, len(arr))
	for i := range arr {
		result[i] = arr[i][:]
	}
	return result
}

// Validation functions
func validateInputsK2(request *Enygmak2Request) error {
	return validateInputsGeneric(request.AnonymitySet[:], request.SenderID, request.PreviousSenderBalance, request.PreviousSenderRandomValue, convertCommitArray(request.PreviousCommits[:]))
}

func validateInputsK3(request *Enygmak3Request) error {
	return validateInputsGeneric(request.AnonymitySet[:], request.SenderID, request.PreviousSenderBalance, request.PreviousSenderRandomValue, convertCommitArray(request.PreviousCommits[:]))
}

func validateInputsK4(request *Enygmak4Request) error {
	return validateInputsGeneric(request.AnonymitySet[:], request.SenderID, request.PreviousSenderBalance, request.PreviousSenderRandomValue, convertCommitArray(request.PreviousCommits[:]))
}

func validateInputsK5(request *Enygmak5Request) error {
	return validateInputsGeneric(request.AnonymitySet[:], request.SenderID, request.PreviousSenderBalance, request.PreviousSenderRandomValue, convertCommitArray(request.PreviousCommits[:]))
}

func validateInputsK6(request *Enygmak6Request) error {
	return validateInputsGeneric(request.AnonymitySet[:], request.SenderID, request.PreviousSenderBalance, request.PreviousSenderRandomValue, convertCommitArray(request.PreviousCommits[:]))
}

type PedersenPoint struct {
	X string
	Y string
}

func computePedersenCommitment(value, randomness string) (*PedersenPoint, error) {
	// Convert strings to big.Int
	valueBig := new(big.Int)
	randomnessBig := new(big.Int)

	if _, ok := valueBig.SetString(value, 10); !ok {
		return nil, fmt.Errorf("invalid value: %s", value)
	}

	if _, ok := randomnessBig.SetString(randomness, 10); !ok {
		return nil, fmt.Errorf("invalid randomness: %s", randomness)
	}

	// Use the same G and H points as the circuit
	// G point from circuit
	G := primitives.GBabyJub

	// H point from circuit
	H := primitives.HBabyJub

	// Compute vG = value * G
	vG := babyjub.NewPoint().Mul(valueBig, G)

	// Compute rH = randomness * H
	rH := babyjub.NewPoint().Mul(randomnessBig, H)

	// Compute commitment = vG + rH
	commitment := babyjub.NewPoint().Projective().Add(vG.Projective(), rH.Projective()).Affine()

	return &PedersenPoint{
		X: commitment.X.String(),
		Y: commitment.Y.String(),
	}, nil
}

// Circuit loading functions for each k value
func getOrLoadCircuitK2(pkPath, r1csPath string) *CompiledCircuit {
	circuitCacheK2Once.Do(func() {
		fmt.Println("Loading pre-compiled circuit for k=2...")
		start := time.Now()

		r1cs, err := loadConstraintSystem(r1csPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load K=2 constraint system: %v", err))
		}

		pk, err := primitives.LoadProvingKey(ecc.BN254, pkPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load K=2 proving key: %v", err))
		}

		circuitCacheK2 = &CompiledCircuit{
			R1CS: r1cs,
			PK:   pk,
		}

		fmt.Printf("✓ Circuit K=2 loaded and cached in %v\n", time.Since(start))
	})
	return circuitCacheK2
}

func getOrLoadCircuitK3(pkPath, r1csPath string) *CompiledCircuit {
	circuitCacheK3Once.Do(func() {
		fmt.Println("Loading pre-compiled circuit for k=3...")
		start := time.Now()

		r1cs, err := loadConstraintSystem(r1csPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load K=3 constraint system: %v", err))
		}

		pk, err := primitives.LoadProvingKey(ecc.BN254, pkPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load K=3 proving key: %v", err))
		}

		circuitCacheK3 = &CompiledCircuit{
			R1CS: r1cs,
			PK:   pk,
		}

		fmt.Printf("✓ Circuit K=3 loaded and cached in %v\n", time.Since(start))
	})
	return circuitCacheK3
}

func getOrLoadCircuitK4(pkPath, r1csPath string) *CompiledCircuit {
	circuitCacheK4Once.Do(func() {
		fmt.Println("Loading pre-compiled circuit for k=4...")
		start := time.Now()

		r1cs, err := loadConstraintSystem(r1csPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load K=4 constraint system: %v", err))
		}

		pk, err := primitives.LoadProvingKey(ecc.BN254, pkPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load K=4 proving key: %v", err))
		}

		circuitCacheK4 = &CompiledCircuit{
			R1CS: r1cs,
			PK:   pk,
		}

		fmt.Printf("✓ Circuit K=4 loaded and cached in %v\n", time.Since(start))
	})
	return circuitCacheK4
}

func getOrLoadCircuitK5(pkPath, r1csPath string) *CompiledCircuit {
	circuitCacheK5Once.Do(func() {
		fmt.Println("Loading pre-compiled circuit for k=5...")
		start := time.Now()

		r1cs, err := loadConstraintSystem(r1csPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load K=5 constraint system: %v", err))
		}

		pk, err := primitives.LoadProvingKey(ecc.BN254, pkPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load K=5 proving key: %v", err))
		}

		circuitCacheK5 = &CompiledCircuit{
			R1CS: r1cs,
			PK:   pk,
		}

		fmt.Printf("✓ Circuit K=5 loaded and cached in %v\n", time.Since(start))
	})
	return circuitCacheK5
}

func getOrLoadCircuitK6(pkPath, r1csPath string) *CompiledCircuit {
	circuitCacheK6Once.Do(func() {
		fmt.Println("Loading pre-compiled circuit for k=6...")
		start := time.Now()

		r1cs, err := loadConstraintSystem(r1csPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load K=6 constraint system: %v", err))
		}

		pk, err := primitives.LoadProvingKey(ecc.BN254, pkPath)
		if err != nil {
			panic(fmt.Sprintf("Failed to load K=6 proving key: %v", err))
		}

		circuitCacheK6 = &CompiledCircuit{
			R1CS: r1cs,
			PK:   pk,
		}

		fmt.Printf("✓ Circuit K=6 loaded and cached in %v\n", time.Since(start))
	})
	return circuitCacheK6
}

// Updated handler function to accept r1cs path
func NewHandler(k int, pkPath, vkPath, r1csPath string) gin.HandlerFunc {
	// Pre-load the circuit for this k value
	var compiled *CompiledCircuit
	switch k {
	case 2:
		compiled = getOrLoadCircuitK2(pkPath, r1csPath)
	case 3:
		compiled = getOrLoadCircuitK3(pkPath, r1csPath)
	case 4:
		compiled = getOrLoadCircuitK4(pkPath, r1csPath)
	case 5:
		compiled = getOrLoadCircuitK5(pkPath, r1csPath)
	case 6:
		compiled = getOrLoadCircuitK6(pkPath, r1csPath)
	default:
		panic(fmt.Sprintf("Unsupported k value: %d", k))
	}

	return func(c *gin.Context) {
		totalStart := time.Now()

		switch k {
		case 2:
			handleK2(c, compiled, totalStart)
		case 3:
			handleK3(c, compiled, totalStart)
		case 4:
			handleK4(c, compiled, totalStart)
		case 5:
			handleK5(c, compiled, totalStart)
		case 6:
			handleK6(c, compiled, totalStart)
		}
	}
}

func handleK2(c *gin.Context, compiled *CompiledCircuit, totalStart time.Time) {
	var request Enygmak2Request
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	bindTime := time.Since(totalStart)

	if err := validateInputsK2(&request); err != nil {
		fmt.Printf("Input validation failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Input validation failed: " + err.Error(),
		})
		return
	}

	var witness Enygmak2Circuit
	setWitness2Optimized(&witness, &request)
	parseTime := time.Since(totalStart)

	response, err := generateProofK2(&witness, compiled, &request)
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
	serializeTime := time.Since(totalStart)

	fmt.Printf("K=2 Timing: Bind=%v, Parse=%v, Prove=%v, Serialize=%v, Total=%v\n",
		bindTime, parseTime-bindTime, proveTime-parseTime, serializeTime-proveTime, serializeTime)

	c.JSON(http.StatusOK, response)
}

func handleK3(c *gin.Context, compiled *CompiledCircuit, totalStart time.Time) {
	var request Enygmak3Request
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	bindTime := time.Since(totalStart)

	if err := validateInputsK3(&request); err != nil {
		fmt.Printf("Input validation failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Input validation failed: " + err.Error(),
		})
		return
	}

	var witness Enygmak3Circuit
	setWitness3Optimized(&witness, &request)
	parseTime := time.Since(totalStart)

	response, err := generateProofK3(&witness, compiled, &request)
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
	serializeTime := time.Since(totalStart)

	fmt.Printf("K=3 Timing: Bind=%v, Parse=%v, Prove=%v, Serialize=%v, Total=%v\n",
		bindTime, parseTime-bindTime, proveTime-parseTime, serializeTime-proveTime, serializeTime)

	c.JSON(http.StatusOK, response)
}

func handleK4(c *gin.Context, compiled *CompiledCircuit, totalStart time.Time) {
	var request Enygmak4Request
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	bindTime := time.Since(totalStart)

	if err := validateInputsK4(&request); err != nil {
		fmt.Printf("Input validation failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Input validation failed: " + err.Error(),
		})
		return
	}

	var witness Enygmak4Circuit
	setWitness4Optimized(&witness, &request)
	parseTime := time.Since(totalStart)

	response, err := generateProofK4(&witness, compiled, &request)
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
	serializeTime := time.Since(totalStart)

	fmt.Printf("K=4 Timing: Bind=%v, Parse=%v, Prove=%v, Serialize=%v, Total=%v\n",
		bindTime, parseTime-bindTime, proveTime-parseTime, serializeTime-proveTime, serializeTime)

	c.JSON(http.StatusOK, response)
}

func handleK5(c *gin.Context, compiled *CompiledCircuit, totalStart time.Time) {
	var request Enygmak5Request
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	bindTime := time.Since(totalStart)

	if err := validateInputsK5(&request); err != nil {
		fmt.Printf("Input validation failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Input validation failed: " + err.Error(),
		})
		return
	}

	var witness Enygmak5Circuit
	setWitness5Optimized(&witness, &request)
	parseTime := time.Since(totalStart)

	response, err := generateProofK5(&witness, compiled, &request)
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
	serializeTime := time.Since(totalStart)

	fmt.Printf("K=5 Timing: Bind=%v, Parse=%v, Prove=%v, Serialize=%v, Total=%v\n",
		bindTime, parseTime-bindTime, proveTime-parseTime, serializeTime-proveTime, serializeTime)

	c.JSON(http.StatusOK, response)
}

func handleK6(c *gin.Context, compiled *CompiledCircuit, totalStart time.Time) {
	var request Enygmak6Request
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	bindTime := time.Since(totalStart)

	if err := validateInputsK6(&request); err != nil {
		fmt.Printf("Input validation failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Input validation failed: " + err.Error(),
		})
		return
	}

	var witness Enygmak6Circuit
	setWitness6Optimized(&witness, &request)
	parseTime := time.Since(totalStart)

	response, err := generateProofK6(&witness, compiled, &request)
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
	serializeTime := time.Since(totalStart)

	fmt.Printf("K=6 Timing: Bind=%v, Parse=%v, Prove=%v, Serialize=%v, Total=%v\n",
		bindTime, parseTime-bindTime, proveTime-parseTime, serializeTime-proveTime, serializeTime)

	c.JSON(http.StatusOK, response)
}

// Helper function to detect constraint errors
func containsConstraintError(errStr string) bool {
	return strings.Contains(errStr, "constraint") && strings.Contains(errStr, "is not satisfied")
}

// Generic proof generation function
func generateProofGeneric(witness frontend.Circuit, compiled *CompiledCircuit) (*EnygmaResponseAPI, []string, error) {
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

	response := &EnygmaResponseAPI{
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

func generateProofK2(witness frontend.Circuit, compiled *CompiledCircuit, request *Enygmak2Request) (*EnygmaResponseAPI, error) {
	response, _, err := generateProofGeneric(witness, compiled)
	if err != nil {
		return nil, err
	}
	response.Public_Signal = generatePublicSignal2Optimized(request)
	return response, nil
}

func generateProofK3(witness frontend.Circuit, compiled *CompiledCircuit, request *Enygmak3Request) (*EnygmaResponseAPI, error) {
	response, _, err := generateProofGeneric(witness, compiled)
	if err != nil {
		return nil, err
	}
	response.Public_Signal = generatePublicSignal3Optimized(request)
	return response, nil
}

func generateProofK4(witness frontend.Circuit, compiled *CompiledCircuit, request *Enygmak4Request) (*EnygmaResponseAPI, error) {
	response, _, err := generateProofGeneric(witness, compiled)
	if err != nil {
		return nil, err
	}
	response.Public_Signal = generatePublicSignal4Optimized(request)
	return response, nil
}

func generateProofK5(witness frontend.Circuit, compiled *CompiledCircuit, request *Enygmak5Request) (*EnygmaResponseAPI, error) {
	response, _, err := generateProofGeneric(witness, compiled)
	if err != nil {
		return nil, err
	}
	response.Public_Signal = generatePublicSignal5Optimized(request)
	return response, nil
}

func generateProofK6(witness frontend.Circuit, compiled *CompiledCircuit, request *Enygmak6Request) (*EnygmaResponseAPI, error) {
	response, _, err := generateProofGeneric(witness, compiled)
	if err != nil {
		return nil, err
	}
	response.Public_Signal = generatePublicSignal6Optimized(request)
	return response, nil
}

// Witness setting functions
func setWitness2Optimized(witness *Enygmak2Circuit, request *Enygmak2Request) {
	witness.SenderId = frontend.Variable(request.SenderID)
	witness.SenderTxValue = parseBigIntOptimized(request.SenderTxValue)
	witness.SecretKey = parseBigIntOptimized(request.SecretKey)
	witness.PreviousSenderBalance = parseBigIntOptimized(request.PreviousSenderBalance)
	witness.PreviousSenderRandomValue = parseBigIntOptimized(request.PreviousSenderRandomValue)
	witness.Nullifier = parseBigIntOptimized(request.Nullifier)
	witness.BlockNumber = frontend.Variable(request.BlockNumber)

	for i := 0; i < 2; i++ {
		witness.SharedSecrets[i] = parseBigIntOptimized(request.SharedSecrets[i])
		witness.HashedSharedSecrets[i] = parseBigIntOptimized(request.HashedSharedSecrets[i])
		witness.PublicKey[i] = parseBigIntOptimized(request.PublicKey[i])
		witness.PreviousCommits[i][0] = parseBigIntOptimized(request.PreviousCommits[i][0])
		witness.PreviousCommits[i][1] = parseBigIntOptimized(request.PreviousCommits[i][1])
		witness.TxCommits[i][0] = parseBigIntOptimized(request.TxCommits[i][0])
		witness.TxCommits[i][1] = parseBigIntOptimized(request.TxCommits[i][1])
		witness.TxValues[i] = parseBigIntOptimized(request.TxValues[i])
		witness.TxRandomValues[i] = parseBigIntOptimized(request.TxRandomValues[i])
		witness.AnonymitySet[i] = parseBigIntOptimized(request.AnonymitySet[i])
		witness.MessageTags[i] = parseBigIntOptimized(request.MessageTags[i])
	}
}

func setWitness3Optimized(witness *Enygmak3Circuit, request *Enygmak3Request) {
	witness.SenderId = frontend.Variable(request.SenderID)
	witness.SenderTxValue = parseBigIntOptimized(request.SenderTxValue)
	witness.SecretKey = parseBigIntOptimized(request.SecretKey)
	witness.PreviousSenderBalance = parseBigIntOptimized(request.PreviousSenderBalance)
	witness.PreviousSenderRandomValue = parseBigIntOptimized(request.PreviousSenderRandomValue)
	witness.Nullifier = parseBigIntOptimized(request.Nullifier)
	witness.BlockNumber = frontend.Variable(request.BlockNumber)

	for i := 0; i < 3; i++ {
		witness.SharedSecrets[i] = parseBigIntOptimized(request.SharedSecrets[i])
		witness.HashedSharedSecrets[i] = parseBigIntOptimized(request.HashedSharedSecrets[i])
		witness.PublicKey[i] = parseBigIntOptimized(request.PublicKey[i])
		witness.PreviousCommits[i][0] = parseBigIntOptimized(request.PreviousCommits[i][0])
		witness.PreviousCommits[i][1] = parseBigIntOptimized(request.PreviousCommits[i][1])
		witness.TxCommits[i][0] = parseBigIntOptimized(request.TxCommits[i][0])
		witness.TxCommits[i][1] = parseBigIntOptimized(request.TxCommits[i][1])
		witness.TxValues[i] = parseBigIntOptimized(request.TxValues[i])
		witness.TxRandomValues[i] = parseBigIntOptimized(request.TxRandomValues[i])
		witness.AnonymitySet[i] = parseBigIntOptimized(request.AnonymitySet[i])
		witness.MessageTags[i] = parseBigIntOptimized(request.MessageTags[i])
	}
}

func setWitness4Optimized(witness *Enygmak4Circuit, request *Enygmak4Request) {
	witness.SenderId = frontend.Variable(request.SenderID)
	witness.SenderTxValue = parseBigIntOptimized(request.SenderTxValue)
	witness.SecretKey = parseBigIntOptimized(request.SecretKey)
	witness.PreviousSenderBalance = parseBigIntOptimized(request.PreviousSenderBalance)
	witness.PreviousSenderRandomValue = parseBigIntOptimized(request.PreviousSenderRandomValue)
	witness.Nullifier = parseBigIntOptimized(request.Nullifier)
	witness.BlockNumber = frontend.Variable(request.BlockNumber)

	for i := 0; i < 4; i++ {
		witness.SharedSecrets[i] = parseBigIntOptimized(request.SharedSecrets[i])
		witness.HashedSharedSecrets[i] = parseBigIntOptimized(request.HashedSharedSecrets[i])
		witness.PublicKey[i] = parseBigIntOptimized(request.PublicKey[i])
		witness.PreviousCommits[i][0] = parseBigIntOptimized(request.PreviousCommits[i][0])
		witness.PreviousCommits[i][1] = parseBigIntOptimized(request.PreviousCommits[i][1])
		witness.TxCommits[i][0] = parseBigIntOptimized(request.TxCommits[i][0])
		witness.TxCommits[i][1] = parseBigIntOptimized(request.TxCommits[i][1])
		witness.TxValues[i] = parseBigIntOptimized(request.TxValues[i])
		witness.TxRandomValues[i] = parseBigIntOptimized(request.TxRandomValues[i])
		witness.AnonymitySet[i] = parseBigIntOptimized(request.AnonymitySet[i])
		witness.MessageTags[i] = parseBigIntOptimized(request.MessageTags[i])
	}
}

func setWitness5Optimized(witness *Enygmak5Circuit, request *Enygmak5Request) {
	witness.SenderId = frontend.Variable(request.SenderID)
	witness.SenderTxValue = parseBigIntOptimized(request.SenderTxValue)
	witness.SecretKey = parseBigIntOptimized(request.SecretKey)
	witness.PreviousSenderBalance = parseBigIntOptimized(request.PreviousSenderBalance)
	witness.PreviousSenderRandomValue = parseBigIntOptimized(request.PreviousSenderRandomValue)
	witness.Nullifier = parseBigIntOptimized(request.Nullifier)
	witness.BlockNumber = frontend.Variable(request.BlockNumber)

	for i := 0; i < 5; i++ {
		witness.SharedSecrets[i] = parseBigIntOptimized(request.SharedSecrets[i])
		witness.HashedSharedSecrets[i] = parseBigIntOptimized(request.HashedSharedSecrets[i])
		witness.PublicKey[i] = parseBigIntOptimized(request.PublicKey[i])
		witness.PreviousCommits[i][0] = parseBigIntOptimized(request.PreviousCommits[i][0])
		witness.PreviousCommits[i][1] = parseBigIntOptimized(request.PreviousCommits[i][1])
		witness.TxCommits[i][0] = parseBigIntOptimized(request.TxCommits[i][0])
		witness.TxCommits[i][1] = parseBigIntOptimized(request.TxCommits[i][1])
		witness.TxValues[i] = parseBigIntOptimized(request.TxValues[i])
		witness.TxRandomValues[i] = parseBigIntOptimized(request.TxRandomValues[i])
		witness.AnonymitySet[i] = parseBigIntOptimized(request.AnonymitySet[i])
		witness.MessageTags[i] = parseBigIntOptimized(request.MessageTags[i])
	}
}

func setWitness6Optimized(witness *Enygmak6Circuit, request *Enygmak6Request) {
	witness.SenderId = frontend.Variable(request.SenderID)
	witness.SenderTxValue = parseBigIntOptimized(request.SenderTxValue)
	witness.SecretKey = parseBigIntOptimized(request.SecretKey)
	witness.PreviousSenderBalance = parseBigIntOptimized(request.PreviousSenderBalance)
	witness.PreviousSenderRandomValue = parseBigIntOptimized(request.PreviousSenderRandomValue)
	witness.Nullifier = parseBigIntOptimized(request.Nullifier)
	witness.BlockNumber = frontend.Variable(request.BlockNumber)

	for i := 0; i < 6; i++ {
		witness.SharedSecrets[i] = parseBigIntOptimized(request.SharedSecrets[i])
		witness.HashedSharedSecrets[i] = parseBigIntOptimized(request.HashedSharedSecrets[i])
		witness.PublicKey[i] = parseBigIntOptimized(request.PublicKey[i])
		witness.PreviousCommits[i][0] = parseBigIntOptimized(request.PreviousCommits[i][0])
		witness.PreviousCommits[i][1] = parseBigIntOptimized(request.PreviousCommits[i][1])
		witness.TxCommits[i][0] = parseBigIntOptimized(request.TxCommits[i][0])
		witness.TxCommits[i][1] = parseBigIntOptimized(request.TxCommits[i][1])
		witness.TxValues[i] = parseBigIntOptimized(request.TxValues[i])
		witness.TxRandomValues[i] = parseBigIntOptimized(request.TxRandomValues[i])
		witness.AnonymitySet[i] = parseBigIntOptimized(request.AnonymitySet[i])
		witness.MessageTags[i] = parseBigIntOptimized(request.MessageTags[i])
	}
}

func parseBigIntOptimized(s string) frontend.Variable {
	bi := bigIntPool.Get()
	defer bigIntPool.Put(bi)

	if _, ok := bi.SetString(s, 10); !ok {
		panic(fmt.Sprintf("Invalid big int: %s", s))
	}

	return frontend.Variable(bi.String())
}

// Public signal generation functions
func generatePublicSignal2Optimized(request *Enygmak2Request) []string {
	publicSignal := make([]string, 0, 18)

	// HashedSharedSecrets (2 values)
	for i := 0; i < 2; i++ {
		publicSignal = append(publicSignal, request.HashedSharedSecrets[i])
	}

	// PublicKey (2 values)
	for i := 0; i < 2; i++ {
		publicSignal = append(publicSignal, request.PublicKey[i])
	}

	// PreviousCommits (2x2 = 4 values)
	for i := 0; i < 2; i++ {
		publicSignal = append(publicSignal, request.PreviousCommits[i][0])
		publicSignal = append(publicSignal, request.PreviousCommits[i][1])
	}

	// TxCommits (2x2 = 4 values)
	for i := 0; i < 2; i++ {
		publicSignal = append(publicSignal, request.TxCommits[i][0])
		publicSignal = append(publicSignal, request.TxCommits[i][1])
	}

	publicSignal = append(publicSignal, request.Nullifier)
	publicSignal = append(publicSignal, request.BlockNumber)

	// AnonymitySet (2 values)
	for i := 0; i < 2; i++ {
		publicSignal = append(publicSignal, request.AnonymitySet[i])
	}

	// MessageTags (2 values)
	for i := 0; i < 2; i++ {
		publicSignal = append(publicSignal, request.MessageTags[i])
	}

	return publicSignal
}

func generatePublicSignal3Optimized(request *Enygmak3Request) []string {
	publicSignal := make([]string, 0, 26)

	// HashedSharedSecrets (3 values)
	for i := 0; i < 3; i++ {
		publicSignal = append(publicSignal, request.HashedSharedSecrets[i])
	}

	// PublicKey (3 values)
	for i := 0; i < 3; i++ {
		publicSignal = append(publicSignal, request.PublicKey[i])
	}

	// PreviousCommits (3x2 = 6 values)
	for i := 0; i < 3; i++ {
		publicSignal = append(publicSignal, request.PreviousCommits[i][0])
		publicSignal = append(publicSignal, request.PreviousCommits[i][1])
	}

	// TxCommits (3x2 = 6 values)
	for i := 0; i < 3; i++ {
		publicSignal = append(publicSignal, request.TxCommits[i][0])
		publicSignal = append(publicSignal, request.TxCommits[i][1])
	}

	publicSignal = append(publicSignal, request.Nullifier)
	publicSignal = append(publicSignal, request.BlockNumber)

	// AnonymitySet (3 values)
	for i := 0; i < 3; i++ {
		publicSignal = append(publicSignal, request.AnonymitySet[i])
	}

	// MessageTags (3 values)
	for i := 0; i < 3; i++ {
		publicSignal = append(publicSignal, request.MessageTags[i])
	}

	return publicSignal
}

func generatePublicSignal4Optimized(request *Enygmak4Request) []string {
	publicSignal := make([]string, 0, 34)

	// HashedSharedSecrets (4 values)
	for i := 0; i < 4; i++ {
		publicSignal = append(publicSignal, request.HashedSharedSecrets[i])
	}

	// PublicKey (4 values)
	for i := 0; i < 4; i++ {
		publicSignal = append(publicSignal, request.PublicKey[i])
	}

	// PreviousCommits (4x2 = 8 values)
	for i := 0; i < 4; i++ {
		publicSignal = append(publicSignal, request.PreviousCommits[i][0])
		publicSignal = append(publicSignal, request.PreviousCommits[i][1])
	}

	// TxCommits (4x2 = 8 values)
	for i := 0; i < 4; i++ {
		publicSignal = append(publicSignal, request.TxCommits[i][0])
		publicSignal = append(publicSignal, request.TxCommits[i][1])
	}

	publicSignal = append(publicSignal, request.Nullifier)
	publicSignal = append(publicSignal, request.BlockNumber)

	// AnonymitySet (4 values)
	for i := 0; i < 4; i++ {
		publicSignal = append(publicSignal, request.AnonymitySet[i])
	}

	// MessageTags (4 values)
	for i := 0; i < 4; i++ {
		publicSignal = append(publicSignal, request.MessageTags[i])
	}

	return publicSignal
}

func generatePublicSignal5Optimized(request *Enygmak5Request) []string {
	publicSignal := make([]string, 0, 42)

	// HashedSharedSecrets (5 values)
	for i := 0; i < 5; i++ {
		publicSignal = append(publicSignal, request.HashedSharedSecrets[i])
	}

	// PublicKey (5 values)
	for i := 0; i < 5; i++ {
		publicSignal = append(publicSignal, request.PublicKey[i])
	}

	// PreviousCommits (5x2 = 10 values)
	for i := 0; i < 5; i++ {
		publicSignal = append(publicSignal, request.PreviousCommits[i][0])
		publicSignal = append(publicSignal, request.PreviousCommits[i][1])
	}

	// TxCommits (5x2 = 10 values)
	for i := 0; i < 5; i++ {
		publicSignal = append(publicSignal, request.TxCommits[i][0])
		publicSignal = append(publicSignal, request.TxCommits[i][1])
	}

	publicSignal = append(publicSignal, request.Nullifier)
	publicSignal = append(publicSignal, request.BlockNumber)

	// AnonymitySet (5 values)
	for i := 0; i < 5; i++ {
		publicSignal = append(publicSignal, request.AnonymitySet[i])
	}

	// MessageTags (5 values)
	for i := 0; i < 5; i++ {
		publicSignal = append(publicSignal, request.MessageTags[i])
	}

	return publicSignal
}

func generatePublicSignal6Optimized(request *Enygmak6Request) []string {
	publicSignal := make([]string, 0, 50)

	// HashedSharedSecrets (6 values)
	for i := 0; i < 6; i++ {
		publicSignal = append(publicSignal, request.HashedSharedSecrets[i])
	}

	// PublicKey (6 values)
	for i := 0; i < 6; i++ {
		publicSignal = append(publicSignal, request.PublicKey[i])
	}

	// PreviousCommits (6x2 = 12 values)
	for i := 0; i < 6; i++ {
		publicSignal = append(publicSignal, request.PreviousCommits[i][0])
		publicSignal = append(publicSignal, request.PreviousCommits[i][1])
	}

	// TxCommits (6x2 = 12 values)
	for i := 0; i < 6; i++ {
		publicSignal = append(publicSignal, request.TxCommits[i][0])
		publicSignal = append(publicSignal, request.TxCommits[i][1])
	}

	publicSignal = append(publicSignal, request.Nullifier)
	publicSignal = append(publicSignal, request.BlockNumber)

	// AnonymitySet (6 values)
	for i := 0; i < 6; i++ {
		publicSignal = append(publicSignal, request.AnonymitySet[i])
	}

	// MessageTags (6 values)
	for i := 0; i < 6; i++ {
		publicSignal = append(publicSignal, request.MessageTags[i])
	}

	return publicSignal
}
