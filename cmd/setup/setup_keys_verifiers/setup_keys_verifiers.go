package main

import (
	enygma_joinsplit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/enygma-joinsplit-dvp"
	erc1155_joinsplit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/erc1155-joinsplit-dvp"
	erc721_ownership "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/erc721-ownership-dvp"
	deposit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-deposit"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-transfer"
	withdraw "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-withdraw"
	primitives "github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func cleanAndCreateDirectories() error {
	// Remove last_build completely if it exists
	if _, err := os.Stat("last_build"); err == nil {
		fmt.Println("🗑️  Removing existing last_build directory...")
		if err := os.RemoveAll("last_build"); err != nil {
			return fmt.Errorf("failed to remove last_build: %v", err)
		}
	}

	// Create directories
	dirs := []string{
		"last_build",
		filepath.Join("last_build", "keys"),
	}

	for _, dir := range dirs {
		fmt.Printf("📁 Creating directory: %s\n", dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	fmt.Println("✅ Directories setup complete!")
	return nil
}

func main() {

	// Clean and create directories first
	if err := cleanAndCreateDirectories(); err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		os.Exit(1)
	}

	// =========================
	// ENYGMA CIRCUITS
	// =========================

	// Generate keys for Enygma K=2 circuit
	log.Println("Generating keys for Enygma K=2 circuit...")
	var enygmaCircuit2 enygma.Enygmak2Circuit
	enygmaCcs2, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &enygmaCircuit2)
	if err != nil {
		log.Fatal("Failed to compile Enygma K=2 circuit:", err)
	}

	enygmaPk2, enygmaVk2, err := groth16.Setup(enygmaCcs2)
	if err != nil {
		log.Fatal("Failed to setup Enygma K=2 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, enygmaPk2, "./last_build/keys/Enygmak2Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, enygmaVk2, "./last_build/keys/Enygmak2Vk.key")
	log.Println("Enygma K=2 keys generated successfully!")

	// Generate Solidity verifier for Enygma K=2
	enygmaF2, err := os.Create("last_build/EnygmaVerifierk2.sol")
	if err != nil {
		log.Fatal("Failed to create Enygma K=2 verifier file:", err)
	}
	defer enygmaF2.Close()

	err = enygmaVk2.ExportSolidity(enygmaF2)
	if err != nil {
		log.Fatal("Failed to export Enygma K=2 Solidity verifier:", err)
	}
	log.Println("Enygma K=2 Solidity verifier generated successfully!")

	// Generate keys for Enygma K=3 circuit
	log.Println("Generating keys for Enygma K=3 circuit...")
	var enygmaCircuit3 enygma.Enygmak3Circuit
	enygmaCcs3, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &enygmaCircuit3)
	if err != nil {
		log.Fatal("Failed to compile Enygma K=3 circuit:", err)
	}

	enygmaPk3, enygmaVk3, err := groth16.Setup(enygmaCcs3)
	if err != nil {
		log.Fatal("Failed to setup Enygma K=3 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, enygmaPk3, "./last_build/keys/Enygmak3Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, enygmaVk3, "./last_build/keys/Enygmak3Vk.key")
	log.Println("Enygma K=3 keys generated successfully!")

	// Generate Solidity verifier for Enygma K=3
	enygmaF3, err := os.Create("last_build/EnygmaVerifierk3.sol")
	if err != nil {
		log.Fatal("Failed to create Enygma K=3 verifier file:", err)
	}
	defer enygmaF3.Close()

	err = enygmaVk3.ExportSolidity(enygmaF3)
	if err != nil {
		log.Fatal("Failed to export Enygma K=3 Solidity verifier:", err)
	}
	log.Println("Enygma K=3 Solidity verifier generated successfully!")

	// Generate keys for Enygma K=4 circuit
	log.Println("Generating keys for Enygma K=4 circuit...")
	var enygmaCircuit4 enygma.Enygmak4Circuit
	enygmaCcs4, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &enygmaCircuit4)
	if err != nil {
		log.Fatal("Failed to compile Enygma K=4 circuit:", err)
	}

	enygmaPk4, enygmaVk4, err := groth16.Setup(enygmaCcs4)
	if err != nil {
		log.Fatal("Failed to setup Enygma K=4 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, enygmaPk4, "./last_build/keys/Enygmak4Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, enygmaVk4, "./last_build/keys/Enygmak4Vk.key")
	log.Println("Enygma K=4 keys generated successfully!")

	// Generate Solidity verifier for Enygma K=4
	enygmaF4, err := os.Create("last_build/EnygmaVerifierk4.sol")
	if err != nil {
		log.Fatal("Failed to create Enygma K=4 verifier file:", err)
	}
	defer enygmaF4.Close()

	err = enygmaVk4.ExportSolidity(enygmaF4)
	if err != nil {
		log.Fatal("Failed to export Enygma K=4 Solidity verifier:", err)
	}
	log.Println("Enygma K=4 Solidity verifier generated successfully!")

	// Generate keys for Enygma K=5 circuit
	log.Println("Generating keys for Enygma K=5 circuit...")
	var enygmaCircuit5 enygma.Enygmak5Circuit
	enygmaCcs5, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &enygmaCircuit5)
	if err != nil {
		log.Fatal("Failed to compile Enygma K=5 circuit:", err)
	}

	enygmaPk5, enygmaVk5, err := groth16.Setup(enygmaCcs5)
	if err != nil {
		log.Fatal("Failed to setup Enygma K=5 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, enygmaPk5, "./last_build/keys/Enygmak5Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, enygmaVk5, "./last_build/keys/Enygmak5Vk.key")
	log.Println("Enygma K=5 keys generated successfully!")

	// Generate Solidity verifier for Enygma K=5
	enygmaF5, err := os.Create("last_build/EnygmaVerifierk5.sol")
	if err != nil {
		log.Fatal("Failed to create Enygma K=5 verifier file:", err)
	}
	defer enygmaF5.Close()

	err = enygmaVk5.ExportSolidity(enygmaF5)
	if err != nil {
		log.Fatal("Failed to export Enygma K=5 Solidity verifier:", err)
	}
	log.Println("Enygma K=5 Solidity verifier generated successfully!")

	// Generate keys for Enygma K=6 circuit
	log.Println("Generating keys for Enygma K=6 circuit...")
	var enygmaCircuit6 enygma.Enygmak6Circuit
	enygmaCcs6, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &enygmaCircuit6)
	if err != nil {
		log.Fatal("Failed to compile Enygma K=6 circuit:", err)
	}

	enygmaPk6, enygmaVk6, err := groth16.Setup(enygmaCcs6)
	if err != nil {
		log.Fatal("Failed to setup Enygma K=6 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, enygmaPk6, "./last_build/keys/Enygmak6Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, enygmaVk6, "./last_build/keys/Enygmak6Vk.key")
	log.Println("Enygma K=6 keys generated successfully!")

	// Generate Solidity verifier for Enygma K=6
	enygmaF6, err := os.Create("last_build/EnygmaVerifierk6.sol")
	if err != nil {
		log.Fatal("Failed to create Enygma K=6 verifier file:", err)
	}
	defer enygmaF6.Close()

	err = enygmaVk6.ExportSolidity(enygmaF6)
	if err != nil {
		log.Fatal("Failed to export Enygma K=6 Solidity verifier:", err)
	}
	log.Println("Enygma K=6 Solidity verifier generated successfully!")

	// =========================
	// WITHDRAW CIRCUITS
	// =========================

	// Generate keys for Withdraw K=2 circuit
	log.Println("Generating keys for Withdraw K=2 circuit...")
	var withdrawCircuit2 withdraw.WithdrawEnygmak2Circuit
	withdrawCcs2, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &withdrawCircuit2)
	if err != nil {
		log.Fatal("Failed to compile Withdraw K=2 circuit:", err)
	}

	withdrawPk2, withdrawVk2, err := groth16.Setup(withdrawCcs2)
	if err != nil {
		log.Fatal("Failed to setup Withdraw K=2 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, withdrawPk2, "./last_build/keys/Withdrawk2Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, withdrawVk2, "./last_build/keys/Withdrawk2Vk.key")
	log.Println("Withdraw K=2 keys generated successfully!")

	// Generate Solidity verifier for Withdraw K=2
	withdrawF2, err := os.Create("last_build/EnygmaWithdrawFromDvpVerifierk2.sol")
	if err != nil {
		log.Fatal("Failed to create Withdraw K=2 verifier file:", err)
	}
	defer withdrawF2.Close()

	err = withdrawVk2.ExportSolidity(withdrawF2)
	if err != nil {
		log.Fatal("Failed to export Withdraw K=2 Solidity verifier:", err)
	}
	log.Println("Withdraw K=2 Solidity verifier generated successfully!")

	// Generate keys for Withdraw K=3 circuit
	log.Println("Generating keys for Withdraw K=3 circuit...")
	var withdrawCircuit3 withdraw.WithdrawEnygmak3Circuit
	withdrawCcs3, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &withdrawCircuit3)
	if err != nil {
		log.Fatal("Failed to compile Withdraw K=3 circuit:", err)
	}

	withdrawPk3, withdrawVk3, err := groth16.Setup(withdrawCcs3)
	if err != nil {
		log.Fatal("Failed to setup Withdraw K=3 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, withdrawPk3, "./last_build/keys/Withdrawk3Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, withdrawVk3, "./last_build/keys/Withdrawk3Vk.key")
	log.Println("Withdraw K=3 keys generated successfully!")

	// Generate Solidity verifier for Withdraw K=3
	withdrawF3, err := os.Create("last_build/EnygmaWithdrawFromDvpVerifierk3.sol")
	if err != nil {
		log.Fatal("Failed to create Withdraw K=3 verifier file:", err)
	}
	defer withdrawF3.Close()

	err = withdrawVk3.ExportSolidity(withdrawF3)
	if err != nil {
		log.Fatal("Failed to export Withdraw K=3 Solidity verifier:", err)
	}
	log.Println("Withdraw K=3 Solidity verifier generated successfully!")

	// Generate keys for Withdraw K=4 circuit
	log.Println("Generating keys for Withdraw K=4 circuit...")
	var withdrawCircuit4 withdraw.WithdrawEnygmak4Circuit
	withdrawCcs4, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &withdrawCircuit4)
	if err != nil {
		log.Fatal("Failed to compile Withdraw K=4 circuit:", err)
	}

	withdrawPk4, withdrawVk4, err := groth16.Setup(withdrawCcs4)
	if err != nil {
		log.Fatal("Failed to setup Withdraw K=4 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, withdrawPk4, "./last_build/keys/Withdrawk4Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, withdrawVk4, "./last_build/keys/Withdrawk4Vk.key")
	log.Println("Withdraw K=4 keys generated successfully!")

	// Generate Solidity verifier for Withdraw K=4
	withdrawF4, err := os.Create("last_build/EnygmaWithdrawFromDvpVerifierk4.sol")
	if err != nil {
		log.Fatal("Failed to create Withdraw K=4 verifier file:", err)
	}
	defer withdrawF4.Close()

	err = withdrawVk4.ExportSolidity(withdrawF4)
	if err != nil {
		log.Fatal("Failed to export Withdraw K=4 Solidity verifier:", err)
	}
	log.Println("Withdraw K=4 Solidity verifier generated successfully!")

	// Generate keys for Withdraw K=5 circuit
	log.Println("Generating keys for Withdraw K=5 circuit...")
	var withdrawCircuit5 withdraw.WithdrawEnygmak5Circuit
	withdrawCcs5, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &withdrawCircuit5)
	if err != nil {
		log.Fatal("Failed to compile Withdraw K=5 circuit:", err)
	}

	withdrawPk5, withdrawVk5, err := groth16.Setup(withdrawCcs5)
	if err != nil {
		log.Fatal("Failed to setup Withdraw K=5 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, withdrawPk5, "./last_build/keys/Withdrawk5Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, withdrawVk5, "./last_build/keys/Withdrawk5Vk.key")
	log.Println("Withdraw K=5 keys generated successfully!")

	// Generate Solidity verifier for Withdraw K=5
	withdrawF5, err := os.Create("last_build/EnygmaWithdrawFromDvpVerifierk5.sol")
	if err != nil {
		log.Fatal("Failed to create Withdraw K=5 verifier file:", err)
	}
	defer withdrawF5.Close()

	err = withdrawVk5.ExportSolidity(withdrawF5)
	if err != nil {
		log.Fatal("Failed to export Withdraw K=5 Solidity verifier:", err)
	}
	log.Println("Withdraw K=5 Solidity verifier generated successfully!")

	// Generate keys for Withdraw K=6 circuit
	log.Println("Generating keys for Withdraw K=6 circuit...")
	var withdrawCircuit6 withdraw.WithdrawEnygmak6Circuit
	withdrawCcs6, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &withdrawCircuit6)
	if err != nil {
		log.Fatal("Failed to compile Withdraw K=6 circuit:", err)
	}

	withdrawPk6, withdrawVk6, err := groth16.Setup(withdrawCcs6)
	if err != nil {
		log.Fatal("Failed to setup Withdraw K=6 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, withdrawPk6, "./last_build/keys/Withdrawk6Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, withdrawVk6, "./last_build/keys/Withdrawk6Vk.key")
	log.Println("Withdraw K=6 keys generated successfully!")

	// Generate Solidity verifier for Withdraw K=6
	withdrawF6, err := os.Create("last_build/EnygmaWithdrawFromDvpVerifierk6.sol")
	if err != nil {
		log.Fatal("Failed to create Withdraw K=6 verifier file:", err)
	}
	defer withdrawF6.Close()

	err = withdrawVk6.ExportSolidity(withdrawF6)
	if err != nil {
		log.Fatal("Failed to export Withdraw K=6 Solidity verifier:", err)
	}
	log.Println("Withdraw K=6 Solidity verifier generated successfully!")

	// =========================
	// DEPOSIT CIRCUITS
	// =========================

	// Generate keys for Deposit K=2 circuit
	log.Println("Generating keys for Deposit K=2 circuit...")
	var depositCircuit2 deposit.DepositEnygmak2Circuit
	depositCcs2, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &depositCircuit2)
	if err != nil {
		log.Fatal("Failed to compile Deposit K=2 circuit:", err)
	}

	depositPk2, depositVk2, err := groth16.Setup(depositCcs2)
	if err != nil {
		log.Fatal("Failed to setup Deposit K=2 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, depositPk2, "./last_build/keys/Depositk2Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, depositVk2, "./last_build/keys/Depositk2Vk.key")
	log.Println("Deposit K=2 keys generated successfully!")

	// Generate Solidity verifier for Deposit K=2
	depositF2, err := os.Create("last_build/EnygmaDepositToDvpVerifierk2.sol")
	if err != nil {
		log.Fatal("Failed to create Deposit K=2 verifier file:", err)
	}
	defer depositF2.Close()

	err = depositVk2.ExportSolidity(depositF2)
	if err != nil {
		log.Fatal("Failed to export Deposit K=2 Solidity verifier:", err)
	}
	log.Println("Deposit K=2 Solidity verifier generated successfully!")

	// Generate keys for Deposit K=3 circuit
	log.Println("Generating keys for Deposit K=3 circuit...")
	var depositCircuit3 deposit.DepositEnygmak3Circuit
	depositCcs3, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &depositCircuit3)
	if err != nil {
		log.Fatal("Failed to compile Deposit K=3 circuit:", err)
	}

	depositPk3, depositVk3, err := groth16.Setup(depositCcs3)
	if err != nil {
		log.Fatal("Failed to setup Deposit K=3 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, depositPk3, "./last_build/keys/Depositk3Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, depositVk3, "./last_build/keys/Depositk3Vk.key")
	log.Println("Deposit K=3 keys generated successfully!")

	// Generate Solidity verifier for Deposit K=3
	depositF3, err := os.Create("last_build/EnygmaDepositToDvpVerifierk3.sol")
	if err != nil {
		log.Fatal("Failed to create Deposit K=3 verifier file:", err)
	}
	defer depositF3.Close()

	err = depositVk3.ExportSolidity(depositF3)
	if err != nil {
		log.Fatal("Failed to export Deposit K=3 Solidity verifier:", err)
	}
	log.Println("Deposit K=3 Solidity verifier generated successfully!")

	// Generate keys for Deposit K=4 circuit
	log.Println("Generating keys for Deposit K=4 circuit...")
	var depositCircuit4 deposit.DepositEnygmak4Circuit
	depositCcs4, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &depositCircuit4)
	if err != nil {
		log.Fatal("Failed to compile Deposit K=4 circuit:", err)
	}

	depositPk4, depositVk4, err := groth16.Setup(depositCcs4)
	if err != nil {
		log.Fatal("Failed to setup Deposit K=4 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, depositPk4, "./last_build/keys/Depositk4Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, depositVk4, "./last_build/keys/Depositk4Vk.key")
	log.Println("Deposit K=4 keys generated successfully!")

	// Generate Solidity verifier for Deposit K=4
	depositF4, err := os.Create("last_build/EnygmaDepositToDvpVerifierk4.sol")
	if err != nil {
		log.Fatal("Failed to create Deposit K=4 verifier file:", err)
	}
	defer depositF4.Close()

	err = depositVk4.ExportSolidity(depositF4)
	if err != nil {
		log.Fatal("Failed to export Deposit K=4 Solidity verifier:", err)
	}
	log.Println("Deposit K=4 Solidity verifier generated successfully!")

	// Generate keys for Deposit K=5 circuit
	log.Println("Generating keys for Deposit K=5 circuit...")
	var depositCircuit5 deposit.DepositEnygmak5Circuit
	depositCcs5, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &depositCircuit5)
	if err != nil {
		log.Fatal("Failed to compile Deposit K=5 circuit:", err)
	}

	depositPk5, depositVk5, err := groth16.Setup(depositCcs5)
	if err != nil {
		log.Fatal("Failed to setup Deposit K=5 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, depositPk5, "./last_build/keys/Depositk5Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, depositVk5, "./last_build/keys/Depositk5Vk.key")
	log.Println("Deposit K=5 keys generated successfully!")

	// Generate Solidity verifier for Deposit K=5
	depositF5, err := os.Create("last_build/EnygmaDepositToDvpVerifierk5.sol")
	if err != nil {
		log.Fatal("Failed to create Deposit K=5 verifier file:", err)
	}
	defer depositF5.Close()

	err = depositVk5.ExportSolidity(depositF5)
	if err != nil {
		log.Fatal("Failed to export Deposit K=5 Solidity verifier:", err)
	}
	log.Println("Deposit K=5 Solidity verifier generated successfully!")

	// Generate keys for Deposit K=6 circuit
	log.Println("Generating keys for Deposit K=6 circuit...")
	var depositCircuit6 deposit.DepositEnygmak6Circuit
	depositCcs6, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &depositCircuit6)
	if err != nil {
		log.Fatal("Failed to compile Deposit K=6 circuit:", err)
	}

	depositPk6, depositVk6, err := groth16.Setup(depositCcs6)
	if err != nil {
		log.Fatal("Failed to setup Deposit K=6 circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, depositPk6, "./last_build/keys/Depositk6Pk.key")
	primitives.SaveVerifyingKey(ecc.BN254, depositVk6, "./last_build/keys/Depositk6Vk.key")
	log.Println("Deposit K=6 keys generated successfully!")

	// Generate Solidity verifier for Deposit K=6
	depositF6, err := os.Create("last_build/EnygmaDepositToDvpVerifierk6.sol")
	if err != nil {
		log.Fatal("Failed to create Deposit K=6 verifier file:", err)
	}
	defer depositF6.Close()

	err = depositVk6.ExportSolidity(depositF6)
	if err != nil {
		log.Fatal("Failed to export Deposit K=6 Solidity verifier:", err)
	}
	log.Println("Deposit K=6 Solidity verifier generated successfully!")

	// =========================
	// JOIN-SPLIT CIRCUITS
	// =========================

	// Generate keys for Enygma Join-Split circuit
	log.Println("Generating keys for Enygma Join-Split circuit...")
	var joinSplitCircuit enygma_joinsplit.EnygmaJoinSplitCircuit
	joinSplitCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &joinSplitCircuit)
	if err != nil {
		log.Fatal("Failed to compile Enygma Join-Split circuit:", err)
	}

	joinSplitPk, joinSplitVk, err := groth16.Setup(joinSplitCcs)
	if err != nil {
		log.Fatal("Failed to setup Enygma Join-Split circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, joinSplitPk, "./last_build/keys/EnygmaJoinSplitPk.key")
	primitives.SaveVerifyingKey(ecc.BN254, joinSplitVk, "./last_build/keys/EnygmaJoinSplitVk.key")
	log.Println("Enygma Join-Split keys generated successfully!")

	// Generate Solidity verifier for Enygma Join-Split
	joinSplitF, err := os.Create("last_build/EnygmaJoinSplitVerifier.sol")
	if err != nil {
		log.Fatal("Failed to create Enygma Join-Split verifier file:", err)
	}
	defer joinSplitF.Close()

	err = joinSplitVk.ExportSolidity(joinSplitF)
	if err != nil {
		log.Fatal("Failed to export Enygma Join-Split Solidity verifier:", err)
	}
	log.Println("Enygma Join-Split Solidity verifier generated successfully!")

	// =========================
	// Erc721 OWNERSHIP CIRCUIT
	// =========================

	// Generate keys for Erc721 Ownership circuit
	log.Println("Generating keys for Erc721 Ownership circuit...")
	var erc721Circuit erc721_ownership.Erc721OwnershipCircuit
	erc721Ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &erc721Circuit)
	if err != nil {
		log.Fatal("Failed to compile Erc721 Ownership circuit:", err)
	}

	erc721Pk, erc721Vk, err := groth16.Setup(erc721Ccs)
	if err != nil {
		log.Fatal("Failed to setup Erc721 Ownership circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, erc721Pk, "./last_build/keys/Erc721OwnershipPk.key")
	primitives.SaveVerifyingKey(ecc.BN254, erc721Vk, "./last_build/keys/Erc721OwnershipVk.key")
	log.Println("Erc721 Ownership keys generated successfully!")

	// Generate Solidity verifier for Erc721 Ownership
	erc721F, err := os.Create("last_build/Erc721OwnershipVerifier.sol")
	if err != nil {
		log.Fatal("Failed to create Erc721 Ownership verifier file:", err)
	}
	defer erc721F.Close()

	err = erc721Vk.ExportSolidity(erc721F)
	if err != nil {
		log.Fatal("Failed to export Erc721 Ownership Solidity verifier:", err)
	}
	log.Println("Erc721 Ownership Solidity verifier generated successfully!")

	// =========================
	// Erc1155 JOINSPLIT CIRCUIT
	// =========================

	// Generate keys for Erc1155 JoinSplit circuit
	log.Println("Generating keys for Erc1155 JoinSplit circuit...")
	var erc1155Circuit erc1155_joinsplit.Erc1155JoinSplitCircuit
	erc1155Ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &erc1155Circuit)
	if err != nil {
		log.Fatal("Failed to compile Erc1155 JoinSplit circuit:", err)
	}

	erc1155Pk, erc1155Vk, err := groth16.Setup(erc1155Ccs)
	if err != nil {
		log.Fatal("Failed to setup Erc1155 JoinSplit circuit:", err)
	}

	primitives.SaveProvingKey(ecc.BN254, erc1155Pk, "./last_build/keys/Erc1155JoinSplitPk.key")
	primitives.SaveVerifyingKey(ecc.BN254, erc1155Vk, "./last_build/keys/Erc1155JoinSplitVk.key")
	log.Println("Erc1155 JoinSplit keys generated successfully!")

	// Generate Solidity verifier for Erc1155 JoinSplit
	erc1155F, err := os.Create("last_build/Erc1155JoinSplitVerifier.sol")
	if err != nil {
		log.Fatal("Failed to create Erc1155 JoinSplit verifier file:", err)
	}
	defer erc1155F.Close()

	err = erc1155Vk.ExportSolidity(erc1155F)
	if err != nil {
		log.Fatal("Failed to export Erc1155 JoinSplit Solidity verifier:", err)
	}
	log.Println("Erc1155 JoinSplit Solidity verifier generated successfully!")

	// =========================
	// FINAL SUMMARY
	// =========================

	log.Println("All circuit keys and verifiers generated successfully!")
	log.Println("Generated files:")
	log.Println("- Keys: ./last_build/keys/Enygmak2Pk.key, ./last_build/keys/Enygmak2Vk.key")
	log.Println("- Keys: ./last_build/keys/Enygmak3Pk.key, ./last_build/keys/Enygmak3Vk.key")
	log.Println("- Keys: ./last_build/keys/Enygmak4Pk.key, ./last_build/keys/Enygmak4Vk.key")
	log.Println("- Keys: ./last_build/keys/Enygmak5Pk.key, ./last_build/keys/Enygmak5Vk.key")
	log.Println("- Keys: ./last_build/keys/Enygmak6Pk.key, ./last_build/keys/Enygmak6Vk.key")
	log.Println("- Keys: ./last_build/keys/Withdrawk2Pk.key, ./last_build/keys/Withdrawk2Vk.key")
	log.Println("- Keys: ./last_build/keys/Withdrawk3Pk.key, ./last_build/keys/Withdrawk3Vk.key")
	log.Println("- Keys: ./last_build/keys/Withdrawk4Pk.key, ./last_build/keys/Withdrawk4Vk.key")
	log.Println("- Keys: ./last_build/keys/Withdrawk5Pk.key, ./last_build/keys/Withdrawk5Vk.key")
	log.Println("- Keys: ./last_build/keys/Withdrawk6Pk.key, ./last_build/keys/Withdrawk6Vk.key")
	log.Println("- Keys: ./last_build/keys/Depositk2Pk.key, ./last_build/keys/Depositk2Vk.key")
	log.Println("- Keys: ./last_build/keys/Depositk3Pk.key, ./last_build/keys/Depositk3Vk.key")
	log.Println("- Keys: ./last_build/keys/Depositk4Pk.key, ./last_build/keys/Depositk4Vk.key")
	log.Println("- Keys: ./last_build/keys/Depositk5Pk.key, ./last_build/keys/Depositk5Vk.key")
	log.Println("- Keys: ./last_build/keys/Depositk6Pk.key, ./last_build/keys/Depositk6Vk.key")
	log.Println("- Keys: ./last_build/keys/EnygmaJoinSplitPk.key, ./last_build/keys/EnygmaJoinSplitVk.key")
	log.Println("- Keys: ./last_build/keys/Erc721OwnershipPk.key, ./last_build/keys/Erc721OwnershipVk.key")
	log.Println("- Keys: ./last_build/keys/Erc1155JoinSplitPk.key, ./last_build/keys/Erc1155JoinSplitVk.key")
	log.Println("- Verifiers: EnygmaVerifierk2.sol, EnygmaVerifierk3.sol, EnygmaVerifierk4.sol, EnygmaVerifierk5.sol, EnygmaVerifierk6.sol")
	log.Println("- Verifiers: EnygmaWithdrawFromDvpVerifierk2.sol, EnygmaWithdrawFromDvpVerifierk3.sol, EnygmaWithdrawFromDvpVerifierk4.sol, EnygmaWithdrawFromDvpVerifierk5.sol, EnygmaWithdrawFromDvpVerifierk6.sol")
	log.Println("- Verifiers: EnygmaDepositToDvpVerifierk2.sol, EnygmaDepositToDvpVerifierk3.sol, EnygmaDepositToDvpVerifierk4.sol, EnygmaDepositToDvpVerifierk5.sol, EnygmaDepositToDvpVerifierk6.sol")
	log.Println("- Verifier: EnygmaJoinSplitVerifier.sol")
	log.Println("- Verifier: Erc721OwnershipVerifier.sol")
	log.Println("- Verifier: Erc1155JoinSplitVerifier.sol")
}
