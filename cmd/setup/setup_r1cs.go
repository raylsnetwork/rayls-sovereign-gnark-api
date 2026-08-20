package main

import (
	enygma_joinsplit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/enygma-joinsplit-dvp"
	erc1155_joinsplit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/erc1155-joinsplit-dvp"
	erc721_ownership "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/erc721-ownership-dvp"
	deposit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-deposit"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-transfer"
	withdraw "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-withdraw"

	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func cleanAndCreateDirectories() error {
	// Remove last_build completely if it exists
	if _, err := os.Stat("last_build/circuits"); err == nil {
		fmt.Println("🗑️  Removing existing last_build directory...")
		if err := os.RemoveAll("last_build/circuits"); err != nil {
			return fmt.Errorf("failed to remove last_build: %v", err)
		}
	}

	// Create directories
	dirs := []string{
		"last_build",
		filepath.Join("last_build", "circuits"),
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

// Helper function to save constraint system
func saveConstraintSystem(ccs constraint.ConstraintSystem, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create constraint system file: %v", err)
	}
	defer file.Close()

	_, err = ccs.WriteTo(file)
	if err != nil {
		return fmt.Errorf("failed to write constraint system: %v", err)
	}

	return nil
}

// Generic function to compile and save a circuit
func compileAndSaveCircuit(circuit frontend.Circuit, circuitType string, k int) error {
	log.Printf("Generating constraint system for %s K=%d circuit...", circuitType, k)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("failed to compile %s K=%d circuit: %v", circuitType, k, err)
	}

	filename := fmt.Sprintf("./last_build/circuits/%sk%d.r1cs", circuitType, k)
	err = saveConstraintSystem(ccs, filename)
	if err != nil {
		return fmt.Errorf("failed to save %s K=%d constraint system: %v", circuitType, k, err)
	}

	log.Printf("%s K=%d constraint system generated successfully!", circuitType, k)
	return nil
}

// Special function for single circuit (no k parameter)
func compileAndSaveSingleCircuit(circuit frontend.Circuit, circuitName string) error {
	log.Printf("Generating constraint system for %s circuit...", circuitName)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("failed to compile %s circuit: %v", circuitName, err)
	}

	filename := fmt.Sprintf("./last_build/circuits/%s.r1cs", circuitName)
	err = saveConstraintSystem(ccs, filename)
	if err != nil {
		return fmt.Errorf("failed to save %s constraint system: %v", circuitName, err)
	}

	log.Printf("%s constraint system generated successfully!", circuitName)
	return nil
}

func generateEnygmaCircuits() error {
	// K=2
	if err := compileAndSaveCircuit(&enygma.Enygmak2Circuit{}, "Enygma", 2); err != nil {
		return err
	}

	// K=3
	if err := compileAndSaveCircuit(&enygma.Enygmak3Circuit{}, "Enygma", 3); err != nil {
		return err
	}

	// K=4
	if err := compileAndSaveCircuit(&enygma.Enygmak4Circuit{}, "Enygma", 4); err != nil {
		return err
	}

	// K=5
	if err := compileAndSaveCircuit(&enygma.Enygmak5Circuit{}, "Enygma", 5); err != nil {
		return err
	}

	// K=6
	if err := compileAndSaveCircuit(&enygma.Enygmak6Circuit{}, "Enygma", 6); err != nil {
		return err
	}

	return nil
}

func generateWithdrawCircuits() error {
	// K=2
	if err := compileAndSaveCircuit(&withdraw.WithdrawEnygmak2Circuit{}, "Withdraw", 2); err != nil {
		return err
	}

	// K=3
	if err := compileAndSaveCircuit(&withdraw.WithdrawEnygmak3Circuit{}, "Withdraw", 3); err != nil {
		return err
	}

	// K=4
	if err := compileAndSaveCircuit(&withdraw.WithdrawEnygmak4Circuit{}, "Withdraw", 4); err != nil {
		return err
	}

	// K=5
	if err := compileAndSaveCircuit(&withdraw.WithdrawEnygmak5Circuit{}, "Withdraw", 5); err != nil {
		return err
	}

	// K=6
	if err := compileAndSaveCircuit(&withdraw.WithdrawEnygmak6Circuit{}, "Withdraw", 6); err != nil {
		return err
	}

	return nil
}

func generateDepositCircuits() error {
	// K=2
	if err := compileAndSaveCircuit(&deposit.DepositEnygmak2Circuit{}, "Deposit", 2); err != nil {
		return err
	}

	// K=3
	if err := compileAndSaveCircuit(&deposit.DepositEnygmak3Circuit{}, "Deposit", 3); err != nil {
		return err
	}

	// K=4
	if err := compileAndSaveCircuit(&deposit.DepositEnygmak4Circuit{}, "Deposit", 4); err != nil {
		return err
	}

	// K=5
	if err := compileAndSaveCircuit(&deposit.DepositEnygmak5Circuit{}, "Deposit", 5); err != nil {
		return err
	}

	// K=6
	if err := compileAndSaveCircuit(&deposit.DepositEnygmak6Circuit{}, "Deposit", 6); err != nil {
		return err
	}

	return nil
}

func generateEnygmaJoinSplitCircuits() error {
	// Enygma Join-Split (Erc20)
	if err := compileAndSaveSingleCircuit(&enygma_joinsplit.EnygmaJoinSplitCircuit{}, "EnygmaJoinSplit"); err != nil {
		return err
	}

	return nil
}

func generateErc721OwnershipCircuit() error {
	// Erc721 Ownership
	if err := compileAndSaveSingleCircuit(&erc721_ownership.Erc721OwnershipCircuit{}, "Erc721Ownership"); err != nil {
		return err
	}

	return nil
}

func generateErc1155JoinSplitCircuit() error {
	// Erc1155 Join-Split
	if err := compileAndSaveSingleCircuit(&erc1155_joinsplit.Erc1155JoinSplitCircuit{}, "Erc1155JoinSplit"); err != nil {
		return err
	}

	return nil
}

func main() {

	// Clean and create directories first
	if err := cleanAndCreateDirectories(); err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		os.Exit(1)
	}

	// Generate all Enygma circuits
	fmt.Println("\n=========================")
	fmt.Println("ENYGMA CIRCUITS")
	fmt.Println("=========================")
	if err := generateEnygmaCircuits(); err != nil {
		log.Fatal(err)
	}

	// Generate all Withdraw circuits
	fmt.Println("\n=========================")
	fmt.Println("WITHDRAW CIRCUITS")
	fmt.Println("=========================")
	if err := generateWithdrawCircuits(); err != nil {
		log.Fatal(err)
	}

	// Generate all Deposit circuits
	fmt.Println("\n=========================")
	fmt.Println("DEPOSIT CIRCUITS")
	fmt.Println("=========================")
	if err := generateDepositCircuits(); err != nil {
		log.Fatal(err)
	}

	// Generate Join-Split circuits
	fmt.Println("\n=========================")
	fmt.Println("JOIN-SPLIT CIRCUITS")
	fmt.Println("=========================")
	if err := generateEnygmaJoinSplitCircuits(); err != nil {
		log.Fatal(err)
	}

	// Generate erc721 circuits
	fmt.Println("\n=========================")
	fmt.Println("721 CIRCUITS")
	fmt.Println("=========================")
	if err := generateErc721OwnershipCircuit(); err != nil {
		log.Fatal(err)
	}

	// Generate erc1155 circuits

	fmt.Println("\n=========================")
	fmt.Println("1155 CIRCUITS")
	fmt.Println("=========================")
	if err := generateErc1155JoinSplitCircuit(); err != nil {
		log.Fatal(err)
	}

	// Print summary
	fmt.Println("\n✅ All constraint systems generated successfully!")
	fmt.Println("\nGenerated files:")

	circuitTypes := []string{"Enygma", "Withdraw", "Deposit"}
	kValues := []int{2, 3, 4, 5, 6}

	for _, circuitType := range circuitTypes {
		fmt.Printf("\n%s Circuits:\n", circuitType)
		for _, k := range kValues {
			fmt.Printf("- ./last_build/circuits/%sk%d.r1cs\n", circuitType, k)
		}
	}

	// Enygma Join-Split circuit
	fmt.Printf("\nEnygma Join-Split Circuit:\n")
	fmt.Printf("- ./last_build/circuits/EnygmaJoinSplit.r1cs\n")

	// Erc721 Ownership circuit
	fmt.Printf("\nErc721 Ownership Circuit:\n")
	fmt.Printf("- ./last_build/circuits/Erc721Ownership.r1cs\n")

	// Erc1155 Join-Split circuit
	fmt.Printf("\nErc1155 Join-Split Circuit:\n")
	fmt.Printf("- ./last_build/circuits/Erc1155JoinSplit.r1cs\n")
}
