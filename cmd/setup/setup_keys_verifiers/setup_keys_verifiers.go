// Command setup_keys_verifiers generates DEVELOPMENT keys and Solidity
// verifiers for the production circuits with a single-party groth16.Setup.
// Whoever runs it knows the toxic waste and can forge proofs, so its output
// must never be deployed: production keys come from the trusted-setup
// ceremony (./ceremony.sh, docs/trusted-setup-ceremony.md).
//
// It refuses to run while the ceremony has a release, because its output would
// overwrite that release's keys in last_build/. Pass -force to do it anyway,
// e.g. to try a circuit change locally; ./ceremony.sh verify then fails until
// last_build/ is restored with `git checkout -- last_build`.
//
// Run it through ./generate_keys_verifiers.sh, which also converts the
// verifiers.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/raylsnetwork/rayls-sovereign-gnark-api/internal/ceremony"
	primitives "github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

func main() {
	ceremonyDir := flag.String("ceremony", "ceremony", "ceremony directory whose releases must not be overwritten")
	out := flag.String("out", "last_build", "output directory")
	force := flag.Bool("force", false, "overwrite a ceremony release's keys with single-party development keys")
	flag.Parse()

	if err := checkNoRelease(*ceremonyDir); err != nil {
		if !*force {
			log.Fatalf("refusing to generate single-party keys: %v\n"+
				"Production keys come from ./ceremony.sh. Pass -force (./generate_keys_verifiers.sh --force)\n"+
				"for local development keys, and restore the release with `git checkout -- %s`.", err, *out)
		}
		log.Printf("WARNING: -force: %v; overwriting it with forgeable development keys", err)
	}

	if err := os.MkdirAll(filepath.Join(*out, "keys"), 0o755); err != nil {
		log.Fatalf("create %s: %v", *out, err)
	}
	for _, c := range ceremony.ProductionCircuits() {
		log.Printf("generating development keys for %s...", c.Name)
		if err := setupCircuit(c, *out); err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("wrote DEVELOPMENT keys and verifiers for %d circuits to %s; do not deploy them", len(ceremony.ProductionCircuits()), *out)
}

// checkNoRelease returns an error if the ceremony in dir has released keys,
// or if its manifest exists but cannot be read. A missing manifest is fine.
func checkNoRelease(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, ceremony.ManifestFile)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	m, err := ceremony.Load(dir)
	if err != nil {
		return fmt.Errorf("cannot tell whether %s has a release: %w", dir, err)
	}
	if r := m.LatestRelease(); r != nil {
		return fmt.Errorf("%s has release v%d, whose keys are in last_build", dir, r.Version)
	}
	return nil
}

// setupCircuit compiles c, runs a single-party setup, and writes its keys and
// raw Solidity verifier under out, named as the ceremony names them.
func setupCircuit(c ceremony.Circuit, out string) error {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c.New())
	if err != nil {
		return fmt.Errorf("compile %s: %w", c.Name, err)
	}
	//gnark-safety:ignore GNARK_UNSAFE_SETUP development keys only; checkNoRelease stops them overwriting a ceremony release unless -force
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("setup %s: %w", c.Name, err)
	}
	if err := primitives.SaveProvingKey(ecc.BN254, pk, filepath.Join(out, "keys", c.Name+"Pk.key")); err != nil {
		return fmt.Errorf("save %s proving key: %w", c.Name, err)
	}
	if err := primitives.SaveVerifyingKey(ecc.BN254, vk, filepath.Join(out, "keys", c.Name+"Vk.key")); err != nil {
		return fmt.Errorf("save %s verifying key: %w", c.Name, err)
	}
	f, err := os.Create(filepath.Join(out, c.Verifier+".sol"))
	if err != nil {
		return fmt.Errorf("create %s verifier: %w", c.Name, err)
	}
	defer f.Close()
	if err := vk.ExportSolidity(f); err != nil {
		return fmt.Errorf("export %s verifier: %w", c.Name, err)
	}
	return f.Close()
}
