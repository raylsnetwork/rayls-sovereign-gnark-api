// Command ceremony runs the perpetual Groth16 trusted setup for the production
// circuits. See docs/trusted-setup-ceremony.md; ceremony.sh wraps it.
//
//	ceremony init        --ptau FILE --ptau-source URL   # import the public phase 1
//	ceremony contribute  --name NAME --beacon-source S    # add to phase 2, announce the next beacon
//	ceremony finalize    --beacon HEX [--out last_build]  # release new keys
//	ceremony verify      [--out last_build] [--ptau FILE]
//	ceremony status
//	ceremony info           # machine-readable state, key=value per line
//	ceremony contributions  # index<TAB>name<TAB>path<TAB>sha256<TAB>beacon per line
//	ceremony releases       # version<TAB>contributions<TAB>beacon source<TAB>beacon value per line
//
// Every subcommand takes --dir (default "ceremony"). Progress goes to stderr;
// contribute prints the contribution hash on stdout.
//
// CEREMONY_DEMO=1 swaps the production circuits for two tiny demo circuits
// and, without --ptau, generates an insecure phase 1 locally, so the whole flow
// can be rehearsed in minutes. Demo keys are useless.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark/logger"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/internal/ceremony"
)

func main() {
	// gnark logs compilation progress to stdout; keep stdout for results.
	logger.Disable()
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "ceremony:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: ceremony <init|contribute|finalize|verify|status|info|contributions|releases> [flags]")
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "ceremony", "ceremony transcript directory")
	demo := os.Getenv("CEREMONY_DEMO") == "1"
	c := &ceremony.Ceremony{Circuits: ceremony.ProductionCircuits(), Log: stderr}
	if demo {
		fmt.Fprintln(stderr, "ceremony: CEREMONY_DEMO=1, using demo circuits (keys are not for production)")
		c.Circuits = ceremony.DemoCircuits()
	}

	switch cmd {
	case "init":
		ptau := fs.String("ptau", "", "snarkjs powers-of-tau file to import as phase 1")
		source := fs.String("ptau-source", "", "where the powers-of-tau file came from (URL)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		c.Dir = *dir
		_, err := c.Init(ceremony.InitOptions{PtauPath: *ptau, PtauSource: *source, Demo: demo && *ptau == ""})
		return err

	case "contribute":
		name := fs.String("name", "", "contributor name (lowercase letters, digits, dashes)")
		beacon := fs.String("beacon-source", "", "future beacon announced for the next release, e.g. \"drand quicknet round N\"")
		if err := fs.Parse(args); err != nil {
			return err
		}
		c.Dir = *dir
		contrib, err := c.Contribute(*name, *beacon)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, contrib.SHA256)
		return nil

	case "finalize":
		beacon := fs.String("beacon", "", "hex value of the beacon announced by the latest contribution")
		out := fs.String("out", "last_build", "where to write keys, R1CS and verifiers")
		if err := fs.Parse(args); err != nil {
			return err
		}
		c.Dir = *dir
		_, err := c.Finalize(*beacon, *out)
		return err

	case "verify":
		out := fs.String("out", "", "also check the artifacts in this directory (e.g. last_build)")
		ptau := fs.String("ptau", "", "also check phase 1 derives from this powers-of-tau file")
		if err := fs.Parse(args); err != nil {
			return err
		}
		c.Dir = *dir
		if err := c.Verify(*out, *ptau); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "ceremony transcript verifies")
		return nil

	case "status", "info", "contributions", "releases":
		if err := fs.Parse(args); err != nil {
			return err
		}
		m, err := ceremony.Load(*dir)
		if err != nil {
			return err
		}
		switch cmd {
		case "status":
			printStatus(stdout, m)
		case "info":
			printInfo(stdout, m)
		case "contributions":
			for _, c := range m.Phase2.Contributions {
				fmt.Fprintf(stdout, "%d\t%s\t%s\t%s\t%s\n", c.Index, c.Name, c.Path, c.SHA256, c.Beacon)
			}
		case "releases":
			for _, r := range m.Phase2.Releases {
				fmt.Fprintf(stdout, "%d\t%d\t%s\t%s\n", r.Version, r.Contributions, r.Beacon.Source, r.Beacon.Value)
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q", cmd)
	}
}

func printStatus(w io.Writer, m *ceremony.Manifest) {
	fmt.Fprintf(w, "circuits: %d, gnark %s\n", len(m.Circuits), m.Gnark)
	fmt.Fprintf(w, "phase 1: %s (2^%d)\n", m.Phase1.Source, m.Phase1.Power)
	if m.Phase1.Source == ceremony.DemoPhase1Source {
		fmt.Fprintln(w, "         WARNING: insecure demo phase 1, never use these keys")
	}
	released := 0
	if r := m.LatestRelease(); r != nil {
		released = r.Contributions
	}
	fmt.Fprintln(w, "phase 2 contributions:")
	for _, c := range m.Phase2.Contributions {
		mark := "released"
		if c.Index > released {
			mark = "pending"
		}
		fmt.Fprintf(w, "  #%d %-20s %s (%s)\n", c.Index, c.Name, c.SHA256, mark)
	}
	fmt.Fprintln(w, "releases:")
	for _, r := range m.Phase2.Releases {
		fmt.Fprintf(w, "  v%d: contributions 1-%d, %s = %s\n", r.Version, r.Contributions, r.Beacon.Source, r.Beacon.Value)
	}
	if m.Pending() {
		fmt.Fprintf(w, "next release waits for: %s\n", m.PendingBeacon())
	}
}

// printInfo writes the state as key=value lines for scripts.
func printInfo(w io.Writer, m *ceremony.Manifest) {
	latest := 0
	if r := m.LatestRelease(); r != nil {
		latest = r.Version
	}
	pending := "0"
	if m.Pending() {
		pending = "1"
	}
	fmt.Fprintf(w, "contributions=%d\n", len(m.Phase2.Contributions))
	fmt.Fprintf(w, "next_index=%d\n", len(m.Phase2.Contributions)+1)
	fmt.Fprintf(w, "latest_release=%d\n", latest)
	fmt.Fprintf(w, "pending=%s\n", pending)
	fmt.Fprintf(w, "pending_beacon=%s\n", m.PendingBeacon())
	fmt.Fprintf(w, "phase1_source=%s\n", m.Phase1.Source)
	fmt.Fprintf(w, "phase1_sha256=%s\n", m.Phase1.PtauSHA256)
}
