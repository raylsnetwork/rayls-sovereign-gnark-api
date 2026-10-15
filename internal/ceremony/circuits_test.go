package ceremony

import "testing"

// Every institution must compile the same R1CS from the same code, or verify
// would reject a valid ceremony. Go randomizes map iteration, so repeated
// compiles exercise that.
func TestProductionCircuitsCompileDeterministically(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("compiles production circuits")
	}
	for _, c := range ProductionCircuits() {
		if c.Name != "Erc721Ownership" && c.Name != "Enygmak2" {
			continue
		}
		c := c
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			first, err := compile(c)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				again, err := compile(c)
				if err != nil {
					t.Fatal(err)
				}
				if again.Hash != first.Hash {
					t.Fatalf("compile %d: R1CS hash %s, first compile %s", i+2, again.Hash, first.Hash)
				}
			}
		})
	}
}

func TestProductionCircuitNamesAreUnique(t *testing.T) {
	t.Parallel()
	names, verifiers := map[string]bool{}, map[string]bool{}
	for _, c := range ProductionCircuits() {
		if names[c.Name] || verifiers[c.Verifier] {
			t.Fatalf("duplicate circuit %s / %s", c.Name, c.Verifier)
		}
		names[c.Name], verifiers[c.Verifier] = true, true
	}
	if len(names) != 18 {
		t.Fatalf("%d production circuits, want 18", len(names))
	}
}
