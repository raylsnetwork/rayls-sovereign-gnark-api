// Package circuittest holds the scaffolding shared by the circuit tests:
// compiling, solving, running tables of forged witnesses, checking that a proof
// binds its public inputs, and setting witness fields by name on circuit
// structs that share field names but not a type.
package circuittest

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Compile compiles c to R1CS over BN254.
func Compile(t testing.TB, c frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return ccs
}

// IsSolved returns nil when assignment a satisfies ccs.
func IsSolved(t testing.TB, ccs constraint.ConstraintSystem, a frontend.Circuit, opts ...solver.Option) error {
	t.Helper()
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	return ccs.IsSolved(w, opts...)
}

// Attack is a forged witness the circuit must reject.
type Attack[C frontend.Circuit] struct {
	Name  string
	Build func(t *testing.T) C
	// Opts lets the attack replace hints, as a dishonest prover can.
	Opts []solver.Option
}

// Mutate returns an Attack.Build that applies mutate to a fresh honest witness.
func Mutate[C frontend.Circuit](honest func(testing.TB) C, mutate func(t *testing.T, w C)) func(*testing.T) C {
	return func(t *testing.T) C {
		w := honest(t)
		mutate(t, w)
		return w
	}
}

// RejectsAttacks fails t for every attack witness that satisfies ccs.
func RejectsAttacks[C frontend.Circuit](t *testing.T, ccs constraint.ConstraintSystem, attacks []Attack[C]) {
	t.Helper()
	for _, tc := range attacks {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			if err := IsSolved(t, ccs, tc.Build(t), tc.Opts...); err == nil {
				t.Fatal("attack witness was accepted")
			}
		})
	}
}

// PublicInputChange edits the public inputs a proof of the honest witness is
// verified against.
type PublicInputChange[C frontend.Circuit] struct {
	Name    string
	Mutate  func(t testing.TB, w C)
	WantErr bool
}

// ProofBindsPublicInputs proves the honest witness once and verifies the proof
// against each change of public inputs. It is skipped in -short mode.
func ProofBindsPublicInputs[C frontend.Circuit](t *testing.T, ccs constraint.ConstraintSystem, honest func(testing.TB) C, changes []PublicInputChange[C]) {
	t.Helper()
	if testing.Short() {
		t.Skip("groth16 setup and prove")
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	w, err := frontend.NewWitness(honest(t), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	for _, tc := range changes {
		t.Run(tc.Name, func(t *testing.T) {
			a := honest(t)
			tc.Mutate(t, a)
			pub, err := frontend.NewWitness(a, ecc.BN254.ScalarField(), frontend.PublicOnly())
			if err != nil {
				t.Fatalf("public witness: %v", err)
			}
			if err := groth16.Verify(proof, vk, pub); (err != nil) != tc.WantErr {
				t.Fatalf("verify err = %v, wantErr %v", err, tc.WantErr)
			}
		})
	}
}

// BenchmarkProve measures groth16.Prove for assignment a.
func BenchmarkProve(b *testing.B, ccs constraint.ConstraintSystem, a frontend.Circuit) {
	b.Helper()
	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatalf("setup: %v", err)
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatalf("witness: %v", err)
	}
	b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := groth16.Prove(ccs, pk, w); err != nil {
			b.Fatalf("prove: %v", err)
		}
	}
}

// Set assigns x to field name of the circuit struct c points to, or to its
// element at idx when the field is an array.
func Set(t testing.TB, c any, name string, x any, idx ...int) {
	t.Helper()
	field(t, c, name, idx...).Set(reflect.ValueOf(x))
}

// Get returns field name of the circuit struct c points to, or its element at idx.
func Get(t testing.TB, c any, name string, idx ...int) any {
	t.Helper()
	return field(t, c, name, idx...).Interface()
}

// Len returns the length of array field name of the circuit struct c points
// to, or of its element at idx.
func Len(t testing.TB, c any, name string, idx ...int) int {
	t.Helper()
	return field(t, c, name, idx...).Len()
}

func field(t testing.TB, c any, name string, idx ...int) reflect.Value {
	t.Helper()
	v := reflect.ValueOf(c).Elem().FieldByName(name)
	if !v.IsValid() {
		t.Fatalf("%T has no field %s", c, name)
	}
	for _, i := range idx {
		v = v.Index(i)
	}
	return v
}
