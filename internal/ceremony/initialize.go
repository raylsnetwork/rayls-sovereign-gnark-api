package ceremony

import (
	"fmt"
	"math/big"
	"slices"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cryptompc "github.com/consensys/gnark-crypto/ecc/bn254/mpcsetup"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// msmThreshold is the number of terms above which a wire's sum uses a
// multi-scalar multiplication instead of one scalar multiplication per term.
const msmThreshold = 32

// initializePhase2 returns the same phase 2 starting state and evaluations as
// gnark's (*mpcsetup.Phase2).Initialize, much faster:
//
//   - the Lagrange-form phase 1 parameters come from lag, computed once per
//     domain size instead of once per circuit;
//   - each wire's sums are computed in parallel across wires, in Jacobian
//     coordinates, with a single batch conversion to affine at the end
//     (gnark adds one term at a time in affine coordinates, on one core).
//
// Group sums do not depend on the order of their terms, so the results are
// identical; the tests compare them byte for byte with gnark's. Circuits with
// Groth16 commitments, which this repository does not use, fall back to
// gnark's implementation.
func initializePhase2(r *cs.R1CS, srs *mpcsetup.SrsCommons, lag *lagrangeBases) (*mpcsetup.Phase2, *mpcsetup.Phase2Evaluations, error) {
	commitments := r.CommitmentInfo.(constraint.Groth16Commitments)
	if len(commitments) > 0 {
		p := new(mpcsetup.Phase2)
		evals := p.Initialize(r, srs)
		return p, &evals, nil
	}
	n := len(srs.G1.AlphaTau)
	if n < r.GetNbConstraints() {
		return nil, nil, fmt.Errorf("%d constraints do not fit phase 1 parameters of size %d", r.GetNbConstraints(), n)
	}

	nbInternal, nbSecret, nbPublic := r.GetNbVariables()
	nWires := nbInternal + nbSecret + nbPublic
	left, right, out := collectTerms(r, nWires)

	coeffs := make([]fr.Element, len(r.Coefficients))
	copy(coeffs, r.Coefficients)
	coeffsBig := make([]big.Int, len(coeffs))
	for i := range coeffs {
		coeffs[i].BigInt(&coeffsBig[i])
	}
	sum := termSummer{coeffs: coeffs, coeffsBig: coeffsBig}

	// Per wire: A = Σ_L c·[Lᵢ(τ)]₁, B = Σ_R c·[Lᵢ(τ)]₁, B₂ = Σ_R c·[Lᵢ(τ)]₂, and
	// K = Σ_L c·[βLᵢ(τ)]₁ + Σ_R c·[αLᵢ(τ)]₁ + Σ_O c·[Lᵢ(τ)]₁ (gnark's βA + αB + C).
	aJ := make([]curve.G1Jac, nWires)
	bJ := make([]curve.G1Jac, nWires)
	kJ := make([]curve.G1Jac, nWires)
	b2 := make([]curve.G2Affine, nWires)
	parallelRange(nWires, func(start, end int) {
		for w := start; w < end; w++ {
			l, rr, o := left.of(w), right.of(w), out.of(w)
			aJ[w] = sum.g1(l, lag.tau1)
			bJ[w] = sum.g1(rr, lag.tau1)
			k := sum.g1(l, lag.betaTau1)
			t := sum.g1(rr, lag.alphaTau1)
			k.AddAssign(&t)
			t = sum.g1(o, lag.tau1)
			k.AddAssign(&t)
			kJ[w] = k
			g2 := sum.g2(rr, lag.tau2)
			b2[w].FromJacobian(&g2)
		}
	})

	var evals mpcsetup.Phase2Evaluations
	evals.PublicAndCommitmentCommitted = commitments.GetPublicAndCommitmentCommitted(commitments.CommitmentIndexes(), nbPublic)
	evals.G1.A = curve.BatchJacobianToAffineG1(aJ)
	evals.G1.B = curve.BatchJacobianToAffineG1(bJ)
	evals.G2.B = b2
	evals.G1.CKK = make([][]curve.G1Affine, 0)
	k := curve.BatchJacobianToAffineG1(kJ)
	// With no commitments, gnark puts public wires in VKK and the rest in PKK.
	evals.G1.VKK = slices.Clone(k[:nbPublic])

	p := new(mpcsetup.Phase2)
	_, _, g1, g2 := curve.Generators()
	p.Parameters.G1.Delta = g1
	p.Parameters.G2.Delta = g2
	p.Parameters.G1.PKK = slices.Clone(k[nbPublic:])
	p.Parameters.G1.Z = vanishingTerms(srs, n)
	p.Parameters.G1.SigmaCKK = make([][]curve.G1Affine, 0)
	p.Parameters.G2.Sigma = make([]curve.G2Affine, 0)
	p.Sigmas = make([]cryptompc.UpdateProof, 0)
	p.Challenge = nil
	return p, &evals, nil
}

// vanishingTerms computes Z as gnark does: [τⁱ(τⁿ − 1)]₁ = [τⁱ⁺ⁿ]₁ − [τⁱ]₁ for
// i < n−1, bit-reversed with a zero last element, then truncated to n−1.
func vanishingTerms(srs *mpcsetup.SrsCommons, n int) []curve.G1Affine {
	jac := make([]curve.G1Jac, n)
	parallelRange(n-1, func(start, end int) {
		for i := start; i < end; i++ {
			var neg curve.G1Affine
			neg.Neg(&srs.G1.Tau[i])
			jac[i].FromAffine(&srs.G1.Tau[i+n])
			jac[i].AddMixed(&neg)
		}
	})
	z := curve.BatchJacobianToAffineG1(jac)
	bitReverse(z)
	return z[:n-1]
}

// termList holds, per wire, the (constraint, coefficient) pairs of one side
// (L, R or O) of the constraints, in counting-sort layout.
type termList struct {
	offsets      []int32 // wire w's terms are entries[offsets[w]:offsets[w+1]]
	constraintOf []uint32
	coeffOf      []uint32
}

func (t *termList) of(w int) termRange {
	lo, hi := t.offsets[w], t.offsets[w+1]
	return termRange{constraints: t.constraintOf[lo:hi], coeffs: t.coeffOf[lo:hi]}
}

type termRange struct {
	constraints []uint32
	coeffs      []uint32
}

// collectTerms groups every constraint term by wire, for each side.
func collectTerms(r *cs.R1CS, nWires int) (left, right, out termList) {
	type raw struct{ wire, constraint, coeff uint32 }
	var l, rr, o []raw
	i := uint32(0)
	it := r.GetR1CIterator()
	for c := it.Next(); c != nil; c = it.Next() {
		for _, t := range c.L {
			l = append(l, raw{uint32(t.WireID()), i, uint32(t.CoeffID())})
		}
		for _, t := range c.R {
			rr = append(rr, raw{uint32(t.WireID()), i, uint32(t.CoeffID())})
		}
		for _, t := range c.O {
			o = append(o, raw{uint32(t.WireID()), i, uint32(t.CoeffID())})
		}
		i++
	}
	group := func(terms []raw) termList {
		tl := termList{offsets: make([]int32, nWires+1)}
		for _, t := range terms {
			tl.offsets[t.wire+1]++
		}
		for w := 0; w < nWires; w++ {
			tl.offsets[w+1] += tl.offsets[w]
		}
		tl.constraintOf = make([]uint32, len(terms))
		tl.coeffOf = make([]uint32, len(terms))
		next := slices.Clone(tl.offsets[:nWires])
		for _, t := range terms {
			j := next[t.wire]
			next[t.wire]++
			tl.constraintOf[j] = t.constraint
			tl.coeffOf[j] = t.coeff
		}
		return tl
	}
	return group(l), group(rr), group(o)
}

// termSummer computes Σ coefficient·base[constraint] over a wire's terms.
type termSummer struct {
	coeffs    []fr.Element
	coeffsBig []big.Int
}

func (s *termSummer) g1(t termRange, base []curve.G1Affine) curve.G1Jac {
	var acc curve.G1Jac
	if len(t.constraints) > msmThreshold {
		points := make([]curve.G1Affine, len(t.constraints))
		scalars := make([]fr.Element, len(t.constraints))
		for j, c := range t.constraints {
			points[j] = base[c]
			scalars[j] = s.coeffs[t.coeffs[j]]
		}
		acc.MultiExp(points, scalars, ecc.MultiExpConfig{NbTasks: 1})
		return acc
	}
	for j, c := range t.constraints {
		p := &base[c]
		switch t.coeffs[j] {
		case constraint.CoeffIdZero:
		case constraint.CoeffIdOne:
			acc.AddMixed(p)
		case constraint.CoeffIdMinusOne:
			var neg curve.G1Affine
			neg.Neg(p)
			acc.AddMixed(&neg)
		case constraint.CoeffIdTwo:
			acc.AddMixed(p)
			acc.AddMixed(p)
		default:
			var tmp curve.G1Jac
			tmp.FromAffine(p)
			tmp.ScalarMultiplication(&tmp, &s.coeffsBig[t.coeffs[j]])
			acc.AddAssign(&tmp)
		}
	}
	return acc
}

func (s *termSummer) g2(t termRange, base []curve.G2Affine) curve.G2Jac {
	var acc curve.G2Jac
	if len(t.constraints) > msmThreshold {
		points := make([]curve.G2Affine, len(t.constraints))
		scalars := make([]fr.Element, len(t.constraints))
		for j, c := range t.constraints {
			points[j] = base[c]
			scalars[j] = s.coeffs[t.coeffs[j]]
		}
		acc.MultiExp(points, scalars, ecc.MultiExpConfig{NbTasks: 1})
		return acc
	}
	for j, c := range t.constraints {
		p := &base[c]
		switch t.coeffs[j] {
		case constraint.CoeffIdZero:
		case constraint.CoeffIdOne:
			acc.AddMixed(p)
		case constraint.CoeffIdMinusOne:
			var neg curve.G2Affine
			neg.Neg(p)
			acc.AddMixed(&neg)
		case constraint.CoeffIdTwo:
			acc.AddMixed(p)
			acc.AddMixed(p)
		default:
			var tmp curve.G2Jac
			tmp.FromAffine(p)
			tmp.ScalarMultiplication(&tmp, &s.coeffsBig[t.coeffs[j]])
			acc.AddAssign(&tmp)
		}
	}
	return acc
}
