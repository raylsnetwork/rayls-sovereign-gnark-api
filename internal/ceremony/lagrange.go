package ceremony

// The G2 Lagrange transform below is adapted from gnark-crypto's
// ecc/bn254/kzg/utils.go (ToLagrangeG1), Copyright 2020-2025 Consensys
// Software Inc., licensed under the Apache License, Version 2.0.

import (
	"fmt"
	"math/big"
	"math/bits"
	"runtime"
	"sync"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
)

// lagrangeBases are phase 1 parameters in Lagrange form for one domain size:
// [Lᵢ(τ)]₁, [Lᵢ(τ)]₂, [αLᵢ(τ)]₁ and [βLᵢ(τ)]₁. They depend only on phase 1 and
// the size, so every circuit of that size shares them. gnark's
// Phase2.Initialize recomputes them for each circuit.
type lagrangeBases struct {
	tau1, alphaTau1, betaTau1 []curve.G1Affine
	tau2                      []curve.G2Affine
}

// lagrangeCache computes each size's bases once and shares them.
type lagrangeCache struct {
	mu    sync.Mutex
	bySrs map[*mpcsetup.SrsCommons]*lagrangeEntry
}

type lagrangeEntry struct {
	once  sync.Once
	bases *lagrangeBases
	err   error
}

func (lc *lagrangeCache) get(srs *mpcsetup.SrsCommons) (*lagrangeBases, error) {
	lc.mu.Lock()
	if lc.bySrs == nil {
		lc.bySrs = make(map[*mpcsetup.SrsCommons]*lagrangeEntry)
	}
	e, ok := lc.bySrs[srs]
	if !ok {
		e = new(lagrangeEntry)
		lc.bySrs[srs] = e
	}
	lc.mu.Unlock()
	e.once.Do(func() { e.bases, e.err = computeLagrange(srs) })
	return e.bases, e.err
}

func computeLagrange(srs *mpcsetup.SrsCommons) (*lagrangeBases, error) {
	n := len(srs.G1.AlphaTau)
	g1 := func(powers []curve.G1Affine) ([]curve.G1Affine, error) {
		return kzg.ToLagrangeG1(append([]curve.G1Affine(nil), powers[:n]...))
	}
	var b lagrangeBases
	var err error
	if b.tau1, err = g1(srs.G1.Tau); err != nil {
		return nil, fmt.Errorf("lagrange tau: %w", err)
	}
	if b.alphaTau1, err = g1(srs.G1.AlphaTau); err != nil {
		return nil, fmt.Errorf("lagrange alpha*tau: %w", err)
	}
	if b.betaTau1, err = g1(srs.G1.BetaTau); err != nil {
		return nil, fmt.Errorf("lagrange beta*tau: %w", err)
	}
	if b.tau2, err = toLagrangeG2(srs.G2.Tau[:n]); err != nil {
		return nil, fmt.Errorf("lagrange tau in G2: %w", err)
	}
	return &b, nil
}

// toLagrangeG2 is kzg.ToLagrangeG1 for G2: an inverse FFT over the powers in
// Jacobian coordinates, scaled by 1/n.
func toLagrangeG2(powers []curve.G2Affine) ([]curve.G2Affine, error) {
	size := len(powers)
	if bits.OnesCount64(uint64(size)) != 1 {
		return nil, fmt.Errorf("len(powers) must be a power of 2")
	}
	twiddlesInv, err := twiddlesInverse(size)
	if err != nil {
		return nil, err
	}
	jac := make([]curve.G2Jac, size)
	for i := range powers {
		jac[i].FromAffine(&powers[i])
	}
	maxSplits := bits.TrailingZeros64(nextPow2(uint64(runtime.NumCPU()))) << 1
	difFFTG2(jac, twiddlesInv, 0, maxSplits, nil)
	bitReverse(jac)

	var inv fr.Element
	inv.SetUint64(uint64(size)).Inverse(&inv)
	var invBig big.Int
	inv.BigInt(&invBig)
	out := make([]curve.G2Affine, size)
	parallelRange(size, func(start, end int) {
		for i := start; i < end; i++ {
			jac[i].ScalarMultiplication(&jac[i], &invBig)
			out[i].FromJacobian(&jac[i])
		}
	})
	return out, nil
}

func twiddlesInverse(cardinality int) ([]*big.Int, error) {
	generator, err := fr.Generator(uint64(cardinality))
	if err != nil {
		return nil, err
	}
	generator.Inverse(&generator)
	stages := bits.TrailingZeros64(uint64(cardinality))
	r := make([]*big.Int, 1+(1<<(stages-1)))
	r[0] = new(big.Int).SetUint64(1)
	if len(r) == 1 {
		return r, nil
	}
	w := generator
	r[1] = new(big.Int)
	w.BigInt(r[1])
	for j := 2; j < len(r); j++ {
		w.Mul(&w, &generator)
		r[j] = new(big.Int)
		w.BigInt(r[j])
	}
	return r, nil
}

func butterflyG2(a, b *curve.G2Jac) {
	t := *a
	a.AddAssign(b)
	t.SubAssign(b)
	b.Set(&t)
}

func difFFTG2(a []curve.G2Jac, twiddles []*big.Int, stage, maxSplits int, done chan struct{}) {
	if done != nil {
		defer close(done)
	}
	n := len(a)
	if n == 1 {
		return
	}
	m := n >> 1
	butterflyG2(&a[0], &a[m])
	stride := 1 << stage
	if m >= 8 {
		parallelRange(m, func(start, end int) {
			if start == 0 {
				start = 1
			}
			j := start * stride
			for i := start; i < end; i++ {
				butterflyG2(&a[i], &a[i+m])
				a[i+m].ScalarMultiplication(&a[i+m], twiddles[j])
				j += stride
			}
		})
	} else {
		j := stride
		for i := 1; i < m; i++ {
			butterflyG2(&a[i], &a[i+m])
			a[i+m].ScalarMultiplication(&a[i+m], twiddles[j])
			j += stride
		}
	}
	if m == 1 {
		return
	}
	if stage < maxSplits {
		ch := make(chan struct{}, 1)
		go difFFTG2(a[m:n], twiddles, stage+1, maxSplits, ch)
		difFFTG2(a[0:m], twiddles, stage+1, maxSplits, nil)
		<-ch
	} else {
		difFFTG2(a[0:m], twiddles, stage+1, maxSplits, nil)
		difFFTG2(a[m:n], twiddles, stage+1, maxSplits, nil)
	}
}

func bitReverse[T any](a []T) {
	n := uint64(len(a))
	nn := uint64(64 - bits.TrailingZeros64(n))
	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev], a[i]
		}
	}
}

func nextPow2(v uint64) uint64 {
	if v <= 1 {
		return 1
	}
	return 1 << bits.Len64(v-1)
}

// parallelRange splits [0, n) into chunks processed on all CPUs.
func parallelRange(n int, fn func(start, end int)) {
	workers := min(runtime.NumCPU(), n)
	if workers <= 1 {
		fn(0, n)
		return
	}
	chunk := (n + workers - 1) / workers
	var wg sync.WaitGroup
	for start := 0; start < n; start += chunk {
		end := min(start+chunk, n)
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(start, end)
		}()
	}
	wg.Wait()
}
