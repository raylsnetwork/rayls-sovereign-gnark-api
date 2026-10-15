package ceremony

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
)

// snarkjs .ptau section types used here.
const (
	ptauHeader    = 1
	ptauTauG1     = 2
	ptauTauG2     = 3
	ptauAlphaTau1 = 4
	ptauBetaTau1  = 5
	ptauBetaG2    = 6
)

const (
	g1Bytes = 2 * fp.Bytes // uncompressed x, y
	g2Bytes = 4 * fp.Bytes // uncompressed x.c0, x.c1, y.c0, y.c1
)

// ImportPtau reads a snarkjs powers-of-tau file (e.g. from the Perpetual
// Powers of Tau) and returns its parameters as gnark phase 1 output, with the
// file's power (log2 of the domain size).
//
// It checks that every point is on the curve and in the prime-order subgroup,
// that the vectors start at the generators, and, with random linear
// combinations, that each vector is consecutive powers of the same tau with
// alpha and beta consistent. It does not replay the ptau ceremony's own
// contributions; snarkjs `powersoftau verify` does that.
func ImportPtau(path string) (*mpcsetup.SrsCommons, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	sections, err := readPtauSections(f)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	power, err := readPtauHeader(f, sections)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	n := 1 << power

	var srs mpcsetup.SrsCommons
	if srs.G1.Tau, err = readG1Section(f, sections, ptauTauG1, 2*n-1); err != nil {
		return nil, 0, err
	}
	if srs.G2.Tau, err = readG2Section(f, sections, ptauTauG2, n); err != nil {
		return nil, 0, err
	}
	if srs.G1.AlphaTau, err = readG1Section(f, sections, ptauAlphaTau1, n); err != nil {
		return nil, 0, err
	}
	if srs.G1.BetaTau, err = readG1Section(f, sections, ptauBetaTau1, n); err != nil {
		return nil, 0, err
	}
	beta, err := readG2Section(f, sections, ptauBetaG2, 1)
	if err != nil {
		return nil, 0, err
	}
	srs.G2.Beta = beta[0]

	if err := checkSRS(&srs); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	return &srs, power, nil
}

type ptauSection struct{ offset, size int64 }

func readPtauSections(f *os.File) (map[uint32]ptauSection, error) {
	var head [12]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if string(head[:4]) != "ptau" {
		return nil, errors.New("not a ptau file")
	}
	if v := binary.LittleEndian.Uint32(head[4:8]); v != 1 {
		return nil, fmt.Errorf("unsupported ptau version %d", v)
	}
	nSections := binary.LittleEndian.Uint32(head[8:12])
	sections := make(map[uint32]ptauSection, nSections)
	pos := int64(12)
	for i := uint32(0); i < nSections; i++ {
		var sh [12]byte
		if _, err := f.ReadAt(sh[:], pos); err != nil {
			return nil, fmt.Errorf("read section header: %w", err)
		}
		typ := binary.LittleEndian.Uint32(sh[:4])
		size := int64(binary.LittleEndian.Uint64(sh[4:12]))
		if _, dup := sections[typ]; dup {
			return nil, fmt.Errorf("duplicate section %d", typ)
		}
		sections[typ] = ptauSection{offset: pos + 12, size: size}
		pos += 12 + size
	}
	return sections, nil
}

func readPtauHeader(f *os.File, sections map[uint32]ptauSection) (int, error) {
	s, ok := sections[ptauHeader]
	if !ok {
		return 0, errors.New("missing header section")
	}
	b := make([]byte, s.size)
	if _, err := f.ReadAt(b, s.offset); err != nil {
		return 0, fmt.Errorf("read header section: %w", err)
	}
	if len(b) < 4 {
		return 0, errors.New("short header section")
	}
	n8 := int(binary.LittleEndian.Uint32(b[:4]))
	if n8 != fp.Bytes || len(b) < 4+n8+4 {
		return 0, fmt.Errorf("unexpected field size %d", n8)
	}
	q := new(big.Int).SetBytes(reverse(b[4 : 4+n8]))
	if q.Cmp(fp.Modulus()) != 0 {
		return 0, errors.New("not a BN254 ptau file")
	}
	power := int(binary.LittleEndian.Uint32(b[4+n8:]))
	if power < 1 || power > 28 {
		return 0, fmt.Errorf("unexpected power %d", power)
	}
	return power, nil
}

func readG1Section(f *os.File, sections map[uint32]ptauSection, typ uint32, count int) ([]curve.G1Affine, error) {
	r, err := sectionReader(f, sections, typ, int64(count)*g1Bytes)
	if err != nil {
		return nil, err
	}
	out := make([]curve.G1Affine, count)
	var buf [g1Bytes]byte
	for i := range out {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, fmt.Errorf("section %d: %w", typ, err)
		}
		if err := setFp(&out[i].X, buf[:fp.Bytes]); err != nil {
			return nil, fmt.Errorf("section %d point %d: %w", typ, i, err)
		}
		if err := setFp(&out[i].Y, buf[fp.Bytes:]); err != nil {
			return nil, fmt.Errorf("section %d point %d: %w", typ, i, err)
		}
		if !out[i].IsOnCurve() || !out[i].IsInSubGroup() {
			return nil, fmt.Errorf("section %d point %d is not a valid G1 point", typ, i)
		}
	}
	return out, nil
}

func readG2Section(f *os.File, sections map[uint32]ptauSection, typ uint32, count int) ([]curve.G2Affine, error) {
	r, err := sectionReader(f, sections, typ, int64(count)*g2Bytes)
	if err != nil {
		return nil, err
	}
	out := make([]curve.G2Affine, count)
	var buf [g2Bytes]byte
	for i := range out {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, fmt.Errorf("section %d: %w", typ, err)
		}
		coords := []*fp.Element{&out[i].X.A0, &out[i].X.A1, &out[i].Y.A0, &out[i].Y.A1}
		for j, c := range coords {
			if err := setFp(c, buf[j*fp.Bytes:(j+1)*fp.Bytes]); err != nil {
				return nil, fmt.Errorf("section %d point %d: %w", typ, i, err)
			}
		}
		if !out[i].IsOnCurve() || !out[i].IsInSubGroup() {
			return nil, fmt.Errorf("section %d point %d is not a valid G2 point", typ, i)
		}
	}
	return out, nil
}

func sectionReader(f *os.File, sections map[uint32]ptauSection, typ uint32, size int64) (io.Reader, error) {
	s, ok := sections[typ]
	if !ok {
		return nil, fmt.Errorf("missing section %d", typ)
	}
	if s.size != size {
		return nil, fmt.Errorf("section %d has %d bytes, expected %d", typ, s.size, size)
	}
	return bufio.NewReaderSize(io.NewSectionReader(f, s.offset, s.size), 1<<20), nil
}

// setFp decodes a little-endian Montgomery-form field element, the encoding
// snarkjs uses and the internal representation of fp.Element.
func setFp(e *fp.Element, b []byte) error {
	if new(big.Int).SetBytes(reverse(b)).Cmp(fp.Modulus()) >= 0 {
		return errors.New("coordinate is not reduced modulo the field")
	}
	for i := range e {
		e[i] = binary.LittleEndian.Uint64(b[8*i:])
	}
	return nil
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// checkSRS checks the structure of phase 1 parameters:
//   - Tau[0] (both groups) are the generators;
//   - G1.Tau, G2.Tau, AlphaTau and BetaTau are each geometric sequences with
//     ratio tau, and the G1 and G2 ratios agree;
//   - BetaTau[0] in G1 and Beta in G2 are the same beta.
//
// The sequence checks use random linear combinations, so one pairing check
// covers a whole vector.
func checkSRS(s *mpcsetup.SrsCommons) error {
	_, _, g1, g2 := curve.Generators()
	n := len(s.G1.AlphaTau)
	if n == 0 || n&(n-1) != 0 || len(s.G1.Tau) != 2*n-1 || len(s.G1.BetaTau) != n || len(s.G2.Tau) != n {
		return errors.New("inconsistent parameter vector lengths")
	}
	if !s.G1.Tau[0].Equal(&g1) || !s.G2.Tau[0].Equal(&g2) {
		return errors.New("tau powers do not start at the generators")
	}
	if n == 1 {
		return nil
	}
	tau2 := s.G2.Tau[1]
	for name, v := range map[string][]curve.G1Affine{"tau": s.G1.Tau, "alpha*tau": s.G1.AlphaTau, "beta*tau": s.G1.BetaTau} {
		if err := checkG1Ratio(v, &tau2, &g2); err != nil {
			return fmt.Errorf("%s powers in G1: %w", name, err)
		}
	}
	if err := checkG2Ratio(s.G2.Tau, &s.G1.Tau[1], &g1); err != nil {
		return fmt.Errorf("tau powers in G2: %w", err)
	}
	// e(BetaTau[0], g2) == e(g1, Beta)
	if ok, err := pairingEqual(s.G1.BetaTau[0], g2, g1, s.G2.Beta); err != nil || !ok {
		return errors.New("beta in G1 and G2 differ")
	}
	return nil
}

// checkG1Ratio checks v[i+1] = tau * v[i] for all i, given [tau]2 and [1]2:
// e(sum r_i v[i], [tau]2) == e(sum r_i v[i+1], [1]2) for random r.
func checkG1Ratio(v []curve.G1Affine, tau2, one2 *curve.G2Affine) error {
	r, err := randomScalars(len(v) - 1)
	if err != nil {
		return err
	}
	var lo, hi curve.G1Affine
	if _, err := lo.MultiExp(v[:len(v)-1], r, ecc.MultiExpConfig{}); err != nil {
		return err
	}
	if _, err := hi.MultiExp(v[1:], r, ecc.MultiExpConfig{}); err != nil {
		return err
	}
	ok, err := pairingEqual(lo, *tau2, hi, *one2)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not consecutive powers of tau")
	}
	return nil
}

// checkG2Ratio is checkG1Ratio for a G2 vector, given [tau]1 and [1]1.
func checkG2Ratio(v []curve.G2Affine, tau1, one1 *curve.G1Affine) error {
	r, err := randomScalars(len(v) - 1)
	if err != nil {
		return err
	}
	var lo, hi curve.G2Affine
	if _, err := lo.MultiExp(v[:len(v)-1], r, ecc.MultiExpConfig{}); err != nil {
		return err
	}
	if _, err := hi.MultiExp(v[1:], r, ecc.MultiExpConfig{}); err != nil {
		return err
	}
	ok, err := pairingEqual(*tau1, lo, *one1, hi)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not consecutive powers of tau")
	}
	return nil
}

// pairingEqual reports whether e(a1, a2) == e(b1, b2).
func pairingEqual(a1 curve.G1Affine, a2 curve.G2Affine, b1 curve.G1Affine, b2 curve.G2Affine) (bool, error) {
	var negB1 curve.G1Affine
	negB1.Neg(&b1)
	return curve.PairingCheck([]curve.G1Affine{a1, negB1}, []curve.G2Affine{a2, b2})
}

func randomScalars(n int) ([]fr.Element, error) {
	r := make([]fr.Element, n)
	for i := range r {
		if _, err := r[i].SetRandom(); err != nil {
			return nil, fmt.Errorf("random scalar: %w", err)
		}
	}
	return r, nil
}
