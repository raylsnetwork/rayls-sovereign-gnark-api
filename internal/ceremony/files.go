package ceremony

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
)

// writeObject writes obj to path (creating parent directories) and returns
// the hex SHA-256 of the bytes written.
func writeObject(path string, obj io.WriterTo) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}
	h := sha256.New()
	w := bufio.NewWriter(io.MultiWriter(f, h))
	if _, err := obj.WriteTo(w); err != nil {
		f.Close()
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readObject reads path into obj after checking that its SHA-256 is want.
func readObject(path, want string, obj io.ReaderFrom) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if got := sha256Hex(b); got != want {
		return fmt.Errorf("%s: sha256 %s, manifest records %s", path, got, want)
	}
	if _, err := obj.ReadFrom(bufio.NewReader(bytes.NewReader(b))); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// fileSHA256 returns the hex SHA-256 of the file at path.
func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return sha256Hex(b), nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// hashOf returns the hex SHA-256 of obj's serialization.
func hashOf(obj io.WriterTo) (string, error) {
	h := sha256.New()
	if _, err := obj.WriteTo(h); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// truncateSRS returns the sealed phase 1 parameters for a domain of size n
// taken from parameters of a larger size N. It keeps the first 2n-1 powers of
// tau in G1 and the first n of the other vectors, which is exactly the
// parameter set for size n under the same secrets.
func truncateSRS(c *mpcsetup.SrsCommons, n uint64) (*mpcsetup.SrsCommons, error) {
	N := uint64(len(c.G1.AlphaTau))
	if n == 0 || n&(n-1) != 0 || n > N {
		return nil, fmt.Errorf("cannot truncate parameters of size %d to %d", N, n)
	}
	var t mpcsetup.SrsCommons
	t.G1.Tau = slices.Clone(c.G1.Tau[:2*n-1])
	t.G1.AlphaTau = slices.Clone(c.G1.AlphaTau[:n])
	t.G1.BetaTau = slices.Clone(c.G1.BetaTau[:n])
	t.G2.Tau = slices.Clone(c.G2.Tau[:n])
	t.G2.Beta = c.G2.Beta
	return &t, nil
}
