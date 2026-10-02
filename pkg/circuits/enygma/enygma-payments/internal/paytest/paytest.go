// Package paytest builds honest witness data for the Enygma payment circuits
// (transfer, deposit, withdraw), computing every value off-circuit the same way
// the circuits constrain it.
package paytest

import (
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/primitives"
)

// L is the BabyJubJub prime subgroup order; Pedersen values and randomness are taken mod L.
var L = primitives.JubJubPrimeSubGroup

// Fixture holds one k-anonymous payment. Index SenderIdx is the sender.
type Fixture struct {
	K, SenderIdx int

	SenderID, SecretKey, PreviousV, PreviousR, BlockNumber *big.Int
	SenderTxValue, Nullifier                               *big.Int

	AnonymitySet, PublicKeys, SharedSecrets []*big.Int
	HashedSharedSecrets, MessageTags        []*big.Int
	TxValues, TxRandom                      []*big.Int
	PreviousCommits, TxCommits              [][2]*big.Int
}

// New builds a fixture where the sender holds previousV and sends senderTxValue.
// TxValues are all zero; call SetTxValues to assign them.
func New(t testing.TB, k, senderIdx int, previousV, senderTxValue int64) *Fixture {
	t.Helper()
	f := &Fixture{
		K: k, SenderIdx: senderIdx,
		SecretKey:     big.NewInt(123456789),
		PreviousV:     big.NewInt(previousV),
		PreviousR:     big.NewInt(4242),
		BlockNumber:   big.NewInt(1000),
		SenderTxValue: big.NewInt(senderTxValue),
	}
	for i := 0; i < k; i++ {
		f.AnonymitySet = append(f.AnonymitySet, big.NewInt(int64(10*(i+1))))
		f.PublicKeys = append(f.PublicKeys, big.NewInt(int64(5000+i)))
		f.SharedSecrets = append(f.SharedSecrets, big.NewInt(int64(900+i)))
		f.PreviousCommits = append(f.PreviousCommits, pedersen(big.NewInt(int64(70+i)), big.NewInt(int64(80+i))))
	}
	f.SenderID = f.AnonymitySet[senderIdx]
	f.PublicKeys[senderIdx] = HashModL(t, f.SecretKey, f.SecretKey)
	f.SharedSecrets[senderIdx] = HashModL(t, f.PreviousR, f.SecretKey)
	f.PreviousCommits[senderIdx] = pedersen(f.PreviousV, f.PreviousR)

	hashTag := Hash(t, big.NewInt(12))
	for i := 0; i < k; i++ {
		f.HashedSharedSecrets = append(f.HashedSharedSecrets, HashModL(t, f.SharedSecrets[i], f.SharedSecrets[i]))
		f.MessageTags = append(f.MessageTags, HashModL(t, hashTag, f.SharedSecrets[i], f.BlockNumber))
	}
	f.Nullifier = Hash(t, f.HashedSharedSecrets[senderIdx], f.BlockNumber)
	f.TxRandom = randomFactors(t, f)
	f.SetTxValues(make([]*big.Int, k)...)
	return f
}

// SetTxValues assigns per-participant values (nil means 0) and recomputes the commitments.
func (f *Fixture) SetTxValues(values ...*big.Int) {
	f.TxValues = make([]*big.Int, f.K)
	f.TxCommits = make([][2]*big.Int, f.K)
	for i := 0; i < f.K; i++ {
		v := big.NewInt(0)
		if values[i] != nil {
			v = values[i]
		}
		f.TxValues[i] = v
		f.TxCommits[i] = pedersen(v, f.TxRandom[i])
	}
}

// Neg returns -v mod L, the value a debited sender commits to.
func Neg(v *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Neg(v), L)
}

// randomFactors mirrors common.CheckRandomFactors: receivers get L - h_i and
// the sender gets the sum of the receivers' h_i mod L.
func randomFactors(t testing.TB, f *Fixture) []*big.Int {
	t.Helper()
	hashRandom := Hash(t, big.NewInt(21))
	out := make([]*big.Int, f.K)
	sum := new(big.Int)
	for i := 0; i < f.K; i++ {
		if i == f.SenderIdx {
			continue
		}
		h := HashModL(t, hashRandom, f.SharedSecrets[i], f.BlockNumber)
		out[i] = new(big.Int).Sub(L, h)
		sum.Add(sum, h)
	}
	out[f.SenderIdx] = sum.Mod(sum, L)
	return out
}

func pedersen(v, r *big.Int) [2]*big.Int {
	p := primitives.PedersenCommitmentBabyJub(v, r)
	return [2]*big.Int{p.X, p.Y}
}

// Hash is Poseidon over in.
func Hash(t testing.TB, in ...*big.Int) *big.Int {
	t.Helper()
	h, err := poseidon.Hash(in)
	if err != nil {
		t.Fatalf("poseidon: %v", err)
	}
	return h
}

// HashModL is Poseidon over in, reduced mod L.
func HashModL(t testing.TB, in ...*big.Int) *big.Int {
	t.Helper()
	return new(big.Int).Mod(Hash(t, in...), L)
}
