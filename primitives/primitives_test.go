package primitives

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

const (
	testSk     = "123456789012345678901234567890"
	testSalt   = "987654321"
	testAmount = "1000000"
	testToken  = "1234567890123456789012345678901234567890"
	testUID    = "42"
)

type publicKeyCircuit struct {
	Sk   frontend.Variable
	Want frontend.Variable `gnark:",public"`
}

func (c *publicKeyCircuit) Define(api frontend.API) error {
	pk, err := PublicKey(api, c.Sk)
	if err != nil {
		return err
	}
	api.AssertIsEqual(pk, c.Want)
	return nil
}

type nullifierCircuit struct {
	Sk, Idx frontend.Variable
	Want    frontend.Variable `gnark:",public"`
}

func (c *nullifierCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(Nullifier(api, c.Sk, c.Idx), c.Want)
	return nil
}

type commitmentsCircuit struct {
	PK, Salt, Amount, Token, UID, TokenID frontend.Variable
	WantERC20, WantERC721, WantERC1155    frontend.Variable `gnark:",public"`
}

func (c *commitmentsCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(CommitmentV2ERC20(api, c.PK, c.Salt, c.Amount, c.Token), c.WantERC20)
	api.AssertIsEqual(CommitmentV2ERC721(api, c.PK, c.Salt, c.UID), c.WantERC721)
	api.AssertIsEqual(CommitmentV2ERC1155(api, c.PK, c.Salt, c.Token, c.TokenID, c.Amount), c.WantERC1155)
	return nil
}

const testDepth = 4

type merkleCircuit struct {
	Leaf, Idx frontend.Variable
	Path      [testDepth]frontend.Variable
	Root      frontend.Variable `gnark:",public"`
}

func (c *merkleCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(MerkleProof(api, c.Leaf, c.Idx, c.Path[:]), c.Root)
	return nil
}

// nativeMerkleRoot mirrors MerkleProof off-circuit.
func nativeMerkleRoot(t *testing.T, leaf *big.Int, idx uint, path []*big.Int) *big.Int {
	t.Helper()
	cur := leaf
	for i, sib := range path {
		left, right := cur, sib
		if idx>>uint(i)&1 == 1 {
			left, right = sib, cur
		}
		h, err := poseidon.Hash([]*big.Int{left, right})
		if err != nil {
			t.Fatalf("poseidon: %v", err)
		}
		cur = h
	}
	return cur
}

func TestPublicKeyMatchesNative(t *testing.T) {
	t.Parallel()
	for _, sk := range []string{"1", testSk, "21888242871839275222246405745257275088548364400416034343698204186575808495616"} {
		t.Run(sk, func(t *testing.T) {
			t.Parallel()
			want := DerivePublicKeyBN254(sk)
			if err := solve(t, &publicKeyCircuit{}, &publicKeyCircuit{Sk: sk, Want: want}); err != nil {
				t.Fatalf("PublicKey(%s) != DerivePublicKeyBN254: %v", sk, err)
			}
		})
	}
}

func TestPublicKeyRejectsForgedKey(t *testing.T) {
	t.Parallel()
	// The attacker knows testSk but claims the victim's public key 1337.
	victimPK := big.NewInt(1337)
	lInv := new(big.Int).ModInverse(JubJubPrimeSubGroup, bn254Modulus)
	forge := forgeModHint(func(x *big.Int) (*big.Int, *big.Int) {
		q := new(big.Int).Sub(x, victimPK)
		q.Mul(q, lInv).Mod(q, bn254Modulus)
		return victimPK, q
	})
	if err := solve(t, &publicKeyCircuit{}, &publicKeyCircuit{Sk: testSk, Want: victimPK}, forge); err == nil {
		t.Fatal("forged public key was accepted")
	}
}

func TestNullifierMatchesNative(t *testing.T) {
	t.Parallel()
	tests := []struct{ sk, idx string }{{testSk, "0"}, {testSk, "7"}, {"1", "255"}}
	for _, tc := range tests {
		t.Run(tc.sk+"/"+tc.idx, func(t *testing.T) {
			t.Parallel()
			want := ComputeNullifierBN254(tc.sk, tc.idx)
			if err := solve(t, &nullifierCircuit{}, &nullifierCircuit{Sk: tc.sk, Idx: tc.idx, Want: want}); err != nil {
				t.Fatalf("Nullifier != ComputeNullifierBN254: %v", err)
			}
		})
	}
}

func TestNullifierRejectsForgedValue(t *testing.T) {
	t.Parallel()
	if err := solve(t, &nullifierCircuit{}, &nullifierCircuit{Sk: testSk, Idx: 7, Want: 1337}); err == nil {
		t.Fatal("forged nullifier was accepted")
	}
}

func TestCommitmentsMatchNative(t *testing.T) {
	t.Parallel()
	pk := DerivePublicKeyBN254(testSk)
	tokenID := "7"
	assignment := &commitmentsCircuit{
		PK: pk, Salt: testSalt, Amount: testAmount, Token: testToken, UID: testUID, TokenID: tokenID,
		WantERC20:   ComputeCommitmentV2ERC20BN254(pk, testSalt, testAmount, testToken),
		WantERC721:  ComputeCommitmentV2ERC721BN254(pk, testSalt, testUID),
		WantERC1155: ComputeCommitmentV2ERC1155BN254(pk, testSalt, testToken, tokenID, testAmount),
	}
	if err := solve(t, &commitmentsCircuit{}, assignment); err != nil {
		t.Fatalf("in-circuit commitments != Compute*BN254: %v", err)
	}

	assignment.WantERC721 = 1337
	if err := solve(t, &commitmentsCircuit{}, assignment); err == nil {
		t.Fatal("forged commitment was accepted")
	}
}

func TestMerkleProof(t *testing.T) {
	t.Parallel()
	leaf := big.NewInt(111)
	path := []*big.Int{big.NewInt(2), big.NewInt(3), big.NewInt(5), big.NewInt(7)}

	tests := []struct {
		name    string
		idx     uint
		root    func(honest *big.Int) *big.Int
		wantErr bool
	}{
		{"honest idx 0", 0, func(h *big.Int) *big.Int { return h }, false},
		{"honest idx 9", 9, func(h *big.Int) *big.Int { return h }, false},
		{"forged root", 9, func(*big.Int) *big.Int { return big.NewInt(1337) }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := &merkleCircuit{Leaf: leaf, Idx: tc.idx, Root: tc.root(nativeMerkleRoot(t, leaf, tc.idx, path))}
			for i := range path {
				a.Path[i] = path[i]
			}
			err := solve(t, &merkleCircuit{}, a)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
