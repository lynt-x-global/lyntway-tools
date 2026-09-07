package cose

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// A small RFC 9162 tree built the long way, so the proof arithmetic in
// merkle.go is checked against the definition rather than against itself.
type refTree struct{ leaves [][]byte }

func (t refTree) mth(lo, hi uint64) []byte {
	switch hi - lo {
	case 0:
		return sha256.New().Sum(nil)
	case 1:
		return leafHash(t.leaves[lo])
	}
	k := uint64(1)
	for k<<1 < hi-lo {
		k <<= 1
	}
	return nodeHash(t.mth(lo, lo+k), t.mth(lo+k, hi))
}

// path implements PATH(m, D[n]) from RFC 9162 section 2.1.3 directly.
func (t refTree) path(m, lo, hi uint64) [][]byte {
	if hi-lo == 1 {
		return nil
	}
	k := uint64(1)
	for k<<1 < hi-lo {
		k <<= 1
	}
	if m < k {
		return append(t.path(m, lo, lo+k), t.mth(lo+k, hi))
	}
	return append(t.path(m-k, lo+k, hi), t.mth(lo, lo+k))
}

// subproof implements SUBPROOF(m, D[n], b) from RFC 9162 section 2.1.4.
func (t refTree) subproof(m, lo, hi uint64, complete bool) [][]byte {
	if m == hi-lo {
		if complete {
			return nil
		}
		return [][]byte{t.mth(lo, hi)}
	}
	k := uint64(1)
	for k<<1 < hi-lo {
		k <<= 1
	}
	if m <= k {
		return append(t.subproof(m, lo, lo+k, complete), t.mth(lo+k, hi))
	}
	return append(t.subproof(m-k, lo+k, hi, false), t.mth(lo, lo+k))
}

func entries(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		sum := sha256.Sum256([]byte{byte(i)})
		out[i] = []byte(hex.EncodeToString(sum[:]))
	}
	return out
}

func logSigner(t *testing.T) (*receipt.Ed25519Signer, receipt.StaticKeyResolver) {
	t.Helper()
	signer, err := receipt.GenerateEd25519Signer("log-key-1")
	if err != nil {
		t.Fatal(err)
	}
	return signer, receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}
}

// Every entry of every tree up to a size that covers the unbalanced
// shapes: a receipt is issued, and verifies against its own entry only.
func TestInclusionReceiptsVerifyForEveryEntry(t *testing.T) {
	signer, keys := logSigner(t)
	for size := 1; size <= 9; size++ {
		tree := refTree{leaves: entries(size)}
		root := tree.mth(0, uint64(size))
		for index := 0; index < size; index++ {
			rcpt, err := SignInclusionReceipt(signer, "log", string(tree.leaves[index]), InclusionProof{
				TreeSize:  uint64(size),
				LeafIndex: uint64(index),
				Path:      tree.path(uint64(index), 0, uint64(size)),
			}, root)
			if err != nil {
				t.Fatalf("size %d index %d: issuing: %v", size, index, err)
			}

			gotSize, gotRoot, err := VerifyInclusionReceipt(rcpt, tree.leaves[index], keys)
			if err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
			if gotSize != uint64(size) || !bytes.Equal(gotRoot, root) {
				t.Errorf("size %d index %d: reconstructed size %d root %x", size, index, gotSize, gotRoot)
			}

			// A different entry must not ride on this proof.
			other := entries(size + 1)[size]
			if _, _, err := VerifyInclusionReceipt(rcpt, other, keys); err == nil {
				t.Errorf("size %d index %d: a receipt verified for an entry it was not issued for", size, index)
			}
		}
	}
}

// The payload is detached, so the only root a verifier sees is the one
// they compute. A receipt from a key the verifier does not trust, or one
// whose proof was altered, must fail at the signature.
func TestInclusionReceiptIsRefusedWhenAlteredOrForeign(t *testing.T) {
	signer, keys := logSigner(t)
	tree := refTree{leaves: entries(5)}
	rcpt, err := SignInclusionReceipt(signer, "log", string(tree.leaves[2]), InclusionProof{
		TreeSize: 5, LeafIndex: 2, Path: tree.path(2, 0, 5),
	}, tree.mth(0, 5))
	if err != nil {
		t.Fatal(err)
	}

	stranger, _ := receipt.GenerateEd25519Signer("log-key-1")
	wrongKey := receipt.StaticKeyResolver{"log-key-1": stranger.Public()}
	if _, _, err := VerifyInclusionReceipt(rcpt, tree.leaves[2], wrongKey); err == nil {
		t.Error("a receipt verified under a key that did not sign it")
	}

	// Flip one byte of the proof, which lives in the unprotected header.
	// The signature does not cover it, so the failure must come from the
	// reconstructed root not being the signed one.
	proofOffset := bytes.Index(rcpt, tree.path(2, 0, 5)[0])
	if proofOffset < 0 {
		t.Fatal("could not find the proof in the receipt")
	}
	tampered := append([]byte(nil), rcpt...)
	tampered[proofOffset] ^= 0x01
	if _, _, err := VerifyInclusionReceipt(tampered, tree.leaves[2], keys); err == nil {
		t.Error("an altered proof still verified")
	}
}

// A receipt whose protected header does not say what kind of log signed it
// cannot be read at all, and one that names a structure this package does
// not know must say so rather than guess.
func TestInclusionReceiptRequiresARecognisedVDS(t *testing.T) {
	signer, keys := logSigner(t)
	tree := refTree{leaves: entries(3)}
	root := tree.mth(0, 3)
	content := Encode(Array{Uint(3), Uint(1), Array{Bytes(tree.path(1, 0, 3)[0]), Bytes(tree.path(1, 0, 3)[1])}})
	vdp := Map{{Key: Uint(labelVDP), Value: Map{{Key: Int(proofInclusion), Value: Array{Bytes(content)}}}}}

	noVDS, err := Sign1With(signer, root, Sign1Options{Detached: true, Unprotected: vdp})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyInclusionReceipt(noVDS, tree.leaves[1], keys); err == nil {
		t.Error("a receipt naming no verifiable data structure was accepted")
	}

	otherVDS, err := Sign1With(signer, root, Sign1Options{
		Detached:    true,
		Protected:   Map{{Key: Uint(labelVDS), Value: Uint(2)}},
		Unprotected: vdp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyInclusionReceipt(otherVDS, tree.leaves[1], keys); err == nil {
		t.Error("a receipt over an unknown verifiable data structure was accepted")
	}
}

// RFC 9942 section 4.4 wants the payload detached so a verifier is forced
// to recompute the root. If a log attaches one anyway it must be the root
// the proof produces; otherwise the receipt contradicts itself.
func TestAnAttachedRootMustMatchTheProof(t *testing.T) {
	signer, keys := logSigner(t)
	tree := refTree{leaves: entries(4)}
	root := tree.mth(0, 4)
	content := Encode(Array{Uint(4), Uint(0), Array{Bytes(tree.path(0, 0, 4)[0]), Bytes(tree.path(0, 0, 4)[1])}})
	opts := Sign1Options{
		Claims:      &Claims{Issuer: "log", Subject: "x"},
		Protected:   Map{{Key: Uint(labelVDS), Value: Uint(vdsRFC9162SHA256)}},
		Unprotected: Map{{Key: Uint(labelVDP), Value: Map{{Key: Int(proofInclusion), Value: Array{Bytes(content)}}}}},
	}

	attached, err := Sign1With(signer, root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyInclusionReceipt(attached, tree.leaves[0], keys); err != nil {
		t.Errorf("a receipt carrying the correct root was refused: %v", err)
	}

	// Signed over a different root, and carrying that root. The proof
	// still reconstructs the real one, and the two disagree.
	wrong := sha256.Sum256([]byte("not the root"))
	lying, err := Sign1With(signer, wrong[:], opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyInclusionReceipt(lying, tree.leaves[0], keys); !errors.Is(err, ErrProof) {
		t.Errorf("a receipt carrying a root its proof does not reach was accepted: err = %v", err)
	}
}

func TestConsistencyReceiptsVerifyBetweenEverySizePair(t *testing.T) {
	signer, keys := logSigner(t)
	const max = 9
	tree := refTree{leaves: entries(max)}
	for from := uint64(1); from < max; from++ {
		for to := from + 1; to <= max; to++ {
			oldRoot, newRoot := tree.mth(0, from), tree.mth(0, to)
			rcpt, err := SignConsistencyReceipt(signer, "log", ConsistencyProof{
				FromSize: from, ToSize: to, Path: tree.subproof(from, 0, to, true),
			}, newRoot)
			if err != nil {
				t.Fatalf("%d→%d: issuing: %v", from, to, err)
			}
			gotFrom, gotTo, gotRoot, err := VerifyConsistencyReceipt(rcpt, oldRoot, keys)
			if err != nil {
				t.Fatalf("%d→%d: %v", from, to, err)
			}
			if gotFrom != from || gotTo != to || !bytes.Equal(gotRoot, newRoot) {
				t.Errorf("%d→%d: reconstructed %d→%d root %x", from, to, gotFrom, gotTo, gotRoot)
			}
			// A verifier holding some other old root must not be told the
			// log grew from it.
			if _, _, _, err := VerifyConsistencyReceipt(rcpt, tree.mth(0, to), keys); err == nil {
				t.Errorf("%d→%d: a consistency receipt verified against the wrong older root", from, to)
			}
		}
	}
}

// The cases RFC 9162 defines as an empty proof cannot be issued: the
// verifier it specifies rejects an empty path, so nobody could check them.
func TestConsistencyReceiptsAreRefusedWhereTheProofWouldBeEmpty(t *testing.T) {
	signer, _ := logSigner(t)
	root := refTree{leaves: entries(4)}.mth(0, 4)
	for _, tc := range []struct{ from, to uint64 }{{0, 4}, {4, 4}, {5, 4}} {
		if _, err := SignConsistencyReceipt(signer, "log", ConsistencyProof{FromSize: tc.from, ToSize: tc.to}, root); err == nil {
			t.Errorf("a consistency receipt from %d to %d was issued", tc.from, tc.to)
		}
	}
}

// Attaching receipts touches only the unprotected header. The statement
// must verify exactly as before, the receipts must come back out, and the
// signed bytes must be untouched.
func TestAttachingReceiptsLeavesTheSignatureIntact(t *testing.T) {
	issuer, err := receipt.GenerateEd25519Signer("issuer-1")
	if err != nil {
		t.Fatal(err)
	}
	issuerKeys := receipt.StaticKeyResolver{issuer.KeyID(): issuer.Public()}
	r := testReceipt(t, issuer)
	statement, err := EncodeReceipt(r, issuer)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := receipt.Digest(r)
	if err != nil {
		t.Fatal(err)
	}

	logKey, logKeys := logSigner(t)
	tree := refTree{leaves: [][]byte{[]byte("0"), []byte(digest), []byte("2")}}
	rcpt, err := SignInclusionReceipt(logKey, "log", digest, InclusionProof{
		TreeSize: 3, LeafIndex: 1, Path: tree.path(1, 0, 3),
	}, tree.mth(0, 3))
	if err != nil {
		t.Fatal(err)
	}

	before, err := Verify1(statement, issuerKeys)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := Receipts(statement); len(got) != 0 {
		t.Fatalf("a fresh statement carries %d receipts", len(got))
	}

	transparent, err := AttachReceipts(statement, [][]byte{rcpt})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(transparent, statement) {
		t.Fatal("attaching a receipt changed nothing")
	}
	after, err := Verify1(transparent, issuerKeys)
	if err != nil {
		t.Fatalf("the statement no longer verifies with a receipt attached: %v", err)
	}
	if !bytes.Equal(before.Payload, after.Payload) || before.KeyID != after.KeyID {
		t.Error("the signed content changed when a receipt was attached")
	}
	// The receipt must be there and must still prove the entry.
	got, err := Receipts(transparent)
	if err != nil || len(got) != 1 || !bytes.Equal(got[0], rcpt) {
		t.Fatalf("receipts came back as %d entries, err %v", len(got), err)
	}
	if _, _, err := VerifyInclusionReceipt(got[0], []byte(digest), logKeys); err != nil {
		t.Errorf("the attached receipt no longer verifies: %v", err)
	}
	// Decoding the transparent statement as a receipt must work too: it
	// is the same receipt with more evidence around it.
	if _, err := DecodeReceipt(transparent, issuerKeys); err != nil {
		t.Errorf("a transparent statement does not decode as a receipt: %v", err)
	}

	// Attaching a second keeps the first.
	again, err := AttachReceipts(transparent, [][]byte{rcpt})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := Receipts(again); len(got) != 2 {
		t.Errorf("attaching a second receipt left %d", len(got))
	}
	// Something that is not a COSE_Sign1 is not a receipt.
	if _, err := AttachReceipts(statement, [][]byte{[]byte("not a receipt")}); err == nil {
		t.Error("garbage was attached as a receipt")
	}
}

// The reconstruction must agree with the RFC's worked example. RFC 9162
// section 2.1.5 gives the inclusion paths for a seven-leaf tree in terms
// of its node names; the shapes here follow it exactly.
func TestInclusionPathShapesFollowRFC9162(t *testing.T) {
	tree := refTree{leaves: entries(7)}
	root := tree.mth(0, 7)
	for index := uint64(0); index < 7; index++ {
		path := tree.path(index, 0, 7)
		got, err := inclusionRoot(leafHash(tree.leaves[index]), index, 7, path)
		if err != nil || !bytes.Equal(got, root) {
			t.Errorf("index %d: %v / root %x", index, err, got)
		}
	}
	// d0's path in the RFC example is [b, h, l]: the sibling leaf, the
	// next subtree, then the right half.
	if len(tree.path(0, 0, 7)) != 3 || len(tree.path(6, 0, 7)) != 2 {
		t.Error("path lengths do not match the RFC 9162 example")
	}
}

// The key the vectors are signed with is derived from a seed, so an
// implementer can reproduce the signatures and not only check them.
func TestDeterministicKeyFromSeed(t *testing.T) {
	var seed [ed25519.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	a := ed25519.NewKeyFromSeed(seed[:])
	b := ed25519.NewKeyFromSeed(seed[:])
	if !bytes.Equal(a, b) {
		t.Fatal("the same seed produced different keys")
	}
}
