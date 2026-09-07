package cose

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// COSE Receipts, as RFC 9942 defines them, over the RFC9162_SHA256
// verifiable data structure — the profile RFC 9943 requires of a SCITT
// transparency service.
//
// A COSE Receipt is a COSE_Sign1 signed by the log. Its protected header
// says which data structure the log is (label 395, "vds"); its unprotected
// header carries the proof (label 396, "vdp"); and its payload is detached
// and is the Merkle root the proof arrives at. The verifier recomputes the
// root from the entry they hold and the proof, then checks the signature
// with that root as the payload. If the entry is not in the log, no root
// the log ever signed comes out, and the signature fails.
//
// # What an entry is, in this profile
//
// RFC 9942 says a verifier applies the proof "to the bytes of a candidate
// entry" and leaves it to the profile to say what those bytes are. Here
// they are the receipt digest — receipt.Digest, the lowercase hex SHA-256
// of the receipt's signing input — as 64 ASCII bytes. Not the raw 32
// bytes, and not the Signed Statement: the log stores digests so that
// publishing it reveals nothing about who governed what, and the leaf is
// hashed from exactly the string the log stores. The leaf hash is
// SHA-256(0x00 || those 64 bytes), as RFC 9162 section 2.1 requires.

// Header labels from RFC 9942.
const (
	// labelReceipts is where a Signed Statement carries its receipts to
	// become a Transparent Statement. Unprotected, because a receipt is
	// added after the statement is signed and the signature must not
	// change when one is.
	labelReceipts = 394

	// labelVDS names the verifiable data structure. Protected: it is what
	// tells a verifier how to read the proof, and a proof read under the
	// wrong rules could reconstruct anything.
	labelVDS = 395

	// labelVDP carries the proofs, keyed by proof type. Unprotected,
	// because the signature covers the root the proof arrives at, and a
	// proof that was altered simply arrives somewhere else.
	labelVDP = 396
)

// vdsRFC9162SHA256 is the registered identifier for a SHA-256 binary
// Merkle tree as RFC 9162 section 2.1 defines it (RFC 9942 table 2).
const vdsRFC9162SHA256 = 1

// Proof types within the vdp map for RFC9162_SHA256 (RFC 9942 section 5).
const (
	proofInclusion   = -1
	proofConsistency = -2
)

// InclusionProof is an RFC 9162 audit path for one entry at one tree size.
type InclusionProof struct {
	TreeSize  uint64
	LeafIndex uint64

	// Path is the sibling hashes from the leaf towards the root, each 32
	// bytes.
	Path [][]byte
}

// ConsistencyProof relates the log at one size to the log at a larger one.
type ConsistencyProof struct {
	FromSize uint64
	ToSize   uint64
	Path     [][]byte
}

// SignInclusionReceipt issues a COSE Receipt proving that an entry is in
// the log at proof.TreeSize, whose root is root.
//
// logID becomes the issuer claim and subject the subject claim, both in
// the protected header as RFC 9943 requires of a receipt. The payload is
// detached; what is signed is the root.
func SignInclusionReceipt(signer receipt.Signer, logID, subject string, proof InclusionProof, root []byte) ([]byte, error) {
	if len(root) != hashSize {
		return nil, fmt.Errorf("cose: the root is %d bytes, not %d", len(root), hashSize)
	}
	if proof.LeafIndex >= proof.TreeSize {
		return nil, fmt.Errorf("cose: leaf index %d is outside a tree of size %d", proof.LeafIndex, proof.TreeSize)
	}
	path, err := encodePath(proof.Path)
	if err != nil {
		return nil, err
	}
	if len(path) != inclusionPathLength(proof.LeafIndex, proof.TreeSize) {
		// Issuing a proof of the wrong shape would produce a receipt that
		// can never verify, signed by us. Better refused here than
		// explained later.
		return nil, fmt.Errorf("cose: %d path nodes where %d are needed for index %d of %d",
			len(path), inclusionPathLength(proof.LeafIndex, proof.TreeSize), proof.LeafIndex, proof.TreeSize)
	}

	content := Encode(Array{Uint(proof.TreeSize), Uint(proof.LeafIndex), path})
	return Sign1With(signer, root, Sign1Options{
		Claims:    &Claims{Issuer: logID, Subject: subject},
		Detached:  true,
		Protected: Map{{Key: Uint(labelVDS), Value: Uint(vdsRFC9162SHA256)}},
		Unprotected: Map{{Key: Uint(labelVDP), Value: Map{
			{Key: Int(proofInclusion), Value: Array{Bytes(content)}},
		}}},
	})
}

// SignConsistencyReceipt issues a COSE Receipt proving that the log at
// proof.FromSize is a prefix of the log at proof.ToSize, whose root is
// newRoot. The subject claim is the log itself, since that is what a
// consistency proof is about.
func SignConsistencyReceipt(signer receipt.Signer, logID string, proof ConsistencyProof, newRoot []byte) ([]byte, error) {
	if len(newRoot) != hashSize {
		return nil, fmt.Errorf("cose: the root is %d bytes, not %d", len(newRoot), hashSize)
	}
	if proof.FromSize == 0 || proof.FromSize >= proof.ToSize {
		// See consistencyRoots: RFC 9162 defines these proofs as empty
		// and its verifier rejects an empty path, so a receipt for them
		// could not be checked by anyone.
		return nil, fmt.Errorf("cose: a consistency receipt relates a smaller tree to a larger one, not %d to %d",
			proof.FromSize, proof.ToSize)
	}
	path, err := encodePath(proof.Path)
	if err != nil {
		return nil, err
	}
	if len(path) == 0 {
		return nil, errors.New("cose: a consistency proof between different sizes is never empty")
	}

	content := Encode(Array{Uint(proof.FromSize), Uint(proof.ToSize), path})
	return Sign1With(signer, newRoot, Sign1Options{
		Claims:    &Claims{Issuer: logID, Subject: logID},
		Detached:  true,
		Protected: Map{{Key: Uint(labelVDS), Value: Uint(vdsRFC9162SHA256)}},
		Unprotected: Map{{Key: Uint(labelVDP), Value: Map{
			{Key: Int(proofConsistency), Value: Array{Bytes(content)}},
		}}},
	})
}

func encodePath(path [][]byte) (Array, error) {
	out := make(Array, 0, len(path))
	for i, node := range path {
		if len(node) != hashSize {
			return nil, fmt.Errorf("cose: path node %d is %d bytes, not %d", i, len(node), hashSize)
		}
		out = append(out, Bytes(node))
	}
	return out, nil
}

// VerifyInclusionReceipt checks a COSE Receipt against the entry the
// caller holds, and returns the tree size it was issued at and the root it
// reconstructs.
//
// This is the two-step verification of RFC 9942 section 5.2.1: apply the
// proof to the entry to get a root, then verify the signature with that
// root as the payload. The root in the receipt, if the log attached one,
// is never trusted — it must equal what the proof produces, or the receipt
// is refused as inconsistent with itself.
//
// A receipt may carry several inclusion proofs; it verifies if any of them
// leads from this entry to a root the log signed.
func VerifyInclusionReceipt(receiptBytes, entry []byte, keys receipt.KeyResolver) (treeSize uint64, root []byte, err error) {
	s, proofs, err := parseReceipt(receiptBytes, proofInclusion)
	if err != nil {
		return 0, nil, err
	}

	leaf := leafHash(entry)
	var last error
	for _, raw := range proofs {
		proof, err := decodeInclusionProof(raw)
		if err != nil {
			last = err
			continue
		}
		candidate, err := inclusionRoot(leaf, proof.LeafIndex, proof.TreeSize, proof.Path)
		if err != nil {
			last = err
			continue
		}
		if !s.detached && !bytes.Equal(s.payload, candidate) {
			last = fmt.Errorf("%w: the receipt carries a root the proof does not arrive at", ErrProof)
			continue
		}
		if _, err := s.verify(candidate, keys); err != nil {
			last = err
			continue
		}
		return proof.TreeSize, candidate, nil
	}
	return 0, nil, last
}

// VerifyConsistencyReceipt checks a COSE Receipt against the older root
// the caller holds, and returns the two sizes it relates and the newer
// root the log signed.
func VerifyConsistencyReceipt(receiptBytes, oldRoot []byte, keys receipt.KeyResolver) (fromSize, toSize uint64, newRoot []byte, err error) {
	s, proofs, err := parseReceipt(receiptBytes, proofConsistency)
	if err != nil {
		return 0, 0, nil, err
	}

	var last error
	for _, raw := range proofs {
		proof, err := decodeConsistencyProof(raw)
		if err != nil {
			last = err
			continue
		}
		_, candidate, err := consistencyRoots(proof.FromSize, proof.ToSize, proof.Path, oldRoot)
		if err != nil {
			last = err
			continue
		}
		if !s.detached && !bytes.Equal(s.payload, candidate) {
			last = fmt.Errorf("%w: the receipt carries a root the proof does not arrive at", ErrProof)
			continue
		}
		if _, err := s.verify(candidate, keys); err != nil {
			last = err
			continue
		}
		return proof.FromSize, proof.ToSize, candidate, nil
	}
	return 0, 0, nil, last
}

// parseReceipt parses a COSE Receipt and returns the encoded proofs of one
// type from its unprotected header.
func parseReceipt(receiptBytes []byte, proofType int64) (*sign1, []Bytes, error) {
	s, err := parseSign1(receiptBytes)
	if err != nil {
		return nil, nil, err
	}
	if !s.header.hasVDS {
		// Without it the proof has no defined reading. RFC 9942 puts the
		// identifier in the protected header so the signature covers
		// which rules the verifier is to apply.
		return nil, nil, fmt.Errorf("%w: the protected header names no verifiable data structure", ErrMalformed)
	}
	if s.header.vds != vdsRFC9162SHA256 {
		return nil, nil, fmt.Errorf("cose: verifiable data structure %d is not RFC9162_SHA256", s.header.vds)
	}

	vdp, ok := s.unprotected.get(Uint(labelVDP))
	if !ok {
		return nil, nil, fmt.Errorf("%w: the receipt carries no proofs", ErrMalformed)
	}
	byType, ok := vdp.(Map)
	if !ok {
		return nil, nil, fmt.Errorf("%w: the proofs header is not a map", ErrMalformed)
	}
	list, ok := byType.get(Int(proofType))
	if !ok {
		return nil, nil, fmt.Errorf("%w: the receipt carries no proof of type %d", ErrMalformed, proofType)
	}
	items, ok := list.(Array)
	if !ok || len(items) == 0 {
		return nil, nil, fmt.Errorf("%w: proofs of type %d are not a non-empty array", ErrMalformed, proofType)
	}
	proofs := make([]Bytes, 0, len(items))
	for _, item := range items {
		raw, ok := item.(Bytes)
		if !ok {
			return nil, nil, fmt.Errorf("%w: a proof is not a byte string", ErrMalformed)
		}
		proofs = append(proofs, raw)
	}
	return s, proofs, nil
}

// decodeProofContent reads the [uint, uint, [+ bstr]] shape both proof
// types share.
func decodeProofContent(raw []byte) (first, second uint64, path [][]byte, err error) {
	value, rest, err := decodeValue(raw)
	if err != nil {
		return 0, 0, nil, err
	}
	if len(rest) != 0 {
		return 0, 0, nil, fmt.Errorf("%w: trailing data after the proof", ErrMalformed)
	}
	parts, ok := value.(Array)
	if !ok || len(parts) != 3 {
		return 0, 0, nil, fmt.Errorf("%w: a proof has three elements", ErrMalformed)
	}
	a, ok := parts[0].(Uint)
	if !ok {
		return 0, 0, nil, fmt.Errorf("%w: proof tree size is not an unsigned integer", ErrMalformed)
	}
	b, ok := parts[1].(Uint)
	if !ok {
		return 0, 0, nil, fmt.Errorf("%w: proof position is not an unsigned integer", ErrMalformed)
	}
	nodes, ok := parts[2].(Array)
	if !ok {
		return 0, 0, nil, fmt.Errorf("%w: proof path is not an array", ErrMalformed)
	}
	for _, n := range nodes {
		node, ok := n.(Bytes)
		if !ok {
			return 0, 0, nil, fmt.Errorf("%w: proof path node is not a byte string", ErrMalformed)
		}
		path = append(path, node)
	}
	return uint64(a), uint64(b), path, nil
}

func decodeInclusionProof(raw []byte) (InclusionProof, error) {
	size, index, path, err := decodeProofContent(raw)
	if err != nil {
		return InclusionProof{}, err
	}
	return InclusionProof{TreeSize: size, LeafIndex: index, Path: path}, nil
}

func decodeConsistencyProof(raw []byte) (ConsistencyProof, error) {
	from, to, path, err := decodeProofContent(raw)
	if err != nil {
		return ConsistencyProof{}, err
	}
	return ConsistencyProof{FromSize: from, ToSize: to, Path: path}, nil
}

// AttachReceipts adds COSE Receipts to a Signed Statement's unprotected
// header under label 394, making it a Transparent Statement (RFC 9943
// section 7). Receipts already present are kept.
//
// The signature is untouched, and must be: it covers the protected header
// and the payload, and the unprotected header is outside both. That is the
// whole reason receipts go there — a log that could only prove inclusion
// by re-signing the statement would be a log that could re-sign it.
func AttachReceipts(signedStatement []byte, receipts [][]byte) ([]byte, error) {
	value, rest, err := decodeValue(signedStatement)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing data after the structure", ErrMalformed)
	}
	tagged, ok := value.(Tag)
	if !ok || tagged.Number != tagSign1 {
		return nil, fmt.Errorf("%w: not a COSE_Sign1", ErrMalformed)
	}
	parts, ok := tagged.Value.(Array)
	if !ok || len(parts) != 4 {
		return nil, fmt.Errorf("%w: a COSE_Sign1 has four elements", ErrMalformed)
	}
	unprotected, ok := parts[1].(Map)
	if !ok {
		return nil, fmt.Errorf("%w: unprotected headers are not a map", ErrMalformed)
	}

	var list Array
	if existing, ok := unprotected.get(Uint(labelReceipts)); ok {
		list, ok = existing.(Array)
		if !ok {
			return nil, fmt.Errorf("%w: the receipts header is not an array", ErrMalformed)
		}
	}
	for i, r := range receipts {
		// Checked for shape only. Verifying would need the log's key,
		// and the party attaching a receipt is usually not the party who
		// will check it.
		if _, err := parseSign1(r); err != nil {
			return nil, fmt.Errorf("cose: receipt %d: %w", i, err)
		}
		list = append(list, Bytes(r))
	}
	if len(list) == 0 {
		return nil, errors.New("cose: no receipts to attach")
	}

	// Re-encoding the unprotected header is safe because it is outside
	// the signature; the protected header and payload are carried through
	// as the exact byte strings they were.
	parts[1] = unprotected.set(Uint(labelReceipts), list)
	return Encode(Tag{Number: tagSign1, Value: parts}), nil
}

// Receipts returns the COSE Receipts attached to a Transparent Statement,
// in order, or none for a Signed Statement that has not been registered.
func Receipts(signedStatement []byte) ([][]byte, error) {
	s, err := parseSign1(signedStatement)
	if err != nil {
		return nil, err
	}
	value, ok := s.unprotected.get(Uint(labelReceipts))
	if !ok {
		return nil, nil
	}
	list, ok := value.(Array)
	if !ok {
		return nil, fmt.Errorf("%w: the receipts header is not an array", ErrMalformed)
	}
	out := make([][]byte, 0, len(list))
	for _, item := range list {
		raw, ok := item.(Bytes)
		if !ok {
			return nil, fmt.Errorf("%w: a receipt is not a byte string", ErrMalformed)
		}
		out = append(out, raw)
	}
	return out, nil
}
