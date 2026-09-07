package cose

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// The RFC 9162 proof arithmetic, for verifying COSE Receipts.
//
// This duplicates what the transparency package does when it issues a
// proof, and the duplication is deliberate. The transparency package
// imports this one to sign its receipts, so this one cannot import it
// back; and a verifier holding a receipt and a public key must not need
// the log's own package to check it — the point of the receipt is that
// the log is not in the room. Both implementations are run against each
// other in the transparency tests, so they cannot drift apart unnoticed.

// Domain separation prefixes from RFC 9162 section 2.1: a leaf is hashed
// under 0x00 and an internal node under 0x01, so a subtree can never be
// passed off as an entry.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// hashSize is the digest length of RFC9162_SHA256, the only verifiable
// data structure this package understands.
const hashSize = sha256.Size

// ErrProof means a proof does not lead from the entry to a root the log
// signed. Either the entry is not in the log at that size, or the proof
// was not issued for it.
var ErrProof = errors.New("cose: the proof does not reconstruct a root the log signed")

// leafHash returns MTH({entry}) = SHA-256(0x00 || entry).
func leafHash(entry []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(entry)
	return h.Sum(nil)
}

// nodeHash returns SHA-256(0x01 || left || right).
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// inclusionRoot applies an inclusion path to a leaf hash, per RFC 9162
// section 2.1.3.2, and returns the root it arrives at.
//
// Only the arithmetic; comparing the result to a root is the caller's
// job, because in a COSE Receipt there is no root to compare against —
// the result becomes the payload the signature is checked over.
func inclusionRoot(leaf []byte, index, size uint64, path [][]byte) ([]byte, error) {
	if size == 0 || index >= size {
		return nil, fmt.Errorf("%w: leaf index %d is outside a tree of size %d", ErrProof, index, size)
	}
	// The path length is fixed by the index and size, so a path of any
	// other length is malformed. Checked before hashing so a hostile
	// proof cannot steer the reconstruction.
	if want := inclusionPathLength(index, size); len(path) != want {
		return nil, fmt.Errorf("%w: %d path nodes where %d are needed", ErrProof, len(path), want)
	}
	for i, node := range path {
		if len(node) != hashSize {
			return nil, fmt.Errorf("%w: path node %d is %d bytes, not %d", ErrProof, i, len(node), hashSize)
		}
	}

	r := leaf
	fn, sn := index, size-1
	for _, p := range path {
		if sn == 0 {
			return nil, fmt.Errorf("%w: more path nodes than the tree can hold", ErrProof)
		}
		if fn%2 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil, fmt.Errorf("%w: the path ended before the root", ErrProof)
	}
	return r, nil
}

// inclusionPathLength returns the exact audit path length for an index in
// a tree of the given size.
func inclusionPathLength(index, size uint64) int {
	if size <= 1 {
		return 0
	}
	length := 0
	fn, sn := index, size-1
	for sn > 0 {
		if fn%2 == 1 || fn != sn {
			length++
		}
		fn >>= 1
		sn >>= 1
	}
	return length
}

// consistencyRoots applies a consistency path per RFC 9162 section
// 2.1.4.2 and returns the two roots it reconstructs: the older, which the
// caller compares with what they hold, and the newer, which becomes the
// receipt's payload.
//
// Neither the empty old tree nor equal sizes are handled here. RFC 9162
// defines both proofs as empty, and its verification algorithm rejects an
// empty path outright; a consistency receipt for either case would be a
// signature over a root the proof does nothing to establish, which is
// what a signed tree head is for.
func consistencyRoots(from, to uint64, path [][]byte, oldRoot []byte) (old, new []byte, err error) {
	if from == 0 || from >= to {
		return nil, nil, fmt.Errorf("%w: a consistency proof relates a smaller tree to a larger one, not %d to %d", ErrProof, from, to)
	}
	if len(oldRoot) != hashSize {
		return nil, nil, fmt.Errorf("%w: the older root is %d bytes, not %d", ErrProof, len(oldRoot), hashSize)
	}
	if len(path) == 0 {
		return nil, nil, fmt.Errorf("%w: the consistency path is empty", ErrProof)
	}
	for i, node := range path {
		if len(node) != hashSize {
			return nil, nil, fmt.Errorf("%w: path node %d is %d bytes, not %d", ErrProof, i, len(node), hashSize)
		}
	}

	// When the old size is a power of two its root is a complete subtree
	// of the new one, and the proof leaves it out because the verifier
	// already holds it.
	nodes := path
	if from&(from-1) == 0 {
		nodes = append([][]byte{oldRoot}, path...)
	}

	fn, sn := from-1, to-1
	for fn%2 == 1 {
		fn >>= 1
		sn >>= 1
	}

	fr, sr := nodes[0], nodes[0]
	for _, c := range nodes[1:] {
		if sn == 0 {
			return nil, nil, fmt.Errorf("%w: more path nodes than the tree can hold", ErrProof)
		}
		if fn%2 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil, nil, fmt.Errorf("%w: the path ended before the root", ErrProof)
	}
	if !bytes.Equal(fr, oldRoot) {
		return nil, nil, fmt.Errorf("%w: the older root is not the one held", ErrProof)
	}
	return fr, sr, nil
}
