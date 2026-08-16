package receipt

import (
	"fmt"
)

// Chaining exists to make deletion detectable.
//
// A standalone signed receipt proves that an action occurred and was
// governed. It proves nothing about what is missing. An operator who
// discards the receipts they dislike leaves a record that is individually
// perfect and collectively false — which is precisely the failure mode an
// auditor or underwriter is trying to rule out.
//
// Each receipt commits to the digest of its predecessor's signing input, so
// removing one receipt breaks every receipt after it. The operator's choice
// becomes visible: publish the whole chain, or publish an obviously broken
// one.
//
// This does not defend against an operator who never issues a receipt in the
// first place. That gap is closed by coverage enforcement outside the
// receipt format, and by an external transparency service that witnesses
// chain heads independently.

// ChainBuilder issues receipts in sequence for a single chain ID.
//
// It is not safe for concurrent use. A chain is inherently ordered, so
// serialise access to it — typically one builder per workspace or session,
// behind that workspace's own lock, or fed by a single writer goroutine.
type ChainBuilder struct {
	chainID  string
	seq      uint64
	prevHash string
	signer   Signer
	started  bool
}

// NewChainBuilder starts a fresh chain at sequence zero.
func NewChainBuilder(chainID string, signer Signer) (*ChainBuilder, error) {
	if chainID == "" {
		return nil, fmt.Errorf("receipt: chain ID must not be empty")
	}
	if signer == nil {
		return nil, fmt.Errorf("receipt: signer must not be nil")
	}
	return &ChainBuilder{chainID: chainID, signer: signer}, nil
}

// ResumeChainBuilder continues an existing chain after a restart.
//
// nextSeq is the sequence number to assign to the next receipt, and
// headDigest is the digest of the most recently issued receipt. Both come
// from durable storage: resuming from stale values forks the chain, which a
// verifier will report as a break.
//
// A chain that has only its genesis receipt outstanding resumes with
// nextSeq 1 and the genesis receipt's digest.
func ResumeChainBuilder(chainID string, signer Signer, nextSeq uint64, headDigest string) (*ChainBuilder, error) {
	b, err := NewChainBuilder(chainID, signer)
	if err != nil {
		return nil, err
	}
	if nextSeq == 0 {
		if headDigest != "" {
			return nil, fmt.Errorf("receipt: cannot resume at seq 0 with a head digest; seq 0 is the genesis position")
		}
		return b, nil
	}
	if !isHexDigest(headDigest) {
		return nil, fmt.Errorf("receipt: head digest must be a lowercase hex SHA-256 digest")
	}
	b.seq = nextSeq
	b.prevHash = headDigest
	b.started = true
	return b, nil
}

// ChainID returns the chain this builder issues into.
func (b *ChainBuilder) ChainID() string { return b.chainID }

// NextSeq returns the sequence number the next issued receipt will carry.
func (b *ChainBuilder) NextSeq() uint64 { return b.seq }

// Head returns the digest of the most recently issued receipt, or the empty
// string if none has been issued.
//
// Persist this alongside NextSeq. Together they are the entire state needed
// to resume the chain, and losing them means starting a new chain rather
// than continuing this one.
func (b *ChainBuilder) Head() string { return b.prevHash }

// Issue populates r's chain position, signs it, and advances the builder.
//
// The caller supplies every field except Chain, Version, and Signature.
// Issue overwrites Chain wholesale: a caller-supplied chain position would
// let a bug or a malicious caller rewrite history by reusing a sequence
// number.
//
// The builder advances only on success. A receipt that fails validation
// leaves the chain untouched, so the next call reuses the same position
// rather than opening a permanent gap that a verifier would report as a
// missing receipt.
func (b *ChainBuilder) Issue(r *Receipt) error {
	r.Chain = Chain{
		ID:       b.chainID,
		Seq:      b.seq,
		PrevHash: b.prevHash,
	}

	if err := Sign(r, b.signer); err != nil {
		return err
	}

	digest, err := Digest(r)
	if err != nil {
		// Unreachable in practice: Sign already canonicalised this receipt
		// successfully. Roll back the signature anyway so the caller is not
		// handed a signed receipt whose chain state was never committed.
		r.Signature = nil
		return err
	}

	b.prevHash = digest
	b.seq++
	b.started = true
	return nil
}

// ChainResult reports the outcome of verifying a sequence of receipts.
type ChainResult struct {
	// ChainID is the chain that was verified.
	ChainID string

	// Length is the number of receipts verified.
	Length int

	// Head is the digest of the last receipt in the sequence.
	Head string

	// Results holds the per-receipt verification results, in order.
	Results []*Result

	// Degraded counts receipts whose governance was not full strength.
	// A chain can be cryptographically perfect and still contain windows
	// where governance was partial; surfacing the count keeps that visible
	// rather than averaging it away.
	Degraded int

	// Bypassed counts receipts where governance did not run at all.
	Bypassed int
}

// VerifyChain verifies a contiguous run of receipts and their links.
//
// receipts must be ordered by sequence and belong to one chain. The run need
// not start at genesis — verifying a window of a long chain is the common
// case — but it must be contiguous, because a gap is indistinguishable from
// a deletion.
//
// Verification stops at the first problem and reports its position, so a
// caller can point at the exact receipt that broke rather than reporting
// that something, somewhere, is wrong.
func VerifyChain(receipts []*Receipt, keys KeyResolver, opts VerifyOptions) (*ChainResult, error) {
	if len(receipts) == 0 {
		return nil, fmt.Errorf("receipt: no receipts to verify")
	}

	chainID := receipts[0].Chain.ID
	out := &ChainResult{
		ChainID: chainID,
		Length:  len(receipts),
		Results: make([]*Result, 0, len(receipts)),
	}

	var prevDigest string
	for i, r := range receipts {
		if r == nil {
			return nil, fmt.Errorf("receipt: nil receipt at position %d", i)
		}
		if r.Chain.ID != chainID {
			return nil, fmt.Errorf("%w: position %d belongs to chain %q, expected %q",
				ErrChainMixed, i, r.Chain.ID, chainID)
		}

		// Sequence continuity. The first receipt establishes the starting
		// position; every subsequent one must be exactly one higher.
		if i > 0 {
			want := receipts[i-1].Chain.Seq + 1
			if r.Chain.Seq != want {
				return nil, fmt.Errorf("%w: position %d has seq %d, expected %d",
					ErrChainDiscontinuous, i, r.Chain.Seq, want)
			}
		}

		res, err := Verify(r, keys, opts)
		if err != nil {
			return nil, fmt.Errorf("receipt: position %d (seq %d): %w", i, r.Chain.Seq, err)
		}

		// Link integrity. Checked after signature verification, because a
		// prev_hash from an unverified receipt is not yet evidence of
		// anything.
		if i > 0 && r.Chain.PrevHash != prevDigest {
			return nil, fmt.Errorf("%w: position %d (seq %d) commits to %s but its predecessor digests to %s",
				ErrChainBroken, i, r.Chain.Seq, r.Chain.PrevHash, prevDigest)
		}

		switch r.Governance.Mode {
		case ModeDegraded:
			out.Degraded++
		case ModeBypassed:
			out.Bypassed++
		}

		out.Results = append(out.Results, res)
		prevDigest = res.Digest
	}

	out.Head = prevDigest
	return out, nil
}
