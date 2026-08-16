// Package anchor obtains external timestamp proofs for receipts.
//
// A signed receipt proves what happened and that it has not been altered.
// It does not prove *when* — the issuance time is a field the issuer wrote,
// and an issuer able to backdate receipts can manufacture a history.
//
// An anchor closes that gap by binding a receipt's digest to a time
// attested by someone else. The IETF compliance profile for signed action
// receipts requires at least one anchoring mechanism for this reason.
//
// Two mechanisms, with different trust properties:
//
//	RFC 3161         A timestamp authority signs the digest. Fast, and the
//	                 answer enterprise auditors already accept. Requires
//	                 trusting the authority.
//	OpenTimestamps   The digest is committed into a public blockchain. No
//	                 trusted party, but confirmation takes hours.
//
// They are complements rather than alternatives, which is why the receipt
// schema carries a list. Anchoring with both means an auditor who distrusts
// the authority still has the independent proof, and vice versa.
//
// # Anchors arrive after signing
//
// An anchor commits to a signed receipt, so it cannot be inside the
// signature — that would be circular. Anchors are therefore excluded from
// the signing input and attached afterwards, which is why attaching one
// never invalidates a receipt.
package anchor

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// Anchorer obtains a timestamp proof for a digest.
//
// Implementations must be safe for concurrent use and must respect context
// cancellation: anchoring happens off the request path, but a hung anchorer
// still leaks goroutines and connections.
type Anchorer interface {
	// Type reports which mechanism this anchorer implements.
	Type() receipt.AnchorType

	// Anchor obtains a proof binding digest to a point in time. digest is
	// the raw hash bytes, not hex.
	Anchor(ctx context.Context, digest []byte) (*receipt.Anchor, error)
}

// ErrNoAnchorers is returned when anchoring is attempted with none
// configured.
var ErrNoAnchorers = errors.New("anchor: no anchorers configured")

// Set anchors with several mechanisms at once.
type Set struct {
	// Anchorers are tried in order. All are attempted regardless of
	// individual failure.
	Anchorers []Anchorer

	// RequireAll makes AnchorAll fail if any anchorer fails.
	//
	// Off by default. A receipt with one anchor is materially better than a
	// receipt with none, and a transient outage at one authority should not
	// discard a proof another already provided.
	RequireAll bool
}

// AnchorAll obtains proofs from every configured anchorer.
//
// Returns the anchors that succeeded and a joined error describing those
// that did not, so a caller can record partial success rather than choosing
// between all and nothing.
func (s *Set) AnchorAll(ctx context.Context, digest []byte) ([]receipt.Anchor, error) {
	if len(s.Anchorers) == 0 {
		return nil, ErrNoAnchorers
	}

	var (
		anchors []receipt.Anchor
		errs    []error
	)
	for _, a := range s.Anchorers {
		got, err := a.Anchor(ctx, digest)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", a.Type(), err))
			continue
		}
		anchors = append(anchors, *got)
	}

	joined := errors.Join(errs...)
	if s.RequireAll && joined != nil {
		return anchors, joined
	}
	if len(anchors) == 0 {
		return nil, joined
	}
	return anchors, nil
}

// AttachTo anchors a receipt and appends the proofs to it.
//
// The receipt must already be signed: an anchor commits to the signed form,
// so anchoring an unsigned receipt would bind a value that is about to
// change.
func AttachTo(ctx context.Context, r *receipt.Receipt, s *Set) error {
	if r.Signature == nil {
		return errors.New("anchor: receipt must be signed before anchoring")
	}

	digest, err := receipt.Digest(r)
	if err != nil {
		return fmt.Errorf("anchor: computing receipt digest: %w", err)
	}
	raw, err := decodeHex(digest)
	if err != nil {
		return err
	}

	anchors, err := s.AnchorAll(ctx, raw)
	if err != nil && len(anchors) == 0 {
		return err
	}
	r.Anchors = append(r.Anchors, anchors...)
	return nil
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("anchor: digest %q has an odd length", s)
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		hi, err := hexVal(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexVal(s[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("anchor: %q is not a hex digit", c)
}

// newAnchor builds a receipt anchor from a raw proof token.
func newAnchor(t receipt.AnchorType, token []byte, at time.Time) *receipt.Anchor {
	return &receipt.Anchor{
		Type:       t,
		Value:      base64.StdEncoding.EncodeToString(token),
		AnchoredAt: receipt.FormatTime(at),
	}
}
