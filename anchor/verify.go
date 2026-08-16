package anchor

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// Anchors were being produced correctly and consumed on trust.
//
// The issuer checks that a timestamp token commits to the receipt's digest
// before attaching it, which is right, but no verifier ever checked it
// again. A receipt reaching an auditor carried a token nobody re-examined,
// so a token issued for entirely different content — or an arbitrary blob —
// would have been reported as an anchored receipt.
//
// That inverts the point of anchoring. An anchor exists because the
// issuer's own clock is not evidence; taking the issuer's word that the
// anchor is genuine puts the trust straight back where it started.
//
// Worse, the anchor list sits outside the receipt's signature — necessarily,
// since an anchor commits to the signed receipt and the two cannot commit
// to each other. So anchored_at is the one field in a receipt that anybody
// can edit without breaking a signature, and until now nothing compared it
// to the time inside the token.

// AnchorResult reports what a timestamp token actually says.
type AnchorResult struct {
	// Type is the anchor scheme checked.
	Type receipt.AnchorType

	// GenTime is the time inside the token, as stated by the authority.
	// This is the value to rely on — not the receipt's anchored_at field,
	// which is outside the signature and outside the token.
	GenTime time.Time

	// ClaimedAt is the receipt's own anchored_at, kept so a caller can see
	// the two together.
	ClaimedAt time.Time

	// Authority is the token's stated policy OID, when it carries one.
	Authority string

	// SerialNumber identifies the token at the authority, which is what an
	// auditor quotes when asking them to confirm it.
	SerialNumber string
}

// Skew reports how far the receipt's claimed anchor time is from the time
// inside the token.
func (r AnchorResult) Skew() time.Duration {
	if r.ClaimedAt.IsZero() {
		return 0
	}
	d := r.ClaimedAt.Sub(r.GenTime)
	if d < 0 {
		return -d
	}
	return d
}

// Errors returned when an anchor cannot be trusted.
var (
	// ErrAnchorDigestMismatch means the token commits to different content.
	// The most important failure here: a token that is entirely genuine but
	// belongs to another receipt.
	ErrAnchorDigestMismatch = errors.New("anchor: the timestamp token commits to different content")

	// ErrAnchorUnsupported means the anchor type is one this build cannot
	// check. Reported rather than ignored: an unchecked anchor must never
	// be mistaken for a checked one.
	ErrAnchorUnsupported = errors.New("anchor: unsupported anchor type")
)

// MaxAnchorSkew is how far a receipt's claimed anchor time may sit from the
// time the authority recorded.
//
// Generous, because the claim is written after the round trip completes and
// a slow authority legitimately widens the gap. Anything beyond this is not
// latency; it is a receipt asserting an anchor time the token does not
// support.
const MaxAnchorSkew = 5 * time.Minute

// Verify checks that an anchor genuinely timestamps the given digest.
//
// # What this proves, and what it does not
//
// It proves the token commits to exactly this digest, that it is a
// well-formed RFC 3161 timestamp, and what time the authority recorded.
// That is the check that catches a token borrowed from another receipt or
// invented outright.
//
// It does not validate the authority's certificate chain, so it does not by
// itself prove that a trusted authority issued the token rather than
// someone with a self-signed certificate. Doing so needs a trust store,
// which would put a policy decision — whose timestamps count — inside a
// package whose whole purpose is to avoid making those decisions for the
// reader. The serial number and time are returned so an auditor can put the
// question to the authority directly.
//
// Stating the limit is the point. An anchor that is silently half-checked
// is worse than one that is not checked at all, because it reads as
// stronger evidence than it is.
func Verify(a *receipt.Anchor, digest []byte) (*AnchorResult, error) {
	if a == nil {
		return nil, errors.New("anchor: nil anchor")
	}
	if len(digest) == 0 {
		return nil, errors.New("anchor: a digest is required to check what the token commits to")
	}
	if a.Type != receipt.AnchorRFC3161 {
		return nil, fmt.Errorf("%w: %s", ErrAnchorUnsupported, a.Type)
	}

	token, err := base64.StdEncoding.DecodeString(a.Value)
	if err != nil {
		return nil, fmt.Errorf("anchor: token is not valid base64: %w", err)
	}

	info, err := parseTSTInfo(token)
	if err != nil {
		return nil, err
	}

	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return nil, fmt.Errorf("anchor: token uses hash algorithm %v, expected SHA-256",
			info.MessageImprint.HashAlgorithm.Algorithm)
	}
	// The entire value of an anchor rests on this comparison. A token for
	// other content is perfectly valid and says nothing whatsoever about
	// this receipt.
	if !bytes.Equal(info.MessageImprint.HashedMessage, digest) {
		return nil, ErrAnchorDigestMismatch
	}

	out := &AnchorResult{
		Type:    a.Type,
		GenTime: info.GenTime.UTC(),
	}
	if info.SerialNumber != nil {
		out.SerialNumber = info.SerialNumber.String()
	}
	if len(info.Policy) > 0 {
		out.Authority = info.Policy.String()
	}
	if a.AnchoredAt != "" {
		if claimed, err := receipt.ParseTime(a.AnchoredAt); err == nil {
			out.ClaimedAt = claimed.UTC()
		}
	}
	return out, nil
}

// VerifyAll checks every anchor on a receipt against its own digest.
//
// Returns one result per anchor, and an error naming the first that failed.
// A receipt with several anchors is claiming several independent
// attestations of its time, so one bad token is a failure of the receipt
// rather than something to average away.
func VerifyAll(r *receipt.Receipt) ([]AnchorResult, error) {
	if r == nil {
		return nil, errors.New("anchor: nil receipt")
	}
	if len(r.Anchors) == 0 {
		return nil, nil
	}

	// Recomputed from the receipt rather than taken as a parameter, using
	// the same function that produced the digest when the anchor was
	// obtained. A digest handed in could be pointed at the wrong bytes, and
	// the check would then pass while proving nothing.
	hexDigest, err := receipt.Digest(r)
	if err != nil {
		return nil, fmt.Errorf("anchor: computing the receipt digest: %w", err)
	}
	digest, err := decodeHex(hexDigest)
	if err != nil {
		return nil, err
	}

	out := make([]AnchorResult, 0, len(r.Anchors))
	for i := range r.Anchors {
		res, err := Verify(&r.Anchors[i], digest)
		if err != nil {
			return out, fmt.Errorf("anchor %d of %d: %w", i+1, len(r.Anchors), err)
		}
		if skew := res.Skew(); skew > MaxAnchorSkew {
			// anchored_at is outside the signature, so it is the one field
			// an attacker can rewrite freely. Disagreement with the token
			// is reported rather than tolerated, because the token is the
			// evidence and the field is only a convenience.
			return out, fmt.Errorf("anchor %d of %d: the receipt claims it was anchored at %s but the authority recorded %s, %s apart",
				i+1, len(r.Anchors), res.ClaimedAt.Format(time.RFC3339),
				res.GenTime.Format(time.RFC3339), skew.Round(time.Second))
		}
		out = append(out, *res)
	}
	return out, nil
}
