package receipt

import (
	"errors"
	"strings"
)

// Sentinel errors returned by verification. Callers should match on these
// with errors.Is rather than comparing strings, and should surface the
// distinction to users: a bad signature and an unknown key are very
// different situations, and collapsing them into "invalid" makes a receipt
// look forged when the verifier was merely misconfigured.
var (
	// ErrNoSignature means the receipt carries no signature at all.
	ErrNoSignature = errors.New("receipt: no signature present")

	// ErrBadSignature means the signature did not verify against the
	// signing input. The receipt has been altered, or it was signed by a
	// different key than the one presented.
	ErrBadSignature = errors.New("receipt: signature verification failed")

	// ErrUnknownKey means the verifier could not resolve the receipt's key
	// ID to a public key. This is a verifier configuration problem, not
	// evidence that the receipt is invalid.
	ErrUnknownKey = errors.New("receipt: signing key not known to this verifier")

	// ErrUnsupportedAlgorithm means the signature algorithm is not one this
	// build implements, or not one the verifier's policy accepts.
	ErrUnsupportedAlgorithm = errors.New("receipt: unsupported signature algorithm")

	// ErrUnsupportedCanonicalization means the signature covers a byte
	// serialization this build cannot reproduce, so the signature cannot be
	// checked either way.
	ErrUnsupportedCanonicalization = errors.New("receipt: unsupported canonicalization")

	// ErrKeyMismatch means the signature's key ID disagrees with the
	// issuer's. A receipt that cannot agree with itself about which key
	// signed it must not be accepted.
	ErrKeyMismatch = errors.New("receipt: signature key_id does not match issuer key_id")

	// ErrChainBroken means a receipt's prev_hash does not match the
	// computed digest of its predecessor. Something was altered or removed.
	ErrChainBroken = errors.New("receipt: chain integrity broken")

	// ErrChainDiscontinuous means sequence numbers skip, repeat, or run
	// backwards. A gap means receipts are missing from the record.
	ErrChainDiscontinuous = errors.New("receipt: chain sequence is not continuous")

	// ErrChainMixed means receipts from different chain IDs were presented
	// as a single chain.
	ErrChainMixed = errors.New("receipt: receipts belong to different chains")
)

// FieldError identifies one schema violation, located at a JSON path.
type FieldError struct {
	// Field is the dotted JSON path of the offending field.
	Field string
	// Reason explains what is wrong and, where useful, why the rule exists.
	Reason string
	// Unrecognised marks a value that is well-formed but not in the
	// vocabulary this build knows — a surface, actor type or identity
	// source added after it was compiled.
	//
	// The distinction exists because a verifier is a long-lived thing in
	// somebody else's hands. When a new surface was added, every verifier
	// already installed reported NOT VERIFIED on a receipt whose signature
	// was perfectly good, which reads as "tampered" rather than "newer than
	// me". Refusing to say what a receipt means is right; implying it was
	// forged is an overclaim in the other direction, and this product does
	// not get to make those.
	Unrecognised bool
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Reason }

// FieldErrors is a set of schema violations.
//
// Validation returns every problem at once rather than stopping at the
// first. A caller fixing a receipt builder wants the whole list, not one
// round trip per mistake.
type FieldErrors []*FieldError

func (fe FieldErrors) Error() string {
	switch len(fe) {
	case 0:
		return "receipt: invalid"
	case 1:
		return "receipt: invalid: " + fe[0].Error()
	}
	var b strings.Builder
	b.WriteString("receipt: invalid (")
	b.WriteString(itoa(len(fe)))
	b.WriteString(" problems):")
	for _, e := range fe {
		b.WriteString("\n  - ")
		b.WriteString(e.Error())
	}
	return b.String()
}

// Fields returns the JSON paths of every violation, in order.
func (fe FieldErrors) Fields() []string {
	out := make([]string, len(fe))
	for i, e := range fe {
		out[i] = e.Field
	}
	return out
}

func (fe *FieldErrors) add(field, reason string) {
	*fe = append(*fe, &FieldError{Field: field, Reason: reason})
}

// addUnknown records a value this build does not recognise, as opposed to
// one that is structurally wrong.
func (fe *FieldErrors) addUnknown(field, reason string) {
	*fe = append(*fe, &FieldError{Field: field, Reason: reason, Unrecognised: true})
}

// OnlyUnrecognised reports whether every problem is an unknown vocabulary
// value rather than a malformed receipt. Empty is false: a caller asking
// this is deciding whether to proceed despite errors, and there are none.
func (fe FieldErrors) OnlyUnrecognised() bool {
	if len(fe) == 0 {
		return false
	}
	for _, e := range fe {
		if !e.Unrecognised {
			return false
		}
	}
	return true
}

func (fe *FieldErrors) merge(other FieldErrors) {
	if len(other) > 0 {
		*fe = append(*fe, other...)
	}
}

// CanonicalizationError reports a value that cannot be canonicalized
// deterministically.
type CanonicalizationError struct {
	// Path is the JSON path at which the problem was found.
	Path string
	// Reason explains why the value cannot be serialized reproducibly.
	Reason string
}

func (e *CanonicalizationError) Error() string {
	return "receipt: cannot canonicalize at " + e.Path + ": " + e.Reason
}
