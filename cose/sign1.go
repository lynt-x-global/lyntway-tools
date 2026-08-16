package cose

import (
	"errors"
	"fmt"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// COSE_Sign1, as RFC 9052 section 4.2 defines it: a four-element array of
// protected headers, unprotected headers, payload and signature, carried
// under tag 18.
//
// The signature does not cover that array. It covers a separate structure —
// the Sig_structure — which includes the protected headers and the payload
// but not the unprotected ones. That separation is the whole point of the
// design: anything a relay may add or change goes in the unprotected
// bucket, and everything the signer meant is in the protected one.

// Tag numbers and header labels from the COSE registries.
const (
	tagSign1 = 18

	labelAlg         = 1
	labelContentType = 3
	labelKeyID       = 4
)

// Algorithm identifiers, which are negative by convention.
const (
	algEdDSA = -8
	algES256 = -7
)

// contentTypeJSON is the CoAP content format for application/json, which is
// what the payload carries.
const contentTypeJSON = 50

// coseAlgorithm maps a receipt algorithm onto its COSE identifier.
func coseAlgorithm(alg receipt.Algorithm) (int64, error) {
	switch alg {
	case receipt.AlgEd25519:
		return algEdDSA, nil
	case receipt.AlgES256:
		return algES256, nil
	default:
		return 0, fmt.Errorf("cose: no COSE algorithm identifier for %q", alg)
	}
}

func receiptAlgorithm(id int64) (receipt.Algorithm, error) {
	switch id {
	case algEdDSA:
		return receipt.AlgEd25519, nil
	case algES256:
		return receipt.AlgES256, nil
	default:
		return "", fmt.Errorf("cose: unsupported COSE algorithm identifier %d", id)
	}
}

// Sign1 wraps a payload in a signed COSE_Sign1.
//
// The key identifier and algorithm go in the protected headers, so a
// verifier learns which key to use from bytes the signature covers rather
// than from bytes anyone could rewrite in transit.
func Sign1(signer receipt.Signer, payload []byte) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("cose: a signer is required")
	}
	alg, err := coseAlgorithm(signer.Algorithm())
	if err != nil {
		return nil, err
	}

	protected := Encode(Map{
		{Key: Uint(labelAlg), Value: Int(alg)},
		{Key: Uint(labelContentType), Value: Uint(contentTypeJSON)},
		{Key: Uint(labelKeyID), Value: Bytes(signer.KeyID())},
	})

	signature, err := signer.Sign(sigStructure(protected, payload))
	if err != nil {
		return nil, fmt.Errorf("cose: signing: %w", err)
	}

	return Encode(Tag{
		Number: tagSign1,
		Value: Array{
			Bytes(protected),
			// Empty. Everything this issuer means is protected, and a
			// header a relay could change is a header a verifier cannot
			// rely on.
			Map{},
			Bytes(payload),
			Bytes(signature),
		},
	}), nil
}

// sigStructure builds the bytes a COSE_Sign1 signature actually covers.
//
// The context string is what stops a signature made for one COSE structure
// being presented as one made for another — the same reason the receipt's
// key attestations carry a domain separator.
func sigStructure(protected, payload []byte) []byte {
	return Encode(Array{
		Text("Signature1"),
		Bytes(protected),
		// No externally supplied data. Present because the structure has
		// four elements regardless, and omitting it would change what is
		// signed.
		Bytes(nil),
		Bytes(payload),
	})
}

// Sign1Result is what a verified COSE_Sign1 turned out to contain.
type Sign1Result struct {
	// Payload is the signed content.
	Payload []byte

	// KeyID names the key from the protected headers.
	KeyID string

	// Algorithm is the scheme the signature used.
	Algorithm receipt.Algorithm
}

// Verify1 checks a COSE_Sign1 and returns what it carried.
func Verify1(encoded []byte, keys receipt.KeyResolver) (*Sign1Result, error) {
	if keys == nil {
		return nil, errors.New("cose: a key resolver is required")
	}

	major, tag, rest, err := decodeHead(encoded)
	if err != nil {
		return nil, err
	}
	if major != majorTag || tag != tagSign1 {
		return nil, fmt.Errorf("%w: not a COSE_Sign1", ErrMalformed)
	}

	major, count, rest, err := decodeHead(rest)
	if err != nil {
		return nil, err
	}
	if major != majorArray || count != 4 {
		return nil, fmt.Errorf("%w: a COSE_Sign1 has four elements", ErrMalformed)
	}

	protected, rest, err := decodeBytes(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: protected headers", err)
	}
	// The unprotected headers are skipped rather than read: nothing here
	// depends on them, and a verifier that acted on an unsigned header
	// would be acting on something anyone could have written.
	rest, err = skipValue(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: unprotected headers", err)
	}
	payload, rest, err := decodeBytes(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: payload", err)
	}
	signature, rest, err := decodeBytes(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: signature", err)
	}
	if len(rest) != 0 {
		// Trailing bytes mean two readers could disagree about where the
		// structure ends, which is a signature covering an ambiguous thing.
		return nil, fmt.Errorf("%w: trailing data after the structure", ErrMalformed)
	}

	algID, keyID, err := readProtected(protected)
	if err != nil {
		return nil, err
	}
	alg, err := receiptAlgorithm(algID)
	if err != nil {
		return nil, err
	}

	public, err := keys.ResolveKey(keyID)
	if err != nil {
		return nil, err
	}
	if !receipt.VerifyRaw(alg, public, sigStructure(protected, payload), signature) {
		return nil, errors.New("cose: signature does not verify")
	}

	return &Sign1Result{Payload: payload, KeyID: keyID, Algorithm: alg}, nil
}

// readProtected extracts the algorithm and key identifier.
func readProtected(protected []byte) (alg int64, keyID string, err error) {
	major, count, rest, err := decodeHead(protected)
	if err != nil {
		return 0, "", err
	}
	if major != majorMap {
		return 0, "", fmt.Errorf("%w: protected headers are not a map", ErrMalformed)
	}

	var sawAlg bool
	for i := uint64(0); i < count; i++ {
		var label uint64
		var labelMajor byte
		labelMajor, label, rest, err = decodeHead(rest)
		if err != nil {
			return 0, "", err
		}
		if labelMajor != majorUint {
			// Labels this package does not emit. Skipped rather than
			// rejected, since a future header must not stop a signature
			// that is otherwise sound from verifying.
			if rest, err = skipValue(rest); err != nil {
				return 0, "", err
			}
			continue
		}

		switch label {
		case labelAlg:
			var m byte
			var v uint64
			m, v, rest, err = decodeHead(rest)
			if err != nil {
				return 0, "", err
			}
			switch m {
			case majorUint:
				alg = int64(v)
			case majorNegInt:
				alg = -1 - int64(v)
			default:
				return 0, "", fmt.Errorf("%w: algorithm is not an integer", ErrMalformed)
			}
			sawAlg = true
		case labelKeyID:
			var raw []byte
			raw, rest, err = decodeBytes(rest)
			if err != nil {
				return 0, "", err
			}
			keyID = string(raw)
		default:
			if rest, err = skipValue(rest); err != nil {
				return 0, "", err
			}
		}
	}

	if !sawAlg {
		// Without a declared algorithm a verifier would have to guess,
		// and guessing which scheme signed something is how algorithm
		// confusion attacks begin.
		return 0, "", fmt.Errorf("%w: protected headers name no algorithm", ErrMalformed)
	}
	if keyID == "" {
		return 0, "", fmt.Errorf("%w: protected headers name no key", ErrMalformed)
	}
	return alg, keyID, nil
}

// skipValue advances past one encoded value.
func skipValue(in []byte) ([]byte, error) {
	major, argument, rest, err := decodeHead(in)
	if err != nil {
		return nil, err
	}
	switch major {
	case majorUint, majorNegInt:
		return rest, nil
	case majorBytes, majorText:
		if uint64(len(rest)) < argument {
			return nil, ErrMalformed
		}
		return rest[argument:], nil
	case majorArray:
		for i := uint64(0); i < argument; i++ {
			if rest, err = skipValue(rest); err != nil {
				return nil, err
			}
		}
		return rest, nil
	case majorMap:
		for i := uint64(0); i < argument*2; i++ {
			if rest, err = skipValue(rest); err != nil {
				return nil, err
			}
		}
		return rest, nil
	case majorTag:
		return skipValue(rest)
	}
	return nil, fmt.Errorf("%w: cannot skip major type %d", ErrMalformed, major)
}
