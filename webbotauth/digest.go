package webbotauth

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Content-Digest, RFC 9530: the body's hash, carried in a header the
// signature can cover.
//
// A signature covers headers and derived components, never the body
// itself, so a signed request whose body is not digested is a signed
// envelope around an open letter. The SDKs digest every non-empty body and
// cover the header; this is the other half, checking the digest against
// the bytes that actually arrived. Without it the header would be a claim
// the server repeated rather than a fact it established.

// ErrDigestMismatch means the body does not hash to what Content-Digest
// says. The body was altered after it was signed, or the client digested
// something other than what it sent; either way the signature proves
// nothing about these bytes.
var ErrDigestMismatch = errors.New("webbotauth: body does not match Content-Digest")

// ErrDigestUnsupported means Content-Digest names no algorithm this
// package computes. Refused rather than ignored: a digest the server
// cannot check is one it must not appear to have checked.
var ErrDigestUnsupported = errors.New("webbotauth: Content-Digest uses no supported algorithm")

// ContentDigest returns the sha-256 Content-Digest value for a body, in the
// form the SDKs send: sha-256=:<base64>:.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// VerifyContentDigest checks a Content-Digest header value against a body.
//
// The header is a dictionary and may name several algorithms; every one
// this package knows is checked and every one must match, because a
// client that sends two digests is asserting both. Unknown algorithms are
// ignored when a known one is present, and refused when none is.
func VerifyContentDigest(header string, body []byte) error {
	header = strings.TrimSpace(header)
	if header == "" {
		return fmt.Errorf("%w: header is empty", ErrDigestUnsupported)
	}

	checked := 0
	for _, entry := range splitDictionary(header) {
		alg, value, ok := strings.Cut(entry, "=")
		if !ok {
			return fmt.Errorf("%w: entry %q has no value", ErrMalformed, entry)
		}
		alg = strings.ToLower(strings.TrimSpace(alg))
		value = strings.TrimSpace(value)
		if len(value) < 2 || !strings.HasPrefix(value, ":") || !strings.HasSuffix(value, ":") {
			return fmt.Errorf("%w: %s digest is not a byte sequence", ErrMalformed, alg)
		}
		claimed, err := decodeBase64Either(value[1 : len(value)-1])
		if err != nil {
			return fmt.Errorf("%w: %s digest is not valid base64", ErrMalformed, alg)
		}

		var actual []byte
		switch alg {
		case "sha-256":
			sum := sha256.Sum256(body)
			actual = sum[:]
		case "sha-512":
			sum := sha512.Sum512(body)
			actual = sum[:]
		default:
			continue
		}
		checked++
		if subtle.ConstantTimeCompare(claimed, actual) != 1 {
			return fmt.Errorf("%w (%s)", ErrDigestMismatch, alg)
		}
	}
	if checked == 0 {
		return ErrDigestUnsupported
	}
	return nil
}
