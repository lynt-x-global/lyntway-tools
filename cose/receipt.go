package cose

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// EncodeReceipt produces the COSE form of a receipt: a SCITT Signed
// Statement as RFC 9943 section 6 defines one.
//
// The payload is the receipt's canonical JSON, unchanged, so the content is
// byte-identical in both forms and there is one schema rather than two that
// must be kept in step.
//
// # What the protected header says
//
// RFC 9943 requires a CWT Claims Set (label 15) naming an issuer and a
// subject, and a key identifier when no certificate is carried. The issuer
// claim is the receipt's Issuer.KeyID — the identifier a verifier already
// resolves to a public key, so a SCITT verifier and this package look up
// the same thing — and the subject is the receipt ID, which is what the
// statement is about. Both duplicate a field of the payload, and
// DecodeReceipt refuses an envelope whose claims disagree with its payload.
//
// # This signs again, and only the issuer can
//
// The two forms sign different things: the JSON form signs its canonical
// bytes, and COSE signs a structure including its own protected headers. So
// this is not a conversion — it is a second issuance of the same statement,
// and it needs the signing key.
//
// That is a property rather than a limitation. Nobody can take a receipt
// they were handed and present it as a COSE receipt from us, which is
// exactly what a conversion anyone could perform would allow.
func EncodeReceipt(r *receipt.Receipt, signer receipt.Signer) ([]byte, error) {
	if r == nil {
		return nil, errors.New("cose: nil receipt")
	}
	if signer == nil {
		return nil, errors.New("cose: encoding a receipt as COSE requires the issuer's key, because it signs again")
	}
	// Validated before signing, exactly as the JSON path does. A second
	// serialisation must not become a way to issue a receipt the schema
	// would have refused.
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if r.Signature != nil && signer.KeyID() != r.Signature.KeyID {
		// Signing the COSE form with a different key would produce two
		// receipts for one action attributed to two issuers, and no reader
		// could tell which was authoritative.
		return nil, fmt.Errorf("cose: the receipt was signed by %q but this key is %q",
			r.Signature.KeyID, signer.KeyID())
	}
	if r.Issuer.KeyID != signer.KeyID() {
		// The issuer claim is about to name this key as the receipt's
		// issuer. If the receipt says otherwise, the claim would be the
		// envelope's word against the payload's.
		return nil, fmt.Errorf("cose: the receipt names issuer key %q but this key is %q",
			r.Issuer.KeyID, signer.KeyID())
	}

	payload, err := receipt.Canonicalize(r)
	if err != nil {
		return nil, fmt.Errorf("cose: canonicalizing the receipt: %w", err)
	}
	return Sign1With(signer, payload, Sign1Options{
		ContentType: Uint(contentTypeJSON),
		Claims:      &Claims{Issuer: r.Issuer.KeyID, Subject: r.ID},
	})
}

// DecodeReceipt verifies a COSE receipt and returns what it carried.
//
// The receipt inside is returned parsed but not re-verified against its own
// JSON signature: the COSE signature already covers these exact bytes, and
// checking the inner one as well would demand the two agree about a
// canonicalisation the outer signature has already fixed.
//
// Receipts issued before the envelope carried CWT claims have none, and
// still verify. When claims are present they must match the payload: a
// SCITT verifier reads the issuer and subject from the header without
// opening the payload, so a header that disagrees with the payload is two
// statements under one signature, and the reader's conclusion depends on
// which they happened to read.
func DecodeReceipt(encoded []byte, keys receipt.KeyResolver) (*receipt.Receipt, error) {
	result, err := Verify1(encoded, keys)
	if err != nil {
		return nil, err
	}

	var r receipt.Receipt
	if err := json.Unmarshal(result.Payload, &r); err != nil {
		return nil, fmt.Errorf("cose: the payload is not a receipt: %w", err)
	}
	// A COSE envelope naming one key around a receipt naming another is a
	// receipt whose issuer depends on which layer you read.
	if r.Signature != nil && r.Signature.KeyID != result.KeyID {
		return nil, fmt.Errorf("cose: the envelope names key %q and the receipt names %q",
			result.KeyID, r.Signature.KeyID)
	}
	if c := result.Claims; c != nil {
		if c.Issuer != r.Issuer.KeyID {
			return nil, fmt.Errorf("cose: the envelope's issuer claim is %q and the receipt's issuer key is %q",
				c.Issuer, r.Issuer.KeyID)
		}
		if c.Subject != r.ID {
			return nil, fmt.Errorf("cose: the envelope's subject claim is %q and the receipt's ID is %q",
				c.Subject, r.ID)
		}
	}
	return &r, nil
}
