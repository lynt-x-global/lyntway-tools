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

	// labelCWTClaims carries a CWT Claims Set (RFC 8392) in a COSE header,
	// registered by RFC 9597. RFC 9943 section 6 requires it in the
	// protected header of every Signed Statement and every Receipt, with
	// the issuer and subject claims inside it.
	labelCWTClaims = 15
)

// CWT claim keys from the RFC 8392 registry. Both are text strings.
const (
	claimIssuer  = 1
	claimSubject = 2
)

// Algorithm identifiers, which are negative by convention.
const (
	algEdDSA = -8
	algES256 = -7
)

// contentTypeJSON is the CoAP content format for application/json, which is
// what a receipt payload carries.
//
// RFC 9943 allows the content type to be a media type string or a CoAP
// content-format integer, so this is conformant as it stands and is left
// as the integer every receipt issued so far has carried. The payload
// names its own schema in its version field; the header only needs to say
// it is JSON.
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

// Claims is the part of a CWT Claims Set this package reads and writes.
//
// The issuer is the identifier a verifier resolves to a key; the subject
// is what the statement is about. RFC 9943 makes both mandatory, and a
// SCITT verifier uses them before it ever looks at the payload — so they
// must agree with the payload, and DecodeReceipt checks that they do.
type Claims struct {
	Issuer  string
	Subject string
}

// Sign1Options shapes a COSE_Sign1 beyond the bare envelope.
//
// The zero value produces exactly what Sign1 always has: algorithm, JSON
// content type and key identifier protected, nothing else.
type Sign1Options struct {
	// Claims, when non-nil, is placed in the protected header under label
	// 15. Protected rather than unprotected because RFC 9597 warns that an
	// unprotected claims set is malleable, and a verifier that resolved a
	// key from a malleable issuer would be resolving whatever it was told.
	Claims *Claims

	// ContentType goes under label 3. Nil omits the header, which a
	// receipt whose payload is a Merkle root wants: a content type on a
	// hash would be a claim about bytes that are not a document.
	ContentType Value

	// Detached signs the payload but does not carry it: the structure
	// holds null where the payload would be, and whoever verifies must
	// already hold the bytes.
	Detached bool

	// Protected are further header entries the signature covers.
	Protected Map

	// Unprotected are header entries the signature does not cover. A
	// verifier may read them to find a proof but must never rely on them
	// for anything the signature is supposed to establish.
	Unprotected Map
}

// Sign1 wraps a payload in a signed COSE_Sign1.
//
// The key identifier and algorithm go in the protected headers, so a
// verifier learns which key to use from bytes the signature covers rather
// than from bytes anyone could rewrite in transit.
func Sign1(signer receipt.Signer, payload []byte) ([]byte, error) {
	return Sign1With(signer, payload, Sign1Options{ContentType: Uint(contentTypeJSON)})
}

// Sign1With wraps a payload in a signed COSE_Sign1 shaped by opts.
func Sign1With(signer receipt.Signer, payload []byte, opts Sign1Options) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("cose: a signer is required")
	}
	alg, err := coseAlgorithm(signer.Algorithm())
	if err != nil {
		return nil, err
	}

	header := Map{
		{Key: Uint(labelAlg), Value: Int(alg)},
		{Key: Uint(labelKeyID), Value: Bytes(signer.KeyID())},
	}
	if opts.ContentType != nil {
		header = append(header, MapEntry{Key: Uint(labelContentType), Value: opts.ContentType})
	}
	if opts.Claims != nil {
		if opts.Claims.Issuer == "" || opts.Claims.Subject == "" {
			// RFC 9943 requires both. Emitting a claims set with one of
			// them blank would produce an envelope that looks conformant
			// and is refused by the first verifier that checks.
			return nil, errors.New("cose: CWT claims need both an issuer and a subject")
		}
		header = append(header, MapEntry{Key: Uint(labelCWTClaims), Value: Map{
			{Key: Uint(claimIssuer), Value: Text(opts.Claims.Issuer)},
			{Key: Uint(claimSubject), Value: Text(opts.Claims.Subject)},
		}})
	}
	for _, e := range opts.Protected {
		if _, taken := header.get(e.Key); taken {
			return nil, fmt.Errorf("cose: protected header %s is set by the envelope and cannot be overridden", describeLabel(e.Key))
		}
		header = append(header, e)
	}
	protected := Encode(header)

	signature, err := signer.Sign(sigStructure(protected, payload))
	if err != nil {
		return nil, fmt.Errorf("cose: signing: %w", err)
	}

	var carried Value = Bytes(payload)
	if opts.Detached {
		carried = Null{}
	}
	unprotected := opts.Unprotected
	if unprotected == nil {
		// Empty by default. Everything this issuer means is protected,
		// and a header a relay could change is a header a verifier cannot
		// rely on.
		unprotected = Map{}
	}

	return Encode(Tag{
		Number: tagSign1,
		Value: Array{
			Bytes(protected),
			unprotected,
			carried,
			Bytes(signature),
		},
	}), nil
}

func describeLabel(v Value) string {
	switch l := v.(type) {
	case Uint:
		return fmt.Sprint(uint64(l))
	case Int:
		return fmt.Sprint(int64(l))
	case Text:
		return fmt.Sprintf("%q", string(l))
	}
	return fmt.Sprintf("%x", Encode(v))
}

// sigStructure builds the bytes a COSE_Sign1 signature actually covers.
//
// The context string is what stops a signature made for one COSE structure
// being presented as one made for another — the same reason the receipt's
// key attestations carry a domain separator.
//
// The payload is always the full payload, whether or not the structure
// carries it: RFC 9052 section 4.4 says the payload "is used here,
// independent of how it is transported".
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

	// Claims is the CWT Claims Set from the protected headers, or nil when
	// the envelope carried none. Receipts issued before SCITT conformance
	// carried none, and they still verify.
	Claims *Claims
}

// sign1 is a parsed COSE_Sign1, before any signature check.
type sign1 struct {
	protected []byte
	header    protectedHeader

	// unprotected is decoded rather than skipped because the SCITT
	// profile carries proofs and receipts there. Nothing in it is trusted;
	// it is where a verifier finds the things it then checks.
	unprotected Map

	payload   []byte
	detached  bool
	signature []byte
}

// parseSign1 splits a COSE_Sign1 into its parts and reads the protected
// headers, checking structure only.
func parseSign1(encoded []byte) (*sign1, error) {
	value, rest, err := decodeValue(encoded)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		// Trailing bytes mean two readers could disagree about where the
		// structure ends, which is a signature covering an ambiguous thing.
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

	protected, ok := parts[0].(Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: protected headers are not a byte string", ErrMalformed)
	}
	unprotected, ok := parts[1].(Map)
	if !ok {
		return nil, fmt.Errorf("%w: unprotected headers are not a map", ErrMalformed)
	}
	signature, ok := parts[3].(Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: signature is not a byte string", ErrMalformed)
	}

	s := &sign1{protected: protected, unprotected: unprotected, signature: signature}
	switch p := parts[2].(type) {
	case Bytes:
		s.payload = p
	case Null:
		s.detached = true
	default:
		return nil, fmt.Errorf("%w: payload is neither a byte string nor null", ErrMalformed)
	}

	s.header, err = readProtected(protected)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// verify checks the signature over the given payload, which for a
// detached structure is what the caller reconstructed.
func (s *sign1) verify(payload []byte, keys receipt.KeyResolver) (*Sign1Result, error) {
	if keys == nil {
		return nil, errors.New("cose: a key resolver is required")
	}
	alg, err := receiptAlgorithm(s.header.alg)
	if err != nil {
		return nil, err
	}
	public, err := keys.ResolveKey(s.header.keyID)
	if err != nil {
		return nil, err
	}
	if !receipt.VerifyRaw(alg, public, sigStructure(s.protected, payload), s.signature) {
		return nil, errors.New("cose: signature does not verify")
	}
	return &Sign1Result{
		Payload:   payload,
		KeyID:     s.header.keyID,
		Algorithm: alg,
		Claims:    s.header.claims,
	}, nil
}

// Verify1 checks a COSE_Sign1 that carries its payload and returns what it
// carried.
//
// A detached payload is refused here rather than guessed at: the caller
// has to say what the payload is, and the profile that detached it says
// how to reconstruct it. VerifyInclusionReceipt is that for COSE Receipts.
func Verify1(encoded []byte, keys receipt.KeyResolver) (*Sign1Result, error) {
	if keys == nil {
		return nil, errors.New("cose: a key resolver is required")
	}
	s, err := parseSign1(encoded)
	if err != nil {
		return nil, err
	}
	if s.detached {
		return nil, errors.New("cose: the payload is detached and must be supplied by the profile that detached it")
	}
	return s.verify(s.payload, keys)
}

// protectedHeader is what this package reads from the protected map.
type protectedHeader struct {
	alg    int64
	keyID  string
	claims *Claims

	// vds is the verifiable data structure of a COSE Receipt (RFC 9942
	// label 395). Only meaningful on receipts; hasVDS says whether it was
	// present at all, since 0 is not a registered value either way.
	vds    int64
	hasVDS bool
}

// readProtected extracts the headers a verifier acts on.
func readProtected(protected []byte) (protectedHeader, error) {
	var h protectedHeader
	if len(protected) == 0 {
		// RFC 9052 section 3 lets an empty map travel as a zero-length
		// string. It names no algorithm, so it is refused below, but it
		// is refused for that reason and not as malformed CBOR.
		return h, fmt.Errorf("%w: protected headers name no algorithm", ErrMalformed)
	}
	value, rest, err := decodeValue(protected)
	if err != nil {
		return h, err
	}
	if len(rest) != 0 {
		return h, fmt.Errorf("%w: trailing data after the protected headers", ErrMalformed)
	}
	m, ok := value.(Map)
	if !ok {
		return h, fmt.Errorf("%w: protected headers are not a map", ErrMalformed)
	}

	var sawAlg bool
	for _, e := range m {
		label, ok := e.Key.(Uint)
		if !ok {
			// Labels this package does not emit. Skipped rather than
			// rejected, since a future header must not stop a signature
			// that is otherwise sound from verifying.
			continue
		}
		switch uint64(label) {
		case labelAlg:
			switch v := e.Value.(type) {
			case Uint:
				h.alg = int64(v)
			case Int:
				h.alg = int64(v)
			default:
				return h, fmt.Errorf("%w: algorithm is not an integer", ErrMalformed)
			}
			sawAlg = true
		case labelKeyID:
			raw, ok := e.Value.(Bytes)
			if !ok {
				return h, fmt.Errorf("%w: key identifier is not a byte string", ErrMalformed)
			}
			h.keyID = string(raw)
		case labelCWTClaims:
			claims, err := readClaims(e.Value)
			if err != nil {
				return h, err
			}
			h.claims = claims
		case labelVDS:
			v, ok := e.Value.(Uint)
			if !ok {
				return h, fmt.Errorf("%w: verifiable data structure identifier is not an unsigned integer", ErrMalformed)
			}
			h.vds, h.hasVDS = int64(v), true
		}
	}

	if !sawAlg {
		// Without a declared algorithm a verifier would have to guess,
		// and guessing which scheme signed something is how algorithm
		// confusion attacks begin.
		return h, fmt.Errorf("%w: protected headers name no algorithm", ErrMalformed)
	}
	if h.keyID == "" {
		return h, fmt.Errorf("%w: protected headers name no key", ErrMalformed)
	}
	return h, nil
}

// readClaims reads the issuer and subject from a CWT Claims Set.
//
// Other claims are carried past untouched. A claims set that names no
// issuer or no subject is refused: RFC 9943 requires both, and a header
// that is present but half-filled is more misleading than one that is
// absent, because a reader would take the present half as checked.
func readClaims(v Value) (*Claims, error) {
	m, ok := v.(Map)
	if !ok {
		return nil, fmt.Errorf("%w: CWT claims are not a map", ErrMalformed)
	}
	var c Claims
	if iss, ok := m.get(Uint(claimIssuer)); ok {
		text, ok := iss.(Text)
		if !ok {
			return nil, fmt.Errorf("%w: CWT issuer claim is not a text string", ErrMalformed)
		}
		c.Issuer = string(text)
	}
	if sub, ok := m.get(Uint(claimSubject)); ok {
		text, ok := sub.(Text)
		if !ok {
			return nil, fmt.Errorf("%w: CWT subject claim is not a text string", ErrMalformed)
		}
		c.Subject = string(text)
	}
	if c.Issuer == "" || c.Subject == "" {
		return nil, fmt.Errorf("%w: CWT claims must name both an issuer and a subject", ErrMalformed)
	}
	return &c, nil
}
