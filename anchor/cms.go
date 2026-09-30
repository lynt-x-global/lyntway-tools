package anchor

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// Checking that somebody actually signed a timestamp token.
//
// # Why this file exists
//
// It did not, and the omission inverted the one rule this product rests
// on. parseTSTInfo read the time and the digest out of a token and nothing
// ever looked at who signed it — SignerInfos was parsed as a raw value and
// never read again. A token with an empty signer set, which anyone can
// mint in a few lines and date to any moment they like, was accepted; the
// verifier printed "anchored" and dropped the warning that says issuance
// time rests on the issuer's clock alone.
//
// So a forged receipt read as strictly stronger evidence than the honest
// one it was made from. An anchor exists to answer "was this backdated",
// and as shipped it answered with the word of whoever held the receipt.
//
// # Why by hand
//
// The root module has no third-party dependencies and CI enforces it, and
// that claim is made to the security reviewers reading the binary that
// signs their evidence. CMS is not in the standard library, so the parts
// RFC 5652 needs for one signer over one encapsulated object are here. It
// is deliberately the narrow case: one SignerInfo, detached-attribute
// signing as RFC 3161 tokens use it, and the signature algorithms real
// authorities issue.
//
// # What this proves, and what it does not
//
// It proves that the certificate inside the token signed the TSTInfo the
// token carries, and that the attributes commit to that TSTInfo. It does
// not prove the certificate belongs to an authority anyone trusts: that
// needs a trust store, which is a policy decision this package exists to
// keep out of. The distinction is reported rather than glossed, because an
// anchor that is silently half-checked reads as stronger than it is, which
// is how this went wrong the first time.

var (
	// ErrTokenUnsigned is a timestamp token nobody signed. Its own class
	// because it is the forgery case, not a malformed-input case: the
	// bytes parse perfectly and assert a time.
	ErrTokenUnsigned = errors.New("anchor: the timestamp token carries no signature")

	// ErrTokenSignature is a token whose signature does not check out
	// against the certificate it ships.
	ErrTokenSignature = errors.New("anchor: the timestamp token's signature does not verify")

	// ErrTokenNoCertificate is a token that signs but ships no certificate,
	// so there is nothing to check the signature against. Refused rather
	// than reported as unchecked, because an anchor nobody can check is
	// not evidence.
	ErrTokenNoCertificate = errors.New("anchor: the timestamp token carries no certificate to verify its signature against")
)

var (
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	oidSigRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSigRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSigRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSigRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSigRSAPSS    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSigECDSA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSigECDSA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSigECDSA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSigECDSAAny  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	oidDigestSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidDigestSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// signerInfo is RFC 5652 section 5.3, parsed for one signer.
type signerInfo struct {
	Version int

	// SID is IssuerAndSerialNumber, or a SubjectKeyIdentifier under [0].
	// Left raw so the choice can be examined without two parses.
	SID asn1.RawValue

	DigestAlgorithm pkix.AlgorithmIdentifier

	// SignedAttrs is implicitly tagged [0] on the wire. The signature is
	// computed over the same bytes re-tagged as a SET, which is why this
	// is kept raw rather than decoded and re-encoded — re-encoding a
	// structure and hoping it round-trips byte for byte is how signature
	// checks come to fail on valid input.
	SignedAttrs asn1.RawValue `asn1:"optional,tag:0"`

	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// signerCheck is what verifySignedData could establish about a token.
type signerCheck struct {
	// Certificate is the signer's certificate, as the token shipped it.
	Certificate *x509.Certificate

	// ChainChecked stays false: no trust store is consulted here. Carried
	// explicitly so the caller reports the limit rather than leaving the
	// reader to assume it away.
	ChainChecked bool
}

// verifySignedData checks that the token's SignerInfo really signs the
// encapsulated content.
//
// Order matters. The certificate is found first, then the attributes are
// checked to commit to the content, then the signature is checked over the
// attributes. Checking the signature before the message-digest attribute
// would prove only that the signer signed *some* attributes, which is the
// substitution this binding exists to prevent.
func verifySignedData(sd *signedData, eContent []byte) (*signerCheck, error) {
	if len(eContent) == 0 {
		return nil, errors.New("anchor: the token encapsulates no content to have been signed")
	}

	if len(sd.SignerInfos.Bytes) == 0 {
		return nil, ErrTokenUnsigned
	}
	// Walked element by element rather than decoded as a slice: SignerInfos
	// is a SET OF, and Go's asn1 will only fill a slice from one through a
	// struct field carrying the "set" tag. Reading the contents directly
	// avoids a wrapper type whose only job is to carry that tag.
	var infos []signerInfo
	for rest := sd.SignerInfos.Bytes; len(rest) > 0; {
		var si signerInfo
		remaining, err := asn1.Unmarshal(rest, &si)
		if err != nil {
			// A SET OF that will not decode as a signer is still, for our
			// purposes, a token we cannot attribute to anybody.
			return nil, fmt.Errorf("%w: %v", ErrTokenUnsigned, err)
		}
		infos = append(infos, si)
		rest = remaining
	}
	if len(infos) == 0 {
		return nil, ErrTokenUnsigned
	}
	if len(infos) > 1 {
		// More than one signer is legal CMS and not something a timestamp
		// authority does. Refused rather than picking one, because
		// choosing silently is how a checked signature ends up belonging
		// to a party the reader never saw.
		return nil, fmt.Errorf("anchor: the token has %d signers; expected exactly one", len(infos))
	}
	si := infos[0]

	certs, err := tokenCertificates(sd)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, ErrTokenNoCertificate
	}
	cert, err := signerCertificate(certs, si)
	if err != nil {
		return nil, err
	}

	digestHash, err := hashForOID(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}

	signed, err := signedBytes(si, eContent, digestHash)
	if err != nil {
		return nil, err
	}

	algo, err := signatureAlgorithm(si, digestHash)
	if err != nil {
		return nil, err
	}
	if err := cert.CheckSignature(algo, signed, si.Signature); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenSignature, err)
	}

	return &signerCheck{Certificate: cert, ChainChecked: false}, nil
}

// signedBytes returns exactly the octets the signature covers.
//
// With signed attributes — which RFC 3161 requires — the signature is over
// the attributes, and the attributes must carry a message-digest equal to
// the hash of the content. Without them it is over the content itself.
func signedBytes(si signerInfo, eContent []byte, h crypto.Hash) ([]byte, error) {
	if len(si.SignedAttrs.Bytes) == 0 {
		return eContent, nil
	}

	if err := attributesCommitToContent(si.SignedAttrs.Bytes, eContent, h); err != nil {
		return nil, err
	}

	// The attributes are transmitted as [0] IMPLICIT and signed as SET.
	// Copy rather than mutate: FullBytes points into the caller's token,
	// and rewriting a tag in place would corrupt the bytes an error
	// message might later quote.
	reTagged := make([]byte, len(si.SignedAttrs.FullBytes))
	copy(reTagged, si.SignedAttrs.FullBytes)
	reTagged[0] = 0x31 // universal, constructed, SET
	return reTagged, nil
}

// attributesCommitToContent checks the message-digest attribute against the
// content, which is the link between what was signed and what is claimed.
func attributesCommitToContent(attrBytes, eContent []byte, h crypto.Hash) error {
	// Walked one at a time for the same reason as SignerInfos: these are
	// the contents of a SET OF, and Go's asn1 fills a slice from one only
	// through a struct field tagged "set".
	var attrs []cmsAttribute
	for rest := attrBytes; len(rest) > 0; {
		var a cmsAttribute
		remaining, err := asn1.Unmarshal(rest, &a)
		if err != nil {
			return fmt.Errorf("anchor: the token's signed attributes could not be read: %w", err)
		}
		attrs = append(attrs, a)
		rest = remaining
	}

	var want []byte
	for _, a := range attrs {
		if !a.Type.Equal(oidMessageDigest) {
			continue
		}
		var got []byte
		if _, err := asn1.Unmarshal(a.Values.Bytes, &got); err != nil {
			return fmt.Errorf("anchor: the token's message-digest attribute could not be read: %w", err)
		}
		want = got
		break
	}
	if want == nil {
		// Without it the signature says nothing about this content.
		return errors.New("anchor: the token's signed attributes carry no message-digest, so they do not commit to the timestamp")
	}

	sum := h.New()
	sum.Write(eContent)
	if !bytes.Equal(sum.Sum(nil), want) {
		return fmt.Errorf("%w: the signed attributes commit to different content than the token carries", ErrTokenSignature)
	}
	return nil
}

// tokenCertificates decodes the certificate set the token ships.
func tokenCertificates(sd *signedData) ([]*x509.Certificate, error) {
	if len(sd.Certificates.Bytes) == 0 {
		return nil, nil
	}
	// CertificateSet is [0] IMPLICIT; x509.ParseCertificates wants a bare
	// concatenation of certificates, which is what the contents are.
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("anchor: the token's certificates could not be read: %w", err)
	}
	return certs, nil
}

// signerCertificate picks the certificate the SignerInfo names.
func signerCertificate(certs []*x509.Certificate, si signerInfo) (*x509.Certificate, error) {
	// SubjectKeyIdentifier form, [0] IMPLICIT OCTET STRING.
	if si.SID.Class == asn1.ClassContextSpecific && si.SID.Tag == 0 {
		for _, c := range certs {
			if bytes.Equal(c.SubjectKeyId, si.SID.Bytes) {
				return c, nil
			}
		}
		return nil, errors.New("anchor: the token names a signing key it does not carry a certificate for")
	}

	var ias issuerAndSerial
	if _, err := asn1.Unmarshal(si.SID.FullBytes, &ias); err != nil {
		return nil, fmt.Errorf("anchor: the token's signer identifier could not be read: %w", err)
	}
	for _, c := range certs {
		if c.SerialNumber != nil && ias.SerialNumber != nil &&
			c.SerialNumber.Cmp(ias.SerialNumber) == 0 &&
			bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) {
			return c, nil
		}
	}
	return nil, errors.New("anchor: the token names a signing certificate it does not carry")
}

func hashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidDigestSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidDigestSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidDigestSHA512):
		return crypto.SHA512, nil
	}
	// SHA-1 is deliberately absent. A timestamp is a statement meant to
	// outlive the thing it is about, and accepting a collision-prone
	// digest here would let one be transplanted onto other content later.
	return 0, fmt.Errorf("anchor: the token uses digest algorithm %v, which is not accepted", oid)
}

// signatureAlgorithm maps the token's algorithm identifiers onto the ones
// crypto/x509 can check.
//
// The signature OID alone is often the bare key algorithm — rsaEncryption
// or id-ecPublicKey — with the digest carried separately, so both are
// needed to name the pair.
func signatureAlgorithm(si signerInfo, h crypto.Hash) (x509.SignatureAlgorithm, error) {
	oid := si.SignatureAlgorithm.Algorithm
	switch {
	case oid.Equal(oidSigRSASHA256):
		return x509.SHA256WithRSA, nil
	case oid.Equal(oidSigRSASHA384):
		return x509.SHA384WithRSA, nil
	case oid.Equal(oidSigRSASHA512):
		return x509.SHA512WithRSA, nil
	case oid.Equal(oidSigECDSA256):
		return x509.ECDSAWithSHA256, nil
	case oid.Equal(oidSigECDSA384):
		return x509.ECDSAWithSHA384, nil
	case oid.Equal(oidSigECDSA512):
		return x509.ECDSAWithSHA512, nil
	case oid.Equal(oidSigRSAPSS):
		switch h {
		case crypto.SHA256:
			return x509.SHA256WithRSAPSS, nil
		case crypto.SHA384:
			return x509.SHA384WithRSAPSS, nil
		case crypto.SHA512:
			return x509.SHA512WithRSAPSS, nil
		}
	case oid.Equal(oidSigRSA):
		switch h {
		case crypto.SHA256:
			return x509.SHA256WithRSA, nil
		case crypto.SHA384:
			return x509.SHA384WithRSA, nil
		case crypto.SHA512:
			return x509.SHA512WithRSA, nil
		}
	case oid.Equal(oidSigECDSAAny):
		switch h {
		case crypto.SHA256:
			return x509.ECDSAWithSHA256, nil
		case crypto.SHA384:
			return x509.ECDSAWithSHA384, nil
		case crypto.SHA512:
			return x509.ECDSAWithSHA512, nil
		}
	}
	return 0, fmt.Errorf("anchor: the token is signed with %v, which is not accepted", oid)
}

// encodeLength writes a DER length, which is needed to rebuild the SET
// wrapper around the signed attributes.
func encodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

// sha256Of is a small helper so callers do not repeat the two lines.
func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
