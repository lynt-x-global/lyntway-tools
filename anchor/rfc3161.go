package anchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// RFC 3161 timestamping, implemented against encoding/asn1 rather than a
// third-party PKI library.
//
// The protocol is small enough to implement directly, and doing so keeps
// the module dependency-free — which matters more here than elsewhere,
// because this code decides whether a timestamp proof is trustworthy.

// Object identifiers used by the protocol.
var (
	oidSHA256      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSignedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCTTSTInfo   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	errNoTSTInfo   = errors.New("anchor: timestamp token contains no TSTInfo")
	errImprintMiss = errors.New("anchor: the timestamp authority signed a different digest than the one submitted")
)

// PKIStatus values from RFC 3161 section 2.4.2.
const (
	statusGranted            = 0
	statusGrantedWithMods    = 1
	statusRejection          = 2
	statusWaiting            = 3
	statusRevocationWarning  = 4
	statusRevocationNotified = 5
)

// --- Request structures -----------------------------------------------------

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     asn1.RawValue         `asn1:"optional,tag:0"`
}

// --- Response structures ----------------------------------------------------

type pkiStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// contentInfo is the CMS wrapper around SignedData.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData is parsed only far enough to reach the encapsulated TSTInfo.
// Certificates, signer infos, and the signature itself are left as raw
// values: verifying them is a separate concern from obtaining the token,
// and any standard RFC 3161 tool can do it offline against the stored
// token.
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

// accuracy is TSTInfo's optional precision statement.
//
// Typed as a struct rather than an asn1.RawValue on purpose. An optional
// RawValue matches ANY element, so when accuracy is absent — which is
// common — it greedily consumes whatever follows. That silently swallowed
// the nonce, leaving replay protection inert while every test that did not
// specifically look for a nonce still passed.
type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// tstInfo is the signed statement: this digest existed at this time.
//
// Every optional field here is typed to the shape the standard defines, so
// that an absent field cannot absorb the one after it.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Accuracy       accuracy      `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,tag:0"`
	Extensions     asn1.RawValue `asn1:"optional,tag:1"`
}

// --- Anchorer ---------------------------------------------------------------

// RFC3161 obtains timestamp tokens from a timestamp authority.
type RFC3161 struct {
	// URL is the TSA endpoint.
	URL string

	// Client issues the HTTP request. Defaults to a client with a 30
	// second timeout — anchoring must never hang a caller indefinitely.
	Client *http.Client

	// RequestCert asks the TSA to embed its certificate in the token.
	//
	// On by default in NewRFC3161, because a token without the signing
	// certificate cannot be verified by a third party who does not already
	// hold it — which defeats the point of an anchor.
	RequestCert bool
}

// NewRFC3161 creates an anchorer for a timestamp authority.
func NewRFC3161(url string) (*RFC3161, error) {
	if url == "" {
		return nil, errors.New("anchor: timestamp authority URL must not be empty")
	}
	return &RFC3161{
		URL:         url,
		Client:      &http.Client{Timeout: 30 * time.Second},
		RequestCert: true,
	}, nil
}

// Type implements Anchorer.
func (a *RFC3161) Type() receipt.AnchorType { return receipt.AnchorRFC3161 }

// Anchor obtains a timestamp token for digest.
//
// The returned token is the complete DER-encoded TimeStampToken, so it can
// be verified later by any standard tool without needing anything else this
// package produced.
func (a *RFC3161) Anchor(ctx context.Context, digest []byte) (*receipt.Anchor, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("anchor: digest must be %d bytes, got %d", sha256.Size, len(digest))
	}

	// A random nonce binds the response to this request, so a replayed
	// token from an earlier exchange cannot be passed off as fresh.
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, fmt.Errorf("anchor: generating nonce: %w", err)
	}

	hashOID, err := hashFor(crypto.SHA256)
	if err != nil {
		return nil, err
	}

	reqDER, err := asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm:  hashOID,
				Parameters: asn1.NullRawValue,
			},
			HashedMessage: digest,
		},
		Nonce:   nonce,
		CertReq: a.RequestCert,
	})
	if err != nil {
		return nil, fmt.Errorf("anchor: encoding timestamp request: %w", err)
	}

	token, genTime, err := a.exchange(ctx, reqDER, digest, nonce)
	if err != nil {
		return nil, err
	}
	return newAnchor(receipt.AnchorRFC3161, token, genTime), nil
}

// exchange posts the request and validates the response.
func (a *RFC3161) exchange(ctx context.Context, reqDER, digest []byte, nonce *big.Int) ([]byte, time.Time, error) {
	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("anchor: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("anchor: contacting timestamp authority: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("anchor: timestamp authority returned HTTP %d", resp.StatusCode)
	}

	// Cap the response so a hostile or broken authority cannot exhaust
	// memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("anchor: reading response: %w", err)
	}

	return parseResponse(body, digest, nonce)
}

// parseResponse validates a TimeStampResp and extracts the token.
//
// Split out from the network call so the validation logic is testable
// against fixtures without a live authority.
func parseResponse(der, digest []byte, nonce *big.Int) ([]byte, time.Time, error) {
	var resp timeStampResp
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, time.Time{}, fmt.Errorf("anchor: decoding timestamp response: %w", err)
	}

	switch resp.Status.Status {
	case statusGranted, statusGrantedWithMods:
		// Accepted.
	case statusRejection:
		return nil, time.Time{}, errors.New("anchor: timestamp authority rejected the request")
	case statusWaiting:
		return nil, time.Time{}, errors.New("anchor: timestamp authority returned a waiting status; asynchronous issuance is not supported")
	case statusRevocationWarning, statusRevocationNotified:
		return nil, time.Time{}, errors.New("anchor: timestamp authority reported a revocation condition")
	default:
		return nil, time.Time{}, fmt.Errorf("anchor: timestamp authority returned status %d", resp.Status.Status)
	}

	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, time.Time{}, errors.New("anchor: response granted but carries no timestamp token")
	}
	token := resp.TimeStampToken.FullBytes

	info, err := parseTSTInfo(token)
	if err != nil {
		return nil, time.Time{}, err
	}

	// The whole value of an anchor rests on it committing to *our* digest.
	// A token for different content would verify perfectly and prove
	// nothing about this receipt, so this check is not optional.
	if !bytes.Equal(info.MessageImprint.HashedMessage, digest) {
		return nil, time.Time{}, errImprintMiss
	}
	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return nil, time.Time{}, fmt.Errorf("anchor: authority used hash algorithm %v, expected SHA-256",
			info.MessageImprint.HashAlgorithm.Algorithm)
	}
	// A mismatched nonce means the response is not an answer to this
	// request — most likely a replayed token.
	if nonce != nil && info.Nonce != nil && info.Nonce.Cmp(nonce) != 0 {
		return nil, time.Time{}, errors.New("anchor: nonce mismatch; the response does not correspond to this request")
	}

	return token, info.GenTime, nil
}

// parseTSTInfo unwraps CMS SignedData to reach the timestamp statement.
func parseTSTInfo(token []byte) (*tstInfo, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(token, &ci); err != nil {
		return nil, fmt.Errorf("anchor: decoding token ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("anchor: token content type is %v, expected CMS SignedData", ci.ContentType)
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("anchor: decoding SignedData: %w", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidCTTSTInfo) {
		return nil, fmt.Errorf("anchor: encapsulated content type is %v, expected TSTInfo",
			sd.EncapContentInfo.EContentType)
	}
	if len(sd.EncapContentInfo.EContent) == 0 {
		return nil, errNoTSTInfo
	}

	var info tstInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &info); err != nil {
		return nil, fmt.Errorf("anchor: decoding TSTInfo: %w", err)
	}
	return &info, nil
}

// hashFor reports the OID for a supported hash. Present so adding SHA-384
// later is a table entry rather than a rewrite.
func hashFor(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA256:
		return oidSHA256, nil
	default:
		return nil, fmt.Errorf("anchor: unsupported hash %v", h)
	}
}
