package anchor

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// A timestamp token nobody signed must not read as an anchor.
//
// This is the defect this file exists for. SignerInfos was parsed and never
// looked at, so a token with an empty signer set — minted in a few lines,
// dated to any moment — was accepted, the verifier printed "anchored", and
// the warning saying issuance time rests on the issuer's clock alone went
// away. A forged receipt read as stronger evidence than the honest one it
// was made from, which is the exact inversion of the rule this product is.
//
// Built by emptying the signer set of a genuine token rather than by
// assembling one from scratch: everything else about it stays valid, so a
// failure here can only be the signature check.
func TestATokenNobodySignedIsRefused(t *testing.T) {
	token, digest := genuineToken(t)

	forged := withEmptySignerSet(t, token)
	if _, _, err := parseTSTInfo(forged); err != nil {
		t.Fatalf("the forged token no longer parses, so this test would pass for the wrong reason: %v", err)
	}

	a := &receipt.Anchor{Type: receipt.AnchorRFC3161, Value: base64.StdEncoding.EncodeToString(forged)}
	res, err := Verify(a, digest)
	if err == nil {
		t.Fatalf("a token with no signer was accepted as an anchor: %+v", res)
	}
	if !strings.Contains(err.Error(), "no signature") {
		t.Errorf("refused, but not as a forgery: %v", err)
	}
}

// The genuine token must still verify, or the check above is just a way of
// refusing everything.
func TestAGenuineTokenStillVerifies(t *testing.T) {
	token, digest := genuineToken(t)

	a := &receipt.Anchor{Type: receipt.AnchorRFC3161, Value: base64.StdEncoding.EncodeToString(token)}
	res, err := Verify(a, digest)
	if err != nil {
		t.Fatalf("a real authority's token was refused: %v", err)
	}
	if !res.SignatureVerified {
		t.Error("the result does not record that the signature was checked")
	}
	if res.ChainVerified {
		t.Error("the result claims the certificate chain was checked; no trust store is consulted here")
	}
	if res.SignerSubject == "" {
		t.Error("the result does not name whose corroboration is being claimed")
	}
}

// An anchor cannot predate the receipt it anchors.
//
// The cheapest defence there is against a forged or borrowed token — no
// trust store, no network — and it was absent. Anchors dated years early
// and years late both passed without a warning, because the only skew
// check compared the token's time against a field derived from that same
// time, so it was always zero.
func TestAnAnchorDatedBeforeItsReceiptIsRefused(t *testing.T) {
	cases := []struct {
		name   string
		issued time.Time
		refuse bool
	}{
		{"issued long after the token was minted", time.Now().Add(7 * 365 * 24 * time.Hour), true},
		{"issued a minute after, which is clock drift", time.Now().Add(time.Minute), false},
	}
	for _, c := range cases {
		res := &AnchorResult{GenTime: time.Now().UTC()}
		r := &receipt.Receipt{IssuedAt: c.issued.UTC().Format(time.RFC3339)}
		err := anchorAfterIssuance(r, res)
		if c.refuse && err == nil {
			t.Errorf("%s: accepted an anchor dated before the receipt existed", c.name)
		}
		if !c.refuse && err != nil {
			t.Errorf("%s: refused ordinary clock drift: %v", c.name, err)
		}
	}
}

// genuineToken returns a real authority's token and the digest it commits
// to, skipping when the fixture is unavailable.
func genuineToken(t *testing.T) ([]byte, []byte) {
	t.Helper()
	token, err := os.ReadFile("testdata/digicert-token.tsr")
	if err != nil {
		t.Skipf("token fixture unavailable: %v", err)
	}
	hexDigest, err := os.ReadFile("testdata/digicert-token.digest")
	if err != nil {
		t.Skipf("digest fixture unavailable: %v", err)
	}
	digest, err := decodeHex(strings.TrimSpace(string(hexDigest)))
	if err != nil {
		t.Fatalf("decoding the fixture digest: %v", err)
	}
	return token, digest
}

// withEmptySignerSet rebuilds a token with its SignerInfos emptied, which
// is what a forger has to produce and what nothing used to notice.
func withEmptySignerSet(t *testing.T, token []byte) []byte {
	t.Helper()
	var ci contentInfo
	if _, err := asn1.Unmarshal(token, &ci); err != nil {
		t.Fatalf("decoding the fixture token: %v", err)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("decoding the fixture SignedData: %v", err)
	}
	sd.SignerInfos = asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: nil}

	inner, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("re-encoding SignedData: %v", err)
	}
	out, err := asn1.Marshal(contentInfo{
		ContentType: ci.ContentType,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner},
	})
	if err != nil {
		t.Fatalf("re-encoding ContentInfo: %v", err)
	}
	return out
}

// The web verifier must reach the same verdict as the command line one.
// It did not: POST /v1/receipts/verify never called VerifyAll, so a
// receipt carrying a garbage anchor lost its "no anchor" warning through
// the API and gained nothing checkable in exchange.
func TestVerifyAllRefusesAForgedAnchorOnARealReceipt(t *testing.T) {
	raw, err := os.ReadFile("../testdata/anchor/rfc3161.json")
	if err != nil {
		t.Skipf("anchor fixture unavailable: %v", err)
	}
	var r receipt.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	if len(r.Anchors) == 0 {
		t.Skip("fixture carries no anchors")
	}
	if _, err := VerifyAll(&r); err != nil {
		t.Fatalf("the genuine fixture did not verify, so this test cannot show anything: %v", err)
	}

	token, err := base64.StdEncoding.DecodeString(r.Anchors[0].Value)
	if err != nil {
		t.Fatalf("decoding the fixture anchor: %v", err)
	}
	r.Anchors[0].Value = base64.StdEncoding.EncodeToString(withEmptySignerSet(t, token))
	if _, err := VerifyAll(&r); err == nil {
		t.Fatal("a receipt carrying a token nobody signed verified as anchored")
	}
}
