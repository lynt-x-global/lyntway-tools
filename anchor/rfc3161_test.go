package anchor

import (
	"context"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// loadFixture returns a genuine DigiCert timestamp token captured from the
// live authority, and the receipt digest it commits to.
//
// A real token rather than a synthesised one, because the parser's job is
// to cope with what authorities actually emit — optional fields present or
// absent, certificates embedded, accuracy unspecified. A hand-built fixture
// would only ever prove the parser agrees with itself.
func loadFixture(t *testing.T) (token, digest []byte) {
	t.Helper()
	token, err := os.ReadFile("testdata/digicert-token.tsr")
	if err != nil {
		t.Fatalf("reading token fixture: %v", err)
	}
	hexDigest, err := os.ReadFile("testdata/digicert-token.digest")
	if err != nil {
		t.Fatalf("reading digest fixture: %v", err)
	}
	digest, err = hex.DecodeString(strings.TrimSpace(string(hexDigest)))
	if err != nil {
		t.Fatalf("decoding digest fixture: %v", err)
	}
	return token, digest
}

// wrapInResponse builds a TimeStampResp around a token, so the response
// parser can be tested against real token bytes.
func wrapInResponse(t *testing.T, token []byte, status int) []byte {
	t.Helper()
	der, err := asn1.Marshal(timeStampResp{
		Status:         pkiStatusInfo{Status: status},
		TimeStampToken: asn1.RawValue{FullBytes: token},
	})
	if err != nil {
		t.Fatalf("marshalling response: %v", err)
	}
	return der
}

func TestParseTSTInfoFromRealToken(t *testing.T) {
	token, digest := loadFixture(t)

	info, err := parseTSTInfo(token)
	if err != nil {
		t.Fatalf("parsing TSTInfo: %v", err)
	}

	if info.Version != 1 {
		t.Errorf("version = %d, want 1", info.Version)
	}
	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Errorf("hash algorithm = %v, want SHA-256", info.MessageImprint.HashAlgorithm.Algorithm)
	}
	if string(info.MessageImprint.HashedMessage) != string(digest) {
		t.Errorf("token commits to %x, want %x", info.MessageImprint.HashedMessage, digest)
	}
	if info.GenTime.IsZero() {
		t.Error("no generation time")
	}
	if info.SerialNumber == nil || info.SerialNumber.Sign() == 0 {
		t.Error("no serial number")
	}
	// The nonce round-tripped, which is what proves the response answers
	// the request rather than being replayed from an earlier exchange.
	if info.Nonce == nil {
		t.Error("no nonce echoed back")
	}
}

// TestImprintMismatchRejected is the check the whole anchor rests on. A
// token for different content verifies perfectly and proves nothing about
// this receipt, so accepting one would make anchoring worthless while
// looking like it worked.
func TestImprintMismatchRejected(t *testing.T) {
	token, _ := loadFixture(t)
	resp := wrapInResponse(t, token, statusGranted)

	wrongDigest := make([]byte, 32)
	for i := range wrongDigest {
		wrongDigest[i] = 0xAA
	}

	if _, _, err := parseResponse(resp, wrongDigest, nil); !errors.Is(err, errImprintMiss) {
		t.Fatalf("err = %v, want errImprintMiss", err)
	}
}

func TestCorrectImprintAccepted(t *testing.T) {
	token, digest := loadFixture(t)
	resp := wrapInResponse(t, token, statusGranted)

	got, genTime, err := parseResponse(resp, digest, nil)
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	if len(got) == 0 {
		t.Error("no token returned")
	}
	if genTime.IsZero() {
		t.Error("no generation time returned")
	}
}

// TestNonceMismatchRejected proves a replayed token is refused.
func TestNonceMismatchRejected(t *testing.T) {
	token, digest := loadFixture(t)
	resp := wrapInResponse(t, token, statusGranted)

	// A nonce that cannot match the one embedded in the captured token.
	other := new(big.Int).SetInt64(1)

	_, _, err := parseResponse(resp, digest, other)
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("err = %v, want a nonce mismatch", err)
	}
}

func TestRejectedStatusesAreRefused(t *testing.T) {
	token, digest := loadFixture(t)

	for _, tc := range []struct {
		name   string
		status int
	}{
		{"rejection", statusRejection},
		{"waiting", statusWaiting},
		{"revocation warning", statusRevocationWarning},
		{"revocation notified", statusRevocationNotified},
		{"unknown", 99},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := wrapInResponse(t, token, tc.status)
			if _, _, err := parseResponse(resp, digest, nil); err == nil {
				t.Errorf("status %d was accepted", tc.status)
			}
		})
	}
}

func TestGrantedWithModsAccepted(t *testing.T) {
	token, digest := loadFixture(t)
	resp := wrapInResponse(t, token, statusGrantedWithMods)
	if _, _, err := parseResponse(resp, digest, nil); err != nil {
		t.Errorf("grantedWithMods was refused: %v", err)
	}
}

func TestMalformedResponsesRejected(t *testing.T) {
	_, digest := loadFixture(t)
	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"empty", nil},
		{"not asn1", []byte("this is not DER at all")},
		{"truncated", []byte{0x30, 0x82, 0xFF, 0xFF}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseResponse(tc.der, digest, nil); err == nil {
				t.Error("malformed response accepted")
			}
		})
	}
}

func TestGrantedWithNoTokenRejected(t *testing.T) {
	_, digest := loadFixture(t)
	der, err := asn1.Marshal(timeStampResp{Status: pkiStatusInfo{Status: statusGranted}})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if _, _, err := parseResponse(der, digest, nil); err == nil {
		t.Error("a granted response with no token was accepted")
	}
}

func TestDigestLengthEnforced(t *testing.T) {
	a, err := NewRFC3161("http://example.invalid")
	if err != nil {
		t.Fatalf("NewRFC3161: %v", err)
	}
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := a.Anchor(context.Background(), make([]byte, n)); err == nil {
			t.Errorf("a %d-byte digest was accepted", n)
		}
	}
}

// TestHTTPErrorsSurface proves a failing authority produces a clear error
// rather than a silently missing anchor.
func TestHTTPErrorsSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	a, _ := NewRFC3161(srv.URL)
	_, err := a.Anchor(context.Background(), make([]byte, 32))
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("err = %v, want an HTTP 503 error", err)
	}
}

// TestServerSuppliedGarbageRejected proves a hostile authority cannot make
// the parser accept nonsense as a proof.
func TestServerSuppliedGarbageRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write([]byte("definitely not a timestamp response"))
	}))
	defer srv.Close()

	a, _ := NewRFC3161(srv.URL)
	if _, err := a.Anchor(context.Background(), make([]byte, 32)); err == nil {
		t.Error("garbage from the authority was accepted as a proof")
	}
}

func TestContextCancellationRespected(t *testing.T) {
	// The handler must have a release the test controls. Blocking purely on
	// the request context deadlocks against srv.Close(), which waits for
	// outstanding requests — the test would hang rather than fail.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	a, _ := NewRFC3161(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if _, err := a.Anchor(ctx, make([]byte, 32)); err == nil {
		t.Error("a hung authority did not produce an error")
	}
}

// --- Set --------------------------------------------------------------------

type stubAnchorer struct {
	typ receipt.AnchorType
	err error
}

func (s stubAnchorer) Type() receipt.AnchorType { return s.typ }
func (s stubAnchorer) Anchor(ctx context.Context, digest []byte) (*receipt.Anchor, error) {
	if s.err != nil {
		return nil, s.err
	}
	return newAnchor(s.typ, []byte("token"), time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)), nil
}

// TestPartialAnchoringSucceeds encodes a deliberate choice: a receipt with
// one anchor is materially better than a receipt with none, so a transient
// outage at one authority must not discard a proof another already gave.
func TestPartialAnchoringSucceeds(t *testing.T) {
	set := &Set{Anchorers: []Anchorer{
		stubAnchorer{typ: receipt.AnchorRFC3161},
		stubAnchorer{typ: receipt.AnchorOpenTimestamps, err: errors.New("calendar unreachable")},
	}}

	anchors, err := set.AnchorAll(context.Background(), make([]byte, 32))
	if err != nil {
		t.Fatalf("partial success was reported as failure: %v", err)
	}
	if len(anchors) != 1 {
		t.Fatalf("got %d anchors, want 1", len(anchors))
	}
	if anchors[0].Type != receipt.AnchorRFC3161 {
		t.Errorf("wrong anchor survived: %s", anchors[0].Type)
	}
}

func TestRequireAllFailsOnPartial(t *testing.T) {
	set := &Set{
		Anchorers: []Anchorer{
			stubAnchorer{typ: receipt.AnchorRFC3161},
			stubAnchorer{typ: receipt.AnchorOpenTimestamps, err: errors.New("down")},
		},
		RequireAll: true,
	}
	if _, err := set.AnchorAll(context.Background(), make([]byte, 32)); err == nil {
		t.Error("RequireAll accepted a partial result")
	}
}

func TestTotalFailureIsAnError(t *testing.T) {
	set := &Set{Anchorers: []Anchorer{
		stubAnchorer{typ: receipt.AnchorRFC3161, err: errors.New("down")},
	}}
	if _, err := set.AnchorAll(context.Background(), make([]byte, 32)); err == nil {
		t.Error("total failure was reported as success")
	}
}

func TestNoAnchorersConfigured(t *testing.T) {
	set := &Set{}
	if _, err := set.AnchorAll(context.Background(), make([]byte, 32)); !errors.Is(err, ErrNoAnchorers) {
		t.Errorf("err = %v, want ErrNoAnchorers", err)
	}
}

// TestAttachToPreservesSignature is the property that makes anchoring safe
// to do after the fact: attaching an anchor must never invalidate the
// receipt it commits to.
func TestAttachToPreservesSignature(t *testing.T) {
	signer, err := receipt.GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	keys := receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}

	r := signedTestReceipt(t, signer)
	before, err := receipt.Digest(r)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	set := &Set{Anchorers: []Anchorer{
		stubAnchorer{typ: receipt.AnchorRFC3161},
		stubAnchorer{typ: receipt.AnchorOpenTimestamps},
	}}
	if err := AttachTo(context.Background(), r, set); err != nil {
		t.Fatalf("AttachTo: %v", err)
	}

	if len(r.Anchors) != 2 {
		t.Fatalf("attached %d anchors, want 2", len(r.Anchors))
	}

	after, err := receipt.Digest(r)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if before != after {
		t.Error("attaching an anchor changed the receipt digest; every chain link after it would break")
	}

	res, err := receipt.Verify(r, keys, receipt.VerifyOptions{})
	if err != nil {
		t.Fatalf("receipt no longer verifies after anchoring: %v", err)
	}
	// The verifier's "no anchor" warning must disappear once anchored.
	for _, w := range res.Warnings {
		if strings.Contains(w, "no external timestamp anchor") {
			t.Error("the missing-anchor warning survived anchoring")
		}
	}
}

func TestAttachToRefusesUnsignedReceipt(t *testing.T) {
	r := &receipt.Receipt{Version: receipt.SchemaVersion}
	set := &Set{Anchorers: []Anchorer{stubAnchorer{typ: receipt.AnchorRFC3161}}}
	if err := AttachTo(context.Background(), r, set); err == nil {
		t.Error("an unsigned receipt was anchored; the anchor would bind a value about to change")
	}
}

func signedTestReceipt(t *testing.T, signer receipt.Signer) *receipt.Receipt {
	t.Helper()
	r := &receipt.Receipt{
		ID:       "rcpt_anchor_test",
		IssuedAt: receipt.Now(),
		Issuer:   receipt.Issuer{KeyID: signer.KeyID()},
		Chain:    receipt.Chain{ID: "ws_anchor", Seq: 0},
		Action: receipt.Action{
			Surface: receipt.SurfacePrimitive, Direction: receipt.DirectionRequest,
			Method: "POST /v1/govern",
		},
		Actor: receipt.Actor{
			Type: receipt.ActorAgent, ID: "a", Source: receipt.IdentityLyntwayKey,
		},
		Content: receipt.Content{
			Algorithm:    receipt.DigestSHA256,
			InputDigest:  receipt.DigestContent([]byte("x")),
			OutputDigest: receipt.DigestContent([]byte("x")),
			Bytes:        1,
		},
		Governance: receipt.Governance{
			Mode: receipt.ModeFull, Decision: receipt.DecisionAllow,
			Detector: receipt.Detector{
				Engine: "test", EngineVersion: "1", RulesetVersion: "1",
				Health: receipt.HealthHealthy,
			},
			Policy: receipt.Policy{ID: "p", Version: "1"},
		},
	}
	if err := receipt.Sign(r, signer); err != nil {
		t.Fatalf("signing: %v", err)
	}
	return r
}

func TestDecodeHex(t *testing.T) {
	got, err := decodeHex("00ff10AB")
	if err != nil {
		t.Fatalf("decodeHex: %v", err)
	}
	want := []byte{0x00, 0xff, 0x10, 0xab}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %x, want %x", got, want)
		}
	}
	for _, bad := range []string{"abc", "zz", "0g"} {
		if _, err := decodeHex(bad); err == nil {
			t.Errorf("decodeHex(%q) accepted invalid input", bad)
		}
	}
}

// TestLiveTimestampAuthority exercises a real authority. Skipped by
// default: CI must not fail because someone else's service is down, and a
// test that depends on the network is a flake waiting to happen.
//
//	go test ./anchor/ -run TestLiveTimestampAuthority -tsa-live
func TestLiveTimestampAuthority(t *testing.T) {
	if os.Getenv("LYNTWAY_TSA_LIVE") != "1" {
		t.Skip("set LYNTWAY_TSA_LIVE=1 to exercise live timestamp authorities")
	}

	for _, url := range []string{
		"http://timestamp.digicert.com",
		"http://timestamp.sectigo.com",
		"http://freetsa.org/tsr",
	} {
		t.Run(url, func(t *testing.T) {
			a, err := NewRFC3161(url)
			if err != nil {
				t.Fatalf("NewRFC3161: %v", err)
			}
			digest := make([]byte, 32)
			if _, err := rand.Read(digest); err != nil {
				t.Fatalf("rand: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			an, err := a.Anchor(ctx, digest)
			if err != nil {
				t.Fatalf("anchoring: %v", err)
			}
			token, err := base64.StdEncoding.DecodeString(an.Value)
			if err != nil {
				t.Fatalf("decoding token: %v", err)
			}
			info, err := parseTSTInfo(token)
			if err != nil {
				t.Fatalf("parsing returned token: %v", err)
			}
			if string(info.MessageImprint.HashedMessage) != string(digest) {
				t.Error("the authority signed a different digest than the one submitted")
			}
			t.Logf("%s issued a %d byte token at %s", url, len(token), an.AnchoredAt)
		})
	}
}
