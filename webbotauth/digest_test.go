package webbotauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestContentDigestMatchesTheSDKForm(t *testing.T) {
	body := []byte(`{"content":"hi"}`)
	got := ContentDigest(body)
	if !strings.HasPrefix(got, "sha-256=:") || !strings.HasSuffix(got, ":") {
		t.Fatalf("form = %q", got)
	}
	if err := VerifyContentDigest(got, body); err != nil {
		t.Errorf("our own digest does not verify: %v", err)
	}
	if err := VerifyContentDigest(got, append([]byte(nil), body[:len(body)-1]...)); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("a changed body verified: %v", err)
	}
}

func TestContentDigestAcceptsSHA512AndRefusesTheUnknown(t *testing.T) {
	body := []byte("bytes")
	sum := sha512.Sum512(body)
	header := "sha-512=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	if err := VerifyContentDigest(header, body); err != nil {
		t.Errorf("sha-512: %v", err)
	}
	// Both named, both checked: a wrong sha-256 beside a right sha-512
	// is a mismatch, not a pass.
	if err := VerifyContentDigest(header+", "+ContentDigest([]byte("other")), body); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("a wrong second digest passed: %v", err)
	}
	if err := VerifyContentDigest("md5=:AAAA:", body); !errors.Is(err, ErrDigestUnsupported) {
		t.Errorf("an unknown algorithm was accepted: %v", err)
	}
	if err := VerifyContentDigest("", body); !errors.Is(err, ErrDigestUnsupported) {
		t.Errorf("an empty header: %v", err)
	}
	if err := VerifyContentDigest("sha-256=notbytes", body); !errors.Is(err, ErrMalformed) {
		t.Errorf("a malformed value: %v", err)
	}
}

// @path is the path as sent, percent-encoding intact. A signer cannot see
// the decoded form, so a verifier that reconstructed it would fail every
// signature over an encoded path.
func TestPathIsVerifiedAsSentNotDecoded(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := StaticKeys{"k1": pub}

	r := httptest.NewRequest("GET", "/v1/files/a%2Fb%20c", nil)
	r.Host = "govern.example"
	if r.URL.Path != "/v1/files/a/b c" || r.URL.EscapedPath() != "/v1/files/a%2Fb%20c" {
		t.Fatalf("the fixture does not exercise encoding: path %q escaped %q", r.URL.Path, r.URL.EscapedPath())
	}

	// Signed over the encoded path, the way every SDK does it.
	inner := `("@method" "@authority" "@path");created=1757203200;expires=1757203500;keyid="k1";alg="ed25519";tag="web-bot-auth"`
	base := "\"@method\": GET\n\"@authority\": govern.example\n\"@path\": /v1/files/a%2Fb%20c\n\"@signature-params\": " + inner
	sig := ed25519.Sign(priv, []byte(base))
	r.Header.Set("Signature-Input", "sig1="+inner)
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")

	if _, err := Verify(r, keys, Options{Now: time.Unix(1757203210, 0)}); err != nil {
		t.Errorf("a signature over the encoded path was refused: %v", err)
	}
}
