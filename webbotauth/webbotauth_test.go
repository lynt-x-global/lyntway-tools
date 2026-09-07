package webbotauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signRequest produces a Web Bot Auth signature the way a conforming agent
// would, so verification is tested against something built independently of
// the verifier rather than against its own output.
func signRequest(t *testing.T, r *http.Request, priv ed25519.PrivateKey, opts signOptions) {
	t.Helper()

	keyID, err := JWKThumbprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if opts.keyID != "" {
		keyID = opts.keyID
	}

	components := opts.components
	if components == nil {
		components = []string{"@authority"}
	}

	var quoted []string
	for _, c := range components {
		quoted = append(quoted, `"`+c+`"`)
	}

	tag := Tag
	if opts.tag != "" {
		tag = opts.tag
	}
	alg := Algorithm
	if opts.alg != "" {
		alg = opts.alg
	}

	created := opts.created
	if created.IsZero() {
		created = time.Now()
	}
	expires := opts.expires
	if expires.IsZero() {
		expires = created.Add(time.Hour)
	}

	params := fmt.Sprintf(`;created=%d;keyid=%q;alg=%q;expires=%d;tag=%q`,
		created.Unix(), keyID, alg, expires.Unix(), tag)
	inner := "(" + strings.Join(quoted, " ") + ")" + params

	// Build the signature base exactly as RFC 9421 specifies, without
	// reusing the verifier's implementation.
	var base strings.Builder
	for _, c := range components {
		var value string
		switch c {
		case "@authority":
			value = strings.ToLower(r.Host)
		case "@method":
			value = strings.ToUpper(r.Method)
		case "@path":
			value = r.URL.Path
		case "signature-agent":
			value = r.Header.Get("Signature-Agent")
		default:
			value = r.Header.Get(c)
		}
		base.WriteString(`"` + c + `": ` + value + "\n")
	}
	base.WriteString(`"@signature-params": ` + inner)

	sig := ed25519.Sign(priv, []byte(base.String()))

	label := "sig1"
	r.Header.Set("Signature-Input", label+"="+inner)
	r.Header.Set("Signature", label+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
}

type signOptions struct {
	components []string
	tag        string
	alg        string
	keyID      string
	created    time.Time
	expires    time.Time
}

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, StaticKeys) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	thumb, err := JWKThumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return pub, priv, StaticKeys{thumb: pub}
}

func newRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://govern.lyntway.com/v1/govern", nil)
	r.Host = "govern.lyntway.com"
	return r
}

func TestVerifyValidSignature(t *testing.T) {
	_, priv, keys := testKeys(t)
	r := newRequest()
	signRequest(t, r, priv, signOptions{})

	res, err := Verify(r, keys, Options{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.KeyID == "" {
		t.Error("no key ID reported")
	}
	if len(res.Covered) != 1 || res.Covered[0] != "@authority" {
		t.Errorf("covered = %v", res.Covered)
	}
}

func TestUnsignedRequest(t *testing.T) {
	_, _, keys := testKeys(t)
	if _, err := Verify(newRequest(), keys, Options{}); !errors.Is(err, ErrNoSignature) {
		t.Errorf("err = %v, want ErrNoSignature", err)
	}
}

// TestTamperedRequestFails proves the signature is bound to the request,
// not merely present on it.
func TestTamperedRequestFails(t *testing.T) {
	_, priv, keys := testKeys(t)

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"authority swapped", func(r *http.Request) { r.Host = "evil.example" }},
		{"signature bytes flipped", func(r *http.Request) {
			raw := r.Header.Get("Signature")
			inner := raw[strings.Index(raw, ":")+1 : strings.LastIndex(raw, ":")]
			sig, _ := base64.StdEncoding.DecodeString(inner)
			sig[0] ^= 0xFF
			r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
		}},
		{"covered component list rewritten", func(r *http.Request) {
			in := r.Header.Get("Signature-Input")
			r.Header.Set("Signature-Input", strings.Replace(in, `("@authority")`, `("@method")`, 1))
		}},
		{"keyid swapped", func(r *http.Request) {
			in := r.Header.Get("Signature-Input")
			start := strings.Index(in, `keyid="`) + 7
			end := strings.Index(in[start:], `"`) + start
			r.Header.Set("Signature-Input", in[:start]+strings.Repeat("A", end-start)+in[end:])
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRequest()
			signRequest(t, r, priv, signOptions{})
			tc.mutate(r)

			if _, err := Verify(r, keys, Options{}); err == nil {
				t.Fatal("a tampered request verified")
			}
		})
	}
}

// TestWrongTagRejected covers domain separation. RFC 9421 signatures are
// used for many things; without the required tag, a signature produced for
// another purpose could be replayed as agent authentication.
func TestWrongTagRejected(t *testing.T) {
	_, priv, keys := testKeys(t)
	r := newRequest()
	signRequest(t, r, priv, signOptions{tag: "some-other-protocol"})

	if _, err := Verify(r, keys, Options{}); !errors.Is(err, ErrWrongTag) {
		t.Errorf("err = %v, want ErrWrongTag", err)
	}
}

// TestAuthorityBindingRequired proves a signature that does not cover the
// host is refused. Without it, a signature captured by one origin could be
// replayed against another.
func TestAuthorityBindingRequired(t *testing.T) {
	_, priv, keys := testKeys(t)
	r := newRequest()
	signRequest(t, r, priv, signOptions{components: []string{"@method"}})

	if _, err := Verify(r, keys, Options{}); !errors.Is(err, ErrMissingAuthority) {
		t.Errorf("err = %v, want ErrMissingAuthority", err)
	}
}

func TestTargetURISatisfiesAuthorityBinding(t *testing.T) {
	_, priv, keys := testKeys(t)
	r := newRequest()
	signRequest(t, r, priv, signOptions{components: []string{"@target-uri"}})

	// The signer's independent base builder does not know @target-uri, so
	// this only needs to reach past the authority check rather than verify.
	_, err := Verify(r, keys, Options{})
	if errors.Is(err, ErrMissingAuthority) {
		t.Error("@target-uri did not satisfy the authority binding requirement")
	}
}

func TestUnsupportedAlgorithmRejected(t *testing.T) {
	_, priv, keys := testKeys(t)
	r := newRequest()
	signRequest(t, r, priv, signOptions{alg: "rsa-pss-sha512"})

	if _, err := Verify(r, keys, Options{}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	_, priv, _ := testKeys(t)
	r := newRequest()
	signRequest(t, r, priv, signOptions{})

	if _, err := Verify(r, StaticKeys{}, Options{}); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("err = %v, want ErrUnknownKey", err)
	}
}

// TestExpiredSignatureRejected and its siblings cover the replay window.
func TestExpiredSignatureRejected(t *testing.T) {
	_, priv, keys := testKeys(t)
	created := time.Now().Add(-2 * time.Hour)
	r := newRequest()
	signRequest(t, r, priv, signOptions{created: created, expires: created.Add(time.Minute)})

	if _, err := Verify(r, keys, Options{}); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestFutureSignatureRejected(t *testing.T) {
	_, priv, keys := testKeys(t)
	future := time.Now().Add(time.Hour)
	r := newRequest()
	signRequest(t, r, priv, signOptions{created: future, expires: future.Add(time.Hour)})

	if _, err := Verify(r, keys, Options{}); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("err = %v, want ErrNotYetValid", err)
	}
}

// TestOldSignatureRejectedEvenWithLongExpiry proves an agent cannot mint a
// signature valid for a decade. An unbounded validity window is a replay
// waiting to happen.
func TestOldSignatureRejectedEvenWithLongExpiry(t *testing.T) {
	_, priv, keys := testKeys(t)
	created := time.Now().Add(-48 * time.Hour)
	r := newRequest()
	signRequest(t, r, priv, signOptions{created: created, expires: time.Now().Add(10000 * time.Hour)})

	if _, err := Verify(r, keys, Options{}); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired for a signature created two days ago", err)
	}
}

func TestClockSkewTolerated(t *testing.T) {
	_, priv, keys := testKeys(t)
	slightlyAhead := time.Now().Add(20 * time.Second)
	r := newRequest()
	signRequest(t, r, priv, signOptions{created: slightlyAhead, expires: slightlyAhead.Add(time.Hour)})

	if _, err := Verify(r, keys, Options{}); err != nil {
		t.Errorf("minor clock drift was not tolerated: %v", err)
	}
}

// TestUnsignedSignatureAgentRejected covers a real attack. If the header
// naming the key directory is not itself signed, it can be swapped for one
// pointing at keys the attacker controls.
func TestUnsignedSignatureAgentRejected(t *testing.T) {
	_, priv, keys := testKeys(t)
	r := newRequest()
	signRequest(t, r, priv, signOptions{components: []string{"@authority"}})
	// Added after signing, so it is present but not covered.
	r.Header.Set("Signature-Agent", `agent="https://attacker.example"`)

	if _, err := Verify(r, keys, Options{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want rejection of an uncovered Signature-Agent", err)
	}
}

func TestSignedSignatureAgentAccepted(t *testing.T) {
	_, priv, keys := testKeys(t)
	r := newRequest()
	r.Header.Set("Signature-Agent", "https://agent.example/.well-known/http-message-signatures-directory")
	signRequest(t, r, priv, signOptions{components: []string{"@authority", "signature-agent"}})

	res, err := Verify(r, keys, Options{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.SignatureAgent == "" {
		t.Error("the signature agent directory was not reported")
	}
}

// TestMultipleSignaturesPicksWebBotAuth proves an unrelated RFC 9421
// signature on the same request is not mistaken for agent identity.
func TestMultipleSignaturesPicksWebBotAuth(t *testing.T) {
	_, priv, keys := testKeys(t)
	r := newRequest()
	signRequest(t, r, priv, signOptions{})

	botInput := r.Header.Get("Signature-Input")
	botSig := r.Header.Get("Signature")

	r.Header.Set("Signature-Input",
		`other=("@method");created=1735689600;keyid="unrelated";tag="some-other-use", `+botInput)
	r.Header.Set("Signature", `other=:AAAA:, `+botSig)

	res, err := Verify(r, keys, Options{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Label != "sig1" {
		t.Errorf("picked label %q, want the web-bot-auth one", res.Label)
	}
}

// --- Thumbprints ------------------------------------------------------------

// TestJWKThumbprintIsStable pins RFC 7638. The thumbprint is over a
// canonical JWK with exactly crv, kty and x in lexicographic order — any
// other member or ordering yields a different value and the key never
// matches.
func TestJWKThumbprintIsStable(t *testing.T) {
	// A fixed key so the expected thumbprint cannot drift.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	thumb, err := JWKThumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if len(thumb) != 43 {
		t.Errorf("thumbprint is %d chars, want 43 for base64url SHA-256", len(thumb))
	}
	if strings.ContainsAny(thumb, "+/=") {
		t.Errorf("thumbprint %q is not base64url without padding", thumb)
	}

	again, _ := JWKThumbprint(pub)
	if thumb != again {
		t.Error("thumbprint is not deterministic")
	}
}

func TestJWKThumbprintRejectsBadKey(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := JWKThumbprint(make([]byte, n)); err == nil {
			t.Errorf("accepted a %d-byte key", n)
		}
	}
}

// TestKeysFromJWKSIndexesByThumbprint proves a directory cannot claim a key
// ID that does not correspond to its key. The keyid in a signature is
// defined as the thumbprint, so trusting a self-declared kid would let a
// directory impersonate another agent.
func TestKeysFromJWKSIndexesByThumbprint(t *testing.T) {
	pub, _, _ := testKeys(t)
	expected, _ := JWKThumbprint(pub)

	jwks := &JWKS{Keys: []JWK{{
		Kty: "OKP", Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Kid: "a-kid-the-directory-made-up",
	}}}

	keys, err := KeysFromJWKS(jwks)
	if err != nil {
		t.Fatalf("KeysFromJWKS: %v", err)
	}
	if _, ok := keys[expected]; !ok {
		t.Error("key is not indexed by its computed thumbprint")
	}
	if _, ok := keys["a-kid-the-directory-made-up"]; ok {
		t.Error("the directory's self-declared kid was trusted")
	}
}

func TestKeysFromJWKSSkipsUnsupportedTypes(t *testing.T) {
	pub, _, _ := testKeys(t)
	jwks := &JWKS{Keys: []JWK{
		{Kty: "RSA", Crv: "", X: "ignored"},
		{Kty: "EC", Crv: "P-256", X: "ignored"},
		{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)},
	}}
	keys, err := KeysFromJWKS(jwks)
	if err != nil {
		t.Fatalf("KeysFromJWKS: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("got %d keys, want 1", len(keys))
	}
}

func TestKeysFromJWKSErrors(t *testing.T) {
	if _, err := KeysFromJWKS(nil); err == nil {
		t.Error("nil JWKS accepted")
	}
	if _, err := KeysFromJWKS(&JWKS{}); err == nil {
		t.Error("empty JWKS accepted")
	}
	if _, err := KeysFromJWKS(&JWKS{Keys: []JWK{{Kty: "OKP", Crv: "Ed25519", X: "!!!not base64"}}}); err == nil {
		t.Error("malformed key material accepted")
	}
}

func TestJWKSDecodesFromJSON(t *testing.T) {
	pub, _, _ := testKeys(t)
	body := fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q}]}`,
		base64.RawURLEncoding.EncodeToString(pub))

	var jwks JWKS
	if err := json.Unmarshal([]byte(body), &jwks); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if _, err := KeysFromJWKS(&jwks); err != nil {
		t.Fatalf("KeysFromJWKS: %v", err)
	}
}

// --- Parsing ----------------------------------------------------------------

func TestMalformedHeadersRejected(t *testing.T) {
	_, _, keys := testKeys(t)

	tests := []struct {
		name  string
		input string
		sig   string
	}{
		{"no component list", `sig1=created=1;tag="web-bot-auth"`, `sig1=:AAAA:`},
		{"unterminated list", `sig1=("@authority";tag="web-bot-auth"`, `sig1=:AAAA:`},
		{"signature not a byte sequence", `sig1=("@authority");tag="web-bot-auth"`, `sig1=AAAA`},
		{"empty component list", `sig1=();tag="web-bot-auth"`, `sig1=:AAAA:`},
		{"label mismatch", `sig1=("@authority");tag="web-bot-auth"`, `other=:AAAA:`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRequest()
			r.Header.Set("Signature-Input", tc.input)
			r.Header.Set("Signature", tc.sig)
			if _, err := Verify(r, keys, Options{}); err == nil {
				t.Error("malformed headers were accepted")
			}
		})
	}
}

func TestMissingKeyIDRejected(t *testing.T) {
	_, _, keys := testKeys(t)
	r := newRequest()
	r.Header.Set("Signature-Input", `sig1=("@authority");created=1735689600;tag="web-bot-auth"`)
	r.Header.Set("Signature", `sig1=:`+base64.StdEncoding.EncodeToString(make([]byte, 64))+`:`)

	if _, err := Verify(r, keys, Options{Now: time.Unix(1735689700, 0)}); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed for a missing keyid", err)
	}
}

func TestCoveredHeaderMustBePresent(t *testing.T) {
	_, priv, keys := testKeys(t)
	r := newRequest()
	r.Header.Set("X-Custom", "value")
	signRequest(t, r, priv, signOptions{components: []string{"@authority", "x-custom"}})
	r.Header.Del("X-Custom")

	if _, err := Verify(r, keys, Options{}); err == nil {
		t.Error("a signature covering an absent header verified")
	}
}

func TestNilInputs(t *testing.T) {
	_, _, keys := testKeys(t)
	if _, err := Verify(nil, keys, Options{}); err == nil {
		t.Error("nil request accepted")
	}
	if _, err := Verify(newRequest(), nil, Options{}); err == nil {
		t.Error("nil resolver accepted")
	}
}
