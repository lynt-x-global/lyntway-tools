package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lynt-x-global/lyntway-tools/webbotauth"
)

// The cross-language vectors: what the Python and TypeScript signers
// produce, and what the Go verifier accepts. This signer must match them
// byte for byte, because the service verifies with that same package and
// a signature that differs in one byte reads as tampering.
const signingVectorsPath = "../../packages/lyntway-py/tests/testdata/signing_vectors.json"

type signingVectors struct {
	KeyID         string `json:"key_id"`
	PrivateKeyPEM string `json:"private_key_pem"`
	PublicKeyB64  string `json:"public_key_b64"`
	Vectors       []struct {
		Name    string `json:"name"`
		Request struct {
			Method string  `json:"method"`
			URL    string  `json:"url"`
			Body   *string `json:"body"`
		} `json:"request"`
		Created  int64  `json:"created"`
		Nonce    string `json:"nonce"`
		VerifyAt int64  `json:"verify_at"`
		Expected struct {
			ContentDigest  *string `json:"content_digest"`
			SignatureInput string  `json:"signature_input"`
			Signature      string  `json:"signature"`
		} `json:"expected"`
	} `json:"vectors"`
}

func loadSigningVectors(t *testing.T) (signingVectors, *requestSigner, ed25519.PublicKey) {
	t.Helper()
	raw, err := os.ReadFile(signingVectorsPath)
	if err != nil {
		t.Fatalf("the vectors are the contract and must be present: %v", err)
	}
	var v signingVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) < 5 {
		t.Fatalf("%d vectors; the file has been cut down", len(v.Vectors))
	}
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "vectors.pem")
	if err := os.WriteFile(pemPath, []byte(v.PrivateKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := loadRequestSigner(config{KeyID: v.KeyID, SigningKey: pemPath})
	if err != nil || signer == nil {
		t.Fatalf("loading the vectors' key: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(v.PublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.key.Public().(ed25519.PublicKey), pub) {
		t.Fatal("the PEM in the vectors does not match its public key")
	}
	return v, signer, ed25519.PublicKey(pub)
}

func TestSignerReproducesTheVectorsAndVerifiesWithTheService(t *testing.T) {
	v, signer, pub := loadSigningVectors(t)
	keys := webbotauth.StaticKeys{v.KeyID: pub}

	for _, vec := range v.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			var body []byte
			if vec.Request.Body != nil {
				body = []byte(*vec.Request.Body)
			}
			req, err := newAPIRequest(config{}, nil, vec.Request.Method, vec.Request.URL, body, "application/json")
			if err != nil {
				t.Fatal(err)
			}
			if err := signer.signAt(req, body, time.Unix(vec.Created, 0), vec.Nonce); err != nil {
				t.Fatal(err)
			}

			if got := req.Header.Get("Signature-Input"); got != vec.Expected.SignatureInput {
				t.Errorf("Signature-Input\n got %s\nwant %s", got, vec.Expected.SignatureInput)
			}
			if got := req.Header.Get("Signature"); got != vec.Expected.Signature {
				t.Errorf("Signature\n got %s\nwant %s", got, vec.Expected.Signature)
			}
			got, present := req.Header["Content-Digest"]
			switch {
			case vec.Expected.ContentDigest == nil && present:
				t.Errorf("Content-Digest %q sent with no body", got)
			case vec.Expected.ContentDigest != nil && (!present || got[0] != *vec.Expected.ContentDigest):
				t.Errorf("Content-Digest = %v, want %s", got, *vec.Expected.ContentDigest)
			}

			// What the service does with it: the same package, at the
			// vector's clock, with the registered public key.
			res, err := webbotauth.Verify(req, keys, webbotauth.Options{Now: time.Unix(vec.VerifyAt, 0)})
			if err != nil {
				t.Fatalf("the service would refuse this: %v", err)
			}
			if res.KeyID != v.KeyID {
				t.Errorf("verified key id %q", res.KeyID)
			}
			if len(body) > 0 {
				if err := webbotauth.VerifyContentDigest(req.Header.Get("Content-Digest"), body); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

// A signed key that presents an altered body must be refused: the digest
// is what binds the signature to the bytes.
func TestSignatureDoesNotSurviveABodyChange(t *testing.T) {
	_, signer, _ := loadSigningVectors(t)
	body := []byte(`{"upstream":"openai"}`)
	req, err := newAPIRequest(config{Origin: "https://govern.example"}, signer, http.MethodPost, "/v1/keys/providers", body, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if err := webbotauth.VerifyContentDigest(req.Header.Get("Content-Digest"), []byte(`{"upstream":"mistral"}`)); err == nil {
		t.Error("a different body matched the digest")
	}
}

// The signer refuses half a configuration and a key it cannot read, and
// is absent — not an error — for a machine that never ran `keys sign`.
func TestRequestSignerLoadsOnlyAWholeConfiguration(t *testing.T) {
	if s, err := loadRequestSigner(config{Origin: "x", Key: "k"}); err != nil || s != nil {
		t.Errorf("no signing key: %v %v", s, err)
	}
	if s, err := loadRequestSigner(config{Origin: "x", Key: "k", KeyID: "key_linked"}); err != nil || s != nil {
		t.Errorf("a linked key id alone is not a signing configuration: %v %v", s, err)
	}
	if _, err := loadRequestSigner(config{Origin: "x", Key: "k", SigningKey: "/nowhere.pem"}); err == nil || !strings.Contains(err.Error(), "no key id") {
		t.Errorf("a path without an id: %v", err)
	}
	if _, err := loadRequestSigner(config{Origin: "x", Key: "k", KeyID: "key_1", SigningKey: filepath.Join(t.TempDir(), "gone.pem")}); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("a missing file: %v", err)
	}
}

// signingService is the service as it treats a key with a registered
// signing key: every request must verify, or it is 401 bad_signature
// with the reason the real server names. It knows exactly the calls
// `keys migrate` and `status` make.
type signingService struct {
	pub   ed25519.PublicKey
	keyID string
	key   string

	mu       sync.Mutex
	seen     []string
	stored   []map[string]string
	refusals []string
}

func (s *signingService) handler() http.Handler {
	keys := webbotauth.StaticKeys{s.keyID: s.pub}
	refuse := func(w http.ResponseWriter, reason string) {
		s.mu.Lock()
		s.refusals = append(s.refusals, reason)
		s.mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  map[string]string{"code": "bad_signature", "message": "Key " + s.keyID + " has a registered signing key, so every request presenting it must carry a valid web-bot-auth signature (reason: " + reason + ")"},
			"reason": reason,
		})
	}
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			s.seen = append(s.seen, r.Method+" "+r.URL.Path)
			s.mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer "+s.key {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			res, err := webbotauth.Verify(r, keys, webbotauth.Options{})
			switch {
			case err == nil:
			case err == webbotauth.ErrNoSignature:
				refuse(w, "missing")
				return
			default:
				refuse(w, "invalid")
				return
			}
			if len(body) > 0 {
				covered := false
				for _, c := range res.Covered {
					covered = covered || c == "content-digest"
				}
				if !covered {
					refuse(w, "body not covered")
					return
				}
				if err := webbotauth.VerifyContentDigest(r.Header.Get("Content-Digest"), body); err != nil {
					refuse(w, "digest mismatch")
					return
				}
			}
			next(w, r)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/upstreams", auth(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{})
	}))
	mux.HandleFunc("GET /v1/keys/providers", auth(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"available": true, "keys": []any{}})
	}))
	mux.HandleFunc("POST /v1/keys/providers", auth(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.stored = append(s.stored, body)
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"stored": map[string]string{"upstream": body["upstream"]}})
	}))
	mux.HandleFunc("POST /v1/log", auth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"receipt":{"id":"rcpt_signed01"},"verify_url":"https://x.test/verify"}`)
	}))
	mux.HandleFunc("POST /v1/keys/{keyID}/signing", auth(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	return mux
}

// signedMachine is a home directory after `keys sign`: config.json names
// the key and the PEM is beside it.
func signedMachine(t *testing.T, origin string) (config, *signingService) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(home, ".lyntway", "keys", "key_signed01.pem")
	if err := os.MkdirAll(filepath.Dir(pemPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	c := config{Origin: origin, Key: "lynt_sk_signed", KeyID: "key_signed01", SigningKey: pemPath}
	return c, &signingService{pub: pub, keyID: c.KeyID, key: c.Key}
}

// The defect from the live service: after `keys sign`, `keys migrate`
// was refused on its first call. Every request it makes must now verify
// against the registered key, including the ones that carry a body.
func TestMigrateSignsEveryCallOnceAKeyIsRegistered(t *testing.T) {
	c, svc := signedMachine(t, "")
	srv := httptest.NewServer(svc.handler())
	defer srv.Close()
	c.Origin = srv.URL
	if _, err := saveConfig(c); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("MISTRAL_API_KEY=mistralfakekey000000000000MNOP\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := capture(t, "", func() {
		if err := runMigrate(dir, c, migrateOptions{Yes: true}); err != nil {
			t.Fatalf("a signed machine was refused: %v", err)
		}
	})
	if len(svc.refusals) != 0 {
		t.Fatalf("the service refused %v", svc.refusals)
	}
	want := []string{"GET /v1/upstreams", "GET /v1/keys/providers", "POST /v1/keys/providers", "POST /v1/log"}
	if strings.Join(svc.seen, ",") != strings.Join(want, ",") {
		t.Errorf("calls = %v, want %v", svc.seen, want)
	}
	if len(svc.stored) != 1 || svc.stored[0]["upstream"] != "mistral" {
		t.Errorf("stored %v", svc.stored)
	}
	if !strings.Contains(out, "Receipt rcpt_signed01") {
		t.Errorf("the migration receipt was not reported:\n%s", out)
	}
	if strings.Contains(out, "mistralfakekey000000000000MNOP") {
		t.Fatalf("a key value was printed:\n%s", out)
	}
}

// The same service refuses the unsigned CLI: this is what the fake in
// keys_test.go never did, which is how the defect shipped.
func TestTheSigningServiceRefusesABareBearer(t *testing.T) {
	c, svc := signedMachine(t, "")
	srv := httptest.NewServer(svc.handler())
	defer srv.Close()
	c.Origin = srv.URL
	unsigned := c
	unsigned.SigningKey = ""

	_, err := storedProviderKeys(unsigned)
	if err == nil || !strings.Contains(err.Error(), "reason: missing") {
		t.Errorf("an unsigned call was not refused as missing: %v", err)
	}
	if strings.Join(svc.refusals, ",") != "missing" {
		t.Errorf("refusals = %v", svc.refusals)
	}
}

// `status` said "Signed in" from the config file alone while the service
// refused every call. It now asks, signed, and reports the refusal.
func TestStatusReportsWhatTheServiceSaysAboutTheKey(t *testing.T) {
	c, svc := signedMachine(t, "")
	srv := httptest.NewServer(svc.handler())
	defer srv.Close()
	c.Origin = srv.URL
	if _, err := saveConfig(c); err != nil {
		t.Fatal(err)
	}

	out := capture(t, "", func() {
		if err := status(); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Signed in to "+srv.URL+"\n") || strings.Contains(out, "refuses this key") {
		t.Errorf("a signed machine should read as signed in:\n%s", out)
	}
	if strings.Join(svc.seen, ",") != "GET /v1/keys/providers" {
		t.Errorf("status called %v", svc.seen)
	}

	// The key the service holds is not the one on disk: the request is
	// signed, the signature is wrong, and status must say so rather
	// than "Signed in".
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.pub = other
	srv2 := httptest.NewServer(svc.handler())
	defer srv2.Close()
	c.Origin = srv2.URL
	if _, err := saveConfig(c); err != nil {
		t.Fatal(err)
	}
	out = capture(t, "", func() {
		if err := status(); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Signed in to "+srv2.URL+", but the service refuses this key: Key key_signed01 has a registered signing key") {
		t.Errorf("a refused key should read as refused:\n%s", out)
	}
	if strings.Contains(out, "Signed in to "+srv2.URL+"\n") {
		t.Errorf("status still claims to be signed in:\n%s", out)
	}

	// A service that cannot be reached is neither.
	c.Origin = "http://127.0.0.1:1"
	if _, err := saveConfig(c); err != nil {
		t.Fatal(err)
	}
	out = capture(t, "", func() {
		if err := status(); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "could not be reached") || strings.Contains(out, "refuses this key") {
		t.Errorf("an unreachable service:\n%s", out)
	}
}

// The proxy's reports to /v1/attest are requests presenting the key too,
// and were being dropped once the key was signed.
func TestProxyReporterSignsItsReports(t *testing.T) {
	c, svc := signedMachine(t, "")
	var got *http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		got = r.Clone(r.Context())
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c.Origin = srv.URL
	signer, err := loadRequestSigner(c)
	if err != nil {
		t.Fatal(err)
	}
	r := newProxyReporter(c, signer)
	r.report(proxyAttestation{Chain: "proxy/ollama", Direction: "request", Decision: "allow", Findings: map[string]int{"pii.email": 1}})
	r.close()
	if got == nil {
		t.Fatal("no report arrived")
	}
	if _, err := webbotauth.Verify(got, webbotauth.StaticKeys{c.KeyID: svc.pub}, webbotauth.Options{}); err != nil {
		t.Errorf("the report does not verify: %v", err)
	}
	if err := webbotauth.VerifyContentDigest(got.Header.Get("Content-Digest"), body); err != nil {
		t.Errorf("the report's digest: %v", err)
	}
}

// A --force re-run registers the new public key under the old one's
// signature, since the old one is what the server still trusts.
func TestKeysSignForceRegistersUnderThePreviousKey(t *testing.T) {
	c, svc := signedMachine(t, "")
	srv := httptest.NewServer(svc.handler())
	defer srv.Close()
	c.Origin = srv.URL
	if _, err := saveConfig(c); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(c.SigningKey)

	out := capture(t, "", func() {
		if err := runSign(c, c.KeyID, true, false); err != nil {
			t.Fatal(err)
		}
	})
	if len(svc.refusals) != 0 {
		t.Fatalf("the re-registration was refused: %v\n%s", svc.refusals, out)
	}
	if !strings.Contains(out, "✓ registered") {
		t.Errorf("not registered:\n%s", out)
	}
	if after, _ := os.ReadFile(c.SigningKey); bytes.Equal(before, after) {
		t.Error("--force did not replace the key")
	}
}

// @path is signed as sent, percent-encoding intact. The verifier reads
// EscapedPath; a signer that used the decoded URL.Path would produce a
// base the service never sees, and no vector has an encoded path to
// catch it.
func TestSignerSignsTheEscapedPath(t *testing.T) {
	v, signer, pub := loadSigningVectors(t)
	req, err := newAPIRequest(config{Origin: "https://govern.example"}, signer, http.MethodGet, "/v1/keys/providers/a%2Fb%20c", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Path == req.URL.EscapedPath() {
		t.Fatal("the fixture does not exercise encoding")
	}
	if _, err := webbotauth.Verify(req, webbotauth.StaticKeys{v.KeyID: pub}, webbotauth.Options{}); err != nil {
		t.Errorf("a signature over an encoded path was refused: %v", err)
	}
}
