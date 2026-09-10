package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
	"unicode"
)

// cliCommand is set by each command before making API calls, so the
// User-Agent header names the action that caused the request.
var cliCommand string

// detectSource looks at the environment to decide which editor or tool
// started this process. The result is part of the User-Agent so the
// activity log can say "from Cursor" rather than just "from a terminal".
func detectSource() string {
	if os.Getenv("CURSOR_TRACE_ID") != "" || os.Getenv("CURSOR_SESSION_ID") != "" {
		return "cursor"
	}
	if os.Getenv("TERM_PROGRAM") == "vscode" {
		return "vscode"
	}
	if os.Getenv("CLAUDE_CODE") != "" {
		return "claude-code"
	}
	return "terminal"
}

func cliUserAgent() string {
	cmd := cliCommand
	if cmd == "" {
		cmd = "unknown"
	}
	return fmt.Sprintf("lyntway-cli/%s (%s; %s; %s)",
		version, cmd, runtime.GOOS, detectSource())
}

// Signing the CLI's own requests.
//
// `keys sign` registers a public key against this machine's Lyntway key,
// and from that moment the service refuses any request presenting the key
// without a signature it can check — httpapi does it in requireAuth,
// before any handler, so there is no route that is exempt. The first
// build registered the key and then went on sending a bare bearer token
// from every command: `keys migrate` answered "does not accept this key;
// run lyntway login again", the proxy's reports were dropped, and
// `status` said "Signed in" while nothing worked. Found on the live
// service, not by any test, because the fake servers took a bearer.
//
// So every request the CLI makes to the configured origin goes through
// newAPIRequest, which signs when config.json names a signing key. The
// profile is the SDKs' one exactly: RFC 9421 with the Web Bot Auth tag,
// Ed25519, covering @method, @authority, @path and — only when there is a
// body — content-digest. The cross-language vectors in
// packages/lyntway-py/tests/testdata/signing_vectors.json are the
// contract; sign_test.go reproduces each one byte for byte and verifies
// it with the same webbotauth package the service runs.

const (
	signatureLabel = "sig1"
	signatureTag   = "web-bot-auth"
	signatureAlg   = "ed25519"

	// signatureTTL is how long a signature stays valid. Short on purpose:
	// a captured request is worth replaying for exactly this long.
	signatureTTL = 300 * time.Second
)

// requestSigner is the private half of the key `keys sign` wrote, and
// the id the public half was registered against.
type requestSigner struct {
	key   ed25519.PrivateKey
	keyID string
}

// loadRequestSigner reads the key config.json names, or returns nil when
// it names none. A key id alone is nil too: a key linked from the browser
// knows its id before `keys sign` has run. A key path without an id is an
// error rather than an unsigned request — the SDKs refuse the same half
// configuration, because somebody who has the file believes their
// requests are signed.
func loadRequestSigner(c config) (*requestSigner, error) {
	if c.SigningKey == "" {
		return nil, nil
	}
	if c.KeyID == "" {
		return nil, fmt.Errorf("config.json names a signing key but no key id; run `lyntway keys sign --key-id <id>`")
	}
	priv, err := readSigningKey(c.SigningKey)
	if err != nil {
		return nil, err
	}
	return &requestSigner{key: priv, keyID: c.KeyID}, nil
}

// readSigningKey opens the PKCS#8 PEM `keys sign` wrote. Only Ed25519 is
// accepted: the service verifies nothing else, and a signature it cannot
// check reads as tampering rather than as unsigned.
func readSigningKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the signing key at %s cannot be read: %v; run `lyntway keys sign --force` or remove it from %s", path, err, "~/.lyntway/config.json")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", path)
	}
	return priv, nil
}

// sign adds Signature-Input, Signature and — for a body — Content-Digest
// to req. body must be the exact bytes that will be sent.
func (s *requestSigner) sign(req *http.Request, body []byte) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	return s.signAt(req, body, time.Now(), base64.RawURLEncoding.EncodeToString(nonce))
}

// signAt is sign with the clock and nonce supplied, so the vectors can be
// reproduced.
func (s *requestSigner) signAt(req *http.Request, body []byte, created time.Time, nonce string) error {
	if req.URL == nil {
		return fmt.Errorf("request has no URL to sign")
	}
	authority, err := signedAuthority(req.URL)
	if err != nil {
		return err
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	nonceQ, err := quotedParam(nonce, "nonce")
	if err != nil {
		return err
	}
	keyIDQ, err := quotedParam(s.keyID, "key id")
	if err != nil {
		return err
	}

	type component struct{ name, value string }
	components := []component{
		{"@method", strings.ToUpper(req.Method)},
		{"@authority", authority},
		{"@path", path},
	}
	if len(body) > 0 {
		digest := contentDigest(body)
		req.Header.Set("Content-Digest", digest)
		components = append(components, component{"content-digest", digest})
	}

	names := make([]string, len(components))
	for i, c := range components {
		names[i] = `"` + c.name + `"`
	}
	c := created.Unix()
	inner := fmt.Sprintf(`(%s);created=%d;expires=%d;nonce=%s;keyid=%s;alg="%s";tag="%s"`,
		strings.Join(names, " "), c, c+int64(signatureTTL/time.Second), nonceQ, keyIDQ, signatureAlg, signatureTag)

	// RFC 9421 §2.5: one line per covered component, then the parameters
	// line, newline-separated with nothing after the last. The verifier
	// rebuilds this from the request and the raw Signature-Input text, so
	// the inner list here must be the same bytes the header carries.
	var base strings.Builder
	for _, c := range components {
		base.WriteString(`"` + c.name + `": ` + c.value + "\n")
	}
	base.WriteString(`"@signature-params": ` + inner)

	sig := ed25519.Sign(s.key, []byte(base.String()))
	req.Header.Set("Signature-Input", signatureLabel+"="+inner)
	req.Header.Set("Signature", signatureLabel+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

// signedAuthority is the @authority component: the host lowercased, with
// a default port dropped and any other kept. The verifier reads the Host
// header as it arrived and strips :443 or :80 by scheme; Go's client
// sends URL.Host as Host, so the two sides agree only if this drops the
// same ports.
func signedAuthority(u *url.URL) (string, error) {
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("url has no host to bind the signature to")
	}
	if strings.Contains(host, ":") {
		// An IPv6 literal: Hostname strips the brackets, Host carries them.
		host = "[" + host + "]"
	}
	port := u.Port()
	switch {
	case port == "":
		return host, nil
	case u.Scheme == "https" && port == "443", u.Scheme == "http" && port == "80":
		return host, nil
	}
	return host + ":" + port, nil
}

// quotedParam serialises a structured-field string parameter. Escaping is
// refused rather than implemented: key ids and nonces never need it, and
// an escape sequence is exactly the kind of detail two parsers disagree
// on in a way that reads as a bad signature.
func quotedParam(value, what string) (string, error) {
	if value == "" || strings.ContainsAny(value, `"\`) {
		return "", fmt.Errorf("%s contains characters that cannot appear in a signature parameter", what)
	}
	for _, r := range value {
		if !unicode.IsPrint(r) {
			return "", fmt.Errorf("%s contains characters that cannot appear in a signature parameter", what)
		}
	}
	return `"` + value + `"`, nil
}

// contentDigest is the RFC 9530 Content-Digest value: sha-256=:base64:.
func contentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// newAPIRequest builds one request to the configured origin: the bearer
// when the config holds a key, and a signature when signer is set. Every
// call the CLI makes to the service is built here, so a route added later
// cannot forget to sign.
func newAPIRequest(c config, signer *requestSigner, method, path string, body []byte, contentType string) (*http.Request, error) {
	var payload io.Reader
	if len(body) > 0 {
		payload = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.Origin+path, payload)
	if err != nil {
		return nil, err
	}
	if c.Key != "" {
		req.Header.Set("Authorization", "Bearer "+c.Key)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", cliUserAgent())
	if len(body) > 0 && contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if signer != nil {
		if err := signer.sign(req, body); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// doAPI sends one JSON call and returns the status and body.
func doAPI(client *http.Client, c config, signer *requestSigner, method, path string, body any) (int, []byte, error) {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	req, err := newAPIRequest(c, signer, method, path, raw, "application/json")
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("reaching %s: %w", c.Origin, err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, got, nil
}
