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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Telling the account what this machine handled, without telling it what
// the content was.
//
// # The problem this fixes
//
// The shim governed tool traffic correctly and wrote receipts to a file on
// the laptop, where nobody ever looked. Somebody ran `lyntway init`, saw
// the shim working, opened their dashboard and found it empty — which
// reads as a broken product rather than as a deliberate boundary.
//
// # The distinction that was conflated
//
// Content must stay on the machine. Findings need not.
//
// A tool result carrying a customer record is the disclosure this exists to
// prevent, so it is inspected here and never sent anywhere. But "this
// laptop's tools handled three email addresses and a card number" is not
// the customer's data — it is a count, and it is exactly what somebody
// needs to see to know the thing is working and where their exposure is.
//
// So classes and counts go to /v1/attest and nothing else does. Not the
// content, not a digest of it, not the values, not the tool's arguments.
//
// # What the receipt is allowed to claim
//
// Attested, never observed. The shim watched this, we did not, and the
// account holder is the one who installed the shim — so the honest reading
// is "a tool you run reported this", which is what /v1/attest is for and
// what it records.
//
// # Failure policy
//
// This sits inside somebody's agent. A reporter that can block a tool call
// or crash an editor is a reporter they uninstall, so every failure here
// ends in a dropped report and a line on stderr. The local receipt file is
// written either way, so nothing is lost that was not already kept.

// reporter sends finding summaries to an account, best effort.
type reporter struct {
	origin string
	key    string
	signer *httpSigner
	client *http.Client

	// queue is bounded and lossy on purpose. A burst of tool calls while
	// the network is slow must not grow memory inside somebody's editor,
	// and a dropped summary costs a row in a dashboard rather than a
	// receipt — the receipts are on disk regardless.
	queue chan attestation

	wg   sync.WaitGroup
	once sync.Once
}

// httpSigner signs HTTP requests with Ed25519 (RFC 9421, web-bot-auth).
type httpSigner struct {
	key   ed25519.PrivateKey
	keyID string
}

// attestation is one governed message, reduced to what may leave.
type attestation struct {
	Server   string
	Chain    string
	Decision string
	Findings map[string]int
	Bytes    int64
}

// localConfig is what `lyntway login` wrote.
type localConfig struct {
	Origin     string `json:"origin"`
	Key        string `json:"key"`
	KeyID      string `json:"key_id"`
	SigningKey string `json:"signing_key"`
}

// newReporter returns a reporter, or nil when this machine is not signed in.
//
// Not signed in is an ordinary state, not an error: the shim is useful on
// its own and the local receipts are written either way. Returning nil
// rather than an error keeps that path silent.
func newReporter() *reporter {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	body, err := os.ReadFile(filepath.Join(home, ".lyntway", "config.json"))
	if err != nil {
		return nil
	}
	var c localConfig
	if err := json.Unmarshal(body, &c); err != nil || c.Origin == "" || c.Key == "" {
		return nil
	}

	var signer *httpSigner
	if c.SigningKey != "" && c.KeyID != "" {
		if priv, err := readPEMKey(c.SigningKey); err == nil {
			signer = &httpSigner{key: priv, keyID: c.KeyID}
		}
	}

	r := &reporter{
		origin: c.Origin,
		key:    c.Key,
		signer: signer,
		// Short. This runs beside an agent waiting on a tool call, and a
		// slow reporter is worse than a missing row.
		client: &http.Client{Timeout: 5 * time.Second},
		queue:  make(chan attestation, 256),
	}
	r.wg.Add(1)
	go r.run()
	return r
}

// report queues a summary. Never blocks, never fails.
func (r *reporter) report(a attestation) {
	if r == nil {
		return
	}
	select {
	case r.queue <- a:
	default:
		// Full. Dropped deliberately rather than blocking the agent.
	}
}

func (r *reporter) run() {
	defer r.wg.Done()
	for a := range r.queue {
		if err := r.send(a); err != nil {
			fmt.Fprintf(os.Stderr, "lyntway-mcp: a summary was not reported: %v\n", err)
		}
	}
}

// send posts one summary.
func (r *reporter) send(a attestation) error {
	findings := make([]map[string]any, 0, len(a.Findings))
	for class, count := range a.Findings {
		findings = append(findings, map[string]any{"class": class, "count": count})
	}

	body, err := json.Marshal(map[string]any{
		"chain_id": a.Chain,
		"tool":     "lyntway-mcp",
		"action": map[string]any{
			"surface":   "mcp",
			"direction": "response",
			"method":    "tools/call",
			// Where the data came from, named as the person would name it.
			// An auditor asking what handled their data wants the server,
			// not the shim that watched it.
			"destination": a.Server,
		},
		"actor": map[string]any{
			"type": "agent",
			"id":   "lyntway-mcp",
		},
		"decision": a.Decision,
		"findings": findings,
		"bytes":    a.Bytes,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, r.origin+"/v1/attest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.key)
	req.Header.Set("Content-Type", "application/json")
	if r.signer != nil {
		if err := r.signer.sign(req, body); err != nil {
			return fmt.Errorf("signing: %w", err)
		}
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("the service answered %d", resp.StatusCode)
	}
	return nil
}

// readPEMKey opens the PKCS#8 PEM file `keys sign` wrote.
func readPEMKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", path)
	}
	return priv, nil
}

// sign adds RFC 9421 web-bot-auth headers to req.
func (s *httpSigner) sign(req *http.Request, body []byte) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	nonceStr := base64.RawURLEncoding.EncodeToString(nonce)

	authority, err := signedAuthority(req.URL)
	if err != nil {
		return err
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}

	type component struct{ name, value string }
	components := []component{
		{"@method", strings.ToUpper(req.Method)},
		{"@authority", authority},
		{"@path", path},
	}
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
		req.Header.Set("Content-Digest", digest)
		components = append(components, component{"content-digest", digest})
	}

	names := make([]string, len(components))
	for i, c := range components {
		names[i] = `"` + c.name + `"`
	}
	created := time.Now().Unix()
	nonceQ, err := quotedSignParam(nonceStr)
	if err != nil {
		return err
	}
	keyIDQ, err := quotedSignParam(s.keyID)
	if err != nil {
		return err
	}
	inner := fmt.Sprintf(`(%s);created=%d;expires=%d;nonce=%s;keyid=%s;alg="ed25519";tag="web-bot-auth"`,
		strings.Join(names, " "), created, created+300, nonceQ, keyIDQ)

	var base strings.Builder
	for _, c := range components {
		base.WriteString(`"` + c.name + `": ` + c.value + "\n")
	}
	base.WriteString(`"@signature-params": ` + inner)

	sig := ed25519.Sign(s.key, []byte(base.String()))
	req.Header.Set("Signature-Input", "sig1="+inner)
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

func signedAuthority(u *url.URL) (string, error) {
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("url has no host")
	}
	if strings.Contains(host, ":") {
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

func quotedSignParam(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, `"\`) {
		return "", fmt.Errorf("value contains characters that cannot appear in a signature parameter")
	}
	for _, r := range value {
		if !unicode.IsPrint(r) {
			return "", fmt.Errorf("value contains characters that cannot appear in a signature parameter")
		}
	}
	return `"` + value + `"`, nil
}

// close drains what is queued and stops.
//
// Bounded, because a shim that hangs on exit is a shim that hangs the
// editor that spawned it. Whatever has not gone by then stays in the local
// receipt file, which is the copy that matters.
func (r *reporter) close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		close(r.queue)
		done := make(chan struct{})
		go func() { r.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	})
}
