package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/govern"
	"github.com/lynt-x-global/lyntway-tools/receipt"
	"github.com/lynt-x-global/lyntway-tools/tokenize"
)

// A local listener in front of a model server that never leaves the
// machine.
//
// # Why the gateway cannot do this
//
// Ollama and LM Studio answer on 127.0.0.1. Nothing on the path between an
// application and a port on the same machine passes through a service of
// ours, so a hosted gateway is blind to every prompt sent to them — and a
// prompt to a local model carries the same customer record as a prompt to
// a hosted one. The only place to see it is on the machine, which is where
// this runs.
//
// # What it does, and where the evidence goes
//
// The application is pointed here instead of at the model server. Every
// request body and every response body passes through the same engine the
// gateway and lyntway-mcp use: detection, substitution under the default
// policy, and a signed receipt for each direction. The receipts are written
// to a file under ~/.lyntway/receipts and signed with a key that lives on
// this machine, and each one says so — a receipt signed here is not a
// receipt signed by the service, and it must not read as one.
//
// When the machine is signed in, the classes and counts of what was found
// are reported to the account so the console shows this traffic at all.
// That report is second-hand from the service's point of view, and the
// service records it as attested. The content, its digests and the values
// found never leave: they were on their way to a model on this machine, and
// sending them anywhere would be the disclosure this exists to prevent.
//
// # Which key signs
//
// Two keys can be on the machine. `lyntway keys sign` writes a keypair whose
// public half is registered with the account under the key's id; lyntway-mcp
// generates one that exists nowhere but this laptop. The first is preferred
// when present: a verifier holding the account's record of that key can tie
// the receipt to the account, where the laptop-only key can only be tied to
// the file it was published beside. Both are still a laptop's key, and the
// issuer name on every receipt says which.

const (
	defaultProxyListen   = "127.0.0.1:11435"
	defaultProxyUpstream = "http://127.0.0.1:11434"

	// proxyStatusPath is where a running proxy describes itself, so
	// `lyntway status` can tell a live listener from a stale pid file.
	proxyStatusPath = "/_lyntway/status"

	// proxyTool is how this names itself to the account. A report whose
	// source is unstated cannot be weighed by whoever reads the receipt.
	proxyTool = "lyntway-proxy"
)

func proxyUsage() {
	fmt.Fprint(os.Stderr, "lyntway proxy — govern a model server on this machine\n"+
		"\n"+
		"Usage:\n"+
		"  lyntway proxy [--listen "+defaultProxyListen+"] [--upstream "+defaultProxyUpstream+"]\n"+
		"                [--name ollama] [--receipts DIR] [--report=false]\n"+
		"\n"+
		"Listens on a loopback port and forwards to Ollama, LM Studio or any\n"+
		"server speaking the OpenAI shape. Each request and response is governed\n"+
		"here, on this machine, and a receipt for each is written to\n"+
		"~/.lyntway/receipts/ signed with this machine's key. Streamed replies are\n"+
		"governed as they pass.\n"+
		"\n"+
		"Point the SDKs at it:\n"+
		"  export OPENAI_BASE_URL=http://"+defaultProxyListen+"/v1\n"+
		"\n"+
		"When this machine is signed in, the classes and counts of what was found\n"+
		"are reported to the account and appear there as attested — the service\n"+
		"did not see the traffic. Content, digests and values never leave.\n"+
		"--report=false keeps even the counts here.\n"+
		"\n"+
		"Verify the receipts with:\n"+
		"  lyntway-verify -chain -keys ~/.lyntway/receipts/keys.json ~/.lyntway/receipts/proxy-ollama.jsonl\n")
}

// proxyOptions is what the flags decide.
type proxyOptions struct {
	Listen   string
	Upstream string
	Name     string
	Receipts string
	Report   bool
}

func proxyCmd(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	fs.Usage = proxyUsage
	var opts proxyOptions
	fs.StringVar(&opts.Listen, "listen", defaultProxyListen, "address to listen on; loopback only")
	fs.StringVar(&opts.Upstream, "upstream", defaultProxyUpstream, "the model server to forward to")
	fs.StringVar(&opts.Name, "name", "", "what to call the upstream in receipts (default: guessed from its port)")
	fs.StringVar(&opts.Receipts, "receipts", "", "directory for receipts (default ~/.lyntway/receipts)")
	fs.BoolVar(&opts.Report, "report", true, "report classes and counts to the account this machine is signed in to")
	_ = fs.Parse(flagsFirst(fs, args))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runProxy(ctx, opts, stdout)
}

// runProxy is the whole of `lyntway proxy` after the flags are read.
func runProxy(ctx context.Context, opts proxyOptions, out io.Writer) error {
	p, err := newLocalProxy(opts)
	if err != nil {
		return err
	}
	defer p.close()

	// Bound before anything is printed, so an address already in use is
	// the first line rather than the last.
	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", opts.Listen, err)
	}
	listen := ln.Addr().String()

	pidPath, err := proxyPIDPath()
	if err == nil {
		_ = writeProxyPID(pidPath, proxyPID{
			PID: os.Getpid(), Listen: listen, Upstream: p.upstream.String(),
			Receipts: p.receiptsPath, Started: time.Now().UTC().Format(time.RFC3339),
		})
		defer os.Remove(pidPath)
	}

	fmt.Fprintf(out, "\nlyntway proxy: listening on %s, fronting %s (%s)\n", listen, p.upstream, p.name)
	if p.receiptsPath != "" {
		fmt.Fprintf(out, "  receipts  %s\n", p.receiptsPath)
		fmt.Fprintf(out, "  signed by %s — verify with:\n", p.keyNote)
		fmt.Fprintf(out, "            lyntway-verify -chain -keys %s %s\n", filepath.Join(filepath.Dir(p.receiptsPath), "keys.json"), p.receiptsPath)
	} else {
		fmt.Fprintf(out, "  receipts  none: this machine has no home directory to keep them in\n")
	}
	switch {
	case p.reporter != nil:
		fmt.Fprintf(out, "  reporting classes and counts to %s, recorded there as attested; content stays here\n", p.reporter.origin)
	case opts.Report:
		fmt.Fprintf(out, "  reporting nothing: this machine is not signed in (`lyntway login`), so the receipts stay here\n")
	default:
		fmt.Fprintf(out, "  reporting nothing (--report=false); the receipts stay here\n")
	}
	fmt.Fprintf(out, "\nPoint the SDKs here:\n  export OPENAI_BASE_URL=http://%s/v1\n\n", listen)

	srv := &http.Server{
		Handler: p,
		// No write timeout: a generation can run for minutes, and a
		// deadline over the whole response cuts it mid-stream with no
		// error. Reads are bounded so an idle client cannot hold a
		// goroutine forever.
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		<-errc
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	p.summary(out)
	return nil
}

// localProxy is the listener and everything one request needs.
type localProxy struct {
	engine   *govern.Engine
	scope    *tokenize.Scope
	upstream *url.URL
	name     string
	chain    string
	client   *http.Client

	receiptsPath string
	sink         *os.File
	keyID        string
	keyNote      string

	// reporter is nil when nothing is to be sent, which is an ordinary
	// state: the receipts on disk are the record either way.
	reporter *proxyReporter

	mu       sync.Mutex
	requests int
	findings map[detect.Class]int
}

func newLocalProxy(opts proxyOptions) (*localProxy, error) {
	host, _, err := net.SplitHostPort(opts.Listen)
	if err != nil {
		return nil, fmt.Errorf("--listen %q is not host:port", opts.Listen)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		// Nothing here authenticates a caller. A listener on a network
		// address would govern anybody's traffic under this machine's key
		// and write it into this user's receipts; a self-hosted server is
		// the tool for that.
		return nil, fmt.Errorf("--listen %s is not a loopback address; this proxy has no authentication and listens only on this machine", opts.Listen)
	}

	upstream, err := url.Parse(opts.Upstream)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" || (upstream.Scheme != "http" && upstream.Scheme != "https") {
		return nil, fmt.Errorf("--upstream %q is not an http(s) URL", opts.Upstream)
	}
	name := sanitiseName(orDefaultName(opts.Name, guessUpstreamName(upstream)))

	c, signedIn := loadConfigQuietly()
	signer, keyNote, err := loadProxySigner(c, signedIn)
	if err != nil {
		return nil, err
	}

	dir := opts.Receipts
	if dir == "" {
		dir = defaultReceiptsDir()
	}
	var (
		receiptsPath string
		store        govern.ChainStore
		sink         *os.File
	)
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("creating %s: %w", dir, err)
		}
		if err := publishProxyKey(filepath.Join(dir, "keys.json"), signer); err != nil {
			return nil, fmt.Errorf("publishing the verifying key: %w", err)
		}
		store = &proxyChainStore{path: filepath.Join(dir, "chain.json")}
		receiptsPath = filepath.Join(dir, "proxy-"+name+".jsonl")
		sink, err = os.OpenFile(receiptsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("opening the receipt file: %w", err)
		}
	}

	engine, err := govern.New(govern.Config{
		Signer:     signer,
		Issuer:     "lyntway proxy (" + keyNote + ")",
		ChainStore: store,
	})
	if err != nil {
		return nil, fmt.Errorf("starting the engine: %w", err)
	}

	// Fresh per run and never written down: a token only has to stay
	// consistent for as long as a reply can refer back to it.
	key := make([]byte, tokenize.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating a tokenisation key: %w", err)
	}
	scope, err := tokenize.NewScope(key, tokenize.NewMemoryStore())
	if err != nil {
		return nil, fmt.Errorf("creating a token scope: %w", err)
	}

	var reporter *proxyReporter
	if opts.Report && signedIn {
		reporter = newProxyReporter(c)
	}

	return &localProxy{
		engine:       engine,
		scope:        scope,
		upstream:     upstream,
		name:         name,
		chain:        "proxy/" + name,
		client:       &http.Client{Transport: &http.Transport{Proxy: nil}},
		receiptsPath: receiptsPath,
		sink:         sink,
		keyID:        signer.KeyID(),
		keyNote:      keyNote,
		reporter:     reporter,
		findings:     make(map[detect.Class]int),
	}, nil
}

func (p *localProxy) close() {
	p.reporter.close()
	if p.sink != nil {
		p.sink.Close()
	}
}

// loadConfigQuietly reads what `lyntway login` wrote, and reports not
// being signed in as a state rather than an error: the proxy governs and
// keeps receipts either way.
func loadConfigQuietly() (config, bool) {
	c, err := loadConfig()
	if err != nil || c.Origin == "" || c.Key == "" {
		return config{}, false
	}
	return c, true
}

// guessUpstreamName names the common servers by the port they default to,
// so a receipt reads "ollama" rather than "127.0.0.1:11434".
func guessUpstreamName(u *url.URL) string {
	switch u.Port() {
	case "11434":
		return "ollama"
	case "1234":
		return "lm-studio"
	}
	return u.Hostname()
}

func orDefaultName(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// sanitiseName reduces a label to what a chain id, a vantage and a file
// name can all carry, since it comes from the command line.
func sanitiseName(name string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			b.WriteRune(c)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 40 {
			break
		}
	}
	if b.Len() == 0 {
		return "upstream"
	}
	return b.String()
}

func defaultReceiptsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".lyntway", "receipts")
}

// loadProxySigner picks the key that signs this machine's receipts.
//
// The `keys sign` key is used when the machine has one: its public half is
// registered with the account, so a receipt signed with it can be tied to
// the account by anyone holding the account's record of the key. Otherwise
// the machine key lyntway-mcp keeps is used — the same file, so a machine
// has one local key rather than one per tool — and generated if absent.
//
// The note returned is what the receipt's issuer name and the start-up
// message say about the key. It says where the key came from and nothing
// about whether the registration succeeded, which this cannot know.
func loadProxySigner(c config, signedIn bool) (receipt.Signer, string, error) {
	if signedIn && c.SigningKey != "" && c.KeyID != "" {
		raw, err := os.ReadFile(c.SigningKey)
		if err != nil {
			return nil, "", fmt.Errorf("the signing key at %s cannot be read: %v; run `lyntway keys sign --force` or remove it from %s", c.SigningKey, err, "~/.lyntway/config.json")
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, "", fmt.Errorf("%s is not a PEM private key", c.SigningKey)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", c.SigningKey, err)
		}
		priv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, "", fmt.Errorf("%s is not an Ed25519 key", c.SigningKey)
		}
		signer, err := receipt.NewEd25519Signer(c.KeyID, priv)
		if err != nil {
			return nil, "", err
		}
		return signer, "key " + c.KeyID + " from lyntway keys sign", nil
	}

	signer, err := loadOrCreateMachineKey()
	if err != nil {
		return nil, "", err
	}
	return signer, "this machine's local key " + signer.KeyID(), nil
}

// loadOrCreateMachineKey returns the key lyntway-mcp signs with, creating
// it the first time. The file holds a 32-byte Ed25519 seed as hex and
// nothing else, which is the format the shim reads; the two tools must
// agree on it or a machine ends up with two "machine keys".
func loadOrCreateMachineKey() (*receipt.Ed25519Signer, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("this machine has no home directory to keep a signing key in: %w", err)
	}
	path := filepath.Join(home, ".lyntway", "mcp-signing.key")

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(seed) != ed25519.SeedSize {
			// Refused rather than replaced: a new key over a corrupt one
			// would leave every receipt already on disk signed by a key
			// that no longer exists anywhere.
			return nil, fmt.Errorf("%s is not a signing key; move it aside to generate a new one", path)
		}
		return machineSigner(seed)
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, fmt.Errorf("reading the signing key: %w", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// O_EXCL: the shim and the proxy starting together on a fresh machine
	// must not both write a key. The loser reads the winner's.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateMachineKey()
	}
	if err != nil {
		return nil, fmt.Errorf("creating the signing key: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%x\n", seed); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return machineSigner(seed)
}

// machineSigner names the key after its public half, exactly as
// lyntway-mcp does, so receipts from both tools verify under one id.
func machineSigner(seed []byte) (*receipt.Ed25519Signer, error) {
	priv := ed25519.NewKeyFromSeed(seed)
	sum := sha256.Sum256(priv.Public().(ed25519.PublicKey))
	return receipt.NewEd25519Signer("local-"+hex.EncodeToString(sum[:8]), priv)
}

// publishProxyKey writes the public key in the format lyntway-verify -keys
// reads. Keys already there are kept: receipts written under an earlier
// key are verifiable only while that key is still published.
func publishProxyKey(path string, signer receipt.Signer) error {
	var kf struct {
		Keys       map[string]string `json:"keys"`
		Algorithms map[string]string `json:"algorithms"`
	}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &kf)
	}
	if kf.Keys == nil {
		kf.Keys = map[string]string{}
	}
	if kf.Algorithms == nil {
		kf.Algorithms = map[string]string{}
	}
	pub, err := receipt.RawPublicKey(signer)
	if err != nil {
		return err
	}
	kf.Keys[signer.KeyID()] = base64.StdEncoding.EncodeToString(pub)
	kf.Algorithms[signer.KeyID()] = string(signer.Algorithm())
	encoded, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return replaceFile(path, append(encoded, '\n'), 0o644)
}

// proxyChainStore keeps each chain's position beside the receipts, so a
// restart continues the chain instead of forking it at zero — which a
// verifier would report as a gap, and a gap reads as deletion.
type proxyChainStore struct {
	path string
	mu   sync.Mutex
}

type proxyChainFile struct {
	Chains map[string]struct {
		NextSeq uint64 `json:"next_seq"`
		Head    string `json:"head"`
	} `json:"chains"`
}

func (s *proxyChainStore) read() (proxyChainFile, error) {
	var cf proxyChainFile
	raw, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(raw, &cf); err != nil {
			return cf, fmt.Errorf("%s is not a chain file; move it aside to start new chains", s.path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return cf, err
	}
	if cf.Chains == nil {
		cf.Chains = map[string]struct {
			NextSeq uint64 `json:"next_seq"`
			Head    string `json:"head"`
		}{}
	}
	return cf, nil
}

func (s *proxyChainStore) LoadChain(chainID string) (uint64, string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cf, err := s.read()
	if err != nil {
		return 0, "", false, err
	}
	pos, ok := cf.Chains[chainID]
	return pos.NextSeq, pos.Head, ok, nil
}

func (s *proxyChainStore) SaveChain(chainID string, nextSeq uint64, head string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cf, err := s.read()
	if err != nil {
		return err
	}
	cf.Chains[chainID] = struct {
		NextSeq uint64 `json:"next_seq"`
		Head    string `json:"head"`
	}{nextSeq, head}
	encoded, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return replaceFile(s.path, append(encoded, '\n'), 0o600)
}

// replaceFile swaps a file's content in one rename, so a proxy killed
// mid-write leaves the previous version rather than half of the new one.
func replaceFile(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// proxyReceiptID is unique across runs. A counter restarted with the
// process would give two receipts one name.
func proxyReceiptID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "rcpt_" + hex.EncodeToString(b[:]), nil
}

// maxProxyBody bounds what is read into memory. A prompt is kilobytes; a
// body past this is not one.
const maxProxyBody = 32 << 20

// hopByHop are the headers that describe one connection rather than the
// message, and must not be carried across to another.
var hopByHop = []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func copyEndToEnd(dst, src http.Header) {
	for k, vs := range src {
		skip := false
		for _, h := range hopByHop {
			if strings.EqualFold(k, h) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func (p *localProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == proxyStatusPath {
		p.writeStatus(w)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxProxyBody+1))
	if err != nil {
		writeProxyError(w, http.StatusBadRequest, "lyntway_bad_request", "the request body could not be read", "")
		return
	}
	if len(body) > maxProxyBody {
		writeProxyError(w, http.StatusRequestEntityTooLarge, "lyntway_too_large", "the request body is larger than this proxy governs", "")
		return
	}

	requestLine := r.Method + " " + r.URL.Path
	actor := proxyActor(r)
	evidence := &receipt.Evidence{
		// This process handled the bytes, on the machine they came from.
		Provenance: receipt.ProvenanceObserved,
		Vantage:    "proxy/" + p.name,
	}

	id, err := proxyReceiptID()
	if err != nil {
		writeProxyError(w, http.StatusInternalServerError, "lyntway_internal", err.Error(), "")
		return
	}
	outRes, err := p.engine.Govern(govern.Request{
		ChainID:   p.chain,
		ReceiptID: id,
		Content:   body,
		Action: receipt.Action{
			Surface:     receipt.SurfaceModel,
			Direction:   receipt.DirectionRequest,
			Method:      requestLine,
			Target:      p.name,
			Destination: p.upstream.Host,
		},
		Actor:    actor,
		Scope:    p.scope,
		Evidence: evidence,
	})
	if err != nil {
		writeProxyError(w, http.StatusInternalServerError, "lyntway_internal", "the request could not be governed: "+err.Error(), "")
		return
	}
	p.record(outRes, requestLine, receipt.DirectionRequest)

	w.Header().Set("X-Lyntway-Request-Receipt", outRes.Receipt.ID)
	w.Header().Set("X-Lyntway-Request-Decision", string(outRes.Decision))
	if outRes.Content == nil {
		// Refused before it reached the model. The client is told which
		// receipt records the decision, in the error shape the SDKs raise
		// as a readable exception.
		writeProxyError(w, http.StatusForbidden, "lyntway_blocked",
			"this request was withheld by policy ("+string(outRes.Decision)+")", outRes.Receipt.ID)
		return
	}

	target := *p.upstream
	target.Path = strings.TrimSuffix(p.upstream.Path, "/") + r.URL.Path
	target.RawQuery = r.URL.RawQuery
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(outRes.Content))
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, "lyntway_upstream", err.Error(), outRes.Receipt.ID)
		return
	}
	copyEndToEnd(req.Header, r.Header)
	// The transport negotiates its own compression and undoes it on the
	// way back. A client's Accept-Encoding forwarded as-is would produce a
	// body this cannot read, let alone govern.
	req.Header.Del("Accept-Encoding")
	req.Header.Del("Content-Length")
	req.ContentLength = int64(len(outRes.Content))

	resp, err := p.client.Do(req)
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, "lyntway_upstream", "the model server did not answer: "+err.Error(), outRes.Receipt.ID)
		return
	}
	defer resp.Body.Close()

	copyEndToEnd(w.Header(), resp.Header)
	w.Header().Del("Content-Length")
	inbound := govern.Request{
		ChainID: p.chain,
		Action: receipt.Action{
			Surface:     receipt.SurfaceModel,
			Direction:   receipt.DirectionResponse,
			Method:      requestLine,
			Target:      p.name,
			Destination: p.upstream.Host,
		},
		Actor:    actor,
		Scope:    p.scope,
		Evidence: evidence,
		// A reply is on its way back to the party whose data it is, so
		// the tokens it echoes are restored rather than substituted again.
		// What matters here is what the model returned and whether policy
		// permits releasing it.
		Inspect: true,
	}

	if frame, ok := streamFraming(resp.Header.Get("Content-Type")); ok {
		p.relayStreamed(w, resp, inbound, requestLine, frame)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyBody))
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, "lyntway_upstream", "the model server's reply could not be read", outRes.Receipt.ID)
		return
	}
	restored, err := p.scope.Restore(raw)
	if err != nil {
		writeProxyError(w, http.StatusInternalServerError, "lyntway_internal", "restoring tokens in the reply: "+err.Error(), outRes.Receipt.ID)
		return
	}
	inbound.Content = restored
	if inbound.ReceiptID, err = proxyReceiptID(); err != nil {
		writeProxyError(w, http.StatusInternalServerError, "lyntway_internal", err.Error(), outRes.Receipt.ID)
		return
	}
	inRes, err := p.engine.Govern(inbound)
	if err != nil {
		writeProxyError(w, http.StatusInternalServerError, "lyntway_internal", "the reply could not be governed: "+err.Error(), outRes.Receipt.ID)
		return
	}
	p.record(inRes, requestLine, receipt.DirectionResponse)
	w.Header().Set("X-Lyntway-Receipt", inRes.Receipt.ID)
	w.Header().Set("X-Lyntway-Decision", string(inRes.Decision))
	if inRes.Content == nil {
		writeProxyError(w, http.StatusForbidden, "lyntway_blocked",
			"the model's reply was withheld by policy ("+string(inRes.Decision)+")", inRes.Receipt.ID)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(inRes.Content)))
	w.WriteHeader(resp.StatusCode)
	w.Write(inRes.Content)
}

// proxyActor describes the caller as far as anything here can: a program
// on this machine, named by what it calls itself. Nothing verifies that,
// and the receipt says so.
func proxyActor(r *http.Request) receipt.Actor {
	id := sanitiseName(strings.TrimSpace(r.Header.Get("User-Agent")))
	if id == "upstream" {
		id = "local-application"
	}
	return receipt.Actor{Type: receipt.ActorAgent, ID: id, Source: receipt.IdentityNone}
}

// writeProxyError answers in the shape the OpenAI SDKs decode, so a refusal
// surfaces as a readable exception rather than a parse failure.
func writeProxyError(w http.ResponseWriter, status int, kind, message, receiptID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	e := map[string]any{"type": kind, "message": message, "source": proxyTool}
	if receiptID != "" {
		e["receipt"] = receiptID
	}
	json.NewEncoder(w).Encode(map[string]any{"error": e})
}

// record keeps the receipt, the counts, and — when signed in — tells the
// account the classes and counts. Content, digests and values stay here.
func (p *localProxy) record(res *govern.Result, requestLine string, dir receipt.Direction) {
	p.mu.Lock()
	p.requests++
	for _, f := range res.Findings {
		p.findings[detect.Class(f.Class)] += f.Count
	}
	p.mu.Unlock()

	if p.reporter != nil {
		classes := make(map[string]int, len(res.Findings))
		for _, f := range res.Findings {
			classes[f.Class] += f.Count
		}
		p.reporter.report(proxyAttestation{
			Chain: p.chain, Destination: p.upstream.Host, Target: p.name,
			Method: requestLine, Direction: string(dir),
			Decision: string(res.Decision), Findings: classes,
			Bytes: res.Receipt.Content.Bytes, Reference: res.Receipt.ID,
		})
	}

	if p.sink == nil {
		return
	}
	encoded, err := json.Marshal(res.Receipt)
	if err != nil {
		return
	}
	// Append and move on: a receipt that cannot be written must not stop
	// the application working, and the failure shows in the file.
	_, _ = p.sink.Write(append(encoded, '\n'))
}

func (p *localProxy) writeStatus(w http.ResponseWriter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	classes := map[string]int{}
	for c, n := range p.findings {
		classes[string(c)] = n
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"tool":      proxyTool,
		"upstream":  p.upstream.String(),
		"name":      p.name,
		"receipts":  p.receiptsPath,
		"key_id":    p.keyID,
		"reporting": p.reporter != nil,
		"requests":  p.requests,
		"findings":  classes,
	})
}

func (p *localProxy) summary(out io.Writer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.requests == 0 {
		fmt.Fprintln(out, "lyntway proxy: stopped; nothing passed through")
		return
	}
	var parts []string
	for class, n := range p.findings {
		parts = append(parts, fmt.Sprintf("%s ×%d", class, n))
	}
	if len(parts) == 0 {
		fmt.Fprintf(out, "lyntway proxy: stopped; governed %d messages, nothing sensitive found\n", p.requests)
		return
	}
	fmt.Fprintf(out, "lyntway proxy: stopped; governed %d messages; %s\n", p.requests, strings.Join(parts, ", "))
}

// Streamed replies.
//
// Ollama streams newline-delimited JSON from its own API and server-sent
// events from its OpenAI-shaped one; LM Studio streams events. Both carry
// the model's text scattered across many small objects, so the text has to
// be reassembled before it can be governed — the one place this proxy has
// to know a provider's format rather than forward bytes.

type streamFrame int

const (
	frameSSE streamFrame = iota
	frameNDJSON
)

func streamFraming(contentType string) (streamFrame, bool) {
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "text/event-stream"):
		return frameSSE, true
	case strings.Contains(ct, "application/x-ndjson"), strings.Contains(ct, "application/jsonl"):
		return frameNDJSON, true
	}
	return 0, false
}

// textPaths are where each known shape carries the model's text. The
// first path present as a string in an event decides the shape for the
// rest of the stream.
var textPaths = []struct {
	name string
	path []string
}{
	{"openai-chat", []string{"choices", "0", "delta", "content"}},
	{"openai-completion", []string{"choices", "0", "text"}},
	{"ollama-chat", []string{"message", "content"}},
	{"ollama-generate", []string{"response"}},
}

// lookup walks a decoded event along a path; "0" steps into an array.
func lookup(v any, path []string) (any, bool) {
	for _, step := range path {
		switch node := v.(type) {
		case map[string]any:
			next, ok := node[step]
			if !ok {
				return nil, false
			}
			v = next
		case []any:
			if step != "0" || len(node) == 0 {
				return nil, false
			}
			v = node[0]
		default:
			return nil, false
		}
	}
	return v, true
}

// withText returns the event with its text replaced, keeping every other
// field — the id, model, timestamps and done flags a client relies on.
func withText(raw []byte, path []string, text string) ([]byte, error) {
	var event any
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, err
	}
	parent, ok := lookup(event, path[:len(path)-1])
	if !ok {
		return nil, errors.New("the event lost its shape")
	}
	obj, ok := parent.(map[string]any)
	if !ok {
		return nil, errors.New("the event lost its shape")
	}
	obj[path[len(path)-1]] = text
	return json.Marshal(event)
}

// streamOutcome is what reached the client, and what the receipt covers.
type streamOutcome struct {
	released  []byte
	findings  []receipt.Finding
	truncated bool
	reason    string
}

// relayStreamed governs a stream as it passes and issues the response
// receipt once it has finished, since the receipt covers exactly what the
// client received. The receipt id travels as a trailer, and on an event
// stream also as a final event, because the headers were sent long before
// it was known.
func (p *localProxy) relayStreamed(w http.ResponseWriter, resp *http.Response, inbound govern.Request, requestLine string, frame streamFrame) {
	w.Header().Set("Trailer", "X-Lyntway-Receipt, X-Lyntway-Decision")
	w.WriteHeader(resp.StatusCode)

	outcome := relayGovernedStream(w, resp.Body, p.engine.NewRestoringStreamGovernor(p.scope), frame)

	inbound.Content = outcome.released
	// The bytes are gone. A block decided now can only be recorded, and
	// the governor saw the whole stream including what it withheld.
	//
	// Only the withheld findings are carried in. Everything the governor
	// released is in Content and will be found again by the receipt's own
	// scan — a substitute is format-preserving, so it matches the same
	// rule its original did — and carrying those in as well counted every
	// email twice. The class that cut the stream is the one the scan can
	// never see, because its bytes were never released.
	inbound.Irrevocable = true
	inbound.Truncated = outcome.truncated
	inbound.PriorFindings = withheldFindings(outcome.findings)
	id, err := proxyReceiptID()
	if err != nil {
		return
	}
	inbound.ReceiptID = id
	inRes, err := p.engine.Govern(inbound)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lyntway proxy: the streamed reply could not be receipted: %v\n", err)
		return
	}
	p.record(inRes, requestLine, receipt.DirectionResponse)
	w.Header().Set("X-Lyntway-Receipt", inRes.Receipt.ID)
	w.Header().Set("X-Lyntway-Decision", string(inRes.Decision))
	if frame == frameSSE {
		fmt.Fprintf(w, "event: lyntway\ndata: {\"truncated\":%v,\"receipt\":%q}\n\n", outcome.truncated, inRes.Receipt.ID)
	}
}

// withheldFindings keeps the findings whose bytes never left the governor.
func withheldFindings(all []receipt.Finding) []receipt.Finding {
	var out []receipt.Finding
	for _, f := range all {
		switch f.Decision {
		case receipt.DecisionBlock, receipt.DecisionRequireApproval:
			out = append(out, f)
		}
	}
	return out
}

// relayGovernedStream reads events from the upstream, governs the text in
// them, and writes governed events to the client as they become safe.
//
// Text is held for a lookback window; structural events are not. Left
// alone that reorders the stream — a done event overtakes the words it is
// supposed to follow, and a client that treats done as the end renders
// nothing. So once any text is outstanding, everything after it waits, and
// the stream reaches the client in the order the server sent it.
func relayGovernedStream(w http.ResponseWriter, upstream io.Reader, g *govern.StreamGovernor, frame streamFrame) *streamOutcome {
	flusher, _ := w.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}
	out := &streamOutcome{}
	settle := func() *streamOutcome {
		out.released = g.Released()
		out.findings = g.Findings()
		out.truncated = out.truncated || g.Truncated()
		return out
	}

	var (
		shapeKnown bool
		textPath   []string
		// template is the last event that carried text. Governed text is
		// re-emitted inside a copy of it, so the client keeps seeing the
		// server's own fields around a text field whose length changed.
		template        []byte
		held            [][]byte
		textOutstanding bool
		dataEvents      int
		closed          bool
	)

	// A stream whose format is never recognised cannot be reassembled and
	// therefore cannot be governed. Recognition gets a short grace — every
	// known format opens with events carrying no text — and then the
	// stream is refused rather than forwarded unexamined.
	const unknownEventGrace = 8

	frameEvent := func(payload []byte) []byte {
		if frame == frameSSE {
			return append(append([]byte("data: "), payload...), '\n', '\n')
		}
		return append(payload, '\n')
	}
	flushHeld := func() {
		for _, block := range held {
			w.Write(block)
		}
		if len(held) > 0 {
			flush()
		}
		held = nil
	}
	emit := func(block []byte) {
		if textOutstanding {
			held = append(held, block)
			return
		}
		w.Write(block)
		flush()
	}
	emitText := func(text []byte) {
		if template == nil {
			return
		}
		event, err := withText(template, textPath, string(text))
		if err != nil {
			return
		}
		w.Write(frameEvent(event))
		flush()
	}
	refuse := func(reason, message string) {
		out.truncated, out.reason = true, reason
		held = nil
		if frame == frameSSE {
			fmt.Fprintf(w, "event: error\ndata: {\"type\":\"lyntway_blocked\",\"message\":%q,\"source\":%q}\n\n", message, proxyTool)
		} else {
			fmt.Fprintf(w, "{\"error\":%q}\n", "lyntway: "+message)
		}
		flush()
	}
	finish := func() bool {
		if closed {
			return true
		}
		closed = true
		tail, err := g.Close()
		if err != nil {
			refuse(err.Error(), "the remainder of this response was withheld by policy")
			return false
		}
		if len(tail) > 0 {
			emitText(tail)
		}
		textOutstanding = false
		flushHeld()
		return true
	}

	// handle takes one event: the raw block as it arrived, and the JSON
	// payload inside it (nil for framing with no data).
	handle := func(block, payload []byte) bool {
		if payload == nil {
			emit(block)
			return true
		}
		if frame == frameSSE && bytes.Equal(payload, []byte("[DONE]")) {
			if !finish() {
				return false
			}
			w.Write(block)
			flush()
			return true
		}
		dataEvents++

		var event any
		if err := json.Unmarshal(payload, &event); err != nil {
			// Not JSON. Nothing to govern in it, but nothing to trust
			// about it either: it waits with the rest.
			emit(block)
			return true
		}
		if !shapeKnown {
			for _, shape := range textPaths {
				if v, ok := lookup(event, shape.path); ok {
					if _, isText := v.(string); isText {
						shapeKnown, textPath = true, shape.path
						break
					}
				}
			}
			if !shapeKnown {
				if dataEvents > unknownEventGrace {
					refuse("the server's streaming format is not recognised, so the response could not be governed",
						"this proxy cannot govern the server's streaming format")
					return false
				}
				// Held until the format is known. Forwarding meanwhile
				// let a short stream through in full before anything
				// established that none of it had been examined.
				held = append(held, block)
				return true
			}
			// Now that the shape is known, what was held while it was
			// not is structural and can go.
			if !textOutstanding {
				flushHeld()
			}
		}

		v, ok := lookup(event, textPath)
		text, isText := v.(string)
		if !ok || !isText || text == "" {
			// Roles, usage, stop reasons, the done flag: no model output,
			// forwarded untouched but not past text still owed.
			emit(block)
			return true
		}

		template = payload
		textOutstanding = true
		released, err := g.Write([]byte(text))
		if err != nil {
			refuse(err.Error(), "the remainder of this response was withheld by policy")
			return false
		}
		if len(released) > 0 {
			emitText(released)
		}
		return true
	}

	scanner := bufio.NewScanner(upstream)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)

	if frame == frameNDJSON {
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			payload := append([]byte(nil), line...)
			if !handle(append(payload, '\n'), payload) {
				return settle()
			}
		}
	} else {
		var lines [][]byte
		flushBlock := func() bool {
			if len(lines) == 0 {
				return true
			}
			var payload []byte
			var block bytes.Buffer
			for _, line := range lines {
				block.Write(line)
				block.WriteByte('\n')
				if bytes.HasPrefix(line, []byte("data:")) {
					payload = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
				}
			}
			block.WriteByte('\n')
			lines = nil
			return handle(block.Bytes(), payload)
		}
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			if len(bytes.TrimSpace(line)) == 0 {
				if !flushBlock() {
					return settle()
				}
				continue
			}
			lines = append(lines, line)
		}
		if !flushBlock() {
			return settle()
		}
	}

	if dataEvents > 0 && !shapeKnown {
		// Ended without ever being recognised: never examined, still
		// held, and dropped rather than released under a receipt that
		// would say otherwise.
		refuse("the server's streaming format is not recognised, so the response could not be governed",
			"this proxy cannot govern the server's streaming format")
		return settle()
	}
	finish()
	return settle()
}

// Reporting to the account.
//
// The same boundary lyntway-mcp keeps: classes and counts go to /v1/attest
// and nothing else does. Not the content, not a digest of it, not the
// values. The service records the report as attested — it did not see the
// traffic, and the receipt it issues says so. Every failure here ends in a
// dropped report and a line on stderr; the local receipt is written either
// way, so nothing is lost that was not already kept.

type proxyReporter struct {
	origin string
	key    string
	client *http.Client
	queue  chan proxyAttestation
	wg     sync.WaitGroup
	once   sync.Once
}

// proxyAttestation is one governed message, reduced to what may leave.
type proxyAttestation struct {
	Chain       string
	Destination string
	Target      string
	Method      string
	Direction   string
	Decision    string
	Findings    map[string]int
	Bytes       int64
	// Reference is the local receipt's id, so a row in the console can be
	// matched to the receipt on the machine that has the evidence.
	Reference string
}

func newProxyReporter(c config) *proxyReporter {
	r := &proxyReporter{
		origin: c.Origin,
		key:    c.Key,
		client: &http.Client{Timeout: 5 * time.Second},
		// Bounded and lossy: a burst while the network is slow must not
		// grow memory, and a dropped summary costs a row in a dashboard
		// rather than a receipt.
		queue: make(chan proxyAttestation, 256),
	}
	r.wg.Add(1)
	go r.run()
	return r
}

func (r *proxyReporter) report(a proxyAttestation) {
	if r == nil {
		return
	}
	select {
	case r.queue <- a:
	default:
	}
}

func (r *proxyReporter) run() {
	defer r.wg.Done()
	for a := range r.queue {
		if err := r.send(a); err != nil {
			fmt.Fprintf(os.Stderr, "lyntway proxy: a summary was not reported: %v\n", err)
		}
	}
}

func (r *proxyReporter) send(a proxyAttestation) error {
	findings := make([]map[string]any, 0, len(a.Findings))
	for class, count := range a.Findings {
		findings = append(findings, map[string]any{"class": class, "count": count})
	}
	body, err := json.Marshal(map[string]any{
		"chain_id": a.Chain,
		"tool":     proxyTool,
		"action": map[string]any{
			"surface":     "model",
			"direction":   a.Direction,
			"method":      a.Method,
			"target":      a.Target,
			"destination": a.Destination,
		},
		"actor":     map[string]any{"type": "agent", "id": proxyTool},
		"decision":  a.Decision,
		"findings":  findings,
		"bytes":     a.Bytes,
		"reference": a.Reference,
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
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s answered %d", r.origin, resp.StatusCode)
	}
	return nil
}

// close drains what is queued, briefly. A proxy that hangs on Ctrl-C is a
// proxy somebody kills, and whatever has not gone is in the file.
func (r *proxyReporter) close() {
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

// The pid file, and what `lyntway status` says about it.

type proxyPID struct {
	PID      int    `json:"pid"`
	Listen   string `json:"listen"`
	Upstream string `json:"upstream"`
	Receipts string `json:"receipts"`
	Started  string `json:"started"`
}

func proxyPIDPath() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".lyntway", "proxy.pid"), nil
}

func writeProxyPID(path string, p proxyPID) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

// probeProxy asks a listener to describe itself. Only an answer naming this
// tool counts: the port may have been taken by something else since the
// pid file was written.
func probeProxy(listen string) (map[string]any, bool) {
	client := &http.Client{Timeout: 700 * time.Millisecond}
	resp, err := client.Get("http://" + listen + proxyStatusPath)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	var got map[string]any
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&got) != nil || got["tool"] != proxyTool {
		return nil, false
	}
	return got, true
}

// proxyStatusLine says whether a local model server is fronted, in one
// line. The pid file says a proxy was started; only a live answer from the
// address it named says one is running now.
func proxyStatusLine(pidPath string, probe func(string) (map[string]any, bool)) string {
	const name = "Local models (Ollama, LM Studio)"
	raw, err := os.ReadFile(pidPath)
	if err != nil {
		return fmt.Sprintf("  · %-46s not fronted — `lyntway proxy`", name)
	}
	var pid proxyPID
	if json.Unmarshal(raw, &pid) != nil || pid.Listen == "" {
		return fmt.Sprintf("  ✗ %-46s the pid file at %s is unreadable; run `lyntway proxy` again", name, pidPath)
	}
	got, ok := probe(pid.Listen)
	if !ok {
		return fmt.Sprintf("  ✗ %-46s not running (last started %s on %s); run `lyntway proxy`", name, pid.Started, pid.Listen)
	}
	upstream, _ := got["upstream"].(string)
	reporting, _ := got["reporting"].(bool)
	report := "receipts stay on this machine"
	if reporting {
		report = "counts reported to the account"
	}
	return fmt.Sprintf("  ✓ %-46s proxy on %s fronting %s; %s\n      OPENAI_BASE_URL=http://%s/v1",
		name, pid.Listen, upstream, report, pid.Listen)
}
