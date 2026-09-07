package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// The proxy is the only thing between an application and a model server
// on the same machine, so every test here runs the real handler against a
// real listener and a fake server: the seams — body in, body out, the
// receipt file, the report — are where the defects live.

const (
	testCard  = "4111 1111 1111 1111"
	testEmail = "priya@acme.example"
	// An AWS access key id, which the default policy blocks. Split so the
	// literal is not itself flagged by a scanner reading this file.
	testAWSKey = "AK" + "IA5J7QWMNBZX2LKPRD"
)

// proxyHome gives the proxy a fresh home directory, so no key, receipt or
// pid file lands on the developer's machine.
func proxyHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// startProxy runs a proxy on an ephemeral port in front of upstream and
// returns its base address.
func startProxy(t *testing.T, upstream string, opts proxyOptions) (string, *localProxy) {
	t.Helper()
	opts.Upstream = upstream
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	p, err := newLocalProxy(opts)
	if err != nil {
		t.Fatalf("newLocalProxy: %v", err)
	}
	t.Cleanup(p.close)
	srv := httptest.NewUnstartedServer(p)
	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL, p
}

func readReceipts(t *testing.T, path string) []*receipt.Receipt {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading receipts: %v", err)
	}
	var out []*receipt.Receipt
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r receipt.Receipt
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("a receipt line is not JSON: %v\n%s", err, line)
		}
		out = append(out, &r)
	}
	return out
}

func findingCount(r *receipt.Receipt, class string) int {
	for _, f := range r.Governance.Findings {
		if f.Class == class {
			return f.Count
		}
	}
	return 0
}

// A card number in a prompt is substituted before it reaches the model
// server, and the receipt for the request says so. The model's reply,
// written in terms of the substitute, comes back with the caller's own
// value restored.
func TestACardNumberIsTokenisedBeforeItReachesTheModel(t *testing.T) {
	home := proxyHome(t)

	var seen []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
		// Echo the prompt back as the model's answer, as a model asked to
		// repeat a value would.
		var req struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(seen, &req)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":%q}}]}`,
			"You said: "+req.Messages[0].Content)
	}))
	defer upstream.Close()

	base, p := startProxy(t, upstream.URL, proxyOptions{Name: "fake-ollama"})

	body := `{"model":"llama3","messages":[{"role":"user","content":"Charge card ` + testCard + ` please"}]}`
	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, answer)
	}
	if strings.Contains(string(seen), testCard) {
		t.Errorf("the card number reached the model server:\n%s", seen)
	}
	if !strings.Contains(string(seen), "Charge card ") {
		t.Errorf("the rest of the prompt did not reach the model server:\n%s", seen)
	}
	if !strings.Contains(string(answer), testCard) {
		t.Errorf("the caller's own value was not restored in the reply:\n%s", answer)
	}
	if got := resp.Header.Get("X-Lyntway-Request-Decision"); got != "tokenize" {
		t.Errorf("request decision header = %q, want tokenize", got)
	}
	if resp.Header.Get("X-Lyntway-Request-Receipt") == "" || resp.Header.Get("X-Lyntway-Receipt") == "" {
		t.Errorf("receipt ids missing from the response headers: %v", resp.Header)
	}

	want := filepath.Join(home, ".lyntway", "receipts", "proxy-fake-ollama.jsonl")
	if p.receiptsPath != want {
		t.Fatalf("receipts at %s, want %s", p.receiptsPath, want)
	}
	rs := readReceipts(t, p.receiptsPath)
	if len(rs) != 2 {
		t.Fatalf("got %d receipts, want a request and a response", len(rs))
	}
	req, res := rs[0], rs[1]
	if req.Action.Direction != receipt.DirectionRequest || res.Action.Direction != receipt.DirectionResponse {
		t.Errorf("directions: %s then %s", req.Action.Direction, res.Action.Direction)
	}
	if req.Governance.Decision != receipt.DecisionTokenize {
		t.Errorf("request receipt decision = %s, want tokenize", req.Governance.Decision)
	}
	if findingCount(req, "pci.card_number") != 1 {
		t.Errorf("request receipt findings = %+v, want one pci.card_number", req.Governance.Findings)
	}
	if req.Evidence == nil || req.Evidence.Provenance != receipt.ProvenanceObserved || req.Evidence.Vantage != "proxy/fake-ollama" {
		t.Errorf("evidence = %+v; this process handled the bytes and must say where it stood", req.Evidence)
	}
	if req.Action.Surface != receipt.SurfaceModel || req.Action.Target != "fake-ollama" || req.Action.Method != "POST /v1/chat/completions" {
		t.Errorf("action = %+v", req.Action)
	}
	if !strings.Contains(req.Issuer.Name, "lyntway proxy") || !strings.Contains(req.Issuer.Name, "local key") {
		t.Errorf("issuer name %q does not say a laptop signed this", req.Issuer.Name)
	}
	if res.Governance.Decision == receipt.DecisionTokenize {
		t.Errorf("the response receipt claims tokenisation; a reply is inspected, not substituted: %+v", res.Governance)
	}
	if res.Chain.Seq != req.Chain.Seq+1 {
		t.Errorf("chain positions %d then %d are not consecutive", req.Chain.Seq, res.Chain.Seq)
	}
}

// A credential the policy blocks never reaches the model server, and the
// client is told which receipt says so.
func TestABlockedRequestNeverReachesTheModel(t *testing.T) {
	proxyHome(t)
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer upstream.Close()
	base, p := startProxy(t, upstream.URL, proxyOptions{})

	body := `{"model":"llama3","messages":[{"role":"user","content":"my key is ` + testAWSKey + `"}]}`
	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(resp.Body)

	if called {
		t.Error("the blocked request reached the model server")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403: %s", resp.StatusCode, answer)
	}
	var e struct {
		Error struct {
			Type    string `json:"type"`
			Receipt string `json:"receipt"`
		} `json:"error"`
	}
	if json.Unmarshal(answer, &e) != nil || e.Error.Type != "lyntway_blocked" || !strings.HasPrefix(e.Error.Receipt, "rcpt_") {
		t.Errorf("the refusal does not name the receipt in the SDKs' error shape: %s", answer)
	}
	rs := readReceipts(t, p.receiptsPath)
	if len(rs) != 1 || rs[0].Governance.Decision != receipt.DecisionBlock {
		t.Fatalf("receipts: %+v", rs)
	}
}

// sseUpstream streams the given fragments as OpenAI-shaped chunks, then a
// usage chunk and [DONE], flushing each so the proxy sees a real stream.
func sseUpstream(t *testing.T, fragments []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		fmt.Fprint(w, `data: {"id":"chatcmpl-9","object":"chat.completion.chunk","model":"llama3","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`+"\n\n")
		f.Flush()
		for _, frag := range fragments {
			chunk, _ := json.Marshal(map[string]any{
				"id": "chatcmpl-9", "object": "chat.completion.chunk", "model": "llama3",
				"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": frag}, "finish_reason": nil}},
			})
			fmt.Fprintf(w, "data: %s\n\n", chunk)
			f.Flush()
			time.Sleep(2 * time.Millisecond)
		}
		fmt.Fprint(w, `data: {"id":"chatcmpl-9","object":"chat.completion.chunk","model":"llama3","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`+"\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
}

// sseText collects the delta text from an event stream and reports the
// order of the structural events around it.
func sseText(t *testing.T, body io.Reader) (text string, events []string) {
	t.Helper()
	sc := bufio.NewScanner(body)
	var eventName string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if eventName != "" {
				events = append(events, eventName)
				eventName = ""
				continue
			}
			if payload == "[DONE]" {
				events = append(events, "[DONE]")
				continue
			}
			var e struct {
				Choices []struct {
					Delta struct {
						Content *string `json:"content"`
					} `json:"delta"`
					FinishReason *string `json:"finish_reason"`
				} `json:"choices"`
			}
			if err := json.Unmarshal([]byte(payload), &e); err != nil {
				t.Fatalf("a chunk is not JSON: %s", payload)
			}
			if len(e.Choices) > 0 && e.Choices[0].Delta.Content != nil && *e.Choices[0].Delta.Content != "" {
				text += *e.Choices[0].Delta.Content
				// One marker for a run of text, so the order of text
				// against the structural events can be asserted.
				if len(events) == 0 || events[len(events)-1] != "text" {
					events = append(events, "text")
				}
			}
			if len(e.Choices) > 0 && e.Choices[0].FinishReason != nil {
				events = append(events, "finish:"+*e.Choices[0].FinishReason)
			}
		}
	}
	return text, events
}

// A streamed reply passes through with its text intact and its findings on
// the receipt, and the stop event still arrives after the last word rather
// than overtaking text that was being held.
func TestAStreamedReplyPassesThroughWithFindings(t *testing.T) {
	proxyHome(t)
	// The email straddles chunk boundaries, which is exactly what
	// per-chunk scanning misses.
	upstream := sseUpstream(t, []string{"Sure, contact pri", "ya@acme.exa", "mple about the order ", "and quote card " + testCard + "."})
	defer upstream.Close()
	base, p := startProxy(t, upstream.URL, proxyOptions{})

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"llama3","stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("content type %q; the stream was not relayed as a stream", ct)
	}
	text, events := sseText(t, resp.Body)

	// A value the model produced that nobody sent it is substituted on the
	// way out, which is what the stream governor does for the gateway too;
	// the words around it arrive intact and in order.
	if strings.Contains(text, testEmail) || strings.Contains(text, testCard) {
		t.Errorf("a value the model produced passed through unsubstituted: %q", text)
	}
	if !strings.HasPrefix(text, "Sure, contact ") || !strings.Contains(text, " about the order and quote card ") || !strings.HasSuffix(text, ".") {
		t.Errorf("the streamed text did not arrive whole: %q", text)
	}
	if got := strings.Join(events, " "); got != "text finish:stop [DONE] lyntway" {
		t.Errorf("structural events in order: %q; the stop must follow the text and the receipt event must be last", got)
	}
	if got := resp.Trailer.Get("X-Lyntway-Receipt"); !strings.HasPrefix(got, "rcpt_") {
		t.Errorf("no receipt id in the trailer: %v", resp.Trailer)
	}

	rs := readReceipts(t, p.receiptsPath)
	if len(rs) != 2 {
		t.Fatalf("got %d receipts, want 2", len(rs))
	}
	res := rs[1]
	if res.Action.Direction != receipt.DirectionResponse {
		t.Fatalf("second receipt is %s", res.Action.Direction)
	}
	// Once each. The governor's findings and the receipt's own scan of the
	// released text both see these; carrying both into the receipt counted
	// every value twice.
	if findingCount(res, "pii.email") != 1 || findingCount(res, "pci.card_number") != 1 {
		t.Errorf("stream receipt findings = %+v; want the email that straddled chunks and the card, once each", res.Governance.Findings)
	}
	if res.Content.Bytes == 0 {
		t.Errorf("the response receipt covers nothing: %+v", res.Content)
	}
	if res.Governance.Decision == receipt.DecisionAllow {
		t.Errorf("a stream with findings is recorded as allow: %+v", res.Governance)
	}
}

// A stream that turns dangerous is cut. The client is told rather than
// left with a reply that simply stops, and the receipt records the class
// that cut it — which the receipt's own scan cannot see, because those
// bytes were never released — as truncated and blocked, once.
func TestAStreamCarryingACredentialIsCutAndTheReceiptSaysWhy(t *testing.T) {
	proxyHome(t)
	upstream := sseUpstream(t, []string{"Here is the key: ", testAWSKey[:6], testAWSKey[6:], " and more text after it."})
	defer upstream.Close()
	base, p := startProxy(t, upstream.URL, proxyOptions{})

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"llama3","stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)
	if strings.Contains(body, testAWSKey) || strings.Contains(body, "more text after") {
		t.Errorf("the credential or what followed it reached the client:\n%s", body)
	}
	if !strings.Contains(body, "event: error") || !strings.Contains(body, "lyntway_blocked") {
		t.Errorf("the client was not told the stream was cut:\n%s", body)
	}
	if strings.Contains(body, "[DONE]") || strings.Contains(body, `"finish_reason":"stop"`) {
		t.Errorf("a cut stream reads as a complete one:\n%s", body)
	}

	rs := readReceipts(t, p.receiptsPath)
	if len(rs) != 2 {
		t.Fatalf("got %d receipts, want 2", len(rs))
	}
	res := rs[1]
	if !res.Content.Truncated {
		t.Errorf("the receipt does not say the stream was cut: %+v", res.Content)
	}
	if findingCount(res, "secret.aws_access_key") != 1 {
		t.Errorf("findings = %+v; want the credential that cut the stream, once", res.Governance.Findings)
	}
	if res.Governance.Decision != receipt.DecisionBlock {
		t.Errorf("decision = %s, want block", res.Governance.Decision)
	}
}

// Ollama's own API streams newline-delimited JSON. The done object carries
// no text and must still reach the client, after the text.
func TestOllamaNDJSONStreamsPassThrough(t *testing.T) {
	proxyHome(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		f := w.(http.Flusher)
		for _, frag := range []string{"Write to ", "priya@acme", ".example today."} {
			line, _ := json.Marshal(map[string]any{"model": "llama3", "message": map[string]any{"role": "assistant", "content": frag}, "done": false})
			w.Write(append(line, '\n'))
			f.Flush()
		}
		w.Write([]byte(`{"model":"llama3","message":{"role":"assistant","content":""},"done":true,"eval_count":7}` + "\n"))
		f.Flush()
	}))
	defer upstream.Close()
	base, p := startProxy(t, upstream.URL, proxyOptions{})

	resp, err := http.Post(base+"/api/chat", "application/json", strings.NewReader(`{"model":"llama3","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var text string
	var last map[string]any
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var e map[string]any
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("a line is not JSON: %s", sc.Text())
		}
		if m, ok := e["message"].(map[string]any); ok {
			text += m["content"].(string)
		}
		last = e
	}
	if !strings.HasPrefix(text, "Write to ") || !strings.HasSuffix(text, " today.") || strings.Contains(text, testEmail) {
		t.Errorf("text = %q; want the words intact around a substituted address", text)
	}
	if last == nil || last["done"] != true || last["eval_count"] != float64(7) {
		t.Errorf("the done object did not arrive last and intact: %v", last)
	}
	if got := resp.Trailer.Get("X-Lyntway-Receipt"); !strings.HasPrefix(got, "rcpt_") {
		t.Errorf("no receipt id in the trailer: %v", resp.Trailer)
	}
	rs := readReceipts(t, p.receiptsPath)
	if len(rs) != 2 || findingCount(rs[1], "pii.email") != 1 {
		t.Errorf("receipts: %d; response findings %+v", len(rs), rs[len(rs)-1].Governance.Findings)
	}
}

// The test that matters for the report. Content, its digests and the
// values found never leave the machine; classes and counts do.
func TestOnlyCountsReachTheAccount(t *testing.T) {
	home := proxyHome(t)

	var mu sync.Mutex
	var reports [][]byte
	var auth string
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/attest" {
			t.Errorf("the proxy called %s on the service; only /v1/attest is expected", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		reports = append(reports, raw)
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer service.Close()
	if _, err := saveConfig(config{Origin: service.URL, Key: "lynt_sk_test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".lyntway", "config.json")); err != nil {
		t.Fatal("the config did not land in the test home")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"Noted, `+testEmail+`."}}]}`)
	}))
	defer upstream.Close()
	base, p := startProxy(t, upstream.URL, proxyOptions{Report: true, Name: "ollama"})
	if p.reporter == nil {
		t.Fatal("a signed-in machine produced no reporter")
	}

	prompt := "Charge " + testCard + " for priya, she is at " + testEmail
	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"llama3","messages":[{"role":"user","content":"`+prompt+`"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	p.close()

	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want one per direction", len(reports))
	}
	if auth != "Bearer lynt_sk_test" {
		t.Errorf("authorization = %q", auth)
	}
	rs := readReceipts(t, p.receiptsPath)
	for i, raw := range reports {
		body := string(raw)
		for _, forbidden := range []string{testCard, "4111", testEmail, "priya", "Charge", "Noted", "content", "digest", "messages", "text", "sha256"} {
			if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
				t.Errorf("report %d carries %q, which must never leave the machine:\n%s", i, forbidden, body)
			}
		}
		var sent struct {
			Tool     string `json:"tool"`
			ChainID  string `json:"chain_id"`
			Decision string `json:"decision"`
			Action   struct {
				Surface     string `json:"surface"`
				Direction   string `json:"direction"`
				Destination string `json:"destination"`
			} `json:"action"`
			Findings []struct {
				Class string `json:"class"`
				Count int    `json:"count"`
			} `json:"findings"`
			Reference string `json:"reference"`
		}
		if err := json.Unmarshal(raw, &sent); err != nil {
			t.Fatalf("report %d is not JSON: %v", i, err)
		}
		if sent.Tool != "lyntway-proxy" || sent.ChainID != "proxy/ollama" || sent.Action.Surface != "model" {
			t.Errorf("report %d names itself wrongly: %+v", i, sent)
		}
		if sent.Action.Destination != strings.TrimPrefix(upstream.URL, "http://") {
			t.Errorf("report %d destination = %q", i, sent.Action.Destination)
		}
		if sent.Reference != rs[i].ID {
			t.Errorf("report %d references %q, local receipt is %q", i, sent.Reference, rs[i].ID)
		}
		counts := map[string]int{}
		for _, f := range sent.Findings {
			counts[f.Class] = f.Count
		}
		switch sent.Action.Direction {
		case "request":
			if counts["pci.card_number"] != 1 || counts["pii.email"] != 1 || sent.Decision != "tokenize" {
				t.Errorf("request report: findings %v decision %s", counts, sent.Decision)
			}
		case "response":
			if counts["pii.email"] != 1 {
				t.Errorf("response report: findings %v", counts)
			}
		default:
			t.Errorf("report %d direction %q", i, sent.Action.Direction)
		}
	}
}

// Not signed in is an ordinary state: the proxy governs and keeps
// receipts, and nothing is sent anywhere. --report=false does the same on
// a signed-in machine.
func TestNothingIsReportedWhenNotSignedInOrAskedNotTo(t *testing.T) {
	proxyHome(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"choices":[]}`)
	}))
	defer upstream.Close()

	_, p := startProxy(t, upstream.URL, proxyOptions{Report: true})
	if p.reporter != nil {
		t.Error("a machine that is not signed in has nowhere to report to, yet a reporter exists")
	}

	called := false
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer service.Close()
	if _, err := saveConfig(config{Origin: service.URL, Key: "lynt_sk_test"}); err != nil {
		t.Fatal(err)
	}
	base, p := startProxy(t, upstream.URL, proxyOptions{Report: false})
	if p.reporter != nil {
		t.Error("--report=false still built a reporter")
	}
	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(`{"messages":[{"content":"`+testEmail+`"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	p.close()
	if called {
		t.Error("the service was called with --report=false")
	}
	if rs := readReceipts(t, p.receiptsPath); len(rs) != 2 {
		t.Errorf("receipts are the record either way; got %d", len(rs))
	}
}

// The receipt file must verify with the verifier anyone can download,
// using the key file published beside it — the whole point of writing
// receipts a laptop signed. The key file and the verifier's -keys format
// are two separate pieces of code that must agree, so the real binary is
// built and run rather than the library called.
func TestTheReceiptFileVerifiesWithLyntwayVerify(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH to build lyntway-verify")
	}
	proxyHome(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer upstream.Close()
	base, p := startProxy(t, upstream.URL, proxyOptions{Name: "ollama"})
	for i := 0; i < 3; i++ {
		resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(`{"messages":[{"content":"card `+testCard+`"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	p.close()

	// A second run continues the chain. Without the chain file every
	// restart would fork it at zero, and the verifier would report the
	// break — a gap indistinguishable from deletion.
	base2, p2 := startProxy(t, upstream.URL, proxyOptions{Name: "ollama"})
	resp, err := http.Post(base2+"/v1/chat/completions", "application/json", strings.NewReader(`{"messages":[{"content":"again"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	p2.close()

	bin := filepath.Join(t.TempDir(), "lyntway-verify")
	build := exec.Command("go", "build", "-o", bin, "../lyntway-verify")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building lyntway-verify: %v\n%s", err, out)
	}
	keys := filepath.Join(filepath.Dir(p.receiptsPath), "keys.json")
	verify := exec.Command(bin, "-chain", "-json", "-keys", keys, p.receiptsPath)
	out, err := verify.CombinedOutput()
	if err != nil {
		t.Fatalf("lyntway-verify rejected the file: %v\n%s", err, out)
	}
	var result struct {
		Valid       bool   `json:"valid"`
		ChainID     string `json:"chain_id"`
		ChainLength int    `json:"chain_length"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("verifier output is not JSON: %s", out)
	}
	if !result.Valid || result.ChainID != "proxy/ollama" || result.ChainLength != 8 {
		t.Errorf("verifier: %+v (want valid, chain proxy/ollama, 8 receipts across two runs)\n%s", result, out)
	}

	// A single receipt verifies too, which is what somebody handed one
	// line of the file will do.
	first := readReceipts(t, p.receiptsPath)[0]
	line, _ := json.Marshal(first)
	one := filepath.Join(t.TempDir(), "one.json")
	if err := os.WriteFile(one, line, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "-keys", keys, one).CombinedOutput(); err != nil {
		t.Errorf("a single receipt did not verify: %v\n%s", err, out)
	}
}

// When the machine holds the key `lyntway keys sign` wrote, receipts are
// signed with it — the one key whose public half the account holds — and
// the issuer says so. Without it, the machine key lyntway-mcp keeps is
// used, so a machine has one local key rather than one per tool.
func TestTheKeysSignKeyIsPreferredAndTheMachineKeyIsShared(t *testing.T) {
	home := proxyHome(t)

	signer, note, err := loadProxySigner(config{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(signer.KeyID(), "local-") || !strings.Contains(note, "local key") {
		t.Errorf("machine key id %q, note %q", signer.KeyID(), note)
	}
	if _, err := os.Stat(filepath.Join(home, ".lyntway", "mcp-signing.key")); err != nil {
		t.Errorf("the machine key was not written where lyntway-mcp reads it: %v", err)
	}
	again, _, err := loadProxySigner(config{}, false)
	if err != nil || again.KeyID() != signer.KeyID() {
		t.Errorf("a second load produced key %q, want %q (err %v)", again.KeyID(), signer.KeyID(), err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemPath := filepath.Join(home, "key.pem")
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	c := config{Origin: "https://lyntway.example", Key: "k", KeyID: "key_abc123", SigningKey: pemPath}
	signer, note, err = loadProxySigner(c, true)
	if err != nil {
		t.Fatal(err)
	}
	if signer.KeyID() != "key_abc123" || !strings.Contains(note, "keys sign") {
		t.Errorf("signer %q, note %q; the registered key should sign", signer.KeyID(), note)
	}
	raw, err := receipt.RawPublicKey(signer)
	if err != nil || !bytes.Equal(raw, pub) {
		t.Errorf("the signer does not hold the key from the PEM")
	}
	// Signed in without a signing key: the machine key, not an error.
	signer, _, err = loadProxySigner(config{Origin: "x", Key: "k"}, true)
	if err != nil || !strings.HasPrefix(signer.KeyID(), "local-") {
		t.Errorf("signed in without `keys sign`: %v, key %v", err, signer)
	}
	// A missing key file is refused, not silently replaced.
	if _, _, err := loadProxySigner(config{Origin: "x", Key: "k", KeyID: "key_abc123", SigningKey: filepath.Join(home, "gone.pem")}, true); err == nil {
		t.Error("a missing signing key was not reported")
	}
}

// A listener anywhere but loopback would govern anyone's traffic under
// this machine's key.
func TestTheProxyRefusesToListenOffLoopback(t *testing.T) {
	proxyHome(t)
	for _, addr := range []string{"0.0.0.0:11435", "192.168.1.5:11435", ":11435"} {
		if _, err := newLocalProxy(proxyOptions{Listen: addr, Upstream: "http://127.0.0.1:11434"}); err == nil {
			t.Errorf("--listen %s was accepted", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "localhost:0", "[::1]:0"} {
		p, err := newLocalProxy(proxyOptions{Listen: addr, Upstream: "http://127.0.0.1:11434"})
		if err != nil {
			t.Errorf("--listen %s was refused: %v", addr, err)
			continue
		}
		p.close()
	}
}

// status must tell a running proxy from a stale pid file, and only a
// listener that answers as this tool counts.
func TestTheStatusLineTellsRunningFromStale(t *testing.T) {
	home := proxyHome(t)
	pidPath := filepath.Join(home, ".lyntway", "proxy.pid")

	never := func(string) (map[string]any, bool) { return nil, false }
	if got := proxyStatusLine(pidPath, never); !strings.Contains(got, "not fronted") || !strings.Contains(got, "lyntway proxy") {
		t.Errorf("no pid file: %q", got)
	}

	if err := writeProxyPID(pidPath, proxyPID{PID: 1, Listen: "127.0.0.1:11435", Upstream: "http://127.0.0.1:11434", Started: "2026-09-07T10:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if got := proxyStatusLine(pidPath, never); !strings.HasPrefix(got, "  ✗") || !strings.Contains(got, "not running") {
		t.Errorf("stale pid file: %q", got)
	}

	live := func(listen string) (map[string]any, bool) {
		if listen != "127.0.0.1:11435" {
			t.Errorf("probed %q", listen)
		}
		return map[string]any{"tool": proxyTool, "upstream": "http://127.0.0.1:11434", "reporting": true}, true
	}
	got := proxyStatusLine(pidPath, live)
	if !strings.HasPrefix(got, "  ✓") || !strings.Contains(got, "fronting http://127.0.0.1:11434") ||
		!strings.Contains(got, "OPENAI_BASE_URL=http://127.0.0.1:11435/v1") || !strings.Contains(got, "counts reported") {
		t.Errorf("running: %q", got)
	}

	// The real probe against a real listener, and against a port that
	// answers but is not us.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	base, _ := startProxy(t, upstream.URL, proxyOptions{Name: "ollama"})
	if info, ok := probeProxy(strings.TrimPrefix(base, "http://")); !ok || info["name"] != "ollama" {
		t.Errorf("the real probe did not recognise a running proxy: %v %v", info, ok)
	}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"tool":"something-else"}`) }))
	defer other.Close()
	if _, ok := probeProxy(strings.TrimPrefix(other.URL, "http://")); ok {
		t.Error("a listener that is not this tool was taken for a proxy")
	}
}

// runProxy end to end: it binds, writes the pid file, prints the base URL
// to export, serves, and cleans up on cancellation.
func TestRunProxyWritesThePIDFileAndRemovesIt(t *testing.T) {
	home := proxyHome(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- runProxy(ctx, proxyOptions{Listen: listen, Upstream: upstream.URL, Report: true}, &out)
	}()

	pidPath := filepath.Join(home, ".lyntway", "proxy.pid")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := probeProxy(listen); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy never answered on %s; output so far:\n%s", listen, out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(pidPath); err != nil {
		t.Errorf("no pid file while running: %v", err)
	}
	if line := proxyStatusLine(pidPath, probeProxy); !strings.HasPrefix(line, "  ✓") {
		t.Errorf("status while running: %q", line)
	}
	resp, err := http.Post("http://"+listen+"/v1/chat/completions", "application/json", strings.NewReader(`{"messages":[{"content":"`+testEmail+`"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runProxy: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runProxy did not stop on cancellation")
	}
	if _, err := os.Stat(pidPath); err == nil {
		t.Error("the pid file was left behind")
	}
	text := out.String()
	for _, want := range []string{"OPENAI_BASE_URL=http://" + listen + "/v1", "not signed in", "pii.email ×1", "governed 2 messages"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, testEmail) {
		t.Errorf("the summary printed a value:\n%s", text)
	}
}
