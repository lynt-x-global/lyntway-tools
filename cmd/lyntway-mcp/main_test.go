package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func testGovernor(t *testing.T) *governor {
	t.Helper()
	// The signing key lives under the home directory; a test must not
	// leave one on the developer's machine.
	t.Setenv("HOME", t.TempDir())
	g, err := newGovernor(t.TempDir()+"/receipts.jsonl", "test-server")
	if err != nil {
		t.Fatalf("governor: %v", err)
	}
	t.Cleanup(g.close)
	return g
}

// The direction that matters. A tool result is about to become part of a
// prompt sent to a model, so substituting values here is what stops them
// leaving the machine at all.
func TestToolResultsAreGovernedOnTheWayBack(t *testing.T) {
	g := testGovernor(t)

	message := `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text",` +
		`"text":"email=priya@acme.com card=4111 1111 1111 1111"}]}}`

	out, err := g.govern([]byte(message), directionToAgent)
	if err != nil {
		t.Fatalf("govern: %v", err)
	}
	got := string(out)

	for _, leaked := range []string{"priya@acme.com", "4111 1111 1111 1111"} {
		if strings.Contains(got, leaked) {
			t.Errorf("a tool result carried %q to the agent:\n%s", leaked, got)
		}
	}
	if !strings.Contains(got, "tokenized.invalid") {
		t.Errorf("nothing was substituted:\n%s", got)
	}

	// The envelope has to survive, or the agent cannot match the reply to
	// its request.
	var envelope map[string]any
	if err := json.Unmarshal(out, &envelope); err != nil {
		t.Fatalf("governing broke the message: %v", err)
	}
	if envelope["id"] != float64(2) || envelope["jsonrpc"] != "2.0" {
		t.Errorf("the protocol envelope was altered: %v", envelope)
	}
}

// Handshakes and capability listings are protocol. Rewriting them would
// break the conversation for no benefit — a tokenised method name is not
// safer, only broken.
func TestProtocolMessagesPassThroughUntouched(t *testing.T) {
	g := testGovernor(t)

	for _, message := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-03-26"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	} {
		out, err := g.govern([]byte(message), directionToServer)
		if err != nil {
			t.Fatalf("govern: %v", err)
		}
		if string(out) != message {
			t.Errorf("a protocol message was rewritten:\n got: %s\nwant: %s", out, message)
		}
	}
}

// Arguments travelling outward are governed too: an agent can put a
// customer's details into a tool call.
func TestToolCallArgumentsAreGoverned(t *testing.T) {
	g := testGovernor(t)

	message := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":` +
		`{"name":"create_issue","arguments":{"body":"contact priya@acme.com"}}}`

	out, err := g.govern([]byte(message), directionToServer)
	if err != nil {
		t.Fatalf("govern: %v", err)
	}
	if strings.Contains(string(out), "priya@acme.com") {
		t.Errorf("the tool received the real address:\n%s", out)
	}
}

// A message that cannot be released is not forwarded. Passing it through
// would mean the one message policy refused is the one that gets out.
func TestARefusedMessageIsNotForwarded(t *testing.T) {
	g := testGovernor(t)

	leaked := "AK" + "IA5J7QWMNBZX2LKPRD"
	message := `{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"key=` + leaked + `"}]}}`

	out, err := g.govern([]byte(message), directionToAgent)
	if err == nil {
		t.Fatalf("a credential was forwarded to the agent:\n%s", out)
	}
	if out != nil {
		t.Error("a refused message still produced output")
	}
}

// The protocol carries more than this needs to know, and refusing
// everything unfamiliar would break the server.
func TestUnrecognisedLinesPassThrough(t *testing.T) {
	g := testGovernor(t)

	for _, line := range []string{"not json at all", `{"some":"other shape"}`} {
		out, err := g.govern([]byte(line), directionToAgent)
		if err != nil {
			t.Fatalf("govern: %v", err)
		}
		if string(out) != line {
			t.Errorf("an unfamiliar line was altered:\n got: %s\nwant: %s", out, line)
		}
	}
}

// Receipts are the point: evidence that tool traffic was governed, written
// where the developer can find it.
func TestReceiptsAreWrittenLocally(t *testing.T) {
	path := t.TempDir() + "/receipts.jsonl"
	t.Setenv("HOME", t.TempDir())
	g, err := newGovernor(path, "test-server")
	if err != nil {
		t.Fatalf("governor: %v", err)
	}

	message := `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"a@b.com"}]}}`
	if _, err := g.govern([]byte(message), directionToAgent); err != nil {
		t.Fatalf("govern: %v", err)
	}
	g.close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading receipts: %v", err)
	}
	line := strings.TrimSpace(strings.Split(string(raw), "\n")[0])
	if line == "" {
		t.Fatal("no receipt was written")
	}

	var r map[string]any
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatalf("the receipt is not valid JSON: %v", err)
	}

	// The strongest claim available anywhere: this process handled the
	// bytes, on the machine where they were produced.
	evidence, _ := r["evidence"].(map[string]any)
	if evidence == nil || evidence["provenance"] != "observed" {
		t.Errorf("a shim receipt is not first-hand: %v", evidence)
	}
	action, _ := r["action"].(map[string]any)
	if action == nil || action["surface"] != "mcp" {
		t.Errorf("surface = %v, want mcp", action["surface"])
	}

	// Content must not appear in a receipt, only digests of it.
	if strings.Contains(line, "a@b.com") {
		t.Error("the receipt contains the content it describes")
	}
}

// The command name comes from the developer's own configuration and
// becomes part of a chain identifier.
func TestServerNamesAreReducedToSafeSegments(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"npx", "npx"},
		{"@modelcontextprotocol/server-github", "-modelcontextprotocol-server-github"},
		{"", "server"},
		{strings.Repeat("x", 100), strings.Repeat("x", 40)},
	} {
		if got := sanitise(tc.in); got != tc.want {
			t.Errorf("sanitise(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// receiptsIn reads every receipt the governor wrote, oldest first.
func receiptsIn(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading receipts: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("a receipt is not valid JSON: %v\n%s", err, line)
		}
		out = append(out, r)
	}
	return out
}

func methodOf(r map[string]any) string {
	action, _ := r["action"].(map[string]any)
	m, _ := action["method"].(string)
	return m
}

// Every server-to-agent message with a result used to be receipted as a
// tool result, so the initialize handshake was recorded as governed tool
// traffic. A receipt names the operation that actually happened.
func TestResponsesAreLabelledByTheRequestTheyAnswer(t *testing.T) {
	path := t.TempDir() + "/receipts.jsonl"
	t.Setenv("HOME", t.TempDir())
	g, err := newGovernor(path, "test-server")
	if err != nil {
		t.Fatalf("governor: %v", err)
	}
	t.Cleanup(g.close)

	exchange := []struct {
		dir     direction
		message string
	}{
		{directionToServer, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`},
		{directionToAgent, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"fake"}}}`},
		{directionToServer, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lookup","arguments":{}}}`},
		{directionToAgent, `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}`},
		{directionToAgent, `{"jsonrpc":"2.0","id":99,"result":{"content":[]}}`},
	}
	for _, step := range exchange {
		if _, err := g.govern([]byte(step.message), step.dir); err != nil {
			t.Fatalf("govern %s: %v", step.message, err)
		}
	}

	var methods []string
	for _, r := range receiptsIn(t, path) {
		methods = append(methods, methodOf(r))
	}
	// The initialize request itself is protocol and is not receipted; its
	// response is, and must say what it is.
	want := []string{"initialize", "tools/call", "tools/call", "unmatched-response"}
	if strings.Join(methods, ",") != strings.Join(want, ",") {
		t.Errorf("receipt methods = %v, want %v", methods, want)
	}
	for _, m := range methods {
		if m == "tools/result" {
			t.Errorf("a response is still labelled %q", m)
		}
	}
}
