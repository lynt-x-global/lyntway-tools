package govern

import (
	"encoding/json"
	"strings"
	"testing"
)

// The failure this exists to prevent, in the shape it actually arrived in.
//
// The model tier reported "jsonrpc" as a person's name. Substitution
// rewrote the key. The result was still valid JSON and no longer a JSON-RPC
// message, so every MCP server answered "Parse error: Invalid JSON-RPC
// message" — to a gateway that reported itself healthy and issued a signed
// receipt saying the request had been governed successfully.
func TestAnObjectKeyIsNeverRewritten(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":1,"method":"initialize",` +
		`"params":{"clientInfo":{"name":"mcp-client","version":"1"}}}`

	keys := jsonObjectKeys([]byte(body))
	if len(keys) == 0 {
		t.Fatal("no object keys were found in a JSON object")
	}
	for _, want := range []string{`"jsonrpc"`, `"method"`, `"clientInfo"`, `"name"`} {
		at := strings.Index(body, want)
		if !withinKey(at, at+len(want), keys) {
			t.Errorf("%s was not recognised as a key, so it could be rewritten", want)
		}
	}

	// The value beside a key must remain fair game, or the fix has removed
	// the product rather than the bug.
	at := strings.Index(body, `"mcp-client"`)
	if withinKey(at+1, at+11, keys) {
		t.Error("a value was treated as a key, so nothing in it would ever be protected")
	}
}

// Keys are structure wherever they appear; strings inside arrays are not.
func TestKeysAreFoundAtEveryDepthAndArraysHaveNone(t *testing.T) {
	const body = `{"outer":{"inner":[{"deep":"v"},"loose"]},"n":1}`
	keys := jsonObjectKeys([]byte(body))

	for _, want := range []string{`"outer"`, `"inner"`, `"deep"`, `"n"`} {
		at := strings.Index(body, want)
		if !withinKey(at, at+len(want), keys) {
			t.Errorf("%s was missed", want)
		}
	}
	// A bare string in an array is a value, not a key.
	at := strings.Index(body, `"loose"`)
	if withinKey(at, at+len(`"loose"`), keys) {
		t.Error(`"loose" is an array element and was treated as a key`)
	}
}

// Escapes must not confuse the walk back to the opening quote.
func TestAnEscapedQuoteInAKeyDoesNotConfuseTheScan(t *testing.T) {
	raw, err := json.Marshal(map[string]string{`we"ird`: "value"})
	if err != nil {
		t.Fatal(err)
	}
	keys := jsonObjectKeys(raw)
	if len(keys) != 1 {
		t.Fatalf("found %d keys in a one-key object: %s", len(keys), raw)
	}
	if got := string(raw[keys[0].start:keys[0].end]); got != `"we\"ird"` {
		t.Errorf("key range covers %s, want the whole escaped key", got)
	}
}

// Anything that is not JSON must be left entirely alone, or ordinary prose
// would stop being protected.
func TestPlainTextHasNoKeys(t *testing.T) {
	for _, s := range []string{
		"Priya Sharma, card 4111 1111 1111 1111",
		"", "   ", "not json at all: {oops",
	} {
		if k := jsonObjectKeys([]byte(s)); k != nil {
			t.Errorf("%q produced key ranges", s)
		}
	}
}

// And the whole path: a value is substituted, the key beside it is not.
//
// The key here is itself an address, so the deterministic ruleset reports
// it without needing the model tier. That matters: an earlier version of
// this test leaned on a span the ruleset never produces, so it passed with
// the guard removed and proved nothing.
func TestSubstitutionRewritesValuesAndLeavesKeys(t *testing.T) {
	engine, scope := streamEngine(t)
	const body = `{"priya@acme.co.uk":"2.0","email":"sam@acme.co.uk"}`

	spans := engine.ruleset.Scan([]byte(body))
	if len(spans) < 2 {
		t.Fatalf("expected the ruleset to find both addresses, found %d", len(spans))
	}

	out, err := alter(Request{Content: []byte(body), Scope: scope}, spans, engine.policy)
	if err != nil {
		t.Fatalf("alter: %v", err)
	}
	got := string(out)

	// The value is data and must go.
	if strings.Contains(got, "sam@acme.co.uk") {
		t.Errorf("the address in the value was not substituted: %s", got)
	}
	// The key is structure and must stay, however much it looks like data.
	if !strings.Contains(got, `"priya@acme.co.uk":`) {
		t.Errorf("an object key was rewritten, so the message changed shape: %s", got)
	}

	var probe map[string]any
	if err := json.Unmarshal(out, &probe); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if _, ok := probe["priya@acme.co.uk"]; !ok {
		t.Errorf("the field is gone; anything reading this message would not find it: %s", got)
	}
}
