package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The demo endpoint answers with the governed content, the decision, the
// findings and the receipt together. Piping that straight into this tool is
// the obvious next move for anybody trying the product, and it used to fail
// with a type error about Receipt.content — which reads as "your receipt is
// malformed" rather than "look one level down". Our own analyst brief
// shipped that broken sequence to Gartner.
func TestAReceiptIsFoundInsideTheDocumentThatCarriesIt(t *testing.T) {
	const inner = `{"version":"lyntway-receipt/1","id":"rcpt_1","content":{"algorithm":"sha-256"}}`
	envelope := `{"content":"redacted text","decision":"redact","receipt":` + inner + `}`

	got, unwrapped := unwrapEnvelope([]byte(envelope))
	if !unwrapped {
		t.Fatal("the receipt inside was not found")
	}
	// Verbatim bytes, not a re-encoding. The signature covers what the
	// issuer wrote, and a field this build has never heard of would be
	// dropped by a round trip and the receipt reported as tampered.
	if string(got) != inner {
		t.Errorf("the inner receipt was altered on the way out:\n got %s\nwant %s", got, inner)
	}
}

// A bare receipt must be left exactly as it is, or every existing caller
// changes behaviour to fix a convenience.
func TestABareReceiptIsNotUnwrapped(t *testing.T) {
	const bare = `{"version":"lyntway-receipt/1","id":"rcpt_1","content":{"algorithm":"sha-256"}}`
	got, unwrapped := unwrapEnvelope([]byte(bare))
	if unwrapped {
		t.Error("a bare receipt was treated as an envelope")
	}
	if string(got) != bare {
		t.Error("a bare receipt was modified")
	}
}

// A receipt that itself carries a "receipt" field is a different document,
// and unwrapping it would verify the wrong one — silently reporting on
// something other than what the caller handed over.
func TestAValidReceiptWins(t *testing.T) {
	outer := `{"version":"lyntway-receipt/1","id":"outer","receipt":{"version":"lyntway-receipt/1","id":"inner"}}`
	got, unwrapped := unwrapEnvelope([]byte(outer))
	if unwrapped {
		t.Fatal("a valid receipt was discarded in favour of one nested inside it")
	}
	var r struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(got, &r); err != nil {
		t.Fatal(err)
	}
	if r.ID != "outer" {
		t.Errorf("verified %q, want the document that was handed over", r.ID)
	}
}

// Anything that is not a document carrying a receipt is passed through
// untouched, so the error a caller sees is about their own file.
func TestNonEnvelopesArePassedThrough(t *testing.T) {
	for _, in := range []string{
		`not json at all`,
		`{"receipt":"a string, not an object"}`,
		`{"receipt":null}`,
		`{"receipt":[]}`,
		`[]`,
		``,
	} {
		got, unwrapped := unwrapEnvelope([]byte(in))
		if unwrapped {
			t.Errorf("%q was treated as an envelope", in)
		}
		if string(got) != in {
			t.Errorf("%q was modified to %q", in, got)
		}
	}
}

// Whitespace and formatting are the normal shape of a file somebody saved
// out of a browser or piped through a formatter.
func TestAnIndentedDocumentStillYieldsItsReceipt(t *testing.T) {
	envelope := "{\n  \"decision\": \"redact\",\n  \"receipt\": {\n    \"version\": \"lyntway-receipt/1\"\n  }\n}"
	got, unwrapped := unwrapEnvelope([]byte(envelope))
	if !unwrapped {
		t.Fatal("an indented document did not yield its receipt")
	}
	if !strings.Contains(string(got), "lyntway-receipt/1") {
		t.Errorf("got %s", got)
	}
}
