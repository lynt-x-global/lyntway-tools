package govern

import (
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// A streamed reply is governed twice: in flight, where every byte is read
// and counted, and again at the end over the text that was delivered, to
// digest and sign it. The second pass used to scan that text and add what
// it found to the in-flight count, so a reply carrying one email was
// receipted as carrying two — once as the value the governor saw, once as
// the token it left behind.
func TestADeliveredStreamIsNotCountedTwice(t *testing.T) {
	e, _ := testEngine(t)
	delivered := []byte("Write to lynt-abcdefghijklm@tokenized.invalid and to priya@acme.example today.")
	res, err := e.Govern(Request{
		ChainID:   "gw/openai/stream",
		ReceiptID: "rstream1",
		Content:   delivered,
		Action:    receipt.Action{Surface: receipt.SurfaceModel, Direction: receipt.DirectionResponse, Method: "POST /v1/chat/completions", Target: "openai", Destination: "api.openai.com"},
		Actor:     receipt.Actor{Type: receipt.ActorAgent, ID: "app", Source: receipt.IdentityNone},
		Evidence:  &receipt.Evidence{Provenance: receipt.ProvenanceObserved, Vantage: "gw/openai"},
		Inspect:   true,
		// The in-flight governor saw both addresses: the caller's own,
		// restored on the way back, and the model's fresh one, which it
		// substituted with the token above.
		Irrevocable:   true,
		PriorFindings: []receipt.Finding{{Class: "pii.email", Count: 2, Decision: receipt.DecisionTokenize}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var emails int
	for _, f := range res.Receipt.Governance.Findings {
		if f.Class == "pii.email" {
			emails += f.Count
		}
	}
	if emails != 2 {
		t.Errorf("the receipt counts %d email findings for a reply that carried two: %+v", emails, res.Receipt.Governance.Findings)
	}
}
