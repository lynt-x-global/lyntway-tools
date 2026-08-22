package govern

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// A receipt must not read as a clean scan of something nobody could read.
//
// Detection works on text. A vision request carries its image as base64
// inside JSON and a document upload can carry a file the same way, and to a
// scanner those are a long run of harmless characters. Finding nothing is
// honest. Reporting it as a full scan is not, and a reader comparing two
// receipts had no way to tell an empty scan from an unread one.
func TestAnEncodedPayloadIsReportedAsUnread(t *testing.T) {
	engine, scope := streamEngine(t)

	blob := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("payload-bytes-", 200)))
	res, err := engine.Govern(Request{
		ChainID: "c", ReceiptID: "r1",
		Content: []byte(`{"image":"data:image/png;base64,` + blob + `"}`),
		Scope:   scope,
		Action: receipt.Action{
			Surface: receipt.SurfacePrimitive, Direction: receipt.DirectionRequest,
			Method: "POST /x",
		},
		Actor: receipt.Actor{Type: receipt.ActorAgent, ID: "a", Source: receipt.IdentityNone},
	})
	if err != nil {
		t.Fatal(err)
	}

	g := res.Receipt.Governance
	if g.Mode != receipt.ModeDegraded {
		t.Errorf("mode = %q, want degraded: part of this content was never examined", g.Mode)
	}
	var named bool
	for _, c := range g.Detector.Components {
		if c.Name == ComponentEncodedContent {
			named = true
			if c.Health != receipt.HealthUnavailable {
				t.Errorf("%s health = %q, want unavailable", c.Name, c.Health)
			}
		}
	}
	if !named {
		t.Errorf("nothing on the receipt says which part could not be read: %+v", g.Detector.Components)
	}
}

// Ordinary text must be unaffected, or every receipt reads degraded and the
// field stops meaning anything.
func TestOrdinaryContentIsStillReportedAsFullyScanned(t *testing.T) {
	engine, scope := streamEngine(t)

	for _, content := range []string{
		"Priya Sharma, card 4111 1111 1111 1111",
		`{"messages":[{"role":"user","content":"summarise the quarterly report"}]}`,
		// An identifier is short, and a token or trace id must not drag a
		// receipt to degraded.
		`{"request_id":"` + strings.Repeat("a", 120) + `"}`,
	} {
		res, err := engine.Govern(Request{
			ChainID: "c", ReceiptID: "r-" + content[:8],
			Content: []byte(content),
			Scope:   scope,
			Action: receipt.Action{
				Surface: receipt.SurfacePrimitive, Direction: receipt.DirectionRequest,
				Method: "POST /x",
			},
			Actor: receipt.Actor{Type: receipt.ActorAgent, ID: "a", Source: receipt.IdentityNone},
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.Receipt.Governance.Mode != receipt.ModeFull {
			t.Errorf("mode = %q for ordinary content: %.40s",
				res.Receipt.Governance.Mode, content)
		}
	}
}

// The threshold decides whether this field is read or ignored.
func TestOnlySubstantialRunsCount(t *testing.T) {
	short := strings.Repeat("A", minimumOpaqueRun-1)
	long := strings.Repeat("A", minimumOpaqueRun)

	if carriesUnreadableContent([]byte(short + " and some ordinary words here to pad it out")) {
		t.Error("a run below the threshold was treated as carried content")
	}
	if !carriesUnreadableContent([]byte("prefix " + long + " suffix")) {
		t.Error("a run at the threshold was not noticed")
	}
	// Broken by punctuation is prose, not a payload.
	broken := strings.Repeat("word.word.", minimumOpaqueRun)
	if carriesUnreadableContent([]byte(broken)) {
		t.Error("ordinary punctuated text was treated as an encoded payload")
	}
}
