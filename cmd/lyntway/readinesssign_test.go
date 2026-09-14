package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The limits are part of the document. An assessor receiving this needs the
// boundaries as much as the findings, and a covering email is not where
// they belong.
func TestTheReportCarriesItsOwnLimits(t *testing.T) {
	rep := buildReport(
		readinessSnapshot{
			TakenAt: "2026-09-15T10:00:00Z", Dir: ".",
			EndpointsChecked: true, Endpoints: []endpointState{{Endpoint: "GET /v1/orders", Verdict: verdictOpen, Status: 200}},
			DepsChecked: true, Deps: []depState{{Ecosystem: "npm", Name: "axios", Version: "0.21.1"}},
		},
		[]change{{true, "axios 0.21.1 has a new advisory"}},
		surfaceDoc{EventsRead: 12, Oldest: "2026-09-01T00:00:00Z", Newest: "2026-09-15T09:00:00Z"},
		true,
	)

	joined := strings.Join(rep.Limits, " | ")
	for _, want := range []string{
		"not a penetration test",
		"says nothing about whether these findings are correct",
		"not an accredited assessor",
		"absent from the estate",
		"GET, HEAD and OPTIONS",
		"version range",
		"not the same as safe",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the report does not state %q:\n%s", want, joined)
		}
	}
	if rep.Surface == nil || rep.Surface.EventsRead != 12 {
		t.Error("the basis the surface rests on did not travel with the report")
	}
}

// A half that did not run must not leave a limit claiming it did, and must
// say plainly that the report covers the other half only.
func TestAReportFromOneHalfSaysSo(t *testing.T) {
	rep := buildReport(
		readinessSnapshot{TakenAt: "2026-09-15T10:00:00Z", Dir: ".", DepsChecked: true,
			Deps: []depState{{Ecosystem: "npm", Name: "axios", Version: "1.16.0"}}},
		nil, surfaceDoc{}, false,
	)
	joined := strings.Join(rep.Limits, " | ")
	if !strings.Contains(joined, "covers dependencies only") {
		t.Errorf("a dependencies-only run did not say so:\n%s", joined)
	}
	if strings.Contains(joined, "GET, HEAD and OPTIONS") {
		t.Errorf("a run that probed nothing claimed to have limited which methods it sent:\n%s", joined)
	}
	if rep.Surface != nil {
		t.Error("a surface section was written for a run that never read one")
	}
}

// Re-indenting a receipt is safe because verification canonicalises before
// checking the signature. What must not happen is losing it: a receipt that
// cannot be re-encoded is written exactly as it arrived.
func TestAReceiptThatCannotBeRewrittenIsKeptAsItArrived(t *testing.T) {
	raw := json.RawMessage(`{"version":"lyntway-receipt/1","id":"rcpt_1"}`)
	if got := receiptJSON(raw); !strings.Contains(string(got), `"id": "rcpt_1"`) {
		t.Errorf("a valid receipt was not re-indented: %s", got)
	}
	broken := json.RawMessage(`{not json`)
	if got := receiptJSON(broken); string(got) != "{not json\n" {
		t.Errorf("an unparseable receipt was altered rather than kept: %q", got)
	}
}
