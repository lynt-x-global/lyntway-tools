package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// The report goes up exactly as it sits on disk. json.Marshal compacts a
// RawMessage, so an upload that went through the ordinary helper would
// arrive with its whitespace stripped, hash to something else, and quietly
// stop matching the receipt — with nothing on either side looking wrong.
func TestTheUploadSendsTheFileByteForByte(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lyntway-readiness.json")
	// Indented, as writeReport writes it.
	body := "{\n  \"format\": \"lyntway-readiness/1\",\n  \"project\": \"checkout\"\n}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		sum := sha256.Sum256(got)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"digest":"` + hex.EncodeToString(sum[:]) + `"}`))
	}))
	defer srv.Close()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	out := capture(t, "", func() {
		if err := uploadReport(config{Origin: srv.URL, Key: "lyk_x"}, path); err != nil {
			t.Fatalf("upload: %v", err)
		}
	})

	if string(got) != body {
		t.Errorf("the service received different bytes:\nsent: %q\ngot : %q", body, got)
	}
	if !strings.Contains(out, "reported to") {
		t.Errorf("the run did not say where it went:\n%s", out)
	}
}

// If the service records a digest that is not the file's, the console would
// show a row matching nothing anybody holds, and the mismatch is the only
// sign of it.
func TestADigestTheServiceDoesNotAgreeWithIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.json")
	if err := os.WriteFile(path, []byte(`{"format":"lyntway-readiness/1","project":"a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"digest":"0000000000000000000000000000000000000000000000000000000000000000"}`))
	}))
	defer srv.Close()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	err := uploadReport(config{Origin: srv.URL, Key: "lyk_x"}, path)
	if err == nil {
		t.Fatal("a digest that disagreed with the file was accepted silently")
	}
	if !strings.Contains(err.Error(), "altered the report in transit") {
		t.Errorf("the error does not say what happened: %v", err)
	}
}
