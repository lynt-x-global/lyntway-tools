package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The shim exists because a tool result carrying a customer record should
// be inspected where it already is rather than shipped somewhere to be
// checked. Reporting summaries must not quietly undo that.

func signedInHome(t *testing.T, origin string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".lyntway")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(localConfig{Origin: origin, Key: "sk-test"})
	if err := os.WriteFile(filepath.Join(dir, "config.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The test that matters. Everything else here is detail.
func TestOnlyClassesAndCountsEverLeaveTheMachine(t *testing.T) {
	var got []byte
	var auth string
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer service.Close()

	signedInHome(t, service.URL)
	rep := newReporter()
	if rep == nil {
		t.Fatal("a signed-in machine produced no reporter")
	}

	rep.report(attestation{
		Server:   "github",
		Chain:    "mcp/github",
		Decision: "tokenize",
		Findings: map[string]int{"pii.email": 3, "pci.card_number": 1},
		Bytes:    2048,
	})
	rep.close()

	if len(got) == 0 {
		t.Fatal("nothing was sent")
	}
	body := string(got)

	// The content of a tool result, a digest of it, or any value found in
	// it must never appear. This is the boundary the whole shim is for.
	for _, forbidden := range []string{
		"priya@", "4111", "content", "digest", "value", "text", "argument",
	} {
		if containsFold(body, forbidden) {
			t.Errorf("the summary carries %q, which must never leave the machine:\n%s",
				forbidden, body)
		}
	}

	var sent struct {
		Tool     string `json:"tool"`
		ChainID  string `json:"chain_id"`
		Decision string `json:"decision"`
		Action   struct {
			Surface     string `json:"surface"`
			Destination string `json:"destination"`
		} `json:"action"`
		Findings []struct {
			Class string `json:"class"`
			Count int    `json:"count"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(got, &sent); err != nil {
		t.Fatalf("unreadable summary: %v\n%s", err, body)
	}

	if sent.Tool != "lyntway-mcp" {
		t.Errorf("the summary does not say what reported it: %q", sent.Tool)
	}
	// An auditor asking what handled their data wants the server, not the
	// shim that happened to be watching.
	if sent.Action.Destination != "github" {
		t.Errorf("destination is %q, want the server being wrapped", sent.Action.Destination)
	}
	if sent.Action.Surface != "mcp" {
		t.Errorf("surface is %q, want mcp", sent.Action.Surface)
	}
	if len(sent.Findings) != 2 {
		t.Errorf("%d findings reported, want 2", len(sent.Findings))
	}
	if auth != "Bearer sk-test" {
		t.Errorf("the account key was not presented: %q", auth)
	}
}

// A machine nobody has signed in on still governs, still writes receipts,
// and reports nothing. That is an ordinary state rather than an error.
func TestAnUnconfiguredMachineReportsNothingAndSaysNothing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if rep := newReporter(); rep != nil {
		t.Error("a machine with no config produced a reporter")
	}
	// The nil reporter has to be safe to call, because record() does.
	var nilRep *reporter
	nilRep.report(attestation{Findings: map[string]int{"pii.email": 1}})
	nilRep.close()
}

// Nothing found is not worth a round trip, and a dashboard row saying "we
// looked and saw nothing" is noise. The local receipt still records it.
// A tool call that found nothing still has to be reported.
//
// This used to assert the opposite, on the reasoning that nothing found is
// not worth a round trip. That was wrong for this product. Somebody runs
// lyntway init, uses a tool, opens the traffic page and sees nothing — and
// an empty page reads as "not covered", not as "covered and clean". For a
// product whose value is knowing what was governed, silence understates
// coverage, which is the direction it must never err in.
//
// The local receipt was always written. What was missing was the dashboard
// agreeing that anything had happened.
func TestACleanToolCallIsStillReported(t *testing.T) {
	var calls int
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer service.Close()

	signedInHome(t, service.URL)
	rep := newReporter()
	rep.report(attestation{Server: "github", Findings: map[string]int{}})
	rep.close()

	if calls != 1 {
		t.Errorf("a governed tool call with no findings produced %d reports; it must produce one, or the traffic page reads as uncovered", calls)
	}
}

// A reporter that was never started must stay silent rather than panic.
// Signing out leaves one in exactly that state.
func TestAnUnstartedReporterStaysSilent(t *testing.T) {
	var rep *reporter
	rep.report(attestation{Server: "github", Findings: map[string]int{"pci.card_number": 1}})
}

// This runs inside somebody's agent. A service that is down, slow or
// refusing must cost a dashboard row, never a tool call.
func TestABrokenServiceDoesNotStopTheAgent(t *testing.T) {
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer service.Close()

	signedInHome(t, service.URL)
	rep := newReporter()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			rep.report(attestation{
				Server:   "github",
				Findings: map[string]int{"pii.email": 1},
			})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reporting blocked the caller; inside an agent that is a hung tool call")
	}
	rep.close()
}

func containsFold(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		indexFold(haystack, needle) >= 0
}

func indexFold(s, sub string) int {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
