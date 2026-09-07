package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lynt-x-global/lyntway-tools/receipt"
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

// signedReceipt builds a receipt the library accepts, lets the test reshape
// it, then signs and verifies it — so what report() is handed is exactly
// what it sees in the field, not a hand-assembled Result.
func signedReceipt(t *testing.T, shape func(r *receipt.Receipt)) (*receipt.Receipt, *receipt.Result) {
	t.Helper()
	signer, err := receipt.GenerateEd25519Signer("key-test-1")
	if err != nil {
		t.Fatal(err)
	}
	r := &receipt.Receipt{
		Version:  receipt.SchemaVersion,
		ID:       "rcpt_01J000000000000000000000",
		IssuedAt: receipt.FormatTime(time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)),
		Issuer:   receipt.Issuer{KeyID: signer.KeyID(), Name: "Lyntway"},
		Chain:    receipt.Chain{ID: "ws_acme", Seq: 0},
		Action: receipt.Action{
			Surface:     receipt.SurfaceModel,
			Direction:   receipt.DirectionRequest,
			Method:      "POST /v1/chat/completions",
			Target:      "claude-opus-5",
			Destination: "api.anthropic.com",
		},
		Actor: receipt.Actor{
			Type:     receipt.ActorAgent,
			ID:       "agent_support_bot",
			Source:   receipt.IdentityEntraAgent,
			Verified: true,
		},
		Content: receipt.Content{
			Algorithm:    receipt.DigestSHA256,
			InputDigest:  receipt.DigestContent([]byte("customer email is priya@acme.com")),
			OutputDigest: receipt.DigestContent([]byte("customer email is priya@acme.com")),
			Bytes:        32,
		},
		Governance: receipt.Governance{
			Mode:     receipt.ModeFull,
			Decision: receipt.DecisionAllow,
			Detector: receipt.Detector{
				Engine:         "lyntway-detect",
				EngineVersion:  "1.4.2",
				RulesetVersion: "pii-2026.08.01",
				Health:         receipt.HealthHealthy,
			},
			Policy: receipt.Policy{ID: "pol_default_pii", Version: "3"},
		},
		Evidence: &receipt.Evidence{Provenance: receipt.ProvenanceObserved, Vantage: "proxy"},
	}
	if shape != nil {
		shape(r)
	}
	if err := receipt.Sign(r, signer); err != nil {
		t.Fatal(err)
	}
	res, err := receipt.Verify(r, receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}, receipt.VerifyOptions{})
	if err != nil {
		t.Fatalf("the test receipt does not verify: %v", err)
	}
	return r, res
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wr
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		io.Copy(&buf, rd)
		close(done)
	}()
	func() {
		defer func() { os.Stdout = orig; wr.Close() }()
		fn()
	}()
	<-done
	return buf.String()
}

const (
	subjectPhrase   = "a record about the traffic, not the traffic itself"
	connectionOnly  = "(the connection only; the content was not read)"
	metadataWarning = "! the digests cover a record about the traffic, not the traffic itself: the issuer carried the bytes without reading them"
)

// A tunnel receipt is first-hand about the connection and blind to its
// content. Printed the way a payload receipt is printed, it read as
// "VERIFIED, first-hand, observed, allow" with an unqualified digest — for
// bytes the issuer never looked at. That is a receipt claiming more than
// happened, which is the one defect this product cannot carry.
func TestAMetadataReceiptIsReportedAsARecordAboutTheTraffic(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	r, res := signedReceipt(t, func(r *receipt.Receipt) {
		r.Content.Subject = receipt.SubjectMetadata
	})

	text := captureStdout(t, func() { report(false, res, r, nil) })
	for _, want := range []string{
		"observed at proxy " + connectionOnly,
		"(covers " + subjectPhrase + ")",
		metadataWarning,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not say %q:\n%s", want, text)
		}
	}

	var out output
	raw := captureStdout(t, func() { report(true, res, r, nil) })
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("JSON output is not JSON: %v\n%s", err, raw)
	}
	if out.Subject != "metadata" {
		t.Errorf("JSON subject = %q, want metadata", out.Subject)
	}
	if !strings.Contains(strings.Join(out.Warnings, "\n"), subjectPhrase) {
		t.Errorf("JSON warnings do not qualify the digest: %q", out.Warnings)
	}
}

// The ordinary receipt — digests over the data itself — must not pick up
// the qualification, or every receipt would read as if it covered nothing.
func TestAPayloadReceiptIsNotQualified(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	r, res := signedReceipt(t, nil)

	text := captureStdout(t, func() { report(false, res, r, nil) })
	if strings.Contains(text, subjectPhrase) || strings.Contains(text, connectionOnly) {
		t.Errorf("a payload receipt was qualified as if it were not the data:\n%s", text)
	}
	if !strings.Contains(text, "first-hand, observed at proxy\n") {
		t.Errorf("the evidence line changed for a payload receipt:\n%s", text)
	}

	var out output
	raw := captureStdout(t, func() { report(true, res, r, nil) })
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	if out.Subject != "payload" {
		t.Errorf("JSON subject = %q, want payload", out.Subject)
	}
}

// The receipt library rejects a subject it does not know, so report() never
// sees one today. The wording is still pinned: a future value must read as
// "not the data", never as a stronger claim than metadata.
func TestAnUnknownSubjectReadsWeak(t *testing.T) {
	got := subjectWarning(receipt.ContentSubject("headers"))
	if !strings.Contains(got, subjectPhrase) || !strings.Contains(got, `"headers"`) {
		t.Errorf("unknown subject warning = %q", got)
	}
	if subjectWarning(receipt.SubjectPayload) != "" {
		t.Error("the payload subject produced a warning")
	}
}

// A stream cut by policy is the one receipt that carries "block" beside an
// output digest: the prefix was released before the refused class appeared.
// The library accepts it; this checks the report says what happened rather
// than leaving the reader to conclude the receipt contradicts itself.
func TestATruncatedStreamIsReportedAsCut(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	r, res := signedReceipt(t, func(r *receipt.Receipt) {
		r.Governance.Decision = receipt.DecisionBlock
		r.Content.OutputDigest = receipt.DigestContent([]byte("the delivered prefix"))
		r.Content.Truncated = true
	})

	text := captureStdout(t, func() { report(false, res, r, nil) })
	if !strings.Contains(text, "! "+truncatedWarning) {
		t.Errorf("the report does not say the stream was cut:\n%s", text)
	}

	var out output
	raw := captureStdout(t, func() { report(true, res, r, nil) })
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Truncated {
		t.Error("JSON output does not mark the receipt truncated")
	}
	if !strings.Contains(strings.Join(out.Warnings, "\n"), truncatedWarning) {
		t.Errorf("JSON warnings do not say the stream was cut: %q", out.Warnings)
	}

	// And a complete receipt must not pick it up.
	r, res = signedReceipt(t, nil)
	text = captureStdout(t, func() { report(false, res, r, nil) })
	if strings.Contains(text, truncatedWarning) {
		t.Errorf("a complete receipt was reported as cut:\n%s", text)
	}
}

// A hold somebody released is the one receipt where the decision line on
// its own misleads: require_approval, and yet content left. The report
// has to name who released it, in text and in JSON, or a reader takes
// the release for policy's doing.
func TestAReleasedHoldNamesWhoApprovedIt(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	r, res := signedReceipt(t, func(r *receipt.Receipt) {
		r.Governance.Decision = receipt.DecisionRequireApproval
		r.Governance.Findings = []receipt.Finding{{Class: "custom.project", Count: 1, Decision: receipt.DecisionRequireApproval}}
		r.Governance.Approval = &receipt.Approval{
			ID: "apr_1", Outcome: receipt.ApprovalApproved, DecidedBy: "ops@acme.test", DecidedAt: "2026-09-07T10:00:00Z",
		}
	})

	text := captureStdout(t, func() { report(false, res, r, nil) })
	if !strings.Contains(text, "approval       released by ops@acme.test at 2026-09-07T10:00:00Z (apr_1)") {
		t.Errorf("the report does not say who released the hold:\n%s", text)
	}

	var out output
	raw := captureStdout(t, func() { report(true, res, r, nil) })
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	if out.Approval == nil || out.Approval.DecidedBy != "ops@acme.test" || out.Approval.Outcome != receipt.ApprovalApproved {
		t.Errorf("JSON approval = %+v", out.Approval)
	}

	// And an ordinary receipt says nothing about approval at all.
	plain, plainRes := signedReceipt(t, nil)
	if text := captureStdout(t, func() { report(false, plainRes, plain, nil) }); strings.Contains(text, "approval") {
		t.Errorf("a receipt nobody had to decide mentions approval:\n%s", text)
	}
}
