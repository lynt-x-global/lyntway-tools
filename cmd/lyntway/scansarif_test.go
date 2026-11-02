package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sarifOf(t *testing.T, hits []keyHit) sarifReport {
	t.Helper()
	buf := captureStdout(t)
	if err := printScanSARIF(hits, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var doc sarifReport
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("the document is not JSON: %v\n%s", err, buf.String())
	}
	return doc
}

// The shape GitHub's upload accepts, asserted rather than assumed. A
// document it rejects fails a workflow with a schema error nobody can read.
func TestSARIFCarriesWhatCodeScanningNeeds(t *testing.T) {
	doc := sarifOf(t, []keyHit{
		{File: "src/app.py", Line: 12, Label: "OpenAI key", Class: "secret.openai_key", Last4: "ABCD"},
	})

	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if !strings.HasSuffix(doc.Schema, "sarif-schema-2.1.0.json") {
		t.Errorf("schema = %q", doc.Schema)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("%d runs, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "lyntway" || run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Results) != 1 {
		t.Fatalf("%d results, want 1", len(run.Results))
	}
	r := run.Results[0]
	if r.RuleID != "secret.openai_key" || r.Level != "error" {
		t.Errorf("result = %+v", r)
	}
	loc := r.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "src/app.py" || loc.Region.StartLine != 12 {
		t.Errorf("location = %+v", loc)
	}
	// Every result's rule has to be declared, or code scanning drops it.
	declared := map[string]bool{}
	for _, rule := range run.Tool.Driver.Rules {
		declared[rule.ID] = true
	}
	if !declared[r.RuleID] {
		t.Errorf("result names rule %q, which the driver does not declare", r.RuleID)
	}
}

// A SARIF document is uploaded, stored and shown in a web interface, which
// makes it the worst place in this tool to put a credential.
func TestSARIFNeverCarriesTheKey(t *testing.T) {
	buf := captureStdout(t)
	if err := printScanSARIF([]keyHit{
		{File: "a.env", Line: 1, Label: "OpenAI key", Class: "secret.openai_key", Last4: "ABCD"},
	}, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, tOpenAI) {
		t.Error("the document carries the key itself")
	}
	if !strings.Contains(out, "ABCD") {
		t.Error("the document carries no last4, so nobody can tell which key to revoke")
	}
	if strings.Contains(out, `"snippet"`) {
		t.Error("a snippet field is present; it would carry the matching text")
	}
}

// A clean run still has to produce a document.
//
// Code scanning closes a finding when the run that would report it comes
// back empty. A tool that prints nothing on success leaves every key it
// ever found open forever, and the alert list stops meaning anything.
func TestSARIFIsWrittenEvenWhenNothingIsFound(t *testing.T) {
	doc := sarifOf(t, nil)
	if len(doc.Runs) != 1 {
		t.Fatalf("%d runs, want 1 — an empty run is what closes a fixed finding", len(doc.Runs))
	}
	if doc.Runs[0].Results == nil {
		t.Error("results is null, not an empty array")
	}
}

// Two sightings of one class share a rule; two classes do not.
//
// One "secret found" rule would make "we accept Stripe test keys in
// fixtures" impossible to express without dismissing every secret alert.
func TestSARIFDeclaresOneRulePerClass(t *testing.T) {
	doc := sarifOf(t, []keyHit{
		{File: "a.env", Line: 1, Label: "OpenAI key", Class: "secret.openai_key", Last4: "AAAA"},
		{File: "b.env", Line: 2, Label: "OpenAI key", Class: "secret.openai_key", Last4: "BBBB"},
		{File: "c.env", Line: 3, Label: "Stripe key", Class: "secret.stripe_key", Last4: "CCCC"},
	})
	if n := len(doc.Runs[0].Tool.Driver.Rules); n != 2 {
		t.Errorf("%d rules declared for two classes, want 2", n)
	}
	if n := len(doc.Runs[0].Results); n != 3 {
		t.Errorf("%d results for three sightings, want 3", n)
	}
}

// The fingerprint must not move when the line does.
//
// Code scanning uses it to recognise a finding across runs. If it carried
// the line number, a key somebody had already triaged would reappear as
// new the moment anything above it grew by a line.
func TestSARIFFingerprintsSurviveTheLineMoving(t *testing.T) {
	a := sarifOf(t, []keyHit{{File: "a.env", Line: 1, Label: "OpenAI key", Class: "secret.openai_key", Last4: "ABCD"}})
	b := sarifOf(t, []keyHit{{File: "a.env", Line: 40, Label: "OpenAI key", Class: "secret.openai_key", Last4: "ABCD"}})
	if a.Runs[0].Results[0].PartialFingerprints["lyntwayCredential/v1"] !=
		b.Runs[0].Results[0].PartialFingerprints["lyntwayCredential/v1"] {
		t.Error("the fingerprint changed when only the line number did")
	}
}

// GitHub resolves artifactLocation.uri against the checkout root and will
// not display an absolute one.
func TestSARIFPathsAreRelativeToTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	// The file has to exist for EvalSymlinks to resolve it, which is the
	// case this is about: a symlinked temp or home directory.
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(dir, "config", "app.env")
	if err := os.WriteFile(abs, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := sarifOf(t, []keyHit{{File: abs, Line: 3, Label: "OpenAI key", Class: "secret.openai_key", Last4: "ABCD"}})
	if got := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "config/app.env" {
		t.Errorf("uri = %q, want config/app.env", got)
	}
}
