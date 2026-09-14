package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The promise a document receipt makes, tested the way an auditor would use
// it: they hold a file and a receipt, and nothing else.
func TestHashingTheFileIsWhatSettlesADocumentReceipt(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "assessment.oscal.json")
	const content = `{"assessment-results":{"uuid":"c1a1"}}`
	if err := os.WriteFile(report, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	sum, err := hashFile(report)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	if len(sum) != 64 {
		t.Fatalf("digest %q is not a sha-256", sum)
	}

	// The same bytes must hash the same way every time, or nothing built on
	// this means anything.
	again, err := hashFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if again != sum {
		t.Errorf("hashing the same file twice gave %s then %s", sum, again)
	}

	// One byte different is a different file, and must be seen as one.
	altered := filepath.Join(dir, "altered.oscal.json")
	if err := os.WriteFile(altered, []byte(strings.Replace(content, "c1a1", "c1a2", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := hashFile(altered)
	if err != nil {
		t.Fatal(err)
	}
	if other == sum {
		t.Error("a file with a changed field hashed to the same digest")
	}
}

func TestHashingAMissingFileIsAnInputError(t *testing.T) {
	// Not a verification failure. Somebody who mistyped a path has not been
	// handed a forged document, and telling them so would send them looking
	// for an attacker instead of a typo.
	if _, err := hashFile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("hashing a file that does not exist succeeded")
	}
}

// A document receipt read without a file must not look settled.
func TestADocumentSubjectIsExplainedAsIntegrityOnly(t *testing.T) {
	note := subjectWarning("document")
	for _, want := range []string{"has not been altered", "says nothing about whether"} {
		if !strings.Contains(note, want) {
			t.Errorf("the document explanation is missing %q: %s", want, note)
		}
	}
	// It must not be described as a record about traffic: the digest covers
	// the file itself, and understating that is as wrong as overstating it.
	if strings.Contains(note, "not the traffic itself") {
		t.Errorf("a document digest was described as a record about traffic: %s", note)
	}
}
