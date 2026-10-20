package agentsecrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnAllowedFingerprintIsRetiredAndCounted(t *testing.T) {
	dir := t.TempDir()
	res := Result{
		Files: 10,
		Findings: []Finding{
			{Fingerprint: "aaaaaaaaaaaa", Label: "AWS access key", Last4: "1111", Kind: KindTranscript},
			{Fingerprint: "bbbbbbbbbbbb", Label: "Anthropic key", Last4: "2222", Kind: KindPrompts},
		},
	}

	// The written file carries a comment, which must not be read as part
	// of the fingerprint.
	lines := AllowLines([]Credential{{Fingerprint: "aaaaaaaaaaaa", Label: "AWS access key", Last4: "1111",
		Seen: []Finding{{Kind: KindTranscript}}}})
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "aaaaaaaaaaaa") {
		t.Fatalf("allow line is %q", lines)
	}
	if !strings.Contains(lines[0], "AWS access key") || !strings.Contains(lines[0], "1111") {
		t.Error("the allow line does not say what was retired; a fingerprint alone is unauditable")
	}
	if err := os.WriteFile(filepath.Join(dir, AllowFile),
		[]byte("# judged on 20 Oct\n\n"+lines[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	allow, err := LoadAllow(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !allow["aaaaaaaaaaaa"] {
		t.Fatal("the fingerprint was not read past its comment")
	}
	if len(allow) != 1 {
		t.Errorf("read %d entries, want 1: a comment line became an entry", len(allow))
	}

	out := res.Excluding(allow)
	if len(out.Findings) != 1 || out.Findings[0].Fingerprint != "bbbbbbbbbbbb" {
		t.Errorf("findings after exclusion: %+v", out.Findings)
	}
	if out.Allowed != 1 {
		t.Errorf("Allowed = %d, want 1: a report showing less has to say how much less", out.Allowed)
	}
	// What was read does not change because a finding was retired.
	if out.Files != res.Files {
		t.Errorf("Files changed from %d to %d; the files were still read", res.Files, out.Files)
	}
}

// A missing allowlist is the ordinary case and not an error.
func TestNoAllowlistIsNotAnError(t *testing.T) {
	allow, err := LoadAllow(t.TempDir())
	if err != nil {
		t.Fatalf("a machine with no allowlist errored: %v", err)
	}
	if len(allow) != 0 {
		t.Errorf("got %d entries from nothing", len(allow))
	}
}

// An allowlist that failed to read must not look like one that allowed
// nothing, or every judged finding comes back with no explanation.
func TestAnUnreadableAllowlistIsAnError(t *testing.T) {
	// A directory where the allowlist should be. Opens, and then fails on
	// the first read with EISDIR — for every user, including the root the
	// deploy's image build runs these tests as, where chmod 0000 proves
	// nothing.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, AllowFile), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadAllow(dir); err == nil {
		t.Error("an unreadable allowlist was reported as empty")
	}
}

// Case is not significance: a fingerprint pasted from a report in either
// case retires the same finding.
func TestFingerprintMatchingIgnoresCase(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, AllowFile), []byte("AABBCCDDEEFF\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	allow, err := LoadAllow(dir)
	if err != nil {
		t.Fatal(err)
	}
	res := Result{Findings: []Finding{{Fingerprint: "aabbccddeeff"}}}
	if got := res.Excluding(allow); len(got.Findings) != 0 {
		t.Error("a fingerprint written in capitals did not retire the finding")
	}
}
