package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A file nothing opened must be named, or "no provider keys" is a claim
// about a directory when it is a claim about part of one.
//
// scanPaths skips anything with a NUL byte in its first 8 KB, because
// that is how a binary is told from text, and anything over four
// megabytes. Both are right. Neither was ever mentioned, so on
// 2 November 2026 a directory holding three files — each with a live
// OpenAI key in it — produced "No provider keys in 0 files." and exit 0,
// which passes a CI gate. One of those files had a single NUL byte on
// its first line: a one-character way to hide every secret in a .env
// from this scanner.
func TestFilesNothingOpenedAreNamed(t *testing.T) {
	dir := t.TempDir()
	key := "OPENAI_API_KEY=" + tOpenAI + "\n"

	// A NUL on the first line.
	if err := os.WriteFile(filepath.Join(dir, "nul-first.env"), append([]byte{0, '\n'}, key...), 0o600); err != nil {
		t.Fatal(err)
	}
	// A NUL at the far edge of the window isBinary reads.
	late := append(append([]byte(strings.Repeat("#", 7990)), 0), key...)
	if err := os.WriteFile(filepath.Join(dir, "nul-late.env"), late, 0o600); err != nil {
		t.Fatal(err)
	}
	// Past the size limit.
	big := append([]byte(strings.Repeat("# pad\n", 700_000)), key...)
	if err := os.WriteFile(filepath.Join(dir, "huge.env"), big, 0o600); err != nil {
		t.Fatal(err)
	}

	hits, scanned, skips, err := scanPaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("the fixture is wrong: %d findings, so nothing was skipped", len(hits))
	}
	if scanned != 0 {
		t.Errorf("scanned = %d, want 0", scanned)
	}
	if len(skips) != 3 {
		t.Fatalf("%d files reported as unread, want 3: %+v", len(skips), skips)
	}

	byName := map[string]string{}
	for _, s := range skips {
		byName[filepath.Base(s.Path)] = s.Reason
	}
	for _, name := range []string{"nul-first.env", "nul-late.env", "huge.env"} {
		reason, ok := byName[name]
		if !ok {
			t.Errorf("%s was not named", name)
			continue
		}
		if reason == "" {
			t.Errorf("%s was named with no reason, so nobody can tell whether it matters", name)
		}
	}
	if !strings.Contains(byName["huge.env"], "limit") {
		t.Errorf("the oversize reason does not mention the limit: %q", byName["huge.env"])
	}
	if !strings.Contains(byName["nul-first.env"], "NUL") {
		t.Errorf("the binary reason does not say what made it look binary: %q", byName["nul-first.env"])
	}
}

// The report has to say it, not just carry it.
func TestTheReportNamesWhatItCouldNotRead(t *testing.T) {
	buf := captureStdout(t)
	printSkipped([]skippedFile{
		{Path: "a/secret.env", Reason: "a NUL byte in the first 8 KB, so it reads as binary"},
		{Path: "b/big.log", Reason: "9000000 bytes, over the 4 MB limit"},
	}, "text")
	out := buf.String()
	for _, want := range []string{"a/secret.env", "b/big.log", "could not be read"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not mention %q:\n%s", want, out)
		}
	}
}

// Nothing skipped prints nothing: a line saying "0 files were skipped"
// on every clean run is a line people stop reading.
func TestNothingIsSaidWhenNothingWasSkipped(t *testing.T) {
	buf := captureStdout(t)
	printSkipped(nil, "text")
	if buf.String() != "" {
		t.Errorf("printed %q for an empty list", buf.String())
	}
}

// A readable file beside an unreadable one is still scanned.
func TestASkippedFileDoesNotStopTheRest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.env"), []byte{0, '\n'}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.env"), []byte("OPENAI_API_KEY="+tOpenAI+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hits, scanned, skips, err := scanPaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Errorf("%d findings, want 1 from the readable file", len(hits))
	}
	if scanned != 1 {
		t.Errorf("scanned = %d, want 1", scanned)
	}
	if len(skips) != 1 {
		t.Errorf("%d skipped, want 1", len(skips))
	}
}
