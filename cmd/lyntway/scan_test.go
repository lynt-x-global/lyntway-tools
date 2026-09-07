package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Values used by the tests. Every test that prints ends by asserting none
// of these reached the output: last4 is what a person sees.
const (
	tOpenAI    = "sk-proj-openai00000000000000ABCD"
	tAnthropic = "sk-ant-api03-anthropic00000000WXYZ"
	tGemini    = "AIzaSyGemini000000000000000000000QRST"
	tXAI       = "xai-xai000000000000000000000000EFGH"
	tMistral   = "mistral0000000000000MNOP"
	tGitHub    = "ghp_github000000000000000000000000000IJKL"
	tPEM       = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGx0000000000000000000000000000000000000\n-----END PRIVATE KEY-----"
)

func assertNoValue(t *testing.T, out string) {
	t.Helper()
	for _, v := range []string{tOpenAI, tAnthropic, tGemini, tXAI, tMistral, tGitHub, "MC4CAQAwBQYDK2VwBCIEIGx"} {
		if strings.Contains(out, v) {
			t.Errorf("a key value reached the output:\n%s", out)
		}
	}
}

func TestFindKeysNamesTheProviderAndKeepsTheValue(t *testing.T) {
	text := strings.Join([]string{
		"# settings",                // 1
		"OPENAI_API_KEY=" + tOpenAI, // 2
		"the anthropic one is " + tAnthropic + " for now",  // 3
		"GOOGLE_KEY=" + tGemini,                            // 4
		"curl -H 'Authorization: Bearer " + tXAI + "'",     // 5
		"MISTRAL_API_KEY=" + tMistral,                      // 6
		"token: " + tGitHub,                                // 7
		tPEM,                                               // 8-10
		"OPENAI_API_KEY=sk-your-key-here-xxxxxxxxxxxxxxxx", // 11: placeholder
		"OPENAI_API_KEY=" + tOpenAI + " # " + allowMarker,  // 12: marked
		"ANTHROPIC_API_KEY=" + tAnthropic,                  // 13: name and shape agree — one hit, not two
	}, "\n")

	hits := findKeys(text, 1)
	want := []struct {
		line     int
		label    string
		last4    string
		upstream string
	}{
		{2, "OpenAI key", "ABCD", "openai"},
		{3, "Anthropic key", "WXYZ", "anthropic"},
		{4, "Gemini key", "QRST", "gemini"},
		{5, "xAI key", "EFGH", "xai"},
		{6, "Mistral key", "MNOP", "mistral"},
		{7, "GitHub token", "IJKL", ""},
		{8, "Private key", "----", ""},
		{13, "Anthropic key", "WXYZ", "anthropic"},
	}
	if len(hits) != len(want) {
		t.Fatalf("got %d hits, want %d:\n%+v", len(hits), len(want), hits)
	}
	for i, w := range want {
		h := hits[i]
		if h.Line != w.line || h.Label != w.label || h.Last4 != w.last4 || h.Upstream != w.upstream {
			t.Errorf("hit %d: got line %d %q …%s upstream %q, want line %d %q …%s upstream %q",
				i, h.Line, h.Label, h.Last4, h.Upstream, w.line, w.label, w.last4, w.upstream)
		}
		assertNoValue(t, h.Label+h.Class+h.Last4+h.File)
	}
}

func TestFindKeysOffsetsLinesForAHunk(t *testing.T) {
	hits := findKeys("x\nOPENAI_API_KEY="+tOpenAI, 40)
	if len(hits) != 1 || hits[0].Line != 41 {
		t.Fatalf("got %+v, want one hit at line 41", hits)
	}
}

func TestParseDiffReadsAddedLinesAtTheirNewNumbers(t *testing.T) {
	diff := strings.Join([]string{
		"diff --git a/.env b/.env",
		"--- a/.env",
		"+++ b/.env",
		"@@ -3,0 +4,2 @@ DATABASE_URL=x",
		"+OPENAI_API_KEY=" + tOpenAI,
		"+DEBUG=1",
		"@@ -10 +12 @@",
		"-OLD=1",
		"+NEW=1",
		"diff --git a/src/deploy.sh b/src/deploy.sh",
		"--- a/src/deploy.sh",
		"+++ b/src/deploy.sh",
		"@@ -20,0 +21,4 @@",
		"+cat > key.pem <<EOF",
		"+" + strings.ReplaceAll(tPEM, "\n", "\n+"),
		"\\ No newline at end of file",
	}, "\n")

	hits, added := parseDiff([]byte(diff))
	if added != 7 {
		t.Errorf("counted %d added lines, want 7", added)
	}
	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2: %+v", len(hits), hits)
	}
	if hits[0].File != ".env" || hits[0].Line != 4 || hits[0].Label != "OpenAI key" {
		t.Errorf("first hit: %+v", hits[0])
	}
	// The PEM is three added lines in one hunk; scanned together, the
	// block rule finds it, at the line its header is on.
	if hits[1].File != "src/deploy.sh" || hits[1].Line != 22 || hits[1].Label != "Private key" {
		t.Errorf("second hit: %+v", hits[1])
	}
}

func TestScanCommandAnnotatesAndExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md", "Nothing to see.\n")
	write(".env", "PORT=3000\nOPENAI_API_KEY="+tOpenAI+"\n")
	// Assembled at run time: a token-shaped literal in a test file trips
	// GitHub's push protection on the public mirror, and this test exists
	// to prove the scanner finds exactly such a shape.
	write("notes.txt", "slack, maybe: "+"xoxb"+"-000000000000-slacktoken0000\n")
	write("blob.bin", "\x00\x01"+tGitHub)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join("node_modules", "x", "index.js"), "const k = '"+tAnthropic+"'\n")

	var err error
	out := capture(t, "", func() { err = scanCommand([]string{"--format", "github", dir}) })

	var findings *scanFindings
	if !errors.As(err, &findings) || findings.n != 2 {
		t.Fatalf("got err %v, want two findings", err)
	}
	envPath := filepath.ToSlash(filepath.Join(dir, ".env"))
	if !strings.Contains(out, "::error file="+envPath+",line=2,title=OpenAI key in source::OpenAI key ending …ABCD.") {
		t.Errorf("no annotation for the .env key:\n%s", out)
	}
	if !strings.Contains(out, "Slack token ending …0000") {
		t.Errorf("no annotation for the slack token:\n%s", out)
	}
	if strings.Contains(out, "node_modules") || strings.Contains(out, "blob.bin") {
		t.Errorf("node_modules or a binary was scanned:\n%s", out)
	}
	if !strings.Contains(out, "lyntway keys migrate") {
		t.Errorf("the advice should name keys migrate for a provider key:\n%s", out)
	}
	assertNoValue(t, out)

	// Text format, on a clean tree: exit 0 and a count of what was read.
	out = capture(t, "", func() { err = scanCommand([]string{filepath.Join(dir, "README.md")}) })
	if err != nil || !strings.Contains(out, "No provider keys in 1 file.") {
		t.Errorf("clean scan: err %v, out %q", err, out)
	}

	out = capture(t, "", func() { err = scanCommand([]string{filepath.Join(dir, ".env")}) })
	if err == nil || !strings.Contains(out, envPath+":2\tOpenAI key\t…ABCD") {
		t.Errorf("text format: err %v, out %q", err, out)
	}
	assertNoValue(t, out)
}

// The first build of findKeys panicked on any match that sat on the last
// line of what it was given — which, for a diff scanned hunk by hunk, is
// most keys: a line added to a .env is usually the last line of its hunk.
// The GitHub Action found it on its first real pull request.
func TestFindKeysOnTheLastLineOfAHunkDoesNotPanic(t *testing.T) {
	diff := strings.Join([]string{
		"diff --git a/a/.env b/a/.env",
		"--- a/a/.env",
		"+++ b/a/.env",
		"@@ -1 +1 @@",
		"-OPENAI_API_KEY=",
		"+OPENAI_API_KEY=" + tOpenAI,
		"diff --git a/b/config.yml b/b/config.yml",
		"--- a/b/config.yml",
		"+++ b/b/config.yml",
		"@@ -7,0 +8,3 @@",
		"+github:",
		"+  token: " + tGitHub,
		"+  org: acme",
		"@@ -30,0 +34 @@",
		"+  gemini: " + tGemini,
	}, "\n")
	hits, _ := parseDiff([]byte(diff))
	var got []string
	for _, h := range hits {
		got = append(got, fmt.Sprintf("%s:%d %s …%s", h.File, h.Line, h.Label, h.Last4))
	}
	want := []string{
		"a/.env:1 OpenAI key …ABCD",
		"b/config.yml:9 GitHub token …IJKL",
		"b/config.yml:34 Gemini key …QRST",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v\nwant %v", got, want)
	}
	// And a one-line text, which is the same case without a diff around it.
	if hits := findKeys(tOpenAI, 1); len(hits) != 1 || hits[0].Line != 1 {
		t.Errorf("single line: %+v", hits)
	}
}

func TestGitHubAnnotationEscapesWhatWouldBreakIt(t *testing.T) {
	h := keyHit{File: "a,b:c\n.env", Line: 3, Label: "OpenAI key", Last4: "AB%D", Upstream: "openai"}
	got := githubAnnotation(h)
	if strings.Count(got, "\n") != 0 {
		t.Errorf("a newline survived: %q", got)
	}
	if !strings.HasPrefix(got, "::error file=a%2Cb%3Ac%0A.env,line=3,title=OpenAI key in source::") {
		t.Errorf("properties not escaped: %q", got)
	}
	if !strings.Contains(got, "…AB%25D.") {
		t.Errorf("message not escaped: %q", got)
	}
}

// git is what --diff reads, and its output is what parseDiff parses, so
// the seam between the two is exercised on a real repository: a key on
// the base branch is not a finding, a key that main removed after the
// branch was cut is not a finding, and a key added — committed or not —
// is one.
func TestScanDiffReportsOnlyWhatTheBranchAdded(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	git("init", "-q", "-b", "main")
	write("old.env", "OPENAI_API_KEY="+tOpenAI+"\n") // on the base: not this branch's doing
	write("app.txt", "hello\n")
	git("add", ".")
	git("commit", "-q", "-m", "base")

	git("checkout", "-q", "-b", "feature")
	write("new.env", "PORT=1\nANTHROPIC_API_KEY="+tAnthropic+"\n")
	git("add", ".")
	git("commit", "-q", "-m", "adds a key")

	// main moves on and removes its key. A two-dot diff from the branch
	// would show that removal reversed, as an addition here.
	git("checkout", "-q", "main")
	write("old.env", "OPENAI_API_KEY=\n")
	git("commit", "-q", "-am", "main rotates")
	git("checkout", "-q", "feature")
	write("app.txt", "hello\n"+tGitHub+"\n") // uncommitted, also counts

	hits, added, err := scanDiff(dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	if added == 0 {
		t.Error("no added lines counted")
	}
	var got []string
	for _, h := range hits {
		got = append(got, h.File+":"+h.Label)
		assertNoValue(t, h.File+h.Label+h.Last4)
	}
	want := "app.txt:GitHub token new.env:Anthropic key"
	if strings.Join(got, " ") != want {
		t.Errorf("got %v, want %q", got, want)
	}

	if _, _, err := scanDiff(dir, "no-such-branch"); err == nil || !strings.Contains(err.Error(), "git:") {
		t.Errorf("an unknown revision should surface git's message, got %v", err)
	}

	// The Action's exact invocation, in both flag forms, from the
	// repository's directory.
	t.Chdir(dir)
	for _, args := range [][]string{
		{"--diff", "main", "--format", "github"},
		{"--diff=main", "--format=github"},
		{"--format", "github", "--diff", "main"},
	} {
		var err error
		out := capture(t, "", func() { err = scanCommand(args) })
		var findings *scanFindings
		if !errors.As(err, &findings) || findings.n != 2 {
			t.Errorf("%v: err %v, want two findings:\n%s", args, err, out)
		}
		if !strings.Contains(out, "::error file=new.env,line=2,title=Anthropic key in source::") || !strings.Contains(out, "::error file=app.txt,line=2,") {
			t.Errorf("%v: annotations missing:\n%s", args, out)
		}
		assertNoValue(t, out)
	}
}
