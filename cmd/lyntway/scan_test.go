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
// Bodies are varied rather than padded with a run of zeros.
//
// notAPlaceholderKey refuses eight of one character in a row, because
// npm_example0000000000000000 and hf_xxxxxxxxxxxxxxxx are what a README
// contains and a random key never is. These fixtures were padded exactly
// that way, so every one of them stopped being a credential the moment
// that check existed — a fixture that does not look like the thing it
// stands for tests the wrong code. The distinctive tails are kept,
// because the tests assert on them as last4.
const (
	tOpenAI    = "sk-proj-Qx7bR9mKp2Wv4Nc8Td1Ys6Hf3Jg0LuABCD"
	tAnthropic = "sk-ant-api03-Qx7bR9mKp2Wv4Nc8Td1YsWXYZ"
	tGemini    = "AIzaSyQx7bR9mKp2Wv4Nc8Td1Ys6Hf3JgQRST"
	tXAI       = "xai-Qx7bR9mKp2Wv4Nc8Td1Ys6Hf3JgEFGH"
	tMistral   = "mistralQx7bR9mKp2Wv4NcMNOP"
	tGitHub    = "ghp_Qx7bR9mKp2Wv4Nc8Td1Ys6Hf3Jg0Lu5AeIJKL"
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
		// "Google API key", not "Gemini key": Google issues one key shape
		// for Gemini, Maps and everything else, so the label says what
		// the value is while the upstream says where the gateway would
		// hold it. Those are different facts and the row carries both.
		{4, "Google API key", "QRST", "gemini"},
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
	// Neither may produce a finding. A binary may be *named* — since
	// 2 November 2026 a file nothing opened is reported as unread, so
	// "no finding here" cannot be mistaken for "nothing is here" — so
	// what is asserted is the absence of an ::error for them, not the
	// absence of the name.
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "::error") {
			continue
		}
		if strings.Contains(line, "node_modules") || strings.Contains(line, "blob.bin") {
			t.Errorf("node_modules or a binary was scanned:\n%s", line)
		}
	}
	if !strings.Contains(out, "::warning file=") || !strings.Contains(out, "blob.bin") {
		t.Errorf("the binary was passed over without being named:\n%s", out)
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
		"b/config.yml:34 Google API key …QRST",
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

// `lyntway scan --staged` is documented in three places and must exist.
//
// skill.md lists it, plugin/skills/lyntway/SKILL.md puts it in the
// decision table an agent reads, and plugin/commands/lyntway-scan.md tells
// the agent to add it. The flag was never defined, so flag.ExitOnError
// turned all three into "flag provided but not defined: -staged" and exit
// 2. documented_commands_test.go checks subcommand names only, so it could
// not see a missing flag.
func TestScanStagedScansTheIndex(t *testing.T) {
	// `scan --staged` asks git what is in the index; without git there is
	// no feature to test rather than a feature that is broken. The image
	// the deploy builds its tests in has no git, and a hard failure there
	// said this flag was broken when it was not.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH, and --staged is git asking git")
	}

	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")

	// Committed, so it is not part of what is about to be committed.
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "ok.txt")
	git("-c", "commit.gpgsign=false", "commit", "-qm", "first")

	// Staged, and carrying a key.
	secret := "sk" + "-ant-" + strings.Repeat("y", 40)
	if err := os.WriteFile(filepath.Join(dir, "env.txt"), []byte("ANTHROPIC_API_KEY="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "env.txt")

	hits, _, err := scanStaged(dir)
	if err != nil {
		t.Fatalf("scanStaged: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("a staged key was not found, so --staged cannot gate a commit")
	}

	// And the working tree alone is not what it reads: an unstaged key is
	// not about to be committed.
	if err := os.WriteFile(filepath.Join(dir, "later.txt"), []byte("OPENAI_API_KEY=sk-proj-"+strings.Repeat("z", 48)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, _, err := scanStaged(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(hits) {
		t.Errorf("an unstaged file changed the staged result: %d then %d", len(hits), len(after))
	}
}

// A key inside a secret scanner's own configuration is the repository
// saying it is a fixture. Counting those was how `lyntway scan` greeted a
// developer in this very repository with 73 findings whose top five were
// all .gitleaks.toml allowlist lines — a first screen that is mostly wrong
// is a tool nobody runs twice.
//
// Not skipped, though, and this test pins both halves. Skipping would make
// "add it to the gitleaks allowlist" a way to silence this scanner, which
// is the one move that must never work.
func TestScanDoesNotCountWhatAScannerConfigDeclares(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".gitleaks.toml", "[allowlist]\nregexes = [\n  '''"+tOpenAI+"''',\n]\n")
	write(".env", "OPENAI_API_KEY="+tOpenAI+"\n")

	var err error
	out := capture(t, "", func() { err = scanCommand([]string{dir}) })

	// The .env key is the finding, and it is the only one counted.
	var findings *scanFindings
	if !errors.As(err, &findings) || findings.n != 1 {
		t.Fatalf("got err %v, want exactly one finding — the .env key", err)
	}
	if !strings.Contains(out, "1 value in a secret scanner's own configuration, not counted above") {
		t.Errorf("the allowlist value should still be reported, below the findings:\n%s", out)
	}
	if !strings.Contains(out, ".gitleaks.toml is a gitleaks allowlist") {
		t.Errorf("the output should name the file and what it is:\n%s", out)
	}
	if !strings.Contains(out, "it is still a real key") {
		t.Errorf("the output must not vouch for the claim it is repeating:\n%s", out)
	}
	assertNoValue(t, out)

	// A tree whose only keys are declared exits zero: a gitleaks allowlist
	// must not fail somebody's CI for ever.
	if err := os.Remove(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}
	out = capture(t, "", func() { err = scanCommand([]string{dir}) })
	if err != nil {
		t.Errorf("a tree with only declared values should exit zero, got %v\n%s", err, out)
	}
	if !strings.Contains(out, "No provider keys in") {
		t.Errorf("want a clean result with the declared value noted:\n%s", out)
	}
	if !strings.Contains(out, "not counted above") {
		t.Errorf("the declared value should still be listed on a clean scan:\n%s", out)
	}
}

// The GitHub Action scans a diff, and a pull request that adds one fixture
// to .gitleaks.toml must not fail it. The walk and the diff reader find
// keys by two different routes, and only the walk knew about scanner
// configurations — so the check passed locally and failed in CI, which is
// the worst place for the two to disagree.
func TestScanDiffDoesNotCountWhatAScannerConfigDeclares(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	// The deploy's image build re-runs this suite as root with no global
	// git configuration, so identity and config come from the environment
	// rather than from whatever the host happens to have.
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
	git("init", "-q")
	write("README.md", "start\n")
	git("add", "-A")
	git("commit", "-qm", "first")

	write(".gitleaks.toml", "[allowlist]\nregexes = [\n  '''"+tOpenAI+"''',\n]\n")
	git("add", "-A")
	git("commit", "-qm", "allowlist a fixture")

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	var scanErr error
	out := capture(t, "", func() { scanErr = scanCommand([]string{"--diff", "HEAD~1"}) })
	if scanErr != nil {
		t.Errorf("adding a fixture to a gitleaks allowlist should not fail the check, got %v\n%s", scanErr, out)
	}
	if !strings.Contains(out, "not counted above") {
		t.Errorf("the added value should still be reported:\n%s", out)
	}
	assertNoValue(t, out)
}
