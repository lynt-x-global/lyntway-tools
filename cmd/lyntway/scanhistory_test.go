package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A repository with a key added, then deleted from the tip.
//
// This is the shape of nearly every real leak: somebody notices, removes
// the line, commits, and believes it is handled. The files on disk are
// clean from that moment and every scanner that reads only the tip agrees
// with them.
func historyRepo(t *testing.T) string {
	t.Helper()
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
	write("leak.env", "OPENAI_API_KEY="+tOpenAI+"\n")
	git("add", ".")
	git("commit", "-q", "-m", "adds a key")

	// The "fix": delete the file. The key is still in the commit above.
	if err := os.Remove(filepath.Join(dir, "leak.env")); err != nil {
		t.Fatal(err)
	}
	git("commit", "-q", "-am", "remove the key")

	// One that is still on disk, so the two cases can be told apart.
	write("live.env", "GITHUB_TOKEN="+tGitHub+"\n")
	git("add", ".")
	git("commit", "-q", "-m", "a key that is still here")
	return dir
}

// The whole point: a key deleted from the tip is still found.
func TestHistoryFindsAKeyThatIsNoLongerOnDisk(t *testing.T) {
	dir := historyRepo(t)

	// First, the thing that made this necessary: the files on disk no
	// longer carry it.
	treeHits, _, _, err := scanPaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range treeHits {
		if strings.Contains(h.Label, "OpenAI") {
			t.Fatal("the test repository still has the key on disk; it proves nothing")
		}
	}

	found, commits, err := scanHistory(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	// Two, not three: the commit that only deletes adds nothing, and
	// --diff-filter=ACMR drops it from the log entirely. What is counted
	// is commits that added content, which is what the report says.
	if commits < 2 {
		t.Errorf("read %d commits that added content, want at least 2", commits)
	}
	var openai *historyFinding
	for i := range found {
		if strings.Contains(found[i].Label, "OpenAI") {
			openai = &found[i]
		}
	}
	if openai == nil {
		t.Fatalf("the key deleted from the tip was not found in history; got %d findings", len(found))
	}
	if openai.InWorkingTree {
		t.Error("reported as still in the working tree; it was deleted")
	}
	if len(openai.Commits) == 0 {
		t.Fatal("no commit named, so nobody can find where it came from")
	}
}

// A key still on disk is reported as such, because the remedy differs:
// one needs revoking, the other needs revoking and removing.
func TestHistorySaysWhichKeysAreStillOnDisk(t *testing.T) {
	found, _, err := scanHistory(historyRepo(t), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if strings.Contains(f.Label, "GitHub") && !f.InWorkingTree {
			t.Error("a key that is still on disk was reported as history-only")
		}
	}
}

// The ones no longer on disk come first: they are the ones somebody
// believes are already fixed.
func TestHistoryPutsTheInvisibleOnesFirst(t *testing.T) {
	found, _, err := scanHistory(historyRepo(t), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) < 2 {
		t.Skipf("only %d findings; nothing to order", len(found))
	}
	if found[0].InWorkingTree {
		t.Error("a key still on disk was listed above one that only exists in history")
	}
}

// One credential carried through many commits is one finding.
//
// The count is what a person acts on and what they repeat to somebody
// else. `lyntway history` already holds this line; a second scanner that
// multiplied one key by its commit count would undo it.
func TestHistoryCountsOneCredentialOnce(t *testing.T) {
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
	git("init", "-q", "-b", "main")
	// The same key written into TWO new files in each of five commits.
	//
	// Two per commit, not one: with one, a commit list that appended
	// every sighting and one that appended every commit are the same
	// list, and the test cannot tell them apart. Ten sightings across
	// five commits is one credential in five commits, and nothing here
	// may report it as ten.
	for i := 0; i < 5; i++ {
		for _, suffix := range []string{"a", "b"} {
			name := filepath.Join(dir, "copy"+string(rune('a'+i))+suffix+".env")
			if err := os.WriteFile(name, []byte("OPENAI_API_KEY="+tOpenAI+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		git("add", ".")
		git("commit", "-q", "-m", "copy")
	}

	found, _, err := scanHistory(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range found {
		if strings.Contains(f.Label, "OpenAI") {
			n++
			if len(f.Commits) != 5 {
				t.Errorf("the key is in %d commits, want 5 — the commit list is what makes one line enough", len(f.Commits))
			}
		}
	}
	if n != 1 {
		t.Errorf("one key across five commits produced %d findings, want 1", n)
	}
}

// Nothing printed may carry the key itself, in any format.
func TestHistoryNeverPrintsTheKey(t *testing.T) {
	dir := historyRepo(t)
	found, commits, err := scanHistory(dir, "")
	if err != nil {
		t.Fatal(err)
	}

	for _, render := range []struct {
		name string
		run  func()
	}{
		{"text", func() { printHistory(found, commits) }},
		{"json", func() {
			if err := printHistoryJSON(found, commits); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(render.name, func(t *testing.T) {
			buf := captureStdout(t)
			render.run()
			out := buf.String()
			for _, secret := range []string{tOpenAI, tGitHub} {
				if strings.Contains(out, secret) {
					t.Errorf("the %s report printed the key itself", render.name)
				}
			}
			if !strings.Contains(out, "ABCD") {
				t.Errorf("the %s report does not carry last4, so nobody can tell which key to revoke", render.name)
			}
		})
	}
}

// The order of a scan's findings must not depend on which worker
// finished first.
//
// scanPaths reads files on every core since 2 November 2026. A report
// whose lines move between runs cannot be diffed, cannot be pasted into a
// ticket and compared with the next run, and makes any test that asserts
// on a particular finding pass or fail by luck. The walk fixes the order
// and the pool fills a slot per file; this is the assertion that keeps
// that true.
func TestAScanReportsInTheSameOrderEveryTime(t *testing.T) {
	dir := t.TempDir()
	// Enough files, each with a key, that a racing merge would show.
	for i := 0; i < 200; i++ {
		name := filepath.Join(dir, fmt.Sprintf("f%03d.env", i))
		if err := os.WriteFile(name, []byte("OPENAI_API_KEY="+tOpenAI+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var first []string
	for run := 0; run < 5; run++ {
		hits, scanned, _, err := scanPaths([]string{dir})
		if err != nil {
			t.Fatal(err)
		}
		if scanned != 200 {
			t.Fatalf("run %d read %d files, want 200", run, scanned)
		}
		got := make([]string, 0, len(hits))
		for _, h := range hits {
			got = append(got, h.File)
		}
		if run == 0 {
			first = got
			continue
		}
		if len(got) != len(first) {
			t.Fatalf("run %d found %d keys, run 0 found %d", run, len(got), len(first))
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("run %d differs at position %d: %s, run 0 had %s", run, i, got[i], first[i])
			}
		}
	}
}

// The pre-push hook has to see a key that was added and then removed
// before the push.
//
// This is the shape the push guard exists for and the one a tip-to-tip
// diff cannot see: the two tips agree, the key is in a commit between
// them, and it publishes anyway. It is also the likeliest shape in
// practice, because it is what somebody who noticed does.
func TestARangeFindsAKeyAddedAndRemovedWithinIt(t *testing.T) {
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
	write("app.txt", "hello\n")
	git("add", ".")
	git("commit", "-q", "-m", "base")
	base := strings.TrimSpace(gitRead(t, dir, "rev-parse", "HEAD"))

	write("oops.env", "OPENAI_API_KEY="+tOpenAI+"\n")
	git("add", ".")
	git("commit", "-q", "-m", "adds a key")

	if err := os.Remove(filepath.Join(dir, "oops.env")); err != nil {
		t.Fatal(err)
	}
	git("commit", "-q", "-am", "removes it again")

	// What a tip-to-tip diff sees: nothing. Both ends agree.
	diffHits, _, err := scanDiff(dir, base)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range diffHits {
		if strings.Contains(h.Label, "OpenAI") {
			t.Fatal("the diff found it, so this test no longer proves what it says")
		}
	}

	// What the push guard sees.
	found, _, err := scanHistory(dir, base+"..HEAD")
	if err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, f := range found {
		if strings.Contains(f.Label, "OpenAI") {
			ok = true
		}
	}
	if !ok {
		t.Error("a key added and removed inside the pushed range was not found; it would publish")
	}
}

func gitRead(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}
