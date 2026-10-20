package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The one rule this file exists to keep: nothing written here may ever be
// the reason somebody's tool will not start.
//
// An alias would be. `alias claude='lyntway guard -- claude'` breaks
// `claude` completely the day lyntway is uninstalled, moved, or absent
// from a shell with a different PATH — and the person is left with a tool
// that does not run and no reason given. A function that falls through
// degrades to exactly what they had before.

func TestTheWrapperNeverStopsTheToolStarting(t *testing.T) {
	block := guardAliasBlock("zsh", []string{"claude"})

	if strings.Contains(block, "alias claude=") {
		t.Fatal("written as an alias: if lyntway goes missing, claude stops working and nothing says why")
	}
	if !strings.Contains(block, "command -v lyntway") {
		t.Error("the wrapper does not check we are present before using us")
	}
	if !strings.Contains(block, `command claude "$@"`) {
		t.Error("no fall-through to the real command when we are absent")
	}
	// The inner call must be the bare command: guard resolves it with
	// exec.LookPath against PATH, so no shell is involved and the function
	// cannot re-enter itself.
	if !strings.Contains(block, `lyntway guard -- claude "$@"`) {
		t.Error("the governed path does not pass the caller's arguments through")
	}
}

func TestTheFishWrapperUsesFishSyntax(t *testing.T) {
	block := guardAliasBlock("fish", []string{"codex"})
	for _, want := range []string{"function codex", "$argv", "end"} {
		if !strings.Contains(block, want) {
			t.Errorf("fish block has no %q:\n%s", want, block)
		}
	}
	if strings.Contains(block, `"$@"`) {
		t.Error("fish block carries POSIX argument syntax, which fish does not read")
	}
}

// A shell profile may be the most personal file on somebody's machine.
// Everything outside our fence comes back byte for byte.
func TestRemovingTheBlockLeavesEverythingElseUntouched(t *testing.T) {
	before := "export PATH=$PATH:/opt/bin\nalias ll='ls -la'\n"
	after := "\n# my own notes\nexport EDITOR=vim\n"
	body := before + "\n" + guardAliasBlock("zsh", []string{"claude", "codex"}) + after

	stripped, ok := stripGuardAliasBlock(body)
	if !ok {
		t.Fatal("the block was not found")
	}
	if strings.Contains(stripped, "lyntway guard") {
		t.Error("something of ours was left behind")
	}
	if !strings.Contains(stripped, before) || !strings.Contains(stripped, after) {
		t.Errorf("the user's own lines did not survive:\n%q", stripped)
	}

	// A profile with nothing of ours in it is returned unchanged.
	if out, ok := stripGuardAliasBlock(before); ok || out != before {
		t.Error("a profile with no block was reported as having one")
	}
}

// An opening marker with no closing one means somebody edited inside the
// block, or a write was interrupted. Taking everything to the end of the
// file would delete their work, so this refuses rather than guesses.
func TestAHalfWrittenBlockIsRefusedRatherThanGuessedAt(t *testing.T) {
	body := "export A=1\n" + guardAliasOpen + "\nclaude() { :; }\nexport B=2\n"
	out, ok := stripGuardAliasBlock(body)
	if ok {
		t.Fatal("a block with no closing marker was removed anyway")
	}
	if out != body {
		t.Error("the file was modified despite the refusal")
	}
}

// Install, then uninstall, and the profile is byte-for-byte what it was.
func TestInstallAndUninstallRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	profile := filepath.Join(home, ".zshrc")
	original := "export PATH=$PATH:/opt/bin\nalias ll='ls -la'\n"
	if err := os.WriteFile(profile, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	// Answer yes, and print somewhere the test can read.
	in := strings.NewReader("y\n")
	oldIn, oldOut := stdin, stdout
	var out bytes.Buffer
	stdin, stdout, input, inputFrom = in, &out, nil, nil
	defer func() { stdin, stdout, input, inputFrom = oldIn, oldOut, nil, nil }()

	if err := installGuardAlias(&out); err != nil {
		t.Fatalf("install: %v", err)
	}
	after, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), original) {
		t.Error("the user's own lines did not survive the install")
	}

	// Whether a block was written depends on what is installed on the
	// machine running the test, and that is the honest behaviour: we do
	// not offer to wrap software somebody does not have.
	if !strings.Contains(string(after), guardAliasOpen) {
		if !strings.Contains(out.String(), "Nothing here to wrap") {
			t.Errorf("no block written and no reason given:\n%s", out.String())
		}
		return
	}

	if err := uninstallGuardAlias(&out); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	back, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != original {
		t.Errorf("the profile did not come back as it was:\nwant %q\ngot  %q", original, string(back))
	}

	// And a backup was left beside it either way.
	entries, _ := os.ReadDir(home)
	var backups int
	for _, e := range entries {
		if strings.Contains(e.Name(), ".zshrc") && e.Name() != ".zshrc" {
			backups++
		}
	}
	if backups == 0 {
		t.Error("no backup was written beside the profile")
	}
}

// Offering to wrap software somebody does not have reads as a tool that
// did not look. The list comes off the same table guard itself uses.
func TestOnlyToolsThatReadTheSettingAreOffered(t *testing.T) {
	wrappable := guardableApps()
	if wrappable["Ollama"] {
		t.Error("Ollama is offered for wrapping; a local model server is the proxy's job")
	}
	if !wrappable["Claude Code"] {
		t.Error("Claude Code is not offered, and it is the one this was built for")
	}
	for _, bin := range guardAliasTools() {
		var known bool
		for _, d := range aiApps {
			if len(d.Bins) > 0 && d.Bins[0] == bin && wrappable[d.Name] {
				known = true
			}
		}
		if !known {
			t.Errorf("offered to wrap %q, which is not a tool documented to read a base URL", bin)
		}
	}
}

// The generated block is shell source, and nothing else here checks that a
// shell can read it. A missing `fi`, a stray quote, or an unbalanced brace
// would be written into somebody's profile and break every new terminal
// they opened — including the ones they would need to fix it in.
//
// So the block is sourced by a real shell, twice: once with lyntway
// absent, which must run the tool untouched, and once with it present,
// which must run the tool through guard.
func TestARealShellReadsTheBlockAndTheToolStillRuns(t *testing.T) {
	sh, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on PATH to source the block with")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// A stand-in for the real tool, which reports that it ran.
	stub := "#!/bin/sh\necho \"TOOL RAN: $*\"\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(dir, "profile.sh")
	if err := os.WriteFile(profile, []byte(guardAliasBlock("bash", []string{"claude"})), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(path string) string {
		cmd := exec.Command(sh, "-c", ". "+profile+"; claude --model x")
		cmd.Env = []string{"PATH=" + path, "HOME=" + dir}
		out, _ := cmd.CombinedOutput()
		return string(out)
	}

	// lyntway absent: the tool must run anyway. This is the lockout case.
	withoutUs := run(bin + ":/usr/bin:/bin")
	if !strings.Contains(withoutUs, "TOOL RAN: --model x") {
		t.Fatalf("with lyntway absent the tool did not run — this is the lockout:\n%s", withoutUs)
	}

	// lyntway present: it must go through guard, and the tool must still
	// run with the same arguments.
	lw := filepath.Join(bin, "lyntway")
	build := exec.Command("go", "build", "-o", lw, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("could not build the CLI for the second half: %v\n%s", err, out)
	}
	withUs := run(bin + ":/usr/bin:/bin")
	if !strings.Contains(withUs, "running behind Lyntway") {
		t.Errorf("with lyntway present the call did not go through guard:\n%s", withUs)
	}
	if !strings.Contains(withUs, "TOOL RAN: --model x") {
		t.Errorf("guard did not pass the arguments through to the tool:\n%s", withUs)
	}
}

// `lyntway undo` must not put back what it has just taken out.
//
// Nothing tested undo() at all, and it had this shape: the kindEnv branch
// stripped the `lyntway init` block out of the profile and printed a tick,
// then undoRecorded() two steps later restored the whole profile from the
// backup taken at `guard --install` time. That backup contains the init
// block, so the block came back; it predates everything the person has
// edited since, so those edits were discarded; and the tick was printed
// either way. skill.md promises "the profile comes back byte for byte".
func TestUndoRemovesBothBlocksAndKeepsEverythingElse(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SHELL", "/bin/zsh")

	// guardAliasTools only wraps a tool it can find, and findBinary looks
	// in $HOME/.local/bin among other places. Without this the premise
	// depended on claude, codex or aider happening to be installed on
	// whatever machine ran the test: on a laptop it was, in the image the
	// deploy builds its tests in it was not, and the test then refused to
	// prove nothing — correctly, but by failing the deploy.
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Asserted against a host with nothing on its PATH, because the
	// machine running this test usually has claude both installed and
	// running, and either satisfies the detection for its own reasons.
	// This is the one condition CI has and a laptop does not.
	if found := findBinary(agentHost{GOOS: runtime.GOOS, Root: "/", Home: home}, []string{"claude"}); found == "" {
		t.Fatal("the stub is not where findBinary looks, so on a machine with no coding tool this test would prove nothing again")
	}

	profile := filepath.Join(home, ".zshrc")
	const mine = "export EDITOR=vim\nalias gs='git status'\n"
	if err := os.WriteFile(profile, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}

	// Both blocks, as the two commands write them.
	body := mine + "\n" + markerStart + "\nexport OPENAI_BASE_URL=https://lyntway.example\n" + markerEnd + "\n"
	if err := os.WriteFile(profile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Answer yes, and print where the test can read.
	in := strings.NewReader("y\n")
	oldIn, oldOut := stdin, stdout
	var buf bytes.Buffer
	stdin, stdout, input, inputFrom = in, &buf, nil, nil
	defer func() { stdin, stdout, input, inputFrom = oldIn, oldOut, nil, nil }()

	if err := installGuardAlias(&buf); err != nil {
		t.Fatalf("installing the guard block: %v", err)
	}

	after, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), guardAliasOpen) || !strings.Contains(string(after), markerStart) {
		t.Fatalf("the profile does not hold both blocks, so this test proves nothing:\n%s", after)
	}

	// A line added after the install, which a whole-file restore loses.
	withLater := string(after) + "export LATER=1\n"
	if err := os.WriteFile(profile, []byte(withLater), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := undo(); err != nil {
		t.Fatalf("undo: %v", err)
	}

	final, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	got := string(final)
	if strings.Contains(got, markerStart) {
		t.Errorf("the init block is still there after undo:\n%s", got)
	}
	if strings.Contains(got, guardAliasOpen) {
		t.Errorf("the guard block is still there after undo:\n%s", got)
	}
	if !strings.Contains(got, "export LATER=1") {
		t.Errorf("a line added after the install was discarded:\n%s", got)
	}
	if !strings.Contains(got, "alias gs='git status'") {
		t.Errorf("the person's own lines were discarded:\n%s", got)
	}
}
