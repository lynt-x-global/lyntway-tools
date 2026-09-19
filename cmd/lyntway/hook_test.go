package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func hookJSON(prompt string) string {
	b, _ := json.Marshal(map[string]any{
		"session_id": "abc", "cwd": "/tmp/x", "hook_event_name": "UserPromptSubmit", "prompt": prompt,
	})
	return string(b)
}

func TestCheckPromptRefusesAKeyAndSaysItWasNotSent(t *testing.T) {
	cases := []struct {
		prompt string
		want   string // "" means allowed
	}{
		{"fix the failing test in parser.go", ""},
		{"here is my key " + tOpenAI + " please use it", "That looks like an OpenAI key (…ABCD). It was not sent. Store it with `lyntway keys migrate` or paste a Lyntway key instead."},
		{"ANTHROPIC_API_KEY=" + tAnthropic, "That looks like an Anthropic key (…WXYZ). It was not sent. Store it with `lyntway keys migrate` or paste a Lyntway key instead."},
		{"use " + tGitHub + " to push", "That looks like a GitHub token (…IJKL). It was not sent. Take it out of the prompt and send the rest."},
		{"my cert:\n" + tPEM, "That looks like a private key. It was not sent. Take it out of the prompt and send the rest."},
		{tOpenAI + " and " + tGitHub, "That looks like an OpenAI key (…ABCD). 1 more found. It was not sent. Store it with `lyntway keys migrate` or paste a Lyntway key instead."},
		{"example: OPENAI_API_KEY=sk-your-key-here-xxxxxxxxxxxxx", ""},
	}
	for _, c := range cases {
		got, err := checkPrompt(strings.NewReader(hookJSON(c.prompt)))
		if err != nil {
			t.Fatalf("%q: %v", c.prompt, err)
		}
		if got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.prompt, got, c.want)
		}
		assertNoValue(t, got)
	}

	if _, err := checkPrompt(strings.NewReader("not json")); err == nil {
		t.Error("unreadable input should be an error, so the editor reports a broken hook rather than a silent one")
	}
}

func TestHookPromptAnswersEachEditorInItsOwnContract(t *testing.T) {
	var code = -1
	prev := exit
	exit = func(c int) { code = c }
	defer func() { exit = prev }()

	// Claude Code: exit 2 blocks and discards; nothing on stdout.
	out := capture(t, hookJSON("key: "+tOpenAI), func() {
		if err := hookPromptCommand(nil); err != nil {
			t.Fatal(err)
		}
	})
	if code != 2 || out != "" {
		t.Errorf("Claude Code: exit %d, stdout %q; want exit 2 and nothing on stdout", code, out)
	}

	code = -1
	out = capture(t, hookJSON("plain"), func() {
		if err := hookPromptCommand(nil); err != nil {
			t.Fatal(err)
		}
	})
	if code != -1 || out != "" {
		t.Errorf("a clean prompt must exit 0 silently: exit %d, stdout %q", code, out)
	}

	// Cursor: the answer is JSON, and the exit status is not used.
	code = -1
	out = capture(t, hookJSON("key: "+tOpenAI), func() {
		if err := hookPromptCommand([]string{"--cursor"}); err != nil {
			t.Fatal(err)
		}
	})
	var answer struct {
		Continue    bool   `json:"continue"`
		UserMessage string `json:"user_message"`
	}
	if err := json.Unmarshal([]byte(out), &answer); err != nil || answer.Continue || !strings.Contains(answer.UserMessage, "It was not sent") {
		t.Errorf("Cursor block: %q (%v)", out, err)
	}
	if code != -1 {
		t.Errorf("Cursor must not be answered with an exit status: %d", code)
	}
	assertNoValue(t, out)

	out = capture(t, hookJSON("plain"), func() { _ = hookPromptCommand([]string{"--cursor"}) })
	if strings.TrimSpace(out) != `{"continue":true}` {
		t.Errorf("Cursor allow: %q", out)
	}
}

func TestHookInstallKeepsWhatWasThereAndUninstallTakesOnlyOurs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := `{
  "model": "opus",
  "mcpServers": {"db": {"command": "db-mcp"}},
  "hooks": {
    "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "theirs.sh"}]}],
    "Stop": [{"hooks": [{"type": "command", "command": "notify.sh"}]}]
  }
}
`
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, saved, err := writeHook(path, false)
	if err != nil || !changed {
		t.Fatalf("install: changed=%v err=%v", changed, err)
	}
	if !strings.Contains(filepath.Base(saved), hookBackupSuffix) {
		t.Errorf("backup %q should carry the hook suffix, so init's undo does not restore it", saved)
	}
	if body, _ := os.ReadFile(saved); string(body) != original {
		t.Error("the backup is not the original")
	}
	// A hook backup must not be what `undo` restores for the MCP wrapping.
	if m, _ := filepath.Glob(path + ".lyntway-backup-*"); len(m) != 0 {
		t.Errorf("the hook backup is visible to restore(): %v", m)
	}

	var doc struct {
		Model      string          `json:"model"`
		MCPServers json.RawMessage `json:"mcpServers"`
		Hooks      map[string][]struct {
			Hooks []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
				Timeout int    `json:"timeout"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	read := func() {
		t.Helper()
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		doc.Hooks = nil
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("settings.json is no longer JSON: %v\n%s", err, body)
		}
	}
	read()
	if doc.Model != "opus" || !strings.Contains(string(doc.MCPServers), "db-mcp") {
		t.Error("something other than hooks was changed")
	}
	if len(doc.Hooks["Stop"]) != 1 || len(doc.Hooks["UserPromptSubmit"]) != 2 {
		t.Fatalf("hooks: %+v", doc.Hooks)
	}
	ours := doc.Hooks["UserPromptSubmit"][1].Hooks[0]
	if ours.Type != "command" || !strings.HasSuffix(ours.Command, " hook prompt") || !filepath.IsAbs(strings.Trim(strings.TrimSuffix(ours.Command, " hook prompt"), `"`)) || ours.Timeout == 0 {
		t.Errorf("our entry: %+v", ours)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Errorf("the file's mode changed to %o", info.Mode().Perm())
	}

	if changed, _, err := writeHook(path, false); err != nil || changed {
		t.Errorf("a second install should change nothing: changed=%v err=%v", changed, err)
	}

	removed, err := removeHook(path, false, true)
	if err != nil || !removed {
		t.Fatalf("uninstall: removed=%v err=%v", removed, err)
	}
	read()
	if len(doc.Hooks["UserPromptSubmit"]) != 1 || doc.Hooks["UserPromptSubmit"][0].Hooks[0].Command != "theirs.sh" || len(doc.Hooks["Stop"]) != 1 {
		t.Errorf("uninstall took the wrong thing: %+v", doc.Hooks)
	}
	if removed, _ := removeHook(path, false, true); removed {
		t.Error("nothing left to remove")
	}
}

func TestHookInstallCreatesTheFileAndLeavesNoEmptyKeys(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Cursor, from nothing: the file is created with its version field.
	path := cursorHooksFile()
	if _, saved, err := writeHook(path, true); err != nil || saved != "" {
		t.Fatalf("create: saved=%q err=%v", saved, err)
	}
	body, _ := os.ReadFile(path)
	var doc struct {
		Version int `json:"version"`
		Hooks   map[string][]struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Version != 1 {
		t.Fatalf("cursor file: %s (%v)", body, err)
	}
	if got := doc.Hooks["beforeSubmitPrompt"]; len(got) != 1 || !strings.HasSuffix(got[0].Command, " hook prompt --cursor") {
		t.Errorf("cursor entry: %+v", doc.Hooks)
	}

	// Removing the only entry leaves no empty "hooks" behind.
	if removed, err := removeHook(path, true, false); err != nil || !removed {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(path)
	if strings.Contains(string(body), "hooks") {
		t.Errorf("an empty hooks object was left: %s", body)
	}

	// undo reaches both editors.
	if _, _, err := writeHook(claudeHooksFile(), false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeHook(path, true); err != nil {
		t.Fatal(err)
	}
	out := capture(t, "", func() {
		if n := removeHooksEverywhere(); n != 2 {
			t.Errorf("undo removed %d hooks, want 2", n)
		}
	})
	if strings.Count(out, "hook removed") != 2 {
		t.Errorf("undo output: %q", out)
	}

	// A file that is not a JSON object is refused, not overwritten.
	if err := os.WriteFile(path, []byte("[1,2]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeHook(path, true); err == nil {
		t.Error("an array should be refused")
	}
	if body, _ := os.ReadFile(path); string(body) != "[1,2]" {
		t.Error("the refused file was changed")
	}
}

func TestHookInstallAsksFirst(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	out := capture(t, "n\n", func() {
		if err := hookInstall(nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "sends nothing anywhere") || !strings.Contains(out, "Nothing was changed.") {
		t.Errorf("output: %q", out)
	}
	if exists(claudeHooksFile()) {
		t.Error("a file was written after the person said no")
	}

	out = capture(t, "y\n", func() {
		if err := hookInstall(nil); err != nil {
			t.Fatal(err)
		}
	})
	if !exists(claudeHooksFile()) || !strings.Contains(out, "✓") {
		t.Errorf("not installed after yes: %q", out)
	}
}

func TestGitHookInstallAndUninstall(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Install into an empty hooks directory.
	if err := writeGitHook(gitDir); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	body, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "#!/bin/sh") {
		t.Error("the shebang is missing")
	}
	if !strings.Contains(text, gitHookStart) || !strings.Contains(text, gitHookEnd) {
		t.Error("the lyntway block markers are missing")
	}
	if !strings.Contains(text, "lyntway scan") {
		t.Error("the scan command is missing from the hook")
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(hookPath); info.Mode().Perm()&0o100 == 0 {
			t.Error("the hook is not executable")
		}
	}

	// Idempotent: a second install changes nothing.
	if err := writeGitHook(gitDir); err != nil {
		t.Fatal(err)
	}
	body2, _ := os.ReadFile(hookPath)
	if string(body2) != text {
		t.Error("a second install changed the file")
	}

	// Uninstall removes the block and the file (only shebang remains).
	removed, err := removeGitHook(gitDir)
	if err != nil || !removed {
		t.Fatalf("uninstall: removed=%v err=%v", removed, err)
	}
	if exists(hookPath) {
		t.Error("the file should be removed when only the shebang remains")
	}

	// Uninstall on a missing file is a no-op.
	removed, err = removeGitHook(gitDir)
	if err != nil || removed {
		t.Errorf("second uninstall: removed=%v err=%v", removed, err)
	}
}

func TestGitHookPreservesExistingHooks(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")

	// An existing hook with content should be preserved.
	existing := "#!/bin/sh\necho 'existing hook'\n"
	if err := os.WriteFile(hookPath, []byte(existing), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := writeGitHook(gitDir); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(hookPath)
	text := string(body)
	if !strings.Contains(text, "echo 'existing hook'") {
		t.Error("the existing hook content was lost")
	}
	if !strings.Contains(text, gitHookStart) {
		t.Error("the lyntway block was not appended")
	}

	// Uninstall removes only our block, leaving the original.
	removed, err := removeGitHook(gitDir)
	if err != nil || !removed {
		t.Fatalf("uninstall: removed=%v err=%v", removed, err)
	}
	body, _ = os.ReadFile(hookPath)
	text = string(body)
	if !strings.Contains(text, "echo 'existing hook'") {
		t.Error("uninstall removed the existing hook content")
	}
	if strings.Contains(text, gitHookStart) {
		t.Error("the lyntway block was not removed")
	}
}

func TestFindGitDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// No .git anywhere: not found.
	if got := findGitDir(sub); got != "" {
		t.Errorf("found %q in a tree with no .git", got)
	}
	// Create .git at the root.
	gitDir := filepath.Join(dir, ".git")
	if err := os.Mkdir(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	got := findGitDir(sub)
	if got == "" {
		t.Fatal("findGitDir returned empty for a subdirectory of a git repo")
	}
	// Normalise for comparison on Windows.
	want, _ := filepath.Abs(gitDir)
	got2, _ := filepath.Abs(got)
	if got2 != want {
		t.Errorf("findGitDir = %q, want %q", got2, want)
	}
}

func TestGitHookInstalledReportsCorrectly(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if gitHookInstalled(gitDir) {
		t.Error("should report not installed before writeGitHook")
	}
	if err := writeGitHook(gitDir); err != nil {
		t.Fatal(err)
	}
	if !gitHookInstalled(gitDir) {
		t.Error("should report installed after writeGitHook")
	}
}

// A .env in a directory whose name has a space must still be scanned.
//
// The block interpolated the file list unquoted, so the shell split
// "My Project/.env" into "My" and "Project/.env". The scanner was handed
// two paths that do not exist, failed to stat the first, and exited
// non-zero — which blocked the commit, so the hook looked like it worked.
// It had not scanned anything. The key went unexamined and the developer
// got "stat My: no such file or directory", which reads like a broken
// hook and invites them to remove it.
//
// Windows makes this the common case rather than the awkward one:
// C:\Users\Your Name\project is where a default install puts things, and
// P10.2 of the acceptance protocol asks exactly this question.
func TestTheGitHookScansPathsThatContainSpaces(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on this machine")
	}
	dir := t.TempDir()

	// A stub on PATH that records the arguments it was handed, so the test
	// observes what the shell actually passed rather than trusting the
	// block's text.
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(dir, "args.txt")
	stub := "#!/bin/sh\nshift\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + shellQuote(record) + "; done\nexit 0\n"
	if err := os.WriteFile(filepath.Join(binDir, "lyntway"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}

	script := filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+gitHookBlock+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Stand in for `git diff --cached`, which the block calls to list what
	// is staged. One path with a space is the whole point.
	gitStub := "#!/bin/sh\nprintf '%s\\n' 'My Project/.env'\n"
	if err := os.WriteFile(filepath.Join(binDir, "git"), []byte(gitStub), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, _ := cmd.CombinedOutput()

	got, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the scanner was never called at all: %v\noutput: %s", err, out)
	}
	args := strings.Split(strings.TrimSpace(string(got)), "\n")
	if len(args) != 1 || args[0] != "My Project/.env" {
		t.Errorf("the scanner was handed %q, want exactly [\"My Project/.env\"].\n"+
			"An unquoted expansion split the path, so the file was never scanned.", args)
	}
}

// shellQuote wraps a path for safe interpolation into the test's stub.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
