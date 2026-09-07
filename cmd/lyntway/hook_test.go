package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
