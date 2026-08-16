package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This edits files a developer depends on. Being able to put them back is
// not a nicety — a tool that can break your editor and cannot unbreak it is
// one nobody should run.
func TestAShellProfileRoundTripsExactly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".zshrc")

	original := "export PATH=/usr/local/bin:$PATH\nalias gs='git status'\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := writeEnv(path, "https://lyntway.example", "lyk_test"); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "OPENAI_BASE_URL") {
		t.Fatal("the base URL was not written")
	}
	if !strings.Contains(string(after), "alias gs='git status'") {
		t.Fatal("the person's own settings were lost")
	}

	// And removing the block leaves exactly what was there before.
	restored := removeBlock(string(after))
	if restored != original {
		t.Errorf("undo did not restore the file exactly.\n got: %q\nwant: %q", restored, original)
	}
}

// Running init twice must not leave two blocks disagreeing about the base
// URL, which would work or not depending on which the shell read last.
func TestRunningTwiceLeavesOneBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".zshrc")
	if err := os.WriteFile(path, []byte("export EDITOR=vim\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if _, err := writeEnv(path, "https://lyntway.example", "lyk_test"); err != nil {
			t.Fatal(err)
		}
	}

	body, _ := os.ReadFile(path)
	if n := strings.Count(string(body), markerStart); n != 1 {
		t.Errorf("found %d blocks, want 1", n)
	}
	if !strings.Contains(string(body), "export EDITOR=vim") {
		t.Error("the person's own settings were lost")
	}
}

// A file that was never touched must be left alone by undo.
func TestUndoLeavesUnrelatedFilesAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".zshrc")
	original := "export EDITOR=vim\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := removeBlock(original); got != original {
		t.Errorf("a file with no block was altered: %q", got)
	}
}

// MCP servers must keep running the same program, just through the shim.
func TestWrappingAnMCPServerPreservesWhatItRuns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude_desktop_config.json")
	original := `{
  "mcpServers": {
    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
               "env": {"GITHUB_TOKEN": "ghp_x"}}
  },
  "somethingElse": {"keep": true}
}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	changed, saved, err := wrapMCP(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0] != "github" {
		t.Fatalf("changed = %v, want [github]", changed)
	}
	if saved == "" {
		t.Fatal("no backup was left")
	}

	body, _ := os.ReadFile(path)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("the config is no longer valid JSON: %v", err)
	}
	if _, kept := doc["somethingElse"]; !kept {
		t.Error("unrelated settings were dropped")
	}

	servers, err := mcpServers(path)
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
	}
	if err := json.Unmarshal(servers["github"], &s); err != nil {
		t.Fatal(err)
	}
	if s.Command != "lyntway-mcp" {
		t.Errorf("command = %q, want lyntway-mcp", s.Command)
	}
	want := []string{"--", "npx", "-y", "@modelcontextprotocol/server-github"}
	if strings.Join(s.Args, " ") != strings.Join(want, " ") {
		t.Errorf("args = %v, want %v", s.Args, want)
	}
	if s.Env["GITHUB_TOKEN"] != "ghp_x" {
		t.Error("the server's own environment was lost, so it will not authenticate")
	}
}

// Wrapping twice would nest the shim inside itself: it would work by
// accident and be impossible to reason about.
func TestAnAlreadyWrappedServerIsLeftAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"github":{
		"command":"lyntway-mcp","args":["--","npx","-y","server"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	changed, _, err := wrapMCP(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 {
		t.Errorf("changed = %v, want nothing", changed)
	}
}

// A config shaped in a way this does not understand is one to leave alone
// rather than guess at.
func TestAnUnfamiliarServerShapeIsNotGuessedAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	// A remote server, with a url rather than a command.
	original := `{"mcpServers":{"hosted":{"url":"https://example.invalid/mcp"}}}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	changed, _, err := wrapMCP(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 {
		t.Errorf("a server with no command was rewritten: %v", changed)
	}
	body, _ := os.ReadFile(path)
	if string(body) != original {
		t.Errorf("the file was modified:\n%s", body)
	}
}

// JetBrains has to appear in the output. Somebody whose team uses it needs
// to know it is not covered, and learning that from an auditor is worse.
func TestWhatCannotBeCoveredIsNamed(t *testing.T) {
	var found bool
	for _, tgt := range scan() {
		if strings.Contains(tgt.Name, "JetBrains") {
			found = true
			if tgt.Why == "" {
				t.Error("JetBrains is listed with no explanation")
			}
			if tgt.Found {
				t.Error("JetBrains is claimed as covered")
			}
		}
	}
	if !found {
		t.Error("JetBrains is not mentioned at all, so its absence is silent")
	}
}
