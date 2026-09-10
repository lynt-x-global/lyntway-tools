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

	if _, err := writeEnv(path, config{Origin: "https://lyntway.example", Key: "lyk_test"}); err != nil {
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
		if _, err := writeEnv(path, config{Origin: "https://lyntway.example", Key: "lyk_test"}); err != nil {
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
	if len(changed) < 1 || changed[0] != "github" {
		t.Fatalf("changed = %v, want github first", changed)
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

// The "lyntway" entry is our own remote connection. Wrapping it through
// the shim would govern traffic to ourselves — redundant and circular.
func TestTheLyntwayEntryIsPreservedNotWrapped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	original := `{
  "mcpServers": {
    "lyntway": {"command": "npx", "args": ["-y", "mcp-remote", "https://mcp.lyntway.com/u/abc"]},
    "suno": {"command": "node", "args": ["suno.js"]}
  }
}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	changed, _, err := wrapMCP(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0] != "suno" {
		t.Fatalf("changed = %v, want [suno]", changed)
	}

	servers, err := mcpServers(path)
	if err != nil {
		t.Fatal(err)
	}

	// The lyntway entry must be exactly as it was.
	var lw struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if err := json.Unmarshal(servers["lyntway"], &lw); err != nil {
		t.Fatal(err)
	}
	if lw.Command != "npx" {
		t.Errorf("the lyntway entry was rewritten: command = %q", lw.Command)
	}

	// Suno must be wrapped.
	var sn struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(servers["suno"], &sn); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sn.Command, "lyntway-mcp") {
		t.Errorf("suno was not wrapped: command = %q", sn.Command)
	}
}

// Claude Code keeps its MCP servers in ~/.claude/settings.json with the same
// mcpServers structure. Wrapping must work the same way it does for Desktop.
func TestWrappingClaudeCodeSettingsWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	original := `{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
    "pii_test": {"command": "node", "args": ["pii_server.js"]}
  },
  "permissions": {"allow": ["Bash(*)"]}
}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	changed, saved, err := wrapMCP(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) < 2 {
		t.Fatalf("changed = %v, want at least [filesystem pii_test]", changed)
	}
	if saved == "" {
		t.Fatal("no backup was left")
	}

	body, _ := os.ReadFile(path)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("the config is no longer valid JSON: %v", err)
	}
	if _, kept := doc["permissions"]; !kept {
		t.Error("unrelated settings were dropped")
	}

	servers, err := mcpServers(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"filesystem", "pii_test"} {
		var s struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(servers[name], &s); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(s.Command, "lyntway-mcp") {
			t.Errorf("%s: command = %q, want lyntway-mcp", name, s.Command)
		}
	}
}

// Claude Code must appear in scan() so `lyntway init` lists it.
func TestClaudeCodeAppearsInScan(t *testing.T) {
	var found bool
	for _, tgt := range scan() {
		if tgt.Name == "Claude Code" {
			found = true
			if tgt.Kind != kindMCP {
				t.Errorf("Claude Code kind = %q, want %q", tgt.Kind, kindMCP)
			}
		}
	}
	if !found {
		t.Error("Claude Code is not listed in scan()")
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

// A tool that is installed but needs a manual step must never be reported
// as absent. `status` had no branch for the JSON-configured kind, so an
// installed Continue fell through to "not installed" — which somebody
// reads as nothing to do, leaving an unrouted tool in place until an
// auditor asks why its traffic is missing. Silence about a gap is the one
// failure this command exists to prevent.
func TestEveryKindOfTargetHasSomethingToSay(t *testing.T) {
	seen := map[targetKind]bool{}
	for _, tgt := range scan() {
		seen[tgt.Kind] = true
	}
	for _, kind := range []targetKind{kindEnv, kindJSON, kindMCP, kindManual} {
		if !seen[kind] {
			t.Errorf("scan() no longer produces any %q target, so the branch "+
				"reporting it is untested and free to rot", kind)
		}
	}

	// The bug itself: a found, JSON-configured target reported honestly.
	line := statusLineFor(target{
		Name: "Continue", Kind: kindJSON, Found: true,
		Path: filepath.Join(t.TempDir(), "config.json"),
	}, config{}, func(string) string { return "" })
	if strings.Contains(line, "not installed") {
		t.Errorf("an installed tool is reported as absent: %q", line)
	}
	if !strings.Contains(line, "by hand") {
		t.Errorf("the manual step is not mentioned: %q", line)
	}
}

// Cursor and editors like it are only partly reachable, and the part that
// is not reachable is the part most people use. A base URL applies to
// models somebody added with their own key; whatever comes with the
// editor's own subscription goes to that vendor's servers, and no setting
// anywhere changes it.
//
// Saying "found, here are two lines to paste" without that caveat sells
// coverage the product cannot deliver, and the person discovers it from an
// empty Traffic page rather than from us.
func TestCursorSaysWhatItCannotCover(t *testing.T) {
	var found bool
	for _, tgt := range scan() {
		if tgt.Name != "Cursor" {
			continue
		}
		found = true
		if tgt.Kind != kindManual {
			t.Errorf("Cursor is %q; it cannot be configured automatically", tgt.Kind)
		}
		for _, must := range []string{"your own key", "subscription"} {
			if !strings.Contains(tgt.Why, must) {
				t.Errorf("the Cursor note does not mention %q: %q", must, tgt.Why)
			}
		}
	}
	if !found {
		t.Error("Cursor is not listed at all, so its limits are never stated")
	}
}

// Pointing an SDK at the gateway is half of routing it. The other half is
// the credential: the gateway authenticates our key and forwards the
// provider's, and an SDK has one field for both. Before this, init set the
// base URL, left OPENAI_API_KEY as it was, and every call was refused with
// 401 — while `lyntway status` called the shell routed.
//
// Proved by sourcing the profile in a real shell rather than by reading the
// block back, because the block is shell syntax and the only test of shell
// syntax is a shell.
func TestTheShellBlockPairsTheProviderKeyWhenTheShellStarts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	for _, shell := range []string{"sh", "bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			if _, err := exec.LookPath(shell); err != nil {
				t.Skipf("%s is not installed here", shell)
			}
			dir := t.TempDir()
			profile := filepath.Join(dir, ".profile")
			own := "export OPENAI_API_KEY=sk-real\nexport ANTHROPIC_API_KEY=sk-ant-real\n"
			if err := os.WriteFile(profile, []byte(own), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := writeEnv(profile, config{Origin: "https://lyntway.example", Key: "lyk_test"}); err != nil {
				t.Fatal(err)
			}

			want := "lyk_test~sk-real\nlyk_test\nsk-ant-real\n"
			if got := sourced(t, shell, dir, profile, 1); got != want {
				t.Errorf("after sourcing once:\n got %q\nwant %q", got, want)
			}
			// A profile is often read twice — a login shell and then an
			// interactive one — and pairing twice produces a key with two
			// tildes that the gateway splits in the wrong place.
			if got := sourced(t, shell, dir, profile, 2); got != want {
				t.Errorf("after sourcing twice:\n got %q\nwant %q", got, want)
			}
		})
	}
}

// A shell with no provider key of its own must not be handed a broken one.
// "lyk_test~" with nothing after the tilde authenticates to us and then
// forwards no credential at all, which the provider reports as our fault.
func TestAShellWithNoProviderKeyIsNotGivenABrokenOne(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	dir := t.TempDir()
	profile := filepath.Join(dir, ".profile")
	if err := os.WriteFile(profile, []byte("export EDITOR=vim\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeEnv(profile, config{Origin: "https://lyntway.example", Key: "lyk_test"}); err != nil {
		t.Fatal(err)
	}
	if got, want := sourced(t, "sh", dir, profile, 1), "\nlyk_test\n\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// sourced reads the profile in a clean environment and reports the three
// variables that decide whether a call reaches the gateway authenticated.
func sourced(t *testing.T, shell, home, profile string, times int) string {
	t.Helper()
	script := strings.Repeat(". "+profile+"; ", times) +
		`printf '%s\n%s\n%s\n' "$OPENAI_API_KEY" "$ANTHROPIC_AUTH_TOKEN" "$ANTHROPIC_API_KEY"`
	cmd := exec.Command(shell, "-c", script)
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", shell, err, out)
	}
	return string(out)
}

// Status must report the shell it runs in, not the file it wrote. A block
// in the profile proves nothing about the environment an SDK will read:
// the terminal may be old, the provider key may be set after the block,
// or the pair may have been put in a header the gateway never reads.
func TestStatusDoesNotCallAShellRoutedUntilTheKeyIsPaired(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, ".zshrc")
	c := config{Origin: "https://lyntway.example", Key: "lyk_test"}
	if _, err := writeEnv(profile, c); err != nil {
		t.Fatal(err)
	}
	tgt := target{Name: "Your shell", Kind: kindEnv, Found: true, Path: profile}
	env := func(vars map[string]string) func(string) string {
		return func(name string) string { return vars[name] }
	}
	openaiAt := c.Origin + "/gw/openai/v1"
	anthropicAt := c.Origin + "/gw/anthropic"

	// The block is written but this shell has not read it yet.
	line := statusLineFor(tgt, c, env(nil))
	if strings.Contains(line, "✓") {
		t.Errorf("a shell that has not read the block is called routed:\n%s", line)
	}
	if !strings.Contains(line, "new terminal") {
		t.Errorf("the reader is not told to open a new terminal:\n%s", line)
	}

	// The exact shape that fails: base URL set, key sent as-is, 401.
	line = statusLineFor(tgt, c, env(map[string]string{
		"OPENAI_BASE_URL": openaiAt, "OPENAI_API_KEY": "sk-real",
	}))
	if strings.Contains(line, "✓") {
		t.Errorf("a shell whose every call is refused is called routed:\n%s", line)
	}
	if !strings.Contains(line, "401") || !strings.Contains(line, "lyk_test~") {
		t.Errorf("the failure and the exact fix are not both stated:\n%s", line)
	}

	// Paired, and therefore routed.
	line = statusLineFor(tgt, c, env(map[string]string{
		"OPENAI_BASE_URL": openaiAt, "OPENAI_API_KEY": "lyk_test~sk-real",
	}))
	if !strings.Contains(line, "✓") || !strings.Contains(line, "OpenAI") {
		t.Errorf("a correctly paired shell is not called routed:\n%s", line)
	}

	// Anthropic's SDK sends ANTHROPIC_API_KEY in its own header, which the
	// gateway does not authenticate against. The tilde pair there is the
	// documented OpenAI shape applied to the wrong provider, and it 401s.
	line = statusLineFor(tgt, c, env(map[string]string{
		"ANTHROPIC_BASE_URL": anthropicAt, "ANTHROPIC_API_KEY": "lyk_test~sk-ant-real",
	}))
	if strings.Contains(line, "✓") {
		t.Errorf("a pair in the header the gateway ignores is called routed:\n%s", line)
	}
	if !strings.Contains(line, "ANTHROPIC_AUTH_TOKEN") {
		t.Errorf("the variable that fixes it is not named:\n%s", line)
	}

	// Our key as the bearer, theirs in its own header: this is what works.
	line = statusLineFor(tgt, c, env(map[string]string{
		"ANTHROPIC_BASE_URL": anthropicAt, "ANTHROPIC_AUTH_TOKEN": "lyk_test", "ANTHROPIC_API_KEY": "sk-ant-real",
	}))
	if !strings.Contains(line, "✓") || !strings.Contains(line, "Anthropic") {
		t.Errorf("a correctly configured Anthropic shell is not called routed:\n%s", line)
	}
}
