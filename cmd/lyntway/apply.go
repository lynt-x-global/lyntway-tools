package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Changing somebody's machine, reversibly.
//
// This edits files a developer depends on to work. That earns a standard
// higher than "it worked on mine": nothing is written without a backup
// beside it, every change is fenced by markers so it can be found again,
// and `lyntway undo` puts everything back. A tool that can break your
// editor and cannot unbreak it is not one anybody should run.
//
// Nothing is written at all until the person has seen the list and said
// yes. A tool that reconfigures a machine on launch is a tool people
// uninstall.

const (
	markerStart = "# >>> lyntway >>>"
	markerEnd   = "# <<< lyntway <<<"
)

// backup copies a file beside itself before it is changed.
//
// Named with the time rather than overwritten, so running init twice does
// not destroy the original state the first run preserved.
func backup(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	dest := fmt.Sprintf("%s.lyntway-backup-%s", path, time.Now().UTC().Format("20060102-150405"))
	if err := os.WriteFile(dest, body, 0o600); err != nil {
		return "", err
	}
	return dest, nil
}

// writeEnv adds the environment variables to a shell profile.
//
// Two variables per provider, not one. The base URL sends the SDK to the
// gateway; the credential is what lets it in. The gateway authenticates
// our key and forwards the provider's, and an SDK has one field for both,
// so setting the base URL alone sends the customer's own provider key as
// the bearer and every call is refused. That is what this did for a while,
// while `status` reported the shell routed.
//
// The provider's key is not something this command knows, so the pairing
// is done by the shell at start-up from whatever the profile already sets.
// A key set later, or in a .env file the application reads itself, is not
// reached, which is why `status` checks the live environment rather than
// this file.
//
// The signing lines are written only when `keys sign` has run: an absent
// LYNTWAY_SIGNING_KEY is how an SDK knows not to sign, and a line pointing
// at a file that does not exist would turn every request into an error.
func writeEnv(path string, c config) (string, error) {
	origin, key := c.Origin, c.Key
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}

	var saved string
	if len(existing) > 0 {
		if saved, err = backup(path); err != nil {
			return "", err
		}
	}

	// Any previous block is removed rather than appended to, so running
	// this twice does not leave two blocks disagreeing about the base URL.
	body := removeBlock(string(existing))

	lines := []string{
		markerStart,
		"# Added by `lyntway init`. Remove with `lyntway undo`.",
		"# Your AI traffic is routed through Lyntway so it can be recorded.",
		`export PATH="$HOME/.lyntway/bin:$PATH"`,
		fmt.Sprintf("export OPENAI_BASE_URL=%q", origin+"/gw/openai/v1"),
		fmt.Sprintf("export ANTHROPIC_BASE_URL=%q", origin+"/gw/anthropic"),
		fmt.Sprintf("export LYNTWAY_KEY=%q", key),
		"# The gateway authenticates the Lyntway key and forwards yours. OpenAI's",
		"# SDK has one field for both, so they are joined with a tilde — only when",
		"# your own key is set, and only once, so a profile read twice is not",
		"# paired twice. Anthropic's SDK sends its bearer token separately.",
	}
	lines = append(lines, pairingLines(path)...)
	if c.SigningKey != "" {
		lines = append(lines,
			"# Requests are signed with this key, so the receipt records who sent them.",
			fmt.Sprintf("export LYNTWAY_SIGNING_KEY=%q", c.SigningKey),
			fmt.Sprintf("export LYNTWAY_KEY_ID=%q", c.KeyID))
	}
	lines = append(lines, markerEnd, "")
	block := strings.Join(lines, "\n")

	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	if err := os.WriteFile(path, []byte(body+block), 0o600); err != nil {
		return "", err
	}
	return saved, nil
}

// pairingLines are the shell-specific half of the block.
//
// fish shares neither `case` nor `[` with the Bourne family, so its lines
// are written in its own syntax. `export` itself is fine: fish ships it as
// a compatibility function, which is why the base URLs above need no
// special case.
func pairingLines(profile string) []string {
	if strings.HasSuffix(profile, ".fish") {
		return []string{
			`if set -q OPENAI_API_KEY; and not string match -q '*~*' -- $OPENAI_API_KEY; set -gx OPENAI_API_KEY "$LYNTWAY_KEY~$OPENAI_API_KEY"; end`,
			`set -gx ANTHROPIC_AUTH_TOKEN "$LYNTWAY_KEY"`,
		}
	}
	return []string{
		`if [ -n "$OPENAI_API_KEY" ]; then case "$OPENAI_API_KEY" in *~*) ;; *) export OPENAI_API_KEY="$LYNTWAY_KEY~$OPENAI_API_KEY" ;; esac; fi`,
		`export ANTHROPIC_AUTH_TOKEN="$LYNTWAY_KEY"`,
	}
}

// removeBlock strips a previously written block, markers included.
func removeBlock(body string) string {
	start := strings.Index(body, markerStart)
	if start < 0 {
		return body
	}
	end := strings.Index(body[start:], markerEnd)
	if end < 0 {
		// A start with no end means somebody edited by hand and left it
		// broken. Truncating to the marker is the least destructive
		// reading: everything before it was theirs.
		return strings.TrimRight(body[:start], "\n") + "\n"
	}
	end += start + len(markerEnd)
	rest := strings.TrimLeft(body[end:], "\n")
	return strings.TrimRight(body[:start], "\n") + "\n" + rest
}

// installSelf copies the lyntway and lyntway-mcp binaries to ~/.lyntway/bin/
// so they can be run from any terminal without remembering where they were
// extracted. Running `lyntway undo` six months later should not require
// finding the original download.
func installSelf() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	binDir := filepath.Join(h, ".lyntway", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}

	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	self, _ = filepath.EvalSymlinks(self)
	srcDir := filepath.Dir(self)

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	for _, name := range []string{"lyntway", "lyntway-mcp"} {
		src := filepath.Join(srcDir, name+ext)
		dst := filepath.Join(binDir, name+ext)
		if !exists(src) {
			continue
		}
		if sameFile(src, dst) {
			continue
		}
		if err := copyFile(src, dst); err != nil {
			return "", fmt.Errorf("copying %s: %w", name, err)
		}
	}

	return binDir, nil
}

func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}

// addToUserPath adds a directory to the user's PATH on Windows.
// On macOS and Linux the shell profile block handled by writeEnv already
// exports $HOME/.lyntway/bin onto PATH.
func addToUserPath(dir string) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	// Already there — nothing to do.
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if strings.EqualFold(filepath.Clean(p), filepath.Clean(dir)) {
			return nil
		}
	}

	// Modify the user-level PATH through the registry. Using setx directly
	// can silently truncate a long PATH, so we read and append through
	// .NET instead.
	script := fmt.Sprintf(
		`$p = [Environment]::GetEnvironmentVariable('PATH','User');`+
			` if (-not $p) { $p = '' };`+
			` $d = '%s';`+
			` if ($p -split ';' | Where-Object { $_.Trim() -ieq $d }) { exit 0 };`+
			` [Environment]::SetEnvironmentVariable('PATH', ($p.TrimEnd(';') + ';' + $d), 'User')`,
		dir)
	return exec.Command("powershell", "-NoProfile", "-Command", script).Run()
}

// shimPath returns the absolute path to the lyntway-mcp binary.
//
// Prefers the installed location (~/.lyntway/bin/) which survives the
// download directory being deleted. Falls back to the directory beside
// this binary, then to a bare name for PATH lookup.
func shimPath() string {
	name := "lyntway-mcp"
	if runtime.GOOS == "windows" {
		name = "lyntway-mcp.exe"
	}

	// Prefer the installed copy — it is the permanent one.
	if h, err := os.UserHomeDir(); err == nil {
		installed := filepath.Join(h, ".lyntway", "bin", name)
		if exists(installed) {
			return installed
		}
	}

	// Fall back to beside this binary.
	self, err := os.Executable()
	if err != nil {
		return "lyntway-mcp"
	}
	shim := filepath.Join(filepath.Dir(self), name)
	if exists(shim) {
		return shim
	}
	return "lyntway-mcp"
}

// wrapMCP rewrites a config so every server runs through the shim.
//
// The original command and arguments are preserved after `--`, so undoing
// this is a matter of removing the wrapper rather than reconstructing what
// was there.
func wrapMCP(path string) (changed []string, saved string, err error) {
	servers, err := mcpServers(path)
	if err != nil {
		return nil, "", err
	}
	if len(servers) == 0 {
		return nil, "", nil
	}

	body, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", err
	}

	shim := shimPath()

	wrapped := map[string]json.RawMessage{}
	for name, entry := range servers {
		if name == "lyntway" {
			// The lyntway entry is our own remote connection. Wrapping
			// it through the shim would govern traffic to ourselves,
			// which is redundant and creates a circular dependency.
			continue
		}
		if alreadyWrapped(entry) {
			continue
		}
		var s struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env,omitempty"`
		}
		if err := json.Unmarshal(entry, &s); err != nil || s.Command == "" {
			// Left exactly as it was. A server shaped in a way this does
			// not understand is one to leave alone, not to guess at.
			continue
		}

		next := map[string]any{
			"command": shim,
			"args":    append([]string{"--"}, append([]string{s.Command}, s.Args...)...),
		}
		if len(s.Env) > 0 {
			next["env"] = s.Env
		}
		encoded, err := json.Marshal(next)
		if err != nil {
			return nil, "", err
		}
		wrapped[name] = encoded
		changed = append(changed, name)
	}

	if len(changed) == 0 {
		return nil, "", nil
	}

	// Add the lyntway tool server so the agent can call lyntway_migrate,
	// lyntway_watch, etc. Skipped if a "lyntway" entry already exists.
	// Only added when we are already writing the file (wrapping at least
	// one server), so a config with nothing to wrap is left untouched.
	if _, has := servers["lyntway"]; !has {
		self := selfPath()
		if self != "" {
			entry := map[string]any{
				"command": self,
				"args":    []string{"mcp-server"},
			}
			if encoded, err := json.Marshal(entry); err == nil {
				wrapped["lyntway"] = encoded
				changed = append(changed, "lyntway (tool server)")
			}
		}
	}

	if saved, err = backup(path); err != nil {
		return nil, "", err
	}
	for name, entry := range wrapped {
		servers[name] = entry
	}
	encoded, err := json.Marshal(servers)
	if err != nil {
		return nil, "", err
	}
	doc["mcpServers"] = encoded

	// Indented, because a person reads this file and a single line of JSON
	// is a worse config than the one they had.
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		return nil, "", err
	}
	return changed, saved, nil
}

// restore puts back the most recent backup of a file.
func restore(path string) (bool, error) {
	matches, err := filepath.Glob(path + ".lyntway-backup-*")
	if err != nil || len(matches) == 0 {
		return false, err
	}
	// Sorted by name, which sorts by time because the stamp is ordered.
	newest := matches[len(matches)-1]
	body, err := os.ReadFile(newest)
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return false, err
	}
	return true, nil
}
