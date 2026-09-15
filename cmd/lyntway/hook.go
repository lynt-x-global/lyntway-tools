package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Catching a key before it is sent, at the one moment it can still be
// caught.
//
// The gateway sees a prompt after the tool has sent it. A coding assistant
// runs a hook before that, on the machine, with the prompt on stdin — and
// a hook that finds a key can refuse the prompt, so the key goes nowhere.
// The check is local and sends nothing: the prompt is read, the credential
// rules run over it, and the process exits. Nothing else this repository
// does could honestly say "it was not sent"; this can.
//
// Claude Code calls it UserPromptSubmit and takes exit status 2 as "block
// and discard the prompt", with stderr as the reason shown. Cursor calls
// it beforeSubmitPrompt and reads a JSON answer from stdout instead; its
// documentation does not promise that an exit status blocks that event,
// so the JSON form is used for it and nothing is assumed.

func hook(args []string) error {
	if len(args) == 0 {
		hookUsage()
		return fmt.Errorf("say which: prompt, install or uninstall")
	}
	switch args[0] {
	case "prompt":
		return hookPromptCommand(args[1:])
	case "install":
		return hookInstall(args[1:])
	case "uninstall":
		return hookUninstall(args[1:])
	case "help", "-h", "--help":
		hookUsage()
		return nil
	default:
		hookUsage()
		return fmt.Errorf("no hook command called %q", args[0])
	}
}

func hookUsage() {
	fmt.Fprint(os.Stderr, "lyntway hook — stop a provider key leaving in a prompt or a commit\n"+
		"\n"+
		"Usage:\n"+
		"  lyntway hook install [--cursor] [--git] [--yes]\n"+
		"      Register the check with Claude Code (~/.claude/settings.json), with\n"+
		"      --cursor with Cursor (~/.cursor/hooks.json), or with --git as a\n"+
		"      git pre-commit hook in the current repository. The file is backed up\n"+
		"      beside itself first. Remove with `hook uninstall` or `lyntway undo`.\n"+
		"\n"+
		"  lyntway hook prompt [--cursor]\n"+
		"      What the editor runs. Reads the prompt on stdin, looks for provider keys\n"+
		"      and other credentials, and refuses the prompt if one is there. Nothing\n"+
		"      is sent anywhere by this command; the prompt is read and dropped.\n"+
		"\n"+
		"  lyntway hook uninstall [--cursor] [--git]\n"+
		"      Take the entry out again.\n")
}

// hookInput is the part of what the editor sends that matters here.
// Claude Code and Cursor both call the field "prompt"; everything else
// they send is ignored and never leaves the process.
type hookInput struct {
	Prompt string `json:"prompt"`
}

// maxPrompt bounds what is read. A prompt bigger than this is not one a
// person typed, and reading without limit is how a hook becomes the slow
// part of every keystroke.
const maxPrompt = 8 << 20

// checkPrompt reads the editor's JSON and decides. It returns the message
// to show when the prompt should be refused, and nothing when it may go.
func checkPrompt(in io.Reader) (refusal string, err error) {
	body, err := io.ReadAll(io.LimitReader(in, maxPrompt))
	if err != nil {
		return "", err
	}
	var input hookInput
	if err := json.Unmarshal(body, &input); err != nil {
		return "", fmt.Errorf("the hook's input is not the JSON an editor sends: %v", err)
	}
	hits := findKeys(input.Prompt, 1)
	if len(hits) == 0 {
		return "", nil
	}
	return refusalMessage(hits), nil
}

// refusalMessage is what the person sees instead of an answer.
//
// It names the first key and counts the rest: a prompt with three keys in
// it needs the person to look at the prompt, not read three paragraphs.
// The advice depends on what was found. A provider key has a home —
// `keys migrate` — and a GitHub token or a private key does not, and
// telling somebody to migrate a private key would send them somewhere
// that cannot help.
func refusalMessage(hits []keyHit) string {
	first := hits[0]
	var b strings.Builder
	if first.Last4 == "" || first.Class == "secret.private_key" {
		fmt.Fprintf(&b, "That looks like a %s.", strings.ToLower(first.Label[:1])+first.Label[1:])
	} else {
		fmt.Fprintf(&b, "That looks like %s %s (…%s).", article(first.Label), first.Label, first.Last4)
	}
	if len(hits) > 1 {
		fmt.Fprintf(&b, " %d more found.", len(hits)-1)
	}
	b.WriteString(" It was not sent.")
	if first.Upstream != "" {
		b.WriteString(" Store it with `lyntway keys migrate` or paste a Lyntway key instead.")
	} else {
		b.WriteString(" Take it out of the prompt and send the rest.")
	}
	return b.String()
}

func article(noun string) string {
	switch strings.ToLower(noun[:1]) {
	case "a", "e", "i", "o", "x":
		// "an OpenAI key", "an xAI key" — x is pronounced with a vowel.
		return "an"
	}
	return "a"
}

// hookPromptCommand is what the editor runs on every prompt.
//
// Exit statuses are the editor's contract, not ours. For Claude Code: 0
// lets the prompt through, 2 blocks and discards it with stderr shown,
// anything else is reported and the prompt proceeds — so a broken hook
// never stops somebody working, it only stops protecting them. For
// Cursor the answer is JSON on stdout and the exit status is 0 either
// way.
func hookPromptCommand(args []string) error {
	fs := flag.NewFlagSet("hook prompt", flag.ExitOnError)
	cursor := fs.Bool("cursor", false, "answer in Cursor's JSON form rather than by exit status")
	_ = fs.Parse(args)

	refusal, err := checkPrompt(stdin)
	if *cursor {
		answer := map[string]any{"continue": true}
		if err != nil {
			// Cursor is told to go on: a hook that cannot read its
			// input has no grounds to stop anybody.
			fmt.Fprintf(os.Stderr, "lyntway hook prompt: %v\n", err)
		} else if refusal != "" {
			answer = map[string]any{"continue": false, "user_message": refusal}
		}
		encoded, _ := json.Marshal(answer)
		fmt.Fprintln(stdout, string(encoded))
		return nil
	}
	if err != nil {
		return err
	}
	if refusal == "" {
		return nil
	}
	fmt.Fprintln(os.Stderr, refusal)
	exit(2)
	return nil
}

// exit is os.Exit, swapped by tests that need the command to return.
var exit = os.Exit

// The hook entry, as each editor's settings file expects it.

func claudeHooksFile() string {
	if h := home(); h != "" {
		return filepath.Join(h, ".claude", "settings.json")
	}
	return ""
}

func cursorHooksFile() string {
	if h := home(); h != "" {
		return filepath.Join(h, ".cursor", "hooks.json")
	}
	return ""
}

// hookCommand is the command line the editor will run. The binary is
// named by absolute path: the editor's PATH is not the terminal's, and a
// hook that fails to start protects nobody while looking installed.
func hookCommand(cursor bool) string {
	path := selfPath()
	if strings.ContainsAny(path, " \t\"") {
		path = fmt.Sprintf("%q", path)
	}
	if cursor {
		return path + " hook prompt --cursor"
	}
	return path + " hook prompt"
}

// selfPath prefers the copy `init` installs, which outlives the download.
func selfPath() string {
	name := "lyntway"
	if runtime.GOOS == "windows" {
		name = "lyntway.exe"
	}
	if h := home(); h != "" {
		if installed := filepath.Join(h, ".lyntway", "bin", name); exists(installed) {
			return installed
		}
	}
	self, err := os.Executable()
	if err != nil {
		return name
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		return resolved
	}
	return self
}

// isOurHook recognises the entry this wrote, however the path was quoted.
func isOurHook(command string) bool {
	return strings.Contains(command, "lyntway") && strings.Contains(command, " hook prompt")
}

func hookInstall(args []string) error {
	fs := flag.NewFlagSet("hook install", flag.ExitOnError)
	cursor := fs.Bool("cursor", false, "install for Cursor instead of Claude Code")
	git := fs.Bool("git", false, "install a git pre-commit hook in the current repository")
	yes := fs.Bool("yes", false, "do not ask before writing")
	_ = fs.Parse(args)

	if *git {
		return hookInstallGit(*yes)
	}

	path, editor := claudeHooksFile(), "Claude Code"
	if *cursor {
		path, editor = cursorHooksFile(), "Cursor"
	}
	if path == "" {
		return fmt.Errorf("this machine has no home directory")
	}

	fmt.Fprintf(stdout, "\n%s will run this before every prompt:\n\n  %s\n\n", editor, hookCommand(*cursor))
	fmt.Fprintf(stdout, "It reads the prompt, looks for provider keys and other credentials, and refuses\n")
	fmt.Fprintf(stdout, "the prompt if one is there. It sends nothing anywhere.\n\n")
	if !*yes && !ask(fmt.Sprintf("Add it to %s? A backup is written first. [y/N] ", path)) {
		fmt.Fprintln(stdout, "Nothing was changed.")
		return nil
	}

	changed, saved, err := writeHook(path, *cursor)
	if err != nil {
		return err
	}
	if !changed {
		fmt.Fprintf(stdout, "  · %s — already installed\n", path)
		return nil
	}
	fmt.Fprintf(stdout, "  ✓ %s\n", path)
	if saved != "" {
		fmt.Fprintf(stdout, "      backup: %s\n", filepath.Base(saved))
	}
	fmt.Fprintln(stdout, "\nRemove it with `lyntway hook uninstall` or `lyntway undo`.")
	if !*cursor {
		fmt.Fprintln(stdout, "Claude Code reads the file when it starts; restart a running session.")
	}
	return nil
}

func hookUninstall(args []string) error {
	fs := flag.NewFlagSet("hook uninstall", flag.ExitOnError)
	cursor := fs.Bool("cursor", false, "remove from Cursor instead of Claude Code")
	git := fs.Bool("git", false, "remove the git pre-commit hook from the current repository")
	_ = fs.Parse(args)

	if *git {
		return hookUninstallGit()
	}

	path := claudeHooksFile()
	if *cursor {
		path = cursorHooksFile()
	}
	removed, err := removeHook(path, *cursor, true)
	if err != nil {
		return err
	}
	if !removed {
		fmt.Fprintf(stdout, "  · %s — nothing to remove\n", path)
		return nil
	}
	fmt.Fprintf(stdout, "  ✓ %s — hook removed\n", path)
	return nil
}

// hookBackupSuffix keeps these backups apart from the ones `init` writes
// to the same file. `undo` restores the newest `.lyntway-backup-*` of a
// settings file to take the MCP wrapping out, and a hook backup written
// later would be the newest — restoring it would put the wrapping back.
const hookBackupSuffix = ".lyntway-hook-backup-"

func backupHooksFile(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	dest := path + hookBackupSuffix + time.Now().UTC().Format("20060102-150405")
	return dest, os.WriteFile(dest, body, 0o600)
}

// writeHook adds the entry to an editor's settings file, creating the
// file when there is none. Everything else in the file is kept as it was.
func writeHook(path string, cursor bool) (changed bool, saved string, err error) {
	doc, err := readJSONObject(path)
	if err != nil {
		return false, "", err
	}

	// Cursor:      {"version": 1, "hooks": {"beforeSubmitPrompt": [{"command": …}]}}
	// Claude Code: {"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": …, "timeout": …}]}]}}
	event := "UserPromptSubmit"
	if cursor {
		event = "beforeSubmitPrompt"
	}
	hooks := map[string]json.RawMessage{}
	if raw, ok := doc["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooks); err != nil {
			return false, "", fmt.Errorf("%s has a \"hooks\" entry this does not understand; nothing written", path)
		}
	}
	var groups []json.RawMessage
	if raw, ok := hooks[event]; ok {
		if err := json.Unmarshal(raw, &groups); err != nil {
			return false, "", fmt.Errorf("%s has a %q entry this does not understand; nothing written", path, event)
		}
	}
	for _, g := range groups {
		if hookGroupIsOurs(g, cursor) {
			return false, "", nil
		}
	}

	var entry any
	if cursor {
		entry = map[string]any{"command": hookCommand(true)}
	} else {
		entry = map[string]any{"hooks": []map[string]any{{
			"type":    "command",
			"command": hookCommand(false),
			// Seconds. Scanning a prompt takes milliseconds; the limit
			// is there so a wedged process never holds a prompt hostage.
			"timeout": 10,
		}}}
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return false, "", err
	}
	groups = append(groups, encoded)
	if hooks[event], err = json.Marshal(groups); err != nil {
		return false, "", err
	}
	if doc["hooks"], err = json.Marshal(hooks); err != nil {
		return false, "", err
	}
	if cursor {
		if _, ok := doc["version"]; !ok {
			doc["version"] = json.RawMessage("1")
		}
	}

	if exists(path) {
		if saved, err = backupHooksFile(path); err != nil {
			return false, "", err
		}
	}
	return true, saved, writeJSONObject(path, doc)
}

// removeHook takes our entry out and leaves the rest. With backup, the
// file is copied first; `undo` passes false because the backup it just
// restored from is still there.
func removeHook(path string, cursor bool, backup bool) (bool, error) {
	if !exists(path) {
		return false, nil
	}
	doc, err := readJSONObject(path)
	if err != nil {
		return false, err
	}
	event := "UserPromptSubmit"
	if cursor {
		event = "beforeSubmitPrompt"
	}
	hooks := map[string]json.RawMessage{}
	if raw, ok := doc["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooks); err != nil {
			return false, nil
		}
	}
	var groups []json.RawMessage
	if raw, ok := hooks[event]; ok {
		if err := json.Unmarshal(raw, &groups); err != nil {
			return false, nil
		}
	}
	kept := groups[:0]
	for _, g := range groups {
		if !hookGroupIsOurs(g, cursor) {
			kept = append(kept, g)
		}
	}
	if len(kept) == len(groups) {
		return false, nil
	}
	if len(kept) == 0 {
		delete(hooks, event)
	} else if hooks[event], err = json.Marshal(kept); err != nil {
		return false, err
	}
	if len(hooks) == 0 {
		delete(doc, "hooks")
	} else if doc["hooks"], err = json.Marshal(hooks); err != nil {
		return false, err
	}
	if backup {
		if _, err := backupHooksFile(path); err != nil {
			return false, err
		}
	}
	return true, writeJSONObject(path, doc)
}

// hookGroupIsOurs recognises an entry this command wrote, in either
// editor's shape. A group somebody else wrote that also runs lyntway is
// treated as ours too: there is no second reason to run this command.
func hookGroupIsOurs(group json.RawMessage, cursor bool) bool {
	if cursor {
		var g struct {
			Command string `json:"command"`
		}
		return json.Unmarshal(group, &g) == nil && isOurHook(g.Command)
	}
	var g struct {
		Hooks []struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if json.Unmarshal(group, &g) != nil {
		return false
	}
	for _, h := range g.Hooks {
		if isOurHook(h.Command) {
			return true
		}
	}
	return false
}

// removeHooksEverywhere is what `undo` calls: both editors and the
// current directory's git hook, no backup.
func removeHooksEverywhere() (n int) {
	for _, f := range []struct {
		path   string
		cursor bool
	}{{claudeHooksFile(), false}, {cursorHooksFile(), true}} {
		if f.path == "" {
			continue
		}
		removed, err := removeHook(f.path, f.cursor, false)
		if err != nil {
			fmt.Fprintf(stdout, "  ✗ %s — %v\n", f.path, err)
			continue
		}
		if removed {
			fmt.Fprintf(stdout, "  ✓ %s — hook removed\n", f.path)
			n++
		}
	}
	if gitDir := findGitDir("."); gitDir != "" {
		if removed, err := removeGitHook(gitDir); err != nil {
			fmt.Fprintf(stdout, "  ✗ git pre-commit — %v\n", err)
		} else if removed {
			fmt.Fprintf(stdout, "  ✓ git pre-commit — hook removed\n")
			n++
		}
	}
	return n
}

// Git pre-commit hook: a shell script that runs `lyntway scan` on staged
// .env files before every commit. It is a shell script, not a Go binary,
// because pre-commit hooks must start quickly and shell is what git
// invokes by default. The script delegates to `lyntway scan`, which is
// already the right tool for finding provider keys in files.

const (
	gitHookStart = "# >>> lyntway-scan >>>"
	gitHookEnd   = "# <<< lyntway-scan <<<"
)

// gitHookBlock is the fenced block written into .git/hooks/pre-commit.
// The scanner binary is called by name, not absolute path: the hook runs
// in the same shell as `git commit`, so PATH is the developer's PATH.
var gitHookBlock = strings.Join([]string{
	gitHookStart,
	"# lyntway: refuse a commit that carries a provider key in a .env file.",
	"# Remove this block or run `lyntway hook uninstall --git` to stop.",
	`staged=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.env' || true)`,
	`if [ -n "$staged" ]; then`,
	`  lyntway scan $staged`,
	"fi",
	gitHookEnd,
}, "\n")

// findGitDir walks up from dir until it finds a .git directory.
func findGitDir(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(abs, ".git")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return ""
		}
		abs = parent
	}
}

// gitHookInstalled reports whether the pre-commit hook already contains
// the lyntway block.
func gitHookInstalled(gitDir string) bool {
	path := filepath.Join(gitDir, "hooks", "pre-commit")
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(body), gitHookStart)
}

// hookInstallGit adds the lyntway block to .git/hooks/pre-commit.
func hookInstallGit(yes bool) error {
	gitDir := findGitDir(".")
	if gitDir == "" {
		return fmt.Errorf("not in a git repository")
	}
	if gitHookInstalled(gitDir) {
		fmt.Fprintln(stdout, "  · git pre-commit hook already installed")
		return nil
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	fmt.Fprintf(stdout, "\nA pre-commit hook will run `lyntway scan` on staged .env files before\n")
	fmt.Fprintf(stdout, "every commit. A commit that carries a provider key will be refused.\n")
	fmt.Fprintf(stdout, "The check is local and sends nothing anywhere.\n\n")
	if !yes && !ask(fmt.Sprintf("Add the hook to %s? [y/N] ", hookPath)) {
		fmt.Fprintln(stdout, "Nothing was changed.")
		return nil
	}

	if err := writeGitHook(gitDir); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "  ✓ %s\n", hookPath)
	fmt.Fprintln(stdout, "\nRemove it with `lyntway hook uninstall --git` or `lyntway undo`.")
	return nil
}

// hookUninstallGit removes the lyntway block from .git/hooks/pre-commit.
func hookUninstallGit() error {
	gitDir := findGitDir(".")
	if gitDir == "" {
		return fmt.Errorf("not in a git repository")
	}
	removed, err := removeGitHook(gitDir)
	if err != nil {
		return err
	}
	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	if !removed {
		fmt.Fprintf(stdout, "  · %s — nothing to remove\n", hookPath)
		return nil
	}
	fmt.Fprintf(stdout, "  ✓ %s — hook removed\n", hookPath)
	return nil
}

// writeGitHook appends the lyntway block to .git/hooks/pre-commit,
// creating the file with a shebang when it does not exist.
func writeGitHook(gitDir string) error {
	dir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "pre-commit")
	body, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	text := string(body)
	if strings.Contains(text, gitHookStart) {
		return nil // already present
	}

	if len(body) == 0 {
		text = "#!/bin/sh\n"
	} else if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += "\n" + gitHookBlock + "\n"

	if err := os.WriteFile(path, []byte(text), 0o755); err != nil {
		return err
	}
	return nil
}

// removeGitHook takes the lyntway block out of .git/hooks/pre-commit.
// If nothing meaningful remains, the file is removed.
func removeGitHook(gitDir string) (bool, error) {
	path := filepath.Join(gitDir, "hooks", "pre-commit")
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	text := string(body)
	if !strings.Contains(text, gitHookStart) {
		return false, nil
	}

	start := strings.Index(text, gitHookStart)
	end := strings.Index(text, gitHookEnd)
	if end < 0 {
		return false, nil
	}
	end += len(gitHookEnd)
	// Remove the block and any trailing newline.
	if end < len(text) && text[end] == '\n' {
		end++
	}
	// Remove a leading blank line before the block.
	if start > 0 && text[start-1] == '\n' {
		start--
	}
	rest := text[:start] + text[end:]

	// If only the shebang remains, delete the file.
	trimmed := strings.TrimSpace(rest)
	if trimmed == "" || trimmed == "#!/bin/sh" || trimmed == "#!/usr/bin/env bash" {
		return true, os.Remove(path)
	}
	return true, os.WriteFile(path, []byte(rest), 0o755)
}

func readJSONObject(path string) (map[string]json.RawMessage, error) {
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]json.RawMessage{}, nil
	}
	if err != nil {
		return nil, err
	}
	doc := map[string]json.RawMessage{}
	if len(strings.TrimSpace(string(body))) == 0 {
		return doc, nil
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%s is not a JSON object; nothing written", path)
	}
	return doc, nil
}

func writeJSONObject(path string, doc map[string]json.RawMessage) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	return os.WriteFile(path, append(out, '\n'), mode)
}
