package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Make `guard` a thing that is true rather than a thing you remember.
//
// # Why this exists
//
// dotenvx spreads because it replaces a command somebody already types:
// `node app.js` becomes `dotenvx run -- node app.js`, once, in a script
// they already had. `guard` adds a command they did not have, and asks
// them to remember it every time for the rest of their life. That is the
// whole difference in adoption, and no feature closes it.
//
// So this writes a shell function per tool, once, after asking.
//
// # Why a function and not an alias
//
// An alias is a substitution with no way back. `alias claude='lyntway
// guard -- claude'` breaks `claude` completely the day somebody uninstalls
// us, moves the binary, or opens a shell where PATH is different — and the
// person is left with a tool that does not start and no obvious reason
// why. Nobody may be stopped from working by something we wrote.
//
// The function checks for us first and falls through to the real command
// if we are not there. The worst case is that governance silently stops,
// which `lyntway status` reports, rather than the tool silently dying.
//
// The inner call names the bare command because guard resolves it with
// exec.LookPath against PATH — no shell is involved, so the function
// cannot recurse into itself.

// guardAliasOpen and guardAliasClose fence the block this writes, so it
// can be found again and taken out exactly.
const (
	guardAliasOpen  = "# >>> lyntway guard >>>"
	guardAliasClose = "# <<< lyntway guard <<<"
)

// guardAliasBlock is what gets appended to the profile.
func guardAliasBlock(shell string, tools []string) string {
	var b strings.Builder
	b.WriteString(guardAliasOpen + "\n")
	b.WriteString("# Written by `lyntway guard --install`. Remove it with\n")
	b.WriteString("# `lyntway guard --uninstall`, `lyntway undo`, or by deleting this block.\n")
	b.WriteString("#\n")
	b.WriteString("# Each function runs your tool exactly as before, with its model traffic\n")
	b.WriteString("# governed on this machine. If lyntway is not installed, the tool still\n")
	b.WriteString("# runs — it is never the reason something fails to start.\n")
	for _, t := range tools {
		if shell == "fish" {
			fmt.Fprintf(&b, "function %s\n", t)
			b.WriteString("  if command -v lyntway >/dev/null 2>&1\n")
			fmt.Fprintf(&b, "    lyntway guard -- %s $argv\n", t)
			b.WriteString("  else\n")
			fmt.Fprintf(&b, "    command %s $argv\n", t)
			b.WriteString("  end\n")
			b.WriteString("end\n")
			continue
		}
		fmt.Fprintf(&b, "%s() {\n", t)
		b.WriteString("  if command -v lyntway >/dev/null 2>&1; then\n")
		fmt.Fprintf(&b, "    lyntway guard -- %s \"$@\"\n", t)
		b.WriteString("  else\n")
		fmt.Fprintf(&b, "    command %s \"$@\"\n", t)
		b.WriteString("  fi\n")
		b.WriteString("}\n")
	}
	b.WriteString(guardAliasClose + "\n")
	return b.String()
}

// guardAliasTools names the wrappable tools actually on this machine, in
// a stable order. Empty when there is nothing to wrap, which is a state
// and not an error: offering to wrap software somebody does not have
// reads as a tool that did not look.
func guardAliasTools() []string {
	present := map[string]bool{}
	h := currentHost(false)
	procs, _ := listProcesses(h.GOOS)
	for _, a := range inventory(h, procs) {
		present[a.Name] = true
	}
	wrappable := guardableApps()
	var out []string
	for _, d := range aiApps {
		if !wrappable[d.Name] || !present[d.Name] || len(d.Bins) == 0 {
			continue
		}
		out = append(out, d.Bins[0])
	}
	return out
}

// stripGuardAliasBlock removes the fenced block, and reports whether one
// was there. Everything outside the fence is left byte for byte: this
// edits somebody's shell profile, which may be the most personal file on
// their machine.
func stripGuardAliasBlock(body string) (string, bool) {
	start := strings.Index(body, guardAliasOpen)
	if start < 0 {
		return body, false
	}
	end := strings.Index(body[start:], guardAliasClose)
	if end < 0 {
		// An open fence with no close: the user edited inside the block,
		// or a write was interrupted. Taking everything to the end of the
		// file would delete their work, so this refuses rather than
		// guesses, and the caller says so.
		return body, false
	}
	end += start + len(guardAliasClose)
	if end < len(body) && body[end] == '\n' {
		end++
	}
	// Install writes a blank line before the fence so the block does not
	// run into whatever came above it. Removal takes that line back too,
	// or an install-then-uninstall leaves a growing stack of blank lines
	// in a file somebody did not ask us to touch at all.
	if start >= 2 && body[start-1] == '\n' && body[start-2] == '\n' {
		start--
	}
	out := body[:start] + body[end:]
	return out, true
}

// installGuardAlias writes the block after showing it and asking.
func installGuardAlias(out io.Writer) error {
	profile := shellProfile()
	if profile == "" {
		return fmt.Errorf("the shell in $SHELL is not one this knows how to edit; add the function by hand, or run `lyntway guard -- claude` as it is")
	}
	shell := filepath.Base(os.Getenv("SHELL"))

	tools := guardAliasTools()
	if len(tools) == 0 {
		fmt.Fprintf(out, "\nNothing here to wrap. This looks for the coding tools documented to read\n"+
			"a base-URL setting — Claude Code, Codex and Aider — and none is on this\n"+
			"machine. `lyntway guard -- <command>` still works for anything else.\n\n")
		return nil
	}

	body, err := os.ReadFile(profile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", profile, err)
	}
	if strings.Contains(string(body), guardAliasOpen) {
		fmt.Fprintf(out, "\n%s already has the block. Run `lyntway guard --uninstall` first to change it.\n\n", profile)
		return nil
	}

	block := guardAliasBlock(shell, tools)
	fmt.Fprintf(out, "\nThis would add to %s:\n\n", profile)
	for _, line := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
		fmt.Fprintf(out, "  %s\n", line)
	}
	fmt.Fprintf(out, "\nAfterwards %s runs governed, every time, without being asked for.\n",
		strings.Join(tools, " and "))
	fmt.Fprintf(out, "If lyntway is ever removed, they keep working untouched.\n\n")

	if !ask("Add it? [y/N] ") {
		fmt.Fprintf(out, "Nothing was changed.\n\n")
		return nil
	}

	// A profile that does not exist yet is the ordinary case on a fresh
	// machine, and there is nothing to back up. Taking the error as fatal
	// here meant somebody with no .zshrc could not install the wrapper at
	// all, which is exactly the person most likely to want it.
	backupPath := ""
	if len(body) > 0 {
		if backupPath, err = backup(profile); err != nil {
			return err
		}
	}
	prefix := ""
	if len(body) > 0 && !strings.HasSuffix(string(body), "\n") {
		prefix = "\n"
	}
	if err := os.WriteFile(profile, append(body, []byte(prefix+"\n"+block)...), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", profile, err)
	}

	// Only recorded when there is a backup to restore from. `undo` copies
	// a backup over the file, and a record naming one that was never
	// written would make undo report a missing backup for a file it in
	// fact created.
	rec, _ := loadRecord()
	if backupPath != "" {
		rec.Files = append(rec.Files, changedFile{Path: profile, Backup: backupPath, At: time.Now().UTC().Format(time.RFC3339)})
	}
	if err := saveRecord(rec); err != nil {
		fmt.Fprintf(out, "  (the change was made; recording it for `lyntway undo` failed: %v)\n", err)
	}

	fmt.Fprintf(out, "\n  ✓ %s\n", profile)
	if backupPath != "" {
		fmt.Fprintf(out, "  ✓ backup beside it: %s\n", filepath.Base(backupPath))
	} else {
		fmt.Fprintf(out, "  ✓ created — there was no profile here before\n")
	}
	fmt.Fprintf(out, "\nOpen a new terminal, or run: source %s\n\n", profile)
	return nil
}

// uninstallGuardAlias takes the block out again.
func uninstallGuardAlias(out io.Writer) error {
	profile := shellProfile()
	if profile == "" {
		return fmt.Errorf("the shell in $SHELL is not one this knows how to edit")
	}
	raw, err := os.ReadFile(profile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", profile, err)
	}
	body := string(raw)
	if !strings.Contains(body, guardAliasOpen) {
		fmt.Fprintf(out, "\n%s has no lyntway block.\n\n", profile)
		return nil
	}
	stripped, ok := stripGuardAliasBlock(body)
	if !ok {
		return fmt.Errorf("%s has an opening lyntway marker with no closing one — it has been edited by hand. Remove the block yourself rather than letting this guess where it ends", profile)
	}
	backupPath, err := backup(profile)
	if err != nil {
		return err
	}
	if err := os.WriteFile(profile, []byte(stripped), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", profile, err)
	}
	fmt.Fprintf(out, "\n  ✓ removed from %s\n  ✓ backup beside it: %s\n\nOpen a new terminal for it to take effect.\n\n",
		profile, filepath.Base(backupPath))
	return nil
}
