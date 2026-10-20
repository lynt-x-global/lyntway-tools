package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/agentsecrets"
	"github.com/lynt-x-global/lyntway-tools/secure"
)

// `lyntway secure` — the one command.
//
// Everything the four-step journey did, in one invocation and one
// question: look at what the agents here have already seen, show it, and
// then make the editor refuse a prompt that carries one.
//
// Not "close the hole": this hook reads prompts. The agent opening a
// .env through its own file tool is a different hook point, which these
// editors support and we do not install yet. Both reports say so where
// they make the claim.
//
// The four-step version was the feature working and the product failing.
// Each command after the first is a decision taken by somebody whose
// attention has already moved on, and the hook — the thing that actually
// prevents the next key — was third.

func secureCommand(args []string) error {
	fs := flag.NewFlagSet("secure", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		assumeYes = fs.Bool("yes", false, "do not ask before changing the editor configuration")
		project   = fs.String("project", "", "also read the agent files kept inside this project directory")
	)
	fs.Usage = func() {
		fmt.Fprint(stdout, "lyntway secure — find what your AI tools have already seen\n\n"+
			"Usage:\n  lyntway secure [--project DIR] [--yes]\n\n"+
			"Reads the transcripts, prompt histories, pasted buffers, shell snapshots and\n"+
			"MCP configuration the coding agents on this machine wrote to disk, reports the\n"+
			"credentials in them, and then — after asking once — makes your editor refuse a\n"+
			"prompt carrying a credential before it is sent.\n\n"+
			"Sends nothing. Prints no key. Changes nothing until you say yes, and\n"+
			"`lyntway undo` puts every file back byte for byte.\n\n"+
			"Exits non-zero when it found something, so it works as a check.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("this machine has no home directory to look in: %w", err)
	}
	sources := agentsecrets.Sources(agentsecrets.Host{
		GOOS:         runtime.GOOS,
		Home:         home,
		AppData:      os.Getenv("APPDATA"),
		LocalAppData: os.Getenv("LOCALAPPDATA"),
	})
	if *project != "" {
		abs, err := filepath.Abs(*project)
		if err != nil {
			return err
		}
		sources = append(sources, agentsecrets.ProjectSources(abs)...)
	}

	res := agentsecrets.ScanProgress(sources, agentsecrets.DefaultRules(), progressTo(false))
	allow, err := agentsecrets.LoadAllow(filepath.Join(home, ".lyntway"))
	if err != nil {
		return fmt.Errorf("reading %s: %w", filepath.Join(home, ".lyntway", agentsecrets.AllowFile), err)
	}
	res = res.Excluding(allow)
	clearProgress()

	out := secure.Run(stdout, res, editorInstaller{}, ask, *assumeYes)
	if len(out.Found) > 0 {
		return &historyFindings{n: len(out.Found)}
	}
	return nil
}

// editorInstaller is the side-effecting half of `secure`, kept behind an
// interface so the flow is tested without editing a real editor's
// configuration on whatever machine runs the tests.
type editorInstaller struct{}

// Editors lists the editors present that can take a prompt hook.
//
// Present, not supported: offering to configure Cursor on a machine
// without Cursor writes a file for an editor nobody has, and the summary
// would then claim a protection that protects nothing.
func (editorInstaller) Editors() []string {
	var out []string
	// The editor's own state directory, not its settings file: the file
	// is what we are about to write and is usually absent before we do.
	//
	// os.Stat and not exists(), which answers false for a directory by
	// design — so the first version of this reported "no editor here"
	// on a machine with Claude Code on it, and offered to protect
	// nothing.
	if p := claudeHooksFile(); p != "" && isDir(filepath.Dir(p)) {
		out = append(out, "Claude Code")
	}
	if p := cursorHooksFile(); p != "" && isDir(filepath.Dir(p)) {
		out = append(out, "Cursor")
	}
	return out
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func (editorInstaller) HookInto(editor string) error {
	var args []string
	switch editor {
	case "Claude Code":
		args = []string{"--yes"}
	case "Cursor":
		args = []string{"--cursor", "--yes"}
	default:
		return fmt.Errorf("no hook is known for %s", editor)
	}

	// --yes because secure already asked: asking twice for one decision
	// is what this command exists to remove.
	//
	// And its output is captured rather than printed. hookInstall is a
	// command in its own right and explains itself at length — the path
	// it wrote, that the editor reads the file at startup, how to remove
	// it with a second command. Printed inside this flow that is a wall
	// of text between the findings and the one line that matters, naming
	// commands the person was told they would not need.
	//
	// Kept, not discarded: on failure it is the only description of what
	// went wrong, and a security tool that reports a failure with no
	// detail has reported nothing.
	var captured strings.Builder
	prev := stdout
	stdout = &captured
	err := hookInstall(args)
	stdout = prev
	if err != nil {
		return fmt.Errorf("%w — %s", err, strings.TrimSpace(captured.String()))
	}
	return nil
}
