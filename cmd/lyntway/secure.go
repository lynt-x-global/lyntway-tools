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
		project   = fs.String("project", "", "read this project instead of the directory this was run in")
	)
	fs.Usage = func() {
		fmt.Fprint(stdout, "lyntway secure — find what your AI tools have already seen\n\n"+
			"Usage:\n  lyntway secure [--project DIR] [--yes]\n\n"+
			"Reads the transcripts, prompt histories, pasted buffers, shell snapshots and\n"+
			"MCP configuration the coding agents on this machine wrote to disk, then the\n"+
			"project you are standing in, reports the credentials in both, and then — after\n"+
			"asking once — makes your editor refuse a prompt carrying a credential before\n"+
			"it is sent.\n\n"+
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
	// The project defaults to where the command was run. It used to need
	// --project, which meant the common case — somebody standing in
	// their repository — reported on transcripts and said nothing about
	// the .env two lines away. The flag now overrides the default rather
	// than enabling the behaviour.
	projectDir, readProject := projectToRead(*project, home)
	if readProject {
		sources = append(sources, agentsecrets.ProjectSources(projectDir)...)
	}

	res := agentsecrets.ScanProgress(sources, agentsecrets.DefaultRules(), progressTo(false))
	allow, err := agentsecrets.LoadAllow(filepath.Join(home, ".lyntway"))
	if err != nil {
		return fmt.Errorf("reading %s: %w", filepath.Join(home, ".lyntway", agentsecrets.AllowFile), err)
	}
	res = res.Excluding(allow)

	in := secure.Input{Scan: res, ReadProject: readProject}
	if readProject {
		in.InFiles = projectKeys(projectDir)
		// What to call it, not where it is. Somebody standing in the
		// directory does not need its absolute path read back to them,
		// and under --project the path they typed is the name they
		// already recognise.
		in.ProjectDir = "this project"
		if *project != "" {
			in.ProjectDir = *project
		}
	}
	clearProgress()

	out := secure.Run(stdout, in, editorInstaller{}, ask, *assumeYes)
	if len(out.Found) > 0 || len(out.InFiles) > 0 {
		return &secureFindings{history: len(out.Found), inFiles: len(out.InFiles)}
	}
	return nil
}

// secureFindings is the non-zero exit, and it names the two sources
// apart.
//
// `historyFindings` says "your agents have already seen", which is true
// of a transcript and false of a .env. Summing the two under that
// sentence told somebody with a clean history and two keys in a config
// file that their agents had read both — a report claiming more than
// happened, over the one subject this tool exists to be exact about.
type secureFindings struct{ history, inFiles int }

func (e *secureFindings) Error() string {
	switch {
	case e.history > 0 && e.inFiles > 0:
		return fmt.Sprintf("%d credential%s your agents have already seen, and %d still in this project",
			e.history, pluralS(e.history), e.inFiles)
	case e.history > 0:
		return fmt.Sprintf("%d credential%s your agents have already seen", e.history, pluralS(e.history))
	default:
		return fmt.Sprintf("%d key%s in this project's own files", e.inFiles, pluralS(e.inFiles))
	}
}

// projectToRead decides which directory to walk for keys of its own.
//
// Refuses the home directory and anything above it. A recursive walk from
// $HOME is every repository, cache and backup on the machine: minutes of
// work, a wall of findings from other people's dependencies, and nothing
// a person standing there asked for. `--project` is still honoured as
// typed, because somebody naming a directory has decided.
func projectToRead(flag, home string) (string, bool) {
	if flag != "" {
		abs, err := filepath.Abs(flag)
		if err != nil {
			return "", false
		}
		return abs, true
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	abs, err := filepath.Abs(wd)
	if err != nil {
		return "", false
	}
	if home != "" {
		rel, err := filepath.Rel(abs, home)
		// home is at or below here, so here is $HOME or a parent of it.
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", false
		}
	}
	if abs == filepath.Dir(abs) { // the filesystem root
		return "", false
	}
	return abs, true
}

// projectKeys walks the project for credentials in its own files.
//
// Declared values are dropped, not counted: a value sitting in a gitleaks
// allowlist or a detect-secrets baseline is a claim the repository has
// already made in a reviewable place, and counting them put 73 findings
// in front of a first run in this very repository, 68 of them its own
// fixtures. `lyntway scan` is where the full list including those lives.
//
// A walk that fails returns nothing rather than failing the command. The
// history scan above it has already succeeded and is worth printing; a
// project that cannot be read is a smaller fact than one this command
// could not report at all.
func projectKeys(dir string) []secure.InFile {
	hits, _, _, err := scanPaths([]string{dir})
	if err != nil {
		return nil
	}
	found, _ := splitDeclared(hits)
	out := make([]secure.InFile, 0, len(found))
	for _, h := range found {
		rel, err := filepath.Rel(dir, h.File)
		if err != nil {
			rel = h.File
		}
		out = append(out, secure.InFile{
			Path:  filepath.ToSlash(rel),
			Line:  h.Line,
			Label: h.Label,
			Last4: h.Last4,
			// Upstream, not Catalog: the scanner keeps those apart
			// precisely because a catalog match names a provider and
			// never means the key can be moved.
			Migratable: h.Upstream != "",
		})
	}
	return out
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
