package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/agentsecrets"
)

// `lyntway history` — the credentials this machine's coding agents have
// already seen.
//
// # Why this is a command and not a flag on scan
//
// `lyntway scan` answers "is there a key in this project". This answers
// "is there a key in the places my agents wrote to disk", and the two
// have different subjects, different output and different remedies. A
// key in a .env is rotated and the file rewritten. A key in a transcript
// is in a file nobody edits, no linter reads, no pre-commit hook sees,
// and a laptop backup copies — and the remedy is to revoke the
// credential, because the file will outlive any attempt to clean it.
//
// # What it never does
//
// It sends nothing, it prints no value, and it changes no file. See the
// package documentation in agentsecrets for why each of those is a rule
// rather than a default.

func historyCommand(args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		asJSON     = fs.Bool("json", false, "report as JSON")
		project    = fs.String("project", "", "also read the agent files kept inside this project directory")
		writeAllow = fs.Bool("allow", false, "record every credential in this report as judged, so later runs do not repeat it")
		all        = fs.Bool("all", false, "list every sighting, not one line per credential")
	)
	fs.Usage = func() {
		fmt.Fprint(stdout, "lyntway history — what this machine's AI coding agents have already seen\n\n"+
			"Usage:\n  lyntway history [--project DIR] [--all] [--json]\n  lyntway history --allow\n\n"+
			"Reads the transcripts, prompt histories, pasted buffers, shell snapshots and\n"+
			"MCP configuration files the coding agents on this machine write to disk, and\n"+
			"reports the credentials in them. Sends nothing. Prints no key — a label, the\n"+
			"last four characters and a fingerprint, which is what you need to revoke the\n"+
			"right one and is not enough to use it. Changes no file.\n\n"+
			"Exits non-zero when it finds something, so it works as a check.\n\n"+
			"--allow writes "+agentsecrets.AllowFile+" under ~/.lyntway, recording the\n"+
			"fingerprints in this report as judged. Fingerprints, never values, so the\n"+
			"file is safe to keep and to read later.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("this machine has no home directory to look in: %w", err)
	}
	host := agentsecrets.Host{
		GOOS:         runtime.GOOS,
		Home:         home,
		AppData:      os.Getenv("APPDATA"),
		LocalAppData: os.Getenv("LOCALAPPDATA"),
	}
	sources := agentsecrets.Sources(host)
	if *project != "" {
		sources = append(sources, agentsecrets.ProjectSources(*project)...)
	}

	res := agentsecrets.ScanProgress(sources, agentsecrets.DefaultRules(), progressTo(*asJSON))

	settings := filepath.Join(home, ".lyntway")
	allow, err := agentsecrets.LoadAllow(settings)
	if err != nil {
		// Reported, never ignored: an allowlist that failed to load looks
		// exactly like one that allows nothing, and the person would be
		// handed back every finding they had already judged with no sign
		// that anything went wrong.
		return fmt.Errorf("reading %s: %w", filepath.Join(settings, agentsecrets.AllowFile), err)
	}
	res = res.Excluding(allow)
	creds := res.Credentials()
	clearProgress()

	if *writeAllow {
		return recordJudged(settings, creds)
	}
	if *asJSON {
		return historyJSON(res, creds)
	}
	historyReport(res, creds, *all)
	if len(creds) > 0 {
		return &historyFindings{n: len(creds)}
	}
	return nil
}

// historyFindings makes the process exit non-zero, so this works as a
// check. Its own type rather than scan's, because scan's sentence is
// "N keys found" — about a project, where the remedy is to edit a file —
// and the remedy here is to revoke a credential.
type historyFindings struct{ n int }

func (e *historyFindings) Error() string {
	return fmt.Sprintf("%d credential%s your agents have already seen", e.n, pluralS(e.n))
}

// progressTo returns something to print while the scan runs, or nil.
//
// To stderr, so --json on stdout stays a document a script can parse.
// Only when stderr is a terminal: a carriage return written into a log
// file or a CI transcript is noise, and the same counter on 2,800 lines
// is worse than no counter. Nil under --json as well, because a caller
// redirecting stdout to a file is usually not watching anything.
func progressTo(asJSON bool) func(int, int64) {
	if !wantsProgress(asJSON, stderrIsTerminal()) {
		return nil
	}
	return func(files int, bytes int64) {
		// Every thirty-second file: often enough to look alive, rarely
		// enough that the printing is not itself the cost.
		if files%32 != 0 {
			return
		}
		fmt.Fprintf(os.Stderr, "\r  reading… %d files, %d MB", files, bytes>>20)
	}
}

// wantsProgress is the decision, apart from the mechanism.
//
// Separated because the first version of this folded both into
// progressTo, and the test asserting "--json gets no counter" could not
// fail: `go test` captures stderr, so the terminal check returned nil
// whatever --json said. A test that cannot fail for its own reason is
// the thing this repository keeps catching itself at.
func wantsProgress(asJSON, terminal bool) bool {
	return !asJSON && terminal
}

func stderrIsTerminal() bool {
	info, err := os.Stderr.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// clearProgress removes the counter before anything is printed over it.
func clearProgress() {
	if !stderrIsTerminal() {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[K")
}

// historyReport prints what was found, and what was read.
func historyReport(res agentsecrets.Result, creds []agentsecrets.Credential, all bool) {
	readable := fmt.Sprintf("%d file%s", res.Files, pluralS(res.Files))
	if res.Bytes > 1<<30 {
		readable += fmt.Sprintf(", %.1f GB", float64(res.Bytes)/(1<<30))
	} else if res.Bytes > 1<<20 {
		readable += fmt.Sprintf(", %d MB", res.Bytes>>20)
	}

	if len(creds) == 0 {
		// Three different facts, and they were one sentence.
		//
		// Nothing found because nothing was looked at is not a clean
		// machine; it is a tool that found no agent on this one. The
		// first version said "No credentials … Read 0 files across 0
		// locations" for both, which on a fresh laptop or a CI box reads
		// as "this does not work" — and whoever ran it is right to think
		// so, because it told them nothing they could act on.
		if res.Sources == 0 {
			fmt.Fprint(stdout, "\nNo coding-agent files on this machine, so there was nothing to read.\n\n"+
				"That is not the same as a clean machine. It means none of the places these tools\n"+
				"keep their history exists here — no Claude Code, Codex, Cursor, Windsurf, Gemini\n"+
				"CLI, Cline, Aider or Continue state under your home directory.\n\n"+
				"  If an agent runs as another user or in a container, run this there.\n"+
				"  If the history is inside a project, add it:  lyntway history --project .\n"+
				"  For keys in the project's own files instead:  lyntway scan\n\n")
			return
		}
		// Never "clean" when something went unread. The claim is about
		// what was read, and if anything was not, that is the sentence —
		// the same rule the readiness check is under, where "found
		// nothing" over a sample written to be found is a failure.
		if res.Complete() {
			fmt.Fprintf(stdout, "\nNo credentials in what your agents have written here. Read %s across %d location%s.\n\n",
				readable, res.Sources, pluralS(res.Sources))
			if c := agentsecrets.PlatformCaveat(runtime.GOOS); c != "" {
				fmt.Fprintf(stdout, "%s\n\n", c)
			}
		} else {
			fmt.Fprintf(stdout, "\nNo credentials in the %s this could read — but %d file%s could not be read, "+
				"so this is not a clean machine, it is an incomplete look.\n\n",
				readable, len(res.Unread), pluralS(len(res.Unread)))
		}
		if res.Allowed > 0 {
			fmt.Fprintf(stdout, "%d finding%s already judged and not shown. They are in ~/.lyntway/%s.\n\n",
				res.Allowed, pluralS(res.Allowed), agentsecrets.AllowFile)
		}
		printUnread(res)
		return
	}

	sightings := len(res.Findings)
	fmt.Fprintf(stdout, "\nYour coding agents have seen %d credential%s.\n", len(creds), pluralS(len(creds)))
	// Beside the number, not in a footnote: on a platform the table has
	// not been checked on, a low count is the thing to distrust.
	if c := agentsecrets.PlatformCaveat(runtime.GOOS); c != "" {
		fmt.Fprintf(stdout, "%s\n", c)
	}
	fmt.Fprintf(stdout, "%d sighting%s across %s, in %s.\n\n",
		sightings, pluralS(sightings), readable, strings.Join(res.Tools(), ", "))

	// Said before the list, not after it.
	//
	// The ruleset classifies a string by its shape, and a test fixture is
	// built to have the shape of the thing it stands in for — this
	// repository's own generate AKIA keys and connection strings on
	// purpose. So an agent that read a test suite has seen credentials by
	// this measure, and some of these will be exactly that. Leading with
	// a number and letting somebody discover the caveat at the bottom is
	// how a security tool gets a reputation for crying wolf, and the
	// fingerprint is here so they can settle each one themselves.
	fmt.Fprint(stdout, "Some of these will be test fixtures or documented examples your agent read\n"+
		"rather than live keys: a fixture is built to have the shape of the real thing.\n"+
		"The last four characters and the fingerprint are here so you can tell which.\n\n")

	// Capped unless asked. The first real run printed all 154, about five
	// hundred lines, and a list that long is scrolled past rather than
	// read — the ones that matter are at the top, ordered by how far
	// each spread. `secure` has always capped at twelve; this did not.
	const shown = 20
	for i, c := range creds {
		if i == shown && !all {
			fmt.Fprintf(stdout, "\n  … and %d more, smallest first. `lyntway history --all` lists every one.\n",
				len(creds)-shown)
			break
		}
		kinds := make([]string, 0, 4)
		for _, k := range c.Kinds() {
			kinds = append(kinds, string(k))
		}
		// A PEM block has no useful last four, so the column is blank
		// and the fingerprint is the only thing that tells two apart.
		tail := "…" + c.Last4
		if c.Last4 == "" {
			tail = ""
		}
		fmt.Fprintf(stdout, "  %-28s %-6s  %s\n", c.Label, tail, c.Fingerprint)
		fmt.Fprintf(stdout, "      %d sighting%s in %s\n", len(c.Seen), pluralS(len(c.Seen)), strings.Join(kinds, ", "))
		if all {
			for _, f := range c.Seen {
				where := f.Path
				if f.Line > 0 {
					where = fmt.Sprintf("%s:%d", f.Path, f.Line)
				}
				fmt.Fprintf(stdout, "        %s\n", where)
			}
		} else {
			fmt.Fprintf(stdout, "        first: %s\n", firstPlace(c))
		}
	}

	if res.Allowed > 0 {
		fmt.Fprintf(stdout, "\n%d finding%s already judged and not shown.\n", res.Allowed, pluralS(res.Allowed))
	}
	printUnread(res)

	// Ordered by what it costs the reader.
	//
	// The first version led with `keys migrate`, which answers "not
	// signed in on this machine" — so the first thing a free user was
	// told to do was the one thing that stops and asks them to sign up.
	// A report that has just shown somebody a problem and then gates the
	// fix has spent the only credit it had.
	fmt.Fprint(stdout, "\nWhat to do with this\n"+
		"  These files are not the leak to fix; the credential is. A key in a transcript\n"+
		"  cannot be rotated out of it — the file is not edited, is not linted, and is\n"+
		"  copied by every backup. Revoke and reissue, in that order.\n")

	// The console page for each provider found, not a general lecture.
	//
	// The paragraph above has said "revoke" since the first version and
	// it was still the step nobody took, because knowing to revoke and
	// knowing where are different problems and only the second one is
	// ours to solve. No key is named to any of these pages — we cannot
	// tell which key it is without sending the value somewhere.
	if advice := agentsecrets.RotationAdvice(creds); len(advice) > 0 {
		fmt.Fprint(stdout, "\n  Where to revoke, heaviest first:\n")
		for _, line := range advice {
			fmt.Fprintf(stdout, "    %s\n", line)
		}
	}

	fmt.Fprint(stdout, "\n  Then stop the next one. Neither of these needs an account:\n"+
		"    lyntway hook install      refuse a prompt carrying a key, before it is sent\n"+
		"    lyntway guard -- claude   run the agent with its traffic governed, and a\n"+
		"                              signed receipt of what was stopped\n\n"+
		// Said here and not left for the reader to discover.
		//
		// The hook reads the prompt. It does not see the agent opening a
		// .env through its own file tool, or a shell command printing a
		// key, because those are a different hook point that we do not
		// install yet. Letting "stop the next one" stand without this is
		// the same defect as a receipt claiming more than happened: the
		// reader would take a narrow protection for a general one and
		// find out from somebody else.
		// A command name is never broken across lines. The first version
		// wrapped "lyntway keys migrate" after the first word, which
		// cannot be copied out of a terminal and was caught by the test
		// that looks for the command in the output.
		"  What that does not cover: the hook reads prompts, so it stops a key you type\n"+
		"  or paste. It does not stop the agent reading a .env through its own file tool,\n"+
		"  or a shell command printing one. To put the value beyond either of those,\n"+
		"  `lyntway keys migrate` takes it out of the file and holds it, so the\n"+
		"  agent reads a Lyntway key whatever it opens. That one needs an account.\n\n"+
		"  Judged these already? `lyntway history --allow` records them so later runs\n"+
		"  report only what is new.\n\n")
}

func firstPlace(c agentsecrets.Credential) string {
	if len(c.Seen) == 0 {
		return ""
	}
	f := c.Seen[0]
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d — %s", f.Path, f.Line, f.Why)
	}
	// No line because the file is a store this does not parse. Said
	// rather than left as a bare path, so nobody looks for line 1.
	return fmt.Sprintf("%s — %s (no line: a store read as bytes)", f.Path, f.Why)
}

func printUnread(res agentsecrets.Result) {
	if res.Complete() {
		return
	}
	fmt.Fprintf(stdout, "\nNot read (%d):\n", len(res.Unread))
	for i, u := range res.Unread {
		if i == 6 {
			fmt.Fprintf(stdout, "  … and %d more\n", len(res.Unread)-6)
			break
		}
		fmt.Fprintf(stdout, "  %s — %s\n", u.Path, u.Reason)
	}
	fmt.Fprint(stdout, "  A credential in one of these would not be in the count above.\n")
}

// recordJudged appends this report's fingerprints to the allowlist.
func recordJudged(dir string, creds []agentsecrets.Credential) error {
	if len(creds) == 0 {
		fmt.Fprint(stdout, "\nNothing to record.\n\n")
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, agentsecrets.AllowFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "\n# judged by `lyntway history --allow`\n"); err != nil {
		return err
	}
	for _, line := range agentsecrets.AllowLines(creds) {
		if _, err := fmt.Fprintln(f, line); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "\nRecorded %d credential%s as judged in %s.\n"+
		"Fingerprints only — no value is written to that file.\n"+
		"Revoking them is still yours to do; this only stops them being reported again.\n\n",
		len(creds), pluralS(len(creds)), path)
	return nil
}

func historyJSON(res agentsecrets.Result, creds []agentsecrets.Credential) error {
	type sighting struct {
		Tool string `json:"tool"`
		Kind string `json:"kind"`
		Path string `json:"path"`
		Line int    `json:"line,omitempty"`
	}
	type credential struct {
		Fingerprint string     `json:"fingerprint"`
		Label       string     `json:"label"`
		Class       string     `json:"class"`
		Last4       string     `json:"last4"`
		Seen        []sighting `json:"seen"`
	}
	out := struct {
		Credentials []credential `json:"credentials"`
		Sightings   int          `json:"sightings"`
		FilesRead   int          `json:"files_read"`
		BytesRead   int64        `json:"bytes_read"`
		Locations   int          `json:"locations"`
		Allowed     int          `json:"already_judged,omitempty"`
		// Complete is the field a script should branch on: false means a
		// file could not be read, so an empty credential list is not a
		// clean machine.
		Complete bool     `json:"complete"`
		Unread   []string `json:"unread,omitempty"`
		Ruleset  string   `json:"ruleset"`
	}{
		Sightings: len(res.Findings),
		FilesRead: res.Files,
		BytesRead: res.Bytes,
		Locations: res.Sources,
		Allowed:   res.Allowed,
		Complete:  res.Complete(),
		Ruleset:   agentsecrets.DefaultRules().Version(),
	}
	for _, c := range creds {
		entry := credential{Fingerprint: c.Fingerprint, Label: c.Label, Class: c.Class, Last4: c.Last4}
		for _, f := range c.Seen {
			entry.Seen = append(entry.Seen, sighting{Tool: f.Tool, Kind: string(f.Kind), Path: f.Path, Line: f.Line})
		}
		out.Credentials = append(out.Credentials, entry)
	}
	for _, u := range res.Unread {
		out.Unread = append(out.Unread, u.Path+": "+u.Reason)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	if len(creds) > 0 {
		return &historyFindings{n: len(creds)}
	}
	return nil
}
