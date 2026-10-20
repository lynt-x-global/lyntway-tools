package secure

import (
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/agentsecrets"
)

// goos names the platform, behind a variable so a test running on one can
// check what a reader on another is told. The caveat it feeds is the only
// warning in this package that a macOS test run would never see.
var goos = func() string { return runtime.GOOS }

// writeFound is the first thing anybody sees.
//
// Grouped by credential and ordered by how far each one spread, because
// the number that matters is how many things have to be revoked and not
// how many lines a scanner can print. One key in twenty-one files is one
// revocation.
func writeFound(out io.Writer, o Outcome) {
	res := o.Scan
	size := fmt.Sprintf("%d file%s", res.Files, plural(res.Files))
	switch {
	case res.Bytes > 1<<30:
		size += fmt.Sprintf(", %.1f GB", float64(res.Bytes)/(1<<30))
	case res.Bytes > 1<<20:
		size += fmt.Sprintf(", %d MB", res.Bytes>>20)
	}

	if res.Sources == 0 {
		// Nothing found because nothing was looked at is not a clean
		// machine. Said as its own thing, with somewhere to go.
		fmt.Fprint(out, "\nNo coding-agent files on this machine, so there was nothing to read.\n\n"+
			"That is not a clean machine — it means none of the places these tools keep\n"+
			"their history exists here. If your agent runs as another user or inside a\n"+
			"container, run this there.\n\n")
		return
	}

	if len(o.Found) == 0 {
		if res.Complete() {
			fmt.Fprintf(out, "\nRead %s. No credentials in what your agents have written.\n\n", size)
		} else {
			fmt.Fprintf(out, "\nRead %s and found no credentials — but %d file(s) could not be read,\n"+
				"so this is an incomplete look rather than a clean machine.\n\n", size, len(res.Unread))
		}
		return
	}

	fmt.Fprintf(out, "\nYour AI tools have seen %d credential%s.\n", len(o.Found), plural(len(o.Found)))
	fmt.Fprintf(out, "%d sighting%s across %s.\n\n", len(res.Findings), plural(len(res.Findings)), size)

	// Before the list. A reader who takes the number and stops has to
	// have been told this; one who finds it underneath has already
	// decided the tool exaggerates.
	fmt.Fprint(out, "Some will be test fixtures or examples your agent read, not live keys —\n"+
		"a fixture is built to look like the real thing. The last four characters and\n"+
		"the fingerprint are here so you can tell which.\n\n")

	for i, c := range o.Found {
		if i == 12 {
			fmt.Fprintf(out, "  … and %d more. `lyntway history` lists them all.\n", len(o.Found)-12)
			break
		}
		kinds := make([]string, 0, 3)
		for _, k := range c.Kinds() {
			kinds = append(kinds, string(k))
		}
		fmt.Fprintf(out, "  %-28s …%-5s  %s  %d×  %s\n",
			c.Label, c.Last4, c.Fingerprint, len(c.Seen), strings.Join(kinds, ", "))
	}

	if !res.Complete() {
		fmt.Fprintf(out, "\n%d file%s could not be read, so a credential in one of those is not in\n"+
			"the count above.\n", len(res.Unread), plural(len(res.Unread)))
	}

	// The platform caveat belongs with the count, not at the end.
	//
	// On a platform whose location table has not been checked against a
	// real machine, a wrong path yields no finding and counts as a source
	// that did not exist — which leaves Complete() true. It is the one
	// shortfall here that looks exactly like a clean machine, so the
	// warning has to sit next to the number it undermines.
	if c := agentsecrets.PlatformCaveat(goos()); c != "" {
		fmt.Fprintf(out, "\n%s\n", c)
	}

	// The remedy, and the order is deliberate: the file cannot be fixed,
	// so the credential has to be.
	fmt.Fprint(out, "\nThese files are not the leak to fix — the credential is. A key in a\n"+
		"transcript cannot be rotated out of it: nobody edits that file, no linter\n"+
		"reads it, and every backup has a copy. Revoke and reissue.\n")

	// Where, and not only that. This is the whole command for most
	// people — they will not go on to run `lyntway history` to find the
	// console page, so telling them to revoke without saying where is
	// telling them nothing they can act on.
	if advice := agentsecrets.RotationAdvice(o.Found); len(advice) > 0 {
		fmt.Fprint(out, "\n  Heaviest first:\n")
		for i, line := range advice {
			// Capped like the list above it. A machine with nine
			// providers on it does not need nine lines here to get the
			// point, and `lyntway history` prints every one.
			if i == 5 {
				fmt.Fprintf(out, "    … and %d more. `lyntway history` names them all.\n", len(advice)-5)
				break
			}
			fmt.Fprintf(out, "    %s\n", line)
		}
	}
	fmt.Fprintln(out)
}

// writeDone says what changed, in the words of what it now prevents.
func writeDone(out io.Writer, o Outcome) {
	var done, failed []Step
	for _, s := range o.Steps {
		if s.Done {
			done = append(done, s)
		} else {
			failed = append(failed, s)
		}
	}

	if len(done) > 0 {
		fmt.Fprint(out, "\nDone. A prompt carrying a credential is now refused before it is sent:\n")
		for _, s := range done {
			fmt.Fprintf(out, "  ✓ %s\n", s.What)
		}
	}
	for _, s := range failed {
		// Named, never swallowed. A half-configured machine that reports
		// success is worse than one that reports nothing.
		fmt.Fprintf(out, "  ✗ %s — %s\n", s.What, s.Why)
	}

	if len(failed) > 0 {
		fmt.Fprint(out, "\nSome of it did not take. The machine is partly configured, and the\n"+
			"credentials above still need revoking either way.\n")
	}

	// The limit, printed at the moment the claim is made.
	//
	// This hook reads prompts. It does not see the agent opening a .env
	// through its own file tool, or a shell command printing a key —
	// that is a different hook point, which these editors support and we
	// do not install yet. Leaving it unsaid would let somebody read
	// "done" as cover they do not have, and they would learn the
	// difference from a competitor's comparison table rather than from
	// us. Same rule as a receipt: never claim more than happened.
	if len(done) > 0 {
		fmt.Fprint(out, "\nWhat this does not do: it reads prompts, so it stops a key you type or\n"+
			"paste. It does not stop the agent reading a .env through its own file tool.\n"+
			"Keep the value out of the file instead — `lyntway keys migrate`.\n")
	}

	fmt.Fprint(out, "\n  lyntway undo              puts every file back, byte for byte\n"+
		"  lyntway guard -- claude   run the agent with its traffic governed, and a\n"+
		"                            signed receipt of what was stopped\n\n")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Credentials is the grouped view, re-exported so a caller does not have
// to reach into the scan result to render the same thing twice.
func Credentials(res agentsecrets.Result) []agentsecrets.Credential { return res.Credentials() }
