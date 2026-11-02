package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// Finding provider keys where they should not be: in a file about to be
// committed, or in a prompt about to be sent.
//
// The same finder serves `lyntway scan` and `lyntway hook prompt`, and it
// is built from two sources that already exist rather than a third list
// that would drift from both: the credential rules in the detect package,
// which the gateway itself runs, and the variable-name and value-prefix
// shapes `keys migrate` uses to read a .env file. A key the gateway would
// flag in flight is flagged here before it gets that far, and a key
// `keys migrate` would offer to move is named as one it can move.
//
// Nothing here prints a value. A hit carries the last four characters,
// which is enough to recognise a key and not enough to use it, and the
// tests read everything the command writes and look for the rest.

// keyHit is one credential found in text.
type keyHit struct {
	// Concept is set when this file is a concept document in an Open
	// Knowledge Format bundle — the context files agents read. Nil
	// otherwise, which is almost always.
	Concept *okfConcept

	File string
	Line int // 1-based; the line the match starts on

	// Label is what to call it to a person: "OpenAI key", "GitHub token".
	Label string

	// Class is the detect class, or provider.<upstream> for a key known
	// only by the variable it was assigned to or the prefix it carries.
	Class string

	Last4 string

	// Upstream is set when `keys migrate` could hold this key. A GitHub
	// token or a private key is reported and cannot be migrated, and the
	// advice printed beside it must not say otherwise.
	Upstream string

	// Catalog is the catalog entry this key's prefix belongs to, when the
	// catalog recognised it and the seven migratable shapes did not. It
	// names a provider; it never means the key can be moved, which is why
	// it is separate from Upstream rather than folded into it.
	Catalog string

	// Declared names the secret-scanner configuration this value sits in,
	// when it sits in one: a gitleaks allowlist, a detect-secrets
	// baseline, a git-secrets allowed list. Those files exist to say
	// "these strings are not secrets", and a value in one is a claim the
	// repository already made in a reviewable place.
	//
	// Reported and not counted, rather than skipped. Skipping would make
	// adding a leaked key to a gitleaks allowlist a way to silence this
	// scanner, which is the exact move that must never work. Counting
	// would put 73 findings in front of somebody on their first run of
	// `lyntway scan` in this very repository, 68 of which are its own
	// test fixtures — and a first screen that is mostly wrong is a tool
	// nobody runs twice.
	Declared string

	// Live is what the provider said about this credential when --check
	// asked, and livenessUnknown — the zero value — when nothing asked.
	// That the default is "unknown" rather than "revoked" is the point:
	// see checklive.go.
	Live liveness

	// value is the credential itself, and it is empty unless --check is
	// going to need it.
	//
	// Unexported deliberately. Every report this tool writes — text,
	// JSON, SARIF, the receipt — is built from the fields beside it, and
	// an encoder cannot reach this one however somebody later extends
	// them. The scanner has never retained a credential and the default
	// has to stay that way; retainValues is what turns it on, for the one
	// run that is about to present it to its issuer.
	value string
}

// retainValues says whether findKeys should keep the credential it found.
//
// A switch rather than a parameter: findKeys has eight call sites, one of
// them the hook that runs inside Claude Code's prompt path, and all but
// one of them must never hold a value. Threading a false through all of
// them to serve a single flag would put the dangerous option in every
// signature. It is set once in scanCommand before any scanning starts and
// never written again, which is what makes it safe beside the worker pool.
var retainValues bool

// skipped records files a scan did not read, and why.
//
// # Why this is not an implementation detail
//
// scanPaths skips two kinds of file: anything with a NUL byte in its
// first 8 KB, which is how a binary is told from text, and anything over
// four megabytes. Both are the right call — scanning a PNG produces
// nothing but noise, and reading a 2 GB log to look for a key is how a
// pre-commit hook becomes something people remove.
//
// Neither was ever mentioned. On 2 November 2026 a directory holding
// three files, each with a live OpenAI key in it, produced:
//
//	No provider keys in 0 files.
//
// and exit 0, which passes a CI gate. One file had a single NUL byte on
// its first line; one had a NUL at byte 7,999; one was 4.2 MB. Writing
// a NUL at the top of a .env is a one-character way to hide every secret
// in it from this scanner, and nothing in the output suggested anything
// had been passed over.
//
// The skipping stays. What changes is that "no provider keys" is now a
// claim about a number of files the reader can see, with the rest named
// — the same rule the receipts are built on, applied to the tool that
// writes them.
type skippedFile struct {
	Path   string
	Reason string
}

// declaringFiles are the secret-scanner configurations whose whole point
// is to list strings that are not secrets.
//
// Matched by name because that is what the tools match by. The value is
// what to call the file to a person, and is printed, so somebody reading
// the output can go and check the claim rather than take it.
var declaringFiles = map[string]string{
	".gitleaks.toml":    "gitleaks allowlist",
	"gitleaks.toml":     "gitleaks allowlist",
	".secrets.baseline": "detect-secrets baseline",
	".gitallowed":       "git-secrets allowed list",
}

// allowMarker on a line means the author has looked and this is not a
// key — a fixture, a documented example. The scanner trusts the marker
// and a reviewer can grep for it, which is the point of making it a word.
const allowMarker = "lyntway:allow"

// credentialRules is the gateway's ruleset, used here for its secret.*
// classes only. Built once: compiling the patterns per file would make
// the scan of a large repository visibly slow.
var credentialRules = detect.Default()

// classUpstreams maps the detect classes `keys migrate` can hold to the
// upstream it would store them under.
var classUpstreams = map[detect.Class]string{
	detect.ClassOpenAIKey:    "openai",
	detect.ClassAnthropicKey: "anthropic",
	// Google and xAI were found by the prefix list in dotenv.go until
	// 2 November 2026, when detect gained rules for them. The ruleset now
	// claims the span first, so without these two lines `keys migrate`
	// stopped recognising a key it had been able to move into the gateway
	// — the finding was still correct and the remedy silently went away.
	detect.ClassGoogleAPIKey: "gemini",
	detect.ClassXAIKey:       "xai",
}

// shapePatterns are the value prefixes from providerShapes that the
// detect ruleset has no rule for, as patterns that match a bare value —
// the way a key appears in a prompt, with no variable name beside it.
// Built from providerShapes so a provider added there is found here
// without a second edit.
var shapePatterns = buildShapePatterns()

type shapePattern struct {
	Upstream string
	Pattern  *regexp.Regexp
}

func buildShapePatterns() []shapePattern {
	var out []shapePattern
	for _, p := range providerShapes {
		if p.Prefix == "" {
			continue
		}
		if _, known := classUpstreams[classForPrefix(p.Prefix)]; known {
			continue
		}
		out = append(out, shapePattern{
			Upstream: p.Upstream,
			Pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(` + regexp.QuoteMeta(p.Prefix) + `[A-Za-z0-9_-]{16,})`),
		})
	}
	return out
}

// classForPrefix says which detect class already covers a value prefix.
func classForPrefix(prefix string) detect.Class {
	switch prefix {
	case "sk-ant-":
		return detect.ClassAnthropicKey
	case "sk-":
		return detect.ClassOpenAIKey
	}
	return ""
}

// findKeys reports every credential in text, with 1-based line numbers
// offset by firstLine-1 so a hunk of a diff can be scanned in place.
func findKeys(text string, firstLine int) []keyHit {
	if firstLine < 1 {
		firstLine = 1
	}
	lines := strings.Split(text, "\n")
	starts := make([]int, len(lines))
	for i, off := 1, 0; i < len(lines); i++ {
		off += len(lines[i-1]) + 1
		starts[i] = off
	}
	lineOf := func(offset int) int {
		// The first line starting after the offset is the one after the
		// line that holds it.
		return sort.Search(len(starts), func(i int) bool { return starts[i] > offset }) - 1
	}
	allowed := func(line int) bool {
		return line < len(lines) && strings.Contains(lines[line], allowMarker)
	}

	var hits []keyHit
	covered := map[int][][2]int{} // line → spans already reported on it

	// The gateway's rules first: they see the whole text, so a private
	// key block spanning many lines is one finding at the line it starts.
	for _, sp := range credentialRules.Scan([]byte(text)) {
		if !detect.HasClassPrefix(sp.Class, "secret") {
			continue
		}
		line := lineOf(sp.Start)
		if allowed(line) || looksLikePlaceholder(sp.Value) {
			continue
		}
		hit := keyHit{
			Line:     firstLine + line,
			Label:    detect.Label(sp.Class),
			Class:    string(sp.Class),
			Last4:    last4(sp.Value),
			Upstream: classUpstreams[sp.Class],
		}
		if retainValues {
			hit.value = sp.Value
		}
		hits = append(hits, hit)
		covered[line] = append(covered[line], [2]int{sp.Start - starts[line], sp.End - starts[line]})
	}

	overlaps := func(line, from, to int) bool {
		for _, c := range covered[line] {
			if from < c[1] && to > c[0] {
				return true
			}
		}
		return false
	}

	for i, l := range lines {
		if allowed(i) {
			continue
		}
		for _, sp := range shapePatterns {
			for _, m := range sp.Pattern.FindAllStringSubmatchIndex(l, -1) {
				from, to := m[2], m[3]
				value := l[from:to]
				if overlaps(i, from, to) || looksLikePlaceholder(value) {
					continue
				}
				hits = append(hits, keyHit{
					Line:     firstLine + i,
					Label:    upstreamLabel(sp.Upstream),
					Class:    "provider." + sp.Upstream,
					Last4:    last4(value),
					Upstream: sp.Upstream,
				})
				covered[i] = append(covered[i], [2]int{from, to})
			}
		}

		// A key with no recognisable shape, known only by the name it is
		// assigned to: MISTRAL_API_KEY=… is a key because of the left side.
		key, value, _ := parseEnvLine(l)
		if key == "" {
			continue
		}
		upstream, skip, ok := classify(key, value, nil, "")
		if !ok || skip != "" || upstream == "" {
			// The seven migratable shapes did not recognise it. The
			// catalog knows 51 more by prefix, and naming one is the
			// difference between "2 keys found" and "a Stripe key and a
			// Linear key". It cannot be migrated — nothing here holds a
			// Stripe key for anybody — so Upstream stays empty and the
			// advice printed beside it must not offer to move it.
			if n := nameFromCatalog(key, value); n.Entry != "" || n.Ambiguous > 0 {
				from := strings.LastIndex(l, value)
				if from >= 0 && overlaps(i, from, from+len(value)) {
					continue
				}
				label, class := n.Label+" key", "provider."+n.Entry
				if n.Ambiguous > 0 {
					label = fmt.Sprintf("a key matching %d providers", n.Ambiguous)
					class = "provider.ambiguous"
				}
				hits = append(hits, keyHit{
					Line:    firstLine + i,
					Label:   label,
					Class:   class,
					Last4:   last4(value),
					Catalog: n.Entry,
				})
			}
			continue
		}
		from := strings.LastIndex(l, value)
		if from >= 0 && overlaps(i, from, from+len(value)) {
			continue
		}
		hits = append(hits, keyHit{
			Line:     firstLine + i,
			Label:    upstreamLabel(upstream),
			Class:    "provider." + upstream,
			Last4:    last4(value),
			Upstream: upstream,
		})
	}

	sort.SliceStable(hits, func(a, b int) bool { return hits[a].Line < hits[b].Line })
	return hits
}

// upstreamLabel names a provider key the way detect.Label would, so the
// two sources read alike on a screen.
func upstreamLabel(upstream string) string {
	switch upstream {
	case "openai":
		return "OpenAI key"
	case "anthropic":
		return "Anthropic key"
	case "gemini":
		return "Gemini key"
	case "xai":
		return "xAI key"
	}
	return strings.ToUpper(upstream[:1]) + upstream[1:] + " key"
}

func last4(value string) string {
	if len(value) <= 4 {
		return strings.Repeat("•", len(value))
	}
	return value[len(value)-4:]
}

// scanCommand is `lyntway scan`.
//
// The flags `--diff` and `--format github` are a contract with the GitHub
// Action, which runs `lyntway scan --diff <base> --format github` and
// relies on exit status 1 when anything is found. Change them and the
// action breaks on every repository that uses it.
func scanCommand(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	base := fs.String("diff", "", "scan only the lines added since this git revision (a branch, tag or commit)")
	staged := fs.Bool("staged", false, "scan only what is staged for the next commit")
	history := fs.Bool("history", false, "scan every commit, not the files on disk")
	check := fs.Bool("check", false, "ask each provider whether the key it issued still works (sends it to that provider, never to Lyntway)")
	format := fs.String("format", "text", "text, json, sarif, or github for ::error annotations a workflow shows inline")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "lyntway scan — find provider keys before they are committed\n"+
			"\n"+
			"Usage:\n"+
			"  lyntway scan [paths...]              scan files (default: the current directory)\n"+
			"  lyntway scan --diff origin/main      scan the lines added since a revision\n"+
			"  lyntway scan --staged                scan only what is about to be committed\n"+
			"  lyntway scan --history               scan every commit this repository still carries\n"+
			"  lyntway scan --check                 and ask each provider whether the key still works\n"+
			"\n"+
			"Prints file:line, what the key is, and its last four characters — never\n"+
			"the key. Exits 1 when anything is found, so it can gate a commit or a\n"+
			"pull request. A line carrying the word "+allowMarker+" is skipped.\n"+
			"\n"+
			"--history answers a different question: not what is about to leave, but\n"+
			"what is still in here. Deleting a key from a file does not remove it from\n"+
			"the commit that added it, and every other view reports that repository\n"+
			"clean. One line per credential, however many commits carry it.\n"+
			"\n"+
			"--format sarif writes a SARIF 2.1.0 document for GitHub code scanning,\n"+
			"which keeps a finding against its line across runs and shows it in the\n"+
			"pull request's diff. Upload it with github/codeql-action/upload-sarif.\n"+
			"\n"+
			"Flags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(flagsFirst(fs, args))

	switch *format {
	case "text", "github", "json", "sarif":
	default:
		return fmt.Errorf("--format is text, json, sarif or github, not %q", *format)
	}

	// The value is kept only for the run that is about to present it to
	// its issuer, and this is set before anything scans.
	retainValues = *check

	// History answers a different question from the other three — what is
	// still in here, rather than what is about to leave — so it reports in
	// its own shape rather than being folded into a file:line list that
	// would have to invent a file for a commit nobody has checked out.
	if *history {
		if *check {
			return errCheckNeedsValues
		}
		if *base != "" || *staged {
			return fmt.Errorf("--history scans every commit; --diff and --staged choose a narrower view")
		}
		if fs.NArg() > 1 {
			return fmt.Errorf("--history takes at most one revision")
		}
		rev := ""
		if fs.NArg() == 1 {
			rev = fs.Arg(0)
		}
		found, commits, err := scanHistory(".", rev)
		if err != nil {
			return err
		}
		if *format == "sarif" {
			// SARIF anchors a result to a file and a line in the checked
			// -out tree, and a key in an old commit has neither. Reporting
			// it against the path it used to live at would put a finding
			// on a file that is not there, or worse, on a line of whatever
			// is there now. Refused rather than approximated.
			return fmt.Errorf("--format sarif needs a file and a line to anchor each result, " +
				"and --history reports commits; use --format json")
		}
		if *format == "json" {
			if err := printHistoryJSON(found, commits); err != nil {
				return err
			}
		} else {
			printHistory(found, commits)
		}
		if len(found) == 0 {
			return nil
		}
		return &scanFindings{n: len(found)}
	}

	var (
		hits    []keyHit
		scanned int
		skips   []skippedFile
		unit    string
		err     error
	)
	switch {
	case *base != "" && *staged:
		return fmt.Errorf("--diff and --staged both choose what to scan; use one")
	case *staged:
		if fs.NArg() > 0 {
			return fmt.Errorf("--staged scans the index; paths cannot be given with it")
		}
		hits, scanned, err = scanStaged(".")
		unit = "staged line"
	case *base != "":
		if fs.NArg() > 0 {
			return fmt.Errorf("--diff scans the repository's changes; paths cannot be given with it")
		}
		hits, scanned, err = scanDiff(".", *base)
		unit = "added line"
	default:
		paths := fs.Args()
		if len(paths) == 0 {
			paths = []string{"."}
		}
		hits, scanned, skips, err = scanPaths(paths)
		unit = "file"
	}
	if err != nil {
		return err
	}

	found, declared := splitDeclared(hits)

	if *check && len(found) > 0 {
		// Said before anything leaves, not after. Stderr, so a JSON or
		// SARIF document on stdout stays a document.
		fmt.Fprintln(os.Stderr, liveNotice())
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		checkHits(ctx, found)
		cancel()
	}

	if *format == "json" || *format == "sarif" {
		var err error
		if *format == "json" {
			err = printScanJSON(found, declared, scanned, unit, skips)
		} else {
			// A clean SARIF run still uploads: code scanning closes a
			// finding when the run that would report it comes back empty,
			// and a tool that prints nothing on success leaves every
			// fixed key open forever.
			err = printScanSARIF(found, version)
		}
		if err != nil {
			return err
		}
		if len(found) == 0 {
			return nil
		}
		return &scanFindings{n: len(found)}
	}

	for _, h := range found {
		if *format == "github" {
			fmt.Fprintln(stdout, githubAnnotation(h))
			continue
		}
		if *check {
			fmt.Fprintf(stdout, "%s:%d\t%s\t…%s\t%s\n", h.File, h.Line, h.Label, h.Last4, h.Live)
			continue
		}
		fmt.Fprintf(stdout, "%s:%d\t%s\t…%s\n", h.File, h.Line, h.Label, h.Last4)
	}
	if len(found) == 0 {
		fmt.Fprintf(stdout, "No provider keys in %d %s%s.\n", scanned, unit, pluralS(scanned))
	}
	printSkipped(skips, *format)
	printDeclared(declared, *format)
	if len(found) == 0 {
		return nil
	}

	fmt.Fprintln(stdout)
	if *check {
		if summary := liveSummary(found); summary != "" {
			fmt.Fprintln(stdout, summary)
			fmt.Fprintln(stdout)
		}
	}
	fmt.Fprintln(stdout, scanAdvice(found))
	return &scanFindings{n: len(found)}
}

// printSkipped names the files a scan did not read.
//
// After the findings and before the advice, because it qualifies both: a
// reader who has just been told "no provider keys" needs the next
// sentence to say how much of the directory that covers, and a reader
// looking at six findings needs to know whether there might be a
// seventh somewhere nothing opened.
//
// Named individually up to a handful. A count alone — "4 files skipped"
// — tells somebody there is a gap and not where, which is the shape of a
// warning people learn to scroll past.
func printSkipped(skips []skippedFile, format string) {
	if len(skips) == 0 {
		return
	}
	// In a workflow the only thing read is the annotation stream, and a
	// plain line in the middle of it is a line GitHub discards. The
	// warning level is deliberate: a file nobody opened is not an error
	// — nothing was found in it — and it is not nothing either.
	if format == "github" {
		for _, s := range skips {
			fmt.Fprintf(stdout, "::warning file=%s::Not read, so no finding here means nothing: %s\n",
				s.Path, s.Reason)
		}
		return
	}
	fmt.Fprintf(stdout, "\n%d file%s could not be read, so nothing above is a claim about %s:\n",
		len(skips), pluralS(len(skips)), map[bool]string{true: "it", false: "them"}[len(skips) == 1])
	const show = 10
	for i, s := range skips {
		if i == show {
			fmt.Fprintf(stdout, "  … and %d more\n", len(skips)-show)
			break
		}
		fmt.Fprintf(stdout, "  %s — %s\n", s.Path, s.Reason)
	}
}

// scanFindings is the error `scan` returns when it found something. It
// is an error so the process exits 1, which is what a CI step reads;
// the findings themselves were already printed.
type scanFindings struct{ n int }

func (e *scanFindings) Error() string {
	return fmt.Sprintf("%d key%s found", e.n, pluralS(e.n))
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// splitDeclared separates the hits that are findings from the ones a
// secret-scanner configuration already declares are not.
func splitDeclared(hits []keyHit) (found, declared []keyHit) {
	for _, h := range hits {
		if h.Declared != "" {
			declared = append(declared, h)
			continue
		}
		found = append(found, h)
	}
	return found, declared
}

// printDeclared writes the values a scanner configuration vouches for,
// below the findings and never counted among them.
//
// Printed at all because the alternative is a scanner that can be
// silenced by editing a file in the repository it is scanning. The
// sentence says whose claim it is and that we have not checked it, which
// is the whole of what we honestly know: we can see that the repository
// says these are fixtures, and we cannot see whether that is true.
func printDeclared(declared []keyHit, format string) {
	if len(declared) == 0 {
		return
	}
	if format == "github" {
		for _, h := range declared {
			fmt.Fprintln(stdout, githubNotice(h))
		}
		return
	}
	files := map[string]string{}
	for _, h := range declared {
		files[h.File] = h.Declared
	}
	names := make([]string, 0, len(files))
	for f := range files {
		names = append(names, f)
	}
	sort.Strings(names)

	fmt.Fprintf(stdout, "\n%d value%s in a secret scanner's own configuration, not counted above:\n",
		len(declared), pluralS(len(declared)))
	for _, h := range declared {
		fmt.Fprintf(stdout, "  %s:%d\t%s\t…%s\n", h.File, h.Line, h.Label, h.Last4)
	}
	for _, f := range names {
		fmt.Fprintf(stdout, "\n%s is a %s: it exists to list strings that are not secrets.\n", f, files[f])
	}
	fmt.Fprint(stdout, "That is the repository's claim, not a check we ran. If a real key was put\n"+
		"there to quiet a scanner, it is still a real key.\n")
}

// scanAdvice says what to do, and says it once rather than per hit.
func scanAdvice(hits []keyHit) string {
	var migratable bool
	for _, h := range hits {
		if h.Upstream != "" {
			migratable = true
		}
	}
	lines := []string{"A key in a file is a key in every copy of the file. Rotate each one above."}
	if migratable {
		lines = append(lines, "Provider keys can be held by Lyntway instead: `lyntway keys migrate` moves them out of\n.env files and points the SDKs at the gateway.")
	}
	var concepts []okfConcept
	for _, h := range hits {
		if h.Concept != nil {
			concepts = append(concepts, *h.Concept)
		}
	}
	if s := okfSentence(concepts); s != "" {
		lines = append(lines, s)
	}
	lines = append(lines, "A line that is not a key can be marked "+allowMarker+" and will be skipped.")
	return strings.Join(lines, "\n")
}

// githubAnnotation formats a hit as a workflow command, which GitHub
// renders inline on the pull request at that file and line.
//
// The message text is escaped per the workflow-commands rules: a literal
// newline or percent would otherwise end or corrupt the annotation.
func githubAnnotation(h keyHit) string {
	esc := func(s string) string {
		return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
	}
	prop := func(s string) string {
		return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
	}
	msg := fmt.Sprintf("%s ending …%s. Rotate it; a key in a commit is in every clone.", h.Label, h.Last4)
	if h.Upstream != "" {
		msg += " Move it out of the file with `lyntway keys migrate`."
	}
	return fmt.Sprintf("::error file=%s,line=%d,title=%s::%s", prop(h.File), h.Line, prop(h.Label+" in source"), esc(msg))
}

// githubNotice is a declared value, rendered as a notice rather than an
// error so it appears on the pull request without failing the check.
func githubNotice(h keyHit) string {
	prop := func(s string) string {
		return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
	}
	esc := func(s string) string {
		return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
	}
	return fmt.Sprintf("::notice file=%s,line=%d,title=%s::%s", prop(h.File), h.Line,
		prop("Declared not a secret"),
		esc(fmt.Sprintf("%s ending …%s, in a %s. Not counted as a finding; this repository says it is not a secret.",
			h.Label, h.Last4, h.Declared)))
}

// scanPaths walks files. Directories are descended; .git and node_modules
// are not, and anything that looks binary or is over the size limit is
// counted as skipped rather than scanned, so "no keys" is a claim about
// what was read.
//
// # Why this is two passes and a worker pool
//
// Walking and scanning in one sequential pass took 87 seconds over this
// repository's 32,000 files on one core, with the other cores idle. The
// work is seventy-odd compiled patterns against each file's bytes, which
// is the kind of work that divides perfectly — and a scanner somebody
// runs before every push is a scanner whose speed decides whether they
// keep running it.
//
// The order of the result must not depend on which worker finished
// first. A report whose lines move between runs cannot be diffed, and a
// test that asserts on the first finding would pass or fail by luck. So
// the walk collects paths in the order it met them, the pool fills a slot
// per path, and the slots are flattened in that same order afterwards.
func scanPaths(paths []string) ([]keyHit, int, []skippedFile, error) {
	const maxSize = 4 << 20

	var files []string
	var oversize []skippedFile
	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			return nil, 0, nil, err
		}
		walk := func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path != root && (d.Name() == ".git" || d.Name() == "node_modules") {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			if fi.Size() > maxSize {
				oversize = append(oversize, skippedFile{
					Path:   filepath.ToSlash(path),
					Reason: fmt.Sprintf("%d bytes, over the %d MB limit", fi.Size(), maxSize>>20),
				})
				return nil
			}
			files = append(files, path)
			return nil
		}
		if !info.IsDir() {
			if err := walk(root, fs.FileInfoToDirEntry(info), nil); err != nil {
				return nil, 0, nil, err
			}
			continue
		}
		if err := filepath.WalkDir(root, walk); err != nil {
			return nil, 0, nil, err
		}
	}

	type slot struct {
		hits    []keyHit
		counted bool
		binary  bool
		err     error
	}
	slots := make([]slot, len(files))

	workers := runtime.NumCPU()
	if workers > len(files) {
		workers = len(files)
	}
	if workers < 1 {
		workers = 1
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(files) {
					return
				}
				path := files[i]
				body, err := os.ReadFile(path)
				if err != nil {
					slots[i].err = err
					continue
				}
				if isBinary(body) {
					slots[i].binary = true
					continue
				}
				slots[i].counted = true
				// Recognised, not scanned differently. The file was
				// already read above; this only says what kind of file it
				// turned out to be, so the report can say why a key here
				// travels further than a key in a .env.
				concept, isConcept := okfConceptOf(path, body)
				declared := declaringFiles[filepath.Base(path)]
				for _, h := range findKeys(string(body), 1) {
					h.File = filepath.ToSlash(path)
					if isConcept {
						h.Concept = &concept
					}
					h.Declared = declared
					slots[i].hits = append(slots[i].hits, h)
				}
			}
		}()
	}
	wg.Wait()

	var hits []keyHit
	var scanned int
	skips := oversize
	for i := range slots {
		if slots[i].err != nil {
			return nil, 0, nil, slots[i].err
		}
		if slots[i].binary {
			skips = append(skips, skippedFile{
				Path:   filepath.ToSlash(files[i]),
				Reason: "a NUL byte in the first 8 KB, so it reads as binary",
			})
			continue
		}
		if slots[i].counted {
			scanned++
		}
		hits = append(hits, slots[i].hits...)
	}
	sort.Slice(skips, func(a, b int) bool { return skips[a].Path < skips[b].Path })
	return hits, scanned, skips, nil
}

func isBinary(body []byte) bool {
	head := body
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// scanDiff scans the lines added since base, as `git diff` reports them.
//
// The comparison is against the merge base, not the tip of base: on a
// branch, `git diff origin/main` would also show everything main gained
// since the branch was cut, reversed, and a key somebody else removed
// on main would be reported as added here. Uncommitted changes are
// included, since a pre-commit check is exactly when they matter.
func scanDiff(dir, base string) ([]keyHit, int, error) {
	if strings.HasPrefix(base, "-") {
		return nil, 0, fmt.Errorf("--diff needs a revision, not %q", base)
	}
	args := []string{"diff", "--merge-base", base, "--unified=0", "--no-color", "--no-ext-diff", "--diff-filter=ACMR", "--"}
	out, err := gitOutput(dir, args...)
	if err != nil && strings.Contains(err.Error(), "merge-base") {
		// A git too old for --merge-base: the two-dot form is what it
		// has, and its known over-reporting is the lesser problem.
		out, err = gitOutput(dir, append([]string{"diff", base}, args[3:]...)...)
	}
	if err != nil {
		return nil, 0, err
	}
	hits, lines := parseDiff(out)
	return hits, lines, nil
}

// scanStaged scans exactly what is about to be committed.
//
// Documented in skill.md, in the plugin's SKILL.md decision table and in
// plugin/commands/lyntway-scan.md, and absent from the code — so an agent
// following any of the three ran `lyntway scan --staged` and got
// "flag provided but not defined: -staged" and exit 2. The hook is the
// other half of this: a scan that gates a commit should be able to look at
// the index rather than the working tree, which is what --cached is.
func scanStaged(dir string) ([]keyHit, int, error) {
	out, err := gitOutput(dir, "diff", "--cached", "--unified=0", "--no-color",
		"--no-ext-diff", "--diff-filter=ACMR", "--")
	if err != nil {
		return nil, 0, err
	}
	hits, lines := parseDiff(out)
	return hits, lines, nil
}

func gitOutput(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) || strings.Contains(msg, "fatal:") {
			return nil, fmt.Errorf("git: %s", msg)
		}
		return nil, fmt.Errorf("running git: %s", msg)
	}
	return out, nil
}

// parseDiff scans the added lines of a unified diff and returns the hits
// and how many added lines were read.
//
// Consecutive added lines are scanned together so a private key block
// pasted in whole is found by the rule that needs to see all of it.
func parseDiff(diff []byte) ([]keyHit, int) {
	var (
		hits    []keyHit
		file    string
		next    int // the new-file line number the next added line has
		added   int
		block   []string
		blockAt int
	)
	flush := func() {
		if len(block) == 0 {
			return
		}
		// The same recognition the directory walk does. Without it a pull
		// request that adds one fixture to .gitleaks.toml fails the
		// GitHub Action, which is the one change nobody should have to
		// argue with a secret scanner about.
		declared := declaringFiles[path.Base(file)]
		for _, h := range findKeys(strings.Join(block, "\n"), blockAt) {
			h.File = file
			h.Declared = declared
			hits = append(hits, h)
		}
		block = nil
	}
	sc := bufio.NewScanner(bytes.NewReader(diff))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "+++ "):
			flush()
			file = strings.TrimPrefix(strings.TrimPrefix(l, "+++ "), "b/")
			if i := strings.Index(file, "\t"); i >= 0 {
				file = file[:i]
			}
		case strings.HasPrefix(l, "@@"):
			flush()
			next = hunkStart(l)
		case strings.HasPrefix(l, "+"):
			if len(block) == 0 {
				blockAt = next
			}
			block = append(block, l[1:])
			next++
			added++
		case strings.HasPrefix(l, "-"), strings.HasPrefix(l, "\\"):
			// Removed lines and the no-newline marker do not advance
			// the new file's numbering.
		default:
			flush()
			next++
		}
	}
	flush()
	return hits, added
}

// hunkStart reads the first line number of the new side from a hunk
// header: "@@ -12,3 +14,5 @@" gives 14.
func hunkStart(header string) int {
	i := strings.Index(header, "+")
	if i < 0 {
		return 1
	}
	rest := header[i+1:]
	end := strings.IndexAny(rest, ", @")
	if end < 0 {
		end = len(rest)
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil || n < 1 {
		return 1
	}
	return n
}
