package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

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
		hits = append(hits, keyHit{
			Line:     firstLine + line,
			Label:    detect.Label(sp.Class),
			Class:    string(sp.Class),
			Last4:    last4(sp.Value),
			Upstream: classUpstreams[sp.Class],
		})
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
	format := fs.String("format", "text", "text, or github for ::error annotations a workflow shows inline")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "lyntway scan — find provider keys before they are committed\n"+
			"\n"+
			"Usage:\n"+
			"  lyntway scan [paths...]              scan files (default: the current directory)\n"+
			"  lyntway scan --diff origin/main      scan the lines added since a revision\n"+
			"\n"+
			"Prints file:line, what the key is, and its last four characters — never\n"+
			"the key. Exits 1 when anything is found, so it can gate a commit or a\n"+
			"pull request. A line carrying the word "+allowMarker+" is skipped.\n"+
			"\n"+
			"Flags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(flagsFirst(fs, args))

	if *format != "text" && *format != "github" {
		return fmt.Errorf("--format is text or github, not %q", *format)
	}

	var (
		hits    []keyHit
		scanned int
		unit    string
		err     error
	)
	if *base != "" {
		if fs.NArg() > 0 {
			return fmt.Errorf("--diff scans the repository's changes; paths cannot be given with it")
		}
		hits, scanned, err = scanDiff(".", *base)
		unit = "added line"
	} else {
		paths := fs.Args()
		if len(paths) == 0 {
			paths = []string{"."}
		}
		hits, scanned, err = scanPaths(paths)
		unit = "file"
	}
	if err != nil {
		return err
	}

	for _, h := range hits {
		if *format == "github" {
			fmt.Fprintln(stdout, githubAnnotation(h))
			continue
		}
		fmt.Fprintf(stdout, "%s:%d\t%s\t…%s\n", h.File, h.Line, h.Label, h.Last4)
	}
	if len(hits) == 0 {
		fmt.Fprintf(stdout, "No provider keys in %d %s%s.\n", scanned, unit, pluralS(scanned))
		return nil
	}

	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, scanAdvice(hits))
	return &scanFindings{n: len(hits)}
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

// scanPaths walks files. Directories are descended; .git and node_modules
// are not, and anything that looks binary or is over the size limit is
// counted as skipped rather than scanned, so "no keys" is a claim about
// what was read.
func scanPaths(paths []string) ([]keyHit, int, error) {
	const maxSize = 4 << 20
	var hits []keyHit
	var scanned int
	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			return nil, 0, err
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
			if err != nil || fi.Size() > maxSize {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if isBinary(body) {
				return nil
			}
			scanned++
			for _, h := range findKeys(string(body), 1) {
				h.File = filepath.ToSlash(path)
				hits = append(hits, h)
			}
			return nil
		}
		if !info.IsDir() {
			if err := walk(root, fs.FileInfoToDirEntry(info), nil); err != nil {
				return nil, 0, err
			}
			continue
		}
		if err := filepath.WalkDir(root, walk); err != nil {
			return nil, 0, err
		}
	}
	return hits, scanned, nil
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
		for _, h := range findKeys(strings.Join(block, "\n"), blockAt) {
			h.File = file
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
