package agentsecrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// ErrNotLocal is a file that exists only in cloud storage.
//
// Reading it would pull it down, which is minutes on a synced directory
// and is not this tool's business. It is reported as unread rather than
// fetched; iCloud eviction has already cost this repository a confusing
// afternoon once.
var ErrNotLocal = errors.New("agentsecrets: the file is not stored locally")

const (
	// chunkBytes is how much of a file is held in memory at once.
	//
	// Files are streamed rather than read whole. The cap was 64 MB and a
	// larger file was reported unread, which on the machine this was
	// built against skipped four transcripts of 140 to 289 MB — the
	// longest sessions, and so the ones most likely to hold something
	// somebody pasted. "Not a clean machine, an incomplete look" over
	// exactly the files that matter most is the wrong answer.
	chunkBytes = 8 << 20

	// overlapBytes is carried between chunks so a credential lying
	// across a boundary is still found whole. A PEM private-key block is
	// the longest thing the ruleset matches, at a few kilobytes; 64 KB is
	// far past it and costs nothing.
	overlapBytes = 64 << 10

	// maxFileBytes now limits the pathological rather than the large.
	// Streaming makes memory flat, so this exists only so one enormous
	// file cannot turn a scan into an hour, and it is named in the report
	// when it bites.
	maxFileBytes = 2 << 30
)

// Finding is one credential in one place.
//
// It carries no value. Last4 is what a person needs to tell two keys
// apart when revoking, and is not enough to use one. Printing the value
// would put it in the terminal scrollback and in whatever agent is
// reading that terminal, which is the problem this package exists for.
type Finding struct {
	Tool   string
	Kind   Kind
	Why    string
	Path   string
	Format Format

	// Line is 1-based. Zero where the file has no lines to point at —
	// inside an opaque store, where the match was found by scanning bytes.
	Line int

	// Label is what to call it to a person: "Anthropic key".
	Label string

	// Class is the detect class, for a machine.
	Class string

	// Fingerprint identifies the value without carrying it, so the same
	// key in two files is visibly one key. See credentials.go.
	Fingerprint string

	// Last4 is the final four characters of the matched value.
	Last4 string
}

// Unread is a source that existed and was not scanned, with the reason.
type Unread struct {
	Tool   string
	Path   string
	Reason string
}

// Result is what a scan found and, as importantly, what it did not read.
type Result struct {
	Findings []Finding

	// Files and Bytes are what was actually read.
	Files int
	Bytes int64

	// Sources is how many candidate locations existed on this machine.
	// Absent locations are not counted: a tool that is not installed is
	// not a gap.
	Sources int

	// Unread is every file that existed and could not be read. A report
	// that says "nothing found" while this is non-empty is claiming more
	// than happened, so Complete reports it and the CLI prints it.
	Unread []Unread

	// Allowed counts findings dropped because a person had already
	// judged them. Reported rather than silent: a scan that shows less
	// than it found has to say so.
	Allowed int
}

// Complete reports whether every source that existed was read.
//
// The distinction the whole report rests on. "No keys found" over a
// directory half of which could not be opened is the sentence this
// repository's readiness check calls a failure, for the same reason: the
// claim is about what was read, and a reader cannot tell the difference
// unless it is said.
func (r Result) Complete() bool { return len(r.Unread) == 0 }

// Tools lists the tools something was found in, in reporting order.
func (r Result) Tools() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range r.Findings {
		if !seen[f.Tool] {
			seen[f.Tool] = true
			out = append(out, f.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// Scan reads every source and reports the credentials in them.
//
// rules is the ruleset to use; the caller passes one so the CLI and the
// gateway cannot drift apart about what a credential is. Only classes
// under "secret" are reported: a transcript is full of email addresses
// and that is not what this is for.
func Scan(sources []Source, rules *detect.Ruleset) Result {
	return ScanProgress(sources, rules, nil)
}

// ScanProgress is Scan with a callback as files are finished.
//
// Reading everything on a working machine is not fast: 1.8 GB of agent
// state on the one this was built against takes about a minute and a
// half, and the files that take longest — dense transcripts full of URLs
// and base64 — are the ones most worth reading. A minute of silence from
// a command somebody has just been told to run reads as broken, so the
// caller is given something to print.
//
// onProgress is called from the workers and must be safe to call from
// several goroutines; it is invoked under the same lock that guards the
// result, so an implementation that only prints is fine.
func ScanProgress(sources []Source, rules *detect.Ruleset, onProgress func(files int, bytes int64)) Result {
	var res Result

	// Two passes: find the files, then read them. Separated because the
	// first is a directory walk that has to be sequential to report an
	// unreadable entry against the right source, and the second is the
	// expensive part and is not.
	//
	// 5.3 GB of agent state on the machine this was written against took
	// 1m44s in one goroutine. A tool whose entire pitch is "run this and
	// look" does not get two minutes of somebody's attention, so the
	// reads run across the cores the machine has.
	type job struct {
		src  Source
		path string
	}
	var jobs []job
	for _, src := range sources {
		info, err := os.Stat(src.Path)
		if errors.Is(err, fs.ErrNotExist) {
			// The tool is not installed, or the layout moved. Neither is
			// a finding and neither is an unread file.
			continue
		}
		res.Sources++
		if err != nil {
			res.Unread = append(res.Unread, Unread{src.Tool, src.Path, err.Error()})
			continue
		}
		if !info.IsDir() {
			jobs = append(jobs, job{src, src.Path})
			continue
		}
		walkErr := filepath.WalkDir(src.Path, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// One unreadable entry does not abandon the directory:
				// the rest of somebody's history is still worth reading.
				res.Unread = append(res.Unread, Unread{src.Tool, path, err.Error()})
				return nil
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			jobs = append(jobs, job{src, path})
			return nil
		})
		if walkErr != nil {
			res.Unread = append(res.Unread, Unread{src.Tool, src.Path, walkErr.Error()})
		}
	}

	workers := runtime.NumCPU()
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers < 1 {
		workers = 1
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	next := make(chan job)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range next {
				findings, read, size, unread := scanOne(j.src, j.path, rules)
				mu.Lock()
				res.Findings = append(res.Findings, findings...)
				if read {
					res.Files++
					res.Bytes += size
					if onProgress != nil {
						onProgress(res.Files, res.Bytes)
					}
				}
				if unread != nil {
					res.Unread = append(res.Unread, *unread)
				}
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		next <- j
	}
	close(next)
	wg.Wait()

	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	return res
}

// scanOne reads and scans a single file. Pure, so the workers above need
// no lock while the expensive part runs.
func scanOne(src Source, path string, rules *detect.Ruleset) (findings []Finding, read bool, size int64, unread *Unread) {
	f, info, err := openLocal(path)
	if err != nil {
		return nil, false, 0, &Unread{src.Tool, path, err.Error()}
	}
	defer f.Close()

	buf := make([]byte, 0, chunkBytes+overlapBytes)
	lineBefore := 0 // newlines in the part of the file already behind buf
	for {
		want := cap(buf) - len(buf)
		if want > 0 {
			n, readErr := io.ReadFull(f, buf[len(buf):cap(buf)])
			buf = buf[:len(buf)+n]
			if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
				return nil, false, 0, &Unread{src.Tool, path, readErr.Error()}
			}
			if n < want {
				// The last window: every match in it is reportable.
				findings = append(findings, scanWindow(src, path, buf, rules, lineBefore, len(buf))...)
				return findings, true, info.Size(), nil
			}
		}
		// A match starting at or past chunkBytes may straddle the
		// boundary, so it is left to the next window — which carries
		// the tail and will see it whole. Reporting it here as well is
		// what would make the sighting count grow with the file size.
		findings = append(findings, scanWindow(src, path, buf, rules, lineBefore, chunkBytes)...)

		lineBefore += bytes.Count(buf[:chunkBytes], []byte{'\n'})
		buf = append(buf[:0], buf[chunkBytes:]...)
	}
}

// scanWindow reports the credentials in one window of a file.
//
// limit is where the reportable region ends: a match starting at or past
// it belongs to the next window, which carries enough of this one's tail
// to hold it whole. That is what makes a credential at a chunk boundary
// count once.
func scanWindow(src Source, path string, body []byte, rules *detect.Ruleset,
	lineBefore, limit int) []Finding {
	var findings []Finding

	// An opaque store has no lines to point at. Scanning it as bytes
	// still finds a key, because a conversation is stored readable inside
	// a SQLite page even though the page framing is not.
	lineAddressable := src.Format != FormatOpaque && !bytes.Contains(firstBytes(body), []byte{0})

	// Keep what will be reported, then number the lines in one pass.
	//
	// Counting newlines from the start of the window for each match
	// separately is O(matches × window), which on an 8 MB window holding
	// a hundred matches is most of the run: reading 1.8 GB took 1m12s
	// that way and 2.4 times the data of the 64 MB-capped version cost
	// four times the time. Sorted and walked once instead.
	var keep []detect.Span
	for _, sp := range rules.Scan(body) {
		if sp.Start >= limit {
			continue
		}
		if !detect.HasClassPrefix(sp.Class, "secret") {
			continue
		}
		if looksLikePlaceholder(sp.Value) {
			continue
		}
		keep = append(keep, sp)
	}
	if len(keep) == 0 {
		return nil
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].Start < keep[j].Start })

	lines := make([]int, len(keep))
	if lineAddressable {
		at, count := 0, 0
		for i, sp := range keep {
			count += bytes.Count(body[at:sp.Start], []byte{'\n'})
			at = sp.Start
			lines[i] = 1 + lineBefore + count
		}
	}

	for i, sp := range keep {
		line := lines[i]
		findings = append(findings, Finding{
			Tool:        src.Tool,
			Kind:        src.Kind,
			Why:         src.Why,
			Path:        filepath.ToSlash(path),
			Format:      src.Format,
			Line:        line,
			Label:       detect.Label(sp.Class),
			Class:       string(sp.Class),
			Fingerprint: fingerprint(sp.Value),
			Last4:       last4(string(sp.Class), sp.Value),
		})
	}
	return findings
}

func firstBytes(b []byte) []byte {
	if len(b) > 8000 {
		return b[:8000]
	}
	return b
}

// openLocal opens a file that is actually on this disk.
func openLocal(path string) (*os.File, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("not a regular file")
	}
	if isDataless(info) {
		return nil, nil, ErrNotLocal
	}
	if info.Size() > maxFileBytes {
		return nil, nil, fmt.Errorf("larger than %d MB, so it was not read", maxFileBytes>>20)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, info, nil
}

// last4 is the end of a value, or fewer characters when it is short.
//
// Empty for a PEM block, because the end of one is "-----" and every
// private key on a machine then reports the same four dashes — which
// tells somebody nothing about which key to revoke while looking like it
// does. The first real run found six private keys, all shown as "…----".
// The hook's refusal already knew this and left the value out for
// exactly this class; the report did not.
func last4(class, v string) string {
	if class == "secret.private_key" {
		return ""
	}
	if len(v) <= 4 {
		return v
	}
	return v[len(v)-4:]
}

// looksLikePlaceholder refuses the documented examples.
//
// A transcript is full of them: the agent was shown a README, or wrote
// one. Reporting "sk-ant-api03-YOUR-KEY-HERE" as a credential teaches
// somebody that this tool cries wolf, after which the real finding below
// it is not read either.
func looksLikePlaceholder(v string) bool {
	lower := strings.ToLower(v)

	// A value that is exactly a word is a documentation example. This
	// matters most for a password in a connection URL, where the matched
	// value is the password itself and `postgres://user:password@host`
	// appears in every database tutorial ever written — and in this
	// repository's own comments.
	switch lower {
	case "password", "passwd", "pass", "pw", "secret", "token", "apikey",
		"api_key", "key", "changeme", "hunter2", "mypassword", "s3cret",
		"admin", "root", "postgres", "mysql", "redis", "user", "username":
		return true
	}

	for _, marker := range []string{
		"your", "example", "placeholder", "xxxx", "<", ">", "...",
		"redacted", "changeme", "replace", "dummy", "sample", "notreal",
		"test-key", "fake", "abcdef123456", "0000",

		// An unexpanded template or shell variable: $TOKEN, ${KEY},
		// %SECRET%, {{ api_key }}. The value is the name of the thing,
		// not the thing.
		"$", "{", "}", "%",

		// An ellipsis means somebody shortened it for a document, so
		// what is here is not a whole credential and cannot be used.
		// Both the character and the three dots above.
		"\u2026",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// A value that is one repeated character is nobody's key.
	trimmed := strings.TrimLeft(lower, "abcdefghijklmnopqrstuvwxyz0123456789_-")
	if trimmed == "" && len(lower) > 8 {
		runs := 0
		for i := 1; i < len(lower); i++ {
			if lower[i] != lower[i-1] {
				runs++
			}
		}
		if runs < 3 {
			return true
		}
	}
	return false
}
