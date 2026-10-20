package agentsecrets

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AllowFile is where a person records the credentials they have already
// judged, under the directory the CLI keeps everything else in.
const AllowFile = "agent-secrets-allow"

// LoadAllow reads the fingerprints a person has decided about.
//
// # Why fingerprints and not values
//
// A file listing the secrets somebody has triaged would be a file of
// secrets, written by the tool whose entire promise is not to make one.
// A fingerprint is the first twelve hex characters of a SHA-256 and
// cannot be turned back into the key, so this file is safe to keep, safe
// to commit, and safe to share with a colleague who is looking at the
// same machine.
//
// # Why there has to be an allowlist at all
//
// Because the first real run of this found 101 distinct credentials on
// the machine it was written on, and most were fixtures from building
// this repository — generated AWS keys from a detection benchmark, local
// test keys, example connection strings. A scanner with no way to retire
// a judged finding is a scanner that reports the same hundred things
// every week until somebody stops running it.
//
// A missing file is not an error. Most people will never have one.
func LoadAllow(dir string) (map[string]bool, error) {
	path := filepath.Join(dir, AllowFile)
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	allow := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		// The first field, so a line may carry a note after it.
		allow[strings.ToLower(strings.Fields(line)[0])] = true
	}
	if err := sc.Err(); err != nil {
		// Reported, never ignored: an allowlist that failed to load would
		// otherwise look like one that allowed nothing, and the person
		// would be handed back every finding they had already judged.
		return nil, err
	}
	return allow, nil
}

// Excluding drops the findings a person has already judged.
//
// The counts of what was read are kept as they were: the files were
// still read, and a report that said it had read fewer because some
// findings were retired would be describing a scan that did not happen.
// Allowed records how many were dropped, so the report can say so rather
// than quietly showing less.
func (r Result) Excluding(allow map[string]bool) Result {
	if len(allow) == 0 {
		return r
	}
	out := r
	out.Findings = nil
	out.Allowed = 0
	for _, f := range r.Findings {
		if allow[strings.ToLower(f.Fingerprint)] {
			out.Allowed++
			continue
		}
		out.Findings = append(out.Findings, f)
	}
	return out
}

// AllowLines renders a result as allowlist entries, so a person who has
// looked at a report can retire all of it in one step.
//
// Each line carries the label and where it was seen as a comment: a
// fingerprint alone is unreadable six months later, and an allowlist
// nobody can audit is the thing a security tool must not produce.
func AllowLines(creds []Credential) []string {
	var out []string
	for _, c := range creds {
		kinds := make([]string, 0, len(c.Kinds()))
		for _, k := range c.Kinds() {
			kinds = append(kinds, string(k))
		}
		sort.Strings(kinds)
		out = append(out, c.Fingerprint+"  # "+c.Label+" ending "+c.Last4+
			", seen in "+strings.Join(kinds, ", "))
	}
	return out
}
