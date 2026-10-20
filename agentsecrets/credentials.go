package agentsecrets

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// Credential is one distinct secret, wherever it appears.
//
// # Why the report is grouped and not a list of hits
//
// The first real run of this, against the machine it was written on,
// reported 474 findings. 186 of them were the same key. A person handed
// 474 lines cannot act on any of them; a person told "nineteen distinct
// credentials, and this one is in 186 places" knows exactly what to
// revoke and how far it spread.
//
// It also stops the count being a lie by arithmetic. "474 secrets in your
// agent's history" is a sentence the data does not support, and the number
// that would have gone in a launch post is the one most worth getting
// right — a scanner that inflates is a scanner nobody believes twice.
type Credential struct {
	// Fingerprint identifies the value without carrying it: the first
	// twelve hex characters of its SHA-256. Enough to tell two keys
	// apart and to see the same one in two places, and not enough to
	// use.
	Fingerprint string

	Label string
	Class string
	Last4 string

	// Seen is every place this value appears, in reporting order.
	Seen []Finding
}

// Tools lists the tools this credential reached.
func (c Credential) Tools() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range c.Seen {
		if !seen[f.Tool] {
			seen[f.Tool] = true
			out = append(out, f.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// Kinds lists the kinds of file this credential reached, which is what
// decides how it got there: a prompt history means somebody typed it, a
// file snapshot means the agent opened a file holding it.
func (c Credential) Kinds() []Kind {
	seen := map[Kind]bool{}
	var out []Kind
	for _, f := range c.Seen {
		if !seen[f.Kind] {
			seen[f.Kind] = true
			out = append(out, f.Kind)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Credentials groups the findings by value.
//
// Ordered by how far each one spread — most occurrences first — because
// the one in the most places is the one whose revocation is most urgent
// and most disruptive, and a person deciding what to do first should not
// have to count.
func (r Result) Credentials() []Credential {
	byPrint := map[string]*Credential{}
	var order []string
	for _, f := range r.Findings {
		c, ok := byPrint[f.Fingerprint]
		if !ok {
			c = &Credential{
				Fingerprint: f.Fingerprint,
				Label:       f.Label,
				Class:       f.Class,
				Last4:       f.Last4,
			}
			byPrint[f.Fingerprint] = c
			order = append(order, f.Fingerprint)
		}
		c.Seen = append(c.Seen, f)
	}
	out := make([]Credential, 0, len(order))
	for _, p := range order {
		out = append(out, *byPrint[p])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].Seen) != len(out[j].Seen) {
			return len(out[i].Seen) > len(out[j].Seen)
		}
		return out[i].Label < out[j].Label
	})
	return out
}

// fingerprint identifies a value without carrying it.
func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}
