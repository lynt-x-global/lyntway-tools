package agentsecrets

import (
	"sync"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// DefaultRules is the gateway's ruleset narrowed to credentials.
//
// # Why a subset rather than detect.Default()
//
// The full ruleset carries the PII and prompt-injection rules, and those
// are the expensive ones over prose: case-folded prefilters, phone and
// address shapes, patterns that have to look at every line. A transcript
// is prose. On the machine this was written against, Claude Code alone
// holds 5.3 GB of state and 1.7 GB of transcripts, and the full ruleset
// over that did not finish inside two minutes — which for a tool whose
// whole pitch is "run this and see" is the same as not working.
//
// Narrowing is also the honest shape: this package reports credentials
// and discards everything else, so paying to find an email address in
// somebody's chat history and then dropping it is work nobody asked for
// on data nobody should be reading twice.
//
// # Why the version string is not the gateway's
//
// A ruleset's version has to pin the rules that produced a finding. This
// is a strict subset, so it says so: the gateway's version with a
// "+secrets" suffix. A report that cited the gateway's version while
// running fewer rules would be claiming a scan that did not happen.
func DefaultRules() *detect.Ruleset { return secretsOnce() }

var secretsOnce = sync.OnceValue(func() *detect.Ruleset {
	full := detect.Default()
	var keep []detect.Rule
	for _, r := range full.Rules() {
		if detect.HasClassPrefix(r.Class, "secret") {
			keep = append(keep, r)
		}
	}
	return detect.NewRuleset(full.Version()+"+secrets", keep)
})
