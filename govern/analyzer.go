package govern

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// A second tier of detection, for the things no pattern can enumerate.
//
// # Why the rules can never be enough
//
// A card number carries a checksum. An AWS key carries a vendor prefix. A
// name carries nothing: "Priya Raman" and "Project Voyager" are the same
// shape, and telling them apart needs the surrounding sentence rather than
// the string. The same is true of a street address, an organisation, and
// personal data written in a language the ruleset was not built for.
//
// Those need a model. So the engine takes analyzers alongside its rules.
//
// # What must not be lost by adding one
//
// A receipt's value rests on being re-derivable: the ruleset digest pins
// exactly which patterns ran, so an auditor in September can reproduce a
// decision made in March. A model does not have that property. Weights can
// be pinned, and the arithmetic underneath still varies with batching, with
// hardware, and with the version of a runtime nobody recorded.
//
// If probabilistic findings were merged into the same list and presented
// identically, every receipt would silently inherit the weaker property and
// the strongest claim the product makes would quietly stop being true.
//
// So they are kept apart in the data. A finding from the rules carries no
// detector; a finding from an analyzer names the one that produced it. Both
// are real. They are not the same kind of evidence, and the receipt says
// which is which.
//
// # What happens when the model is down
//
// Nothing dramatic, and that is the point. An analyzer that fails or times
// out is reported unhealthy, the receipt's mode becomes degraded, and the
// rules still run. A customer's traffic is not held up because an inference
// service is restarting, and a receipt from that window never claims the
// scan was complete.
//
// That machinery already existed for exactly this shape of problem. This is
// the first thing to use it.

// Analyzer is a probabilistic detector.
//
// Implementations are expected to be remote: a model server, a sidecar, an
// inference endpoint. The interface is deliberately small so a customer can
// point at their own rather than ours.
type Analyzer interface {
	// Name identifies this analyzer in receipts. It appears on every
	// finding it produces, so it should name the thing an operator would
	// recognise — "presidio", "ner-en", not "analyzer1".
	Name() string

	// Analyze returns spans found in content.
	//
	// Must honour the context deadline. A detector that ignores it becomes
	// the reason a governed request never returns.
	Analyze(ctx context.Context, content []byte) ([]detect.Span, error)

	// Health reports whether this analyzer is currently usable. Called once
	// per governed action, so it must be cheap and must not block.
	Health() receipt.Health
}

// AnalyzerTimeout bounds how long the second tier may take.
//
// Deliberately short. This sits in the request path of a customer's own
// traffic, and a governance layer that adds a second of latency gets
// removed no matter how good its detection is. A slow analyzer is treated
// exactly like a broken one: the rules still ran, the receipt says
// degraded, and the request goes on.
const AnalyzerTimeout = 800 * time.Millisecond

// runAnalyzers collects spans from the probabilistic tier.
//
// Errors are not returned. An analyzer failing is a health event, not a
// request failure: refusing to govern because a model is unreachable would
// turn their outage into the customer's, which is the trade this whole
// package refuses everywhere else.
func (e *Engine) runAnalyzers(content []byte) []detect.Span {
	if len(e.analyzers) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), AnalyzerTimeout)
	defer cancel()

	var found []detect.Span
	for _, a := range e.analyzers {
		if a.Health() == receipt.HealthUnavailable {
			// Skipped rather than called. A detector that has just told us
			// it cannot answer does not need a round trip to prove it, and
			// the health it reported is already on its way to the receipt.
			continue
		}
		spans, err := a.Analyze(ctx, content)
		if err != nil {
			continue
		}
		name := a.Name()
		for i := range spans {
			// Constrained here rather than trusted, so a detector cannot
			// attribute its findings to something else — including to the
			// deterministic tier, which is the only attribution carrying a
			// reproducibility guarantee, and which an empty detector means.
			//
			// A name under its own prefix is kept, because one analyzer can
			// front several models and a receipt naming the specific one is
			// more useful to whoever has to judge the finding. Anything else
			// is replaced with the analyzer's own name: less precise, but it
			// cannot be a lie.
			if !strings.HasPrefix(spans[i].Detector, name+"/") {
				spans[i].Detector = name
			}
		}
		found = append(found, spans...)
	}
	return found
}

// mergeSpans combines deterministic and probabilistic findings.
//
// Where the two overlap, the deterministic one wins. It is the stronger
// claim — a Luhn-checked card number is not improved by a model agreeing —
// and letting a probabilistic span displace it would replace a reproducible
// finding with one that is not.
//
// Overlaps are resolved rather than reported because the downstream
// transform requires non-overlapping spans in order: two claims on the same
// bytes cannot both be substituted.
func mergeSpans(deterministic, probabilistic []detect.Span) []detect.Span {
	if len(probabilistic) == 0 {
		return deterministic
	}

	out := make([]detect.Span, 0, len(deterministic)+len(probabilistic))
	out = append(out, deterministic...)

	for _, p := range probabilistic {
		if overlapsAny(p, deterministic) {
			continue
		}
		out = append(out, p)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].End > out[j].End
	})

	// A second pass, because two probabilistic spans can overlap each
	// other even when neither overlapped a rule.
	deduped := out[:0]
	prevEnd := -1
	for _, s := range out {
		if s.Start < prevEnd {
			continue
		}
		deduped = append(deduped, s)
		prevEnd = s.End
	}
	return deduped
}

func overlapsAny(s detect.Span, others []detect.Span) bool {
	for _, o := range others {
		if s.Start < o.End && o.Start < s.End {
			return true
		}
	}
	return false
}
