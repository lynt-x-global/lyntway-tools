package govern

import (
	"sort"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// What this deployment looks for, and what it does when it finds it.
//
// The console had no answer to the first question a customer asks after a
// request is refused: what stopped it? The Rules page listed the rules
// they had written, which on a new account is none, under a heading saying
// zero — while their traffic had been blocked four times by rules they
// could not see anywhere. "The built-in detectors run regardless" was the
// whole of the explanation, with no list behind it.
//
// Derived from the ruleset and the policy this engine was built with,
// never from a table written out beside them. A catalogue maintained by
// hand is a catalogue that disagrees with the engine the first time either
// changes, and disagreeing about what we detect is worse than saying
// nothing: it is the page a customer would quote back at us.

// Detector is one class this deployment can find deterministically, with
// what the policy does about it.
type Detector struct {
	Class string `json:"class"`
	Label string `json:"label"`

	// Family is the part of the class before the dot, and it is what the
	// policy keys on — PolicyRule.Family — so a page explaining decisions
	// groups by this and not by Category.
	//
	// Category is the other axis and a different vocabulary: it answers
	// "key", "financial", "injection" for the settings that switch
	// categories on and off, and a class with nobody's category is
	// deliberately blank rather than defaulted. Grouping a decisions page
	// by it put thirty-two of thirty-six classes under "Other".
	Family   string `json:"family"`
	Category string `json:"category"`

	// Confidence is the best any rule for this class reaches, and
	// Decision is what the policy does at that confidence.
	Confidence uint8  `json:"confidence"`
	Decision   string `json:"decision"`

	// WeakConfidence and WeakDecision are set only when the class also has
	// a rule that scores lower and is treated differently. A reader told
	// "secrets are blocked" who then meets a logged secret has been
	// misled, and the difference is the policy working as designed.
	WeakConfidence uint8  `json:"weak_confidence,omitempty"`
	WeakDecision   string `json:"weak_decision,omitempty"`

	// Validated is true when at least one rule for the class checks the
	// value structurally — a Luhn digit, mod-97, a Verhoeff check — which
	// is the difference between a pattern that matches the shape and one
	// that matches the thing.
	Validated bool `json:"validated"`

	// Rules names the rule ids behind the class, so a disputed finding on
	// a receipt can be traced to the rule that made it.
	Rules []string `json:"rules"`
}

// Detectors lists what the deterministic tier finds, sorted by class.
func (e *Engine) Detectors() []Detector {
	type agg struct {
		best, worst detect.Confidence
		validated   bool
		rules       []string
	}
	byClass := map[detect.Class]*agg{}
	for _, r := range e.ruleset.Rules() {
		a := byClass[r.Class]
		if a == nil {
			a = &agg{best: r.Confidence, worst: r.Confidence}
			byClass[r.Class] = a
		}
		if r.Confidence > a.best {
			a.best = r.Confidence
		}
		if r.Confidence < a.worst {
			a.worst = r.Confidence
		}
		a.validated = a.validated || r.Validate != nil
		a.rules = append(a.rules, r.ID)
	}

	out := make([]Detector, 0, len(byClass))
	for class, a := range byClass {
		sort.Strings(a.rules)
		family, _, _ := strings.Cut(string(class), ".")
		d := Detector{
			Class:      string(class),
			Label:      detect.Label(class),
			Family:     family,
			Category:   detect.Category(class),
			Confidence: uint8(a.best),
			Decision:   string(e.policy.Decide(class, a.best)),
			Validated:  a.validated,
			Rules:      a.rules,
		}
		if weak := e.policy.Decide(class, a.worst); a.worst != a.best && weak != receipt.Decision(d.Decision) {
			d.WeakConfidence, d.WeakDecision = uint8(a.worst), string(weak)
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Class < out[j].Class })
	return out
}

// PolicyIdentity names the policy deciding what happens to findings.
func (e *Engine) PolicyIdentity() (id, version string) {
	return e.policy.ID, e.policy.Version
}

// RulesetIdentity names the ruleset doing the finding.
func (e *Engine) RulesetIdentity() (version, digest string) {
	return e.ruleset.Version(), e.ruleset.Digest()
}
