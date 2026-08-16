// Package govern wires detection, transformation, and receipt issuance into
// a single governed action.
//
// This is the primitive: content goes in, governed content and a signed
// receipt come out. Everything else in the product — the model gateway, the
// MCP gateway, the database gateway — is a different way of getting content
// into this function.
package govern

import (
	"fmt"
	"sort"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// Policy maps detected classes to enforcement actions.
//
// Policies are data, not code. Buyers do not author policy languages, so
// the product ships packs and exposes a rule shape simple enough to review
// in a pull request.
type Policy struct {
	// ID identifies the policy, recorded in every receipt it decides.
	ID string

	// Version is the exact version that made a decision. Required for
	// reproducibility: a decision must be attributable to precise rules,
	// not to a mutable label.
	Version string

	// Rules are evaluated in order; the first match wins. Order is
	// significant and therefore explicit, rather than depending on map
	// iteration.
	Rules []PolicyRule

	// Default applies when no rule matches. Allow rather than block: a
	// policy that blocks everything it has not been taught about will be
	// switched off within a day, and a governance layer that is switched
	// off governs nothing.
	Default receipt.Decision
}

// PolicyRule maps a class or class family to a decision.
type PolicyRule struct {
	// Class matches exactly, or as a family prefix when Family is set.
	Class detect.Class

	// Family matches every class beneath a prefix: "pii" matches
	// "pii.email" and "pii.phone".
	Family string

	// MinConfidence withholds this rule from findings below a confidence
	// threshold. This is how a policy expresses "redact on a high-
	// confidence match, but only log a weak one" without needing a second
	// rule.
	MinConfidence detect.Confidence

	// Decision is the action to take.
	Decision receipt.Decision
}

func (r PolicyRule) matches(class detect.Class, conf detect.Confidence) bool {
	if conf < r.MinConfidence {
		return false
	}
	if r.Family != "" {
		return detect.HasClassPrefix(class, r.Family)
	}
	return r.Class == class
}

// Decide returns the action for a single finding.
func (p *Policy) Decide(class detect.Class, conf detect.Confidence) receipt.Decision {
	for _, rule := range p.Rules {
		if rule.matches(class, conf) {
			return rule.Decision
		}
	}
	return p.Default
}

// Validate reports whether the policy is usable.
func (p *Policy) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("govern: policy ID must not be empty")
	}
	if p.Version == "" {
		return fmt.Errorf("govern: policy version must not be empty: a decision must be attributable to an exact version")
	}
	if !isKnownDecision(p.Default) {
		return fmt.Errorf("govern: policy default decision %q is not recognised", p.Default)
	}
	for i, r := range p.Rules {
		if r.Class == "" && r.Family == "" {
			return fmt.Errorf("govern: policy rule %d matches neither a class nor a family", i)
		}
		if r.Class != "" && r.Family != "" {
			return fmt.Errorf("govern: policy rule %d sets both class and family; pick one", i)
		}
		if !isKnownDecision(r.Decision) {
			return fmt.Errorf("govern: policy rule %d has unrecognised decision %q", i, r.Decision)
		}
	}
	return nil
}

func isKnownDecision(d receipt.Decision) bool {
	switch d {
	case receipt.DecisionAllow, receipt.DecisionLogOnly, receipt.DecisionTokenize,
		receipt.DecisionRedact, receipt.DecisionRequireApproval, receipt.DecisionBlock:
		return true
	}
	return false
}

// severity orders decisions from least to most restrictive, so a receipt
// can report the strongest action taken across all findings.
var severity = map[receipt.Decision]int{
	receipt.DecisionAllow:           0,
	receipt.DecisionLogOnly:         1,
	receipt.DecisionTokenize:        2,
	receipt.DecisionRedact:          3,
	receipt.DecisionRequireApproval: 4,
	receipt.DecisionBlock:           5,
}

// strongest returns the most restrictive of two decisions.
func strongest(a, b receipt.Decision) receipt.Decision {
	if severity[b] > severity[a] {
		return b
	}
	return a
}

// DefaultPolicy is the shipped pack.
//
// The shape encodes a position taken from the detection accuracy that
// actually exists rather than from how alarming each category sounds:
//
//   - Credentials block. Vendor-prefixed secrets are matched exactly, so
//     the false-positive risk is negligible and the consequence of leaking
//     one is severe.
//   - Personal and financial data is tokenised rather than redacted.
//     Tokenisation preserves the agent's ability to work; irreversible
//     redaction breaks multi-step workflows and gets the governance layer
//     blamed for the outage.
//   - Low-confidence findings are logged, never enforced. An IP address is
//     only personal data in context, and blocking on a weak signal costs
//     more trust than it buys.
func DefaultPolicy() *Policy {
	return &Policy{
		ID:      "pack.core.default",
		Version: "1",
		Rules: []PolicyRule{
			// Credentials never leave. These are exact matches on vendor
			// prefixes and PEM delimiters, so blocking is safe.
			{Family: "secret", MinConfidence: detect.ConfidenceHigh, Decision: receipt.DecisionBlock},
			// A weak credential signal is still worth recording.
			{Family: "secret", Decision: receipt.DecisionLogOnly},

			// Financial identifiers carry checksums, so a match is
			// trustworthy. Tokenised rather than blocked so legitimate
			// payment workflows keep functioning.
			{Family: "pci", MinConfidence: detect.ConfidenceExact, Decision: receipt.DecisionTokenize},

			// Personal data at usable confidence is tokenised, preserving
			// referential integrity for the agent.
			{Family: "pii", MinConfidence: detect.ConfidenceHigh, Decision: receipt.DecisionTokenize},
			// Below that, record without acting.
			{Family: "pii", Decision: receipt.DecisionLogOnly},

			// Prompt injection is recorded, never enforced on by default.
			//
			// Every rule above matches a thing; these match an intent, and
			// intent has no checksum. The same sentence is an attack in a
			// retrieved document and a paragraph in a security training
			// deck, and no pattern can tell those apart. Blocking on a
			// heuristic would make this layer the reason a customer's
			// article about prompt injection failed to send — a worse
			// outcome than the attack, and one they would be right to
			// remove us for.
			//
			// What the finding is for is the receipt: it says an
			// instruction-shaped string reached a model, on which surface
			// and travelling which way, and a customer who decides that
			// matters can enforce on it deliberately.
			{Family: "injection", Decision: receipt.DecisionLogOnly},
		},
		Default: receipt.DecisionAllow,
	}
}

// findingDecisions computes the per-class decisions for a set of spans.
//
// Returned sorted by class so receipts for identical content are
// byte-identical: map iteration order must never reach a signed payload.
func findingDecisions(p *Policy, spans []detect.Span) ([]receipt.Finding, receipt.Decision) {
	type agg struct {
		count    int
		decision receipt.Decision

		// detector is empty while every finding of this class came from
		// the rules, and names the analyzer once one did not.
		//
		// A class found by both tiers is reported as probabilistic, which
		// is the weaker of the two claims. Reporting the stronger one
		// would let a single rule match launder every model finding of the
		// same class into looking reproducible.
		detector string
	}
	byClass := make(map[detect.Class]*agg)

	overall := receipt.DecisionAllow
	for _, s := range spans {
		d := p.Decide(s.Class, s.Confidence)
		a, ok := byClass[s.Class]
		if !ok {
			a = &agg{decision: d}
			byClass[s.Class] = a
		}
		a.count++
		if s.Detector != "" {
			a.detector = s.Detector
		}
		// A class can be matched by rules of differing confidence, so keep
		// the strongest action any of its findings triggered.
		a.decision = strongest(a.decision, d)
		overall = strongest(overall, d)
	}

	out := make([]receipt.Finding, 0, len(byClass))
	for class, a := range byClass {
		out = append(out, receipt.Finding{
			Class:    string(class),
			Count:    a.count,
			Decision: a.decision,
			Detector: a.detector,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Class < out[j].Class })

	return out, overall
}
