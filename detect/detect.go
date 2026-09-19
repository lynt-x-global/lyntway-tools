// Package detect implements the deterministic detection floor.
//
// This is tier one of the classification cascade: fast, exact, and
// reproducible. It is not a replacement for machine-learned detection — it
// is the layer that must keep working when the ML sidecar is unavailable,
// so that governance degrades to "less capable" rather than "absent".
//
// Two properties matter more than raw recall here.
//
// # Reproducibility
//
// Every result is attributable to an exact ruleset version and digest. A
// receipt claiming a finding must be re-derivable months later against the
// same rules, or it cannot be defended when someone disputes it. That rules
// out anything non-deterministic in this package: no model inference, no
// map iteration order leaking into output, no time-dependent behaviour.
//
// # Precision over recall
//
// A false positive here becomes a redaction that corrupts a customer's
// data, or a block that breaks their agent mid-workflow. Patterns that
// cannot be checked structurally — card numbers without Luhn, IBANs without
// mod-97 — are not shipped as high-confidence rules. Recall is what the ML
// tier is for.
package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Class identifies a category of sensitive data.
//
// Dotted and hierarchical so policy can address a family ("pii") or a
// specific type ("pii.email") without a separate grouping mechanism.
type Class string

// Confidence is a rule's reliability, 0–100.
//
// An integer rather than a float, deliberately. Confidence influences which
// findings are safe to enforce on automatically, and integers keep that
// decision reproducible across platforms and serialisation round trips.
type Confidence uint8

const (
	// ConfidenceExact is for patterns validated by a checksum or a
	// structurally unambiguous format. Safe to enforce on automatically.
	ConfidenceExact Confidence = 100

	// ConfidenceHigh is for distinctive patterns with a very low false
	// positive rate — vendor-prefixed credentials, PEM blocks.
	ConfidenceHigh Confidence = 90

	// ConfidenceModerate is for patterns that match real values reliably
	// but also match some legitimate text. Suitable for redaction, not for
	// blocking.
	ConfidenceModerate Confidence = 70

	// ConfidenceLow is for heuristics that need corroboration. Reported,
	// but never the sole basis for an enforcement action.
	ConfidenceLow Confidence = 40
)

// Span is one detected occurrence within a piece of content.
type Span struct {
	// Class is what was detected.
	Class Class

	// Rule is the identifier of the rule that matched, so a finding can be
	// traced to the exact pattern responsible.
	Rule string

	// Detector names what found this.
	//
	// Empty means the deterministic ruleset, which is the reproducible
	// tier: the same content and the same ruleset digest always yield the
	// same spans, which is what lets somebody re-derive a decision months
	// later. A named detector is a probabilistic one, and a finding from it
	// carries a different kind of claim — good recall, no guarantee that
	// re-running produces the same answer.
	//
	// The distinction reaches the receipt, because a reader deciding how
	// much to trust a finding needs to know which of those they are
	// holding.
	Detector string

	// Start and End are byte offsets into the scanned content, half-open.
	Start, End int

	// Confidence is the matching rule's reliability.
	Confidence Confidence

	// Value is the matched text.
	//
	// Held so that tokenisation can substitute deterministically. It never
	// leaves this process: receipts carry digests and counts, never
	// detected values. Callers must not log it.
	Value string
}

// Len returns the span's length in bytes.
func (s Span) Len() int { return s.End - s.Start }

// Rule is one deterministic pattern.
type Rule struct {
	// ID uniquely identifies the rule within a ruleset and appears in
	// spans, so a disputed finding can be traced to its source.
	ID string

	// Class is what the rule detects.
	Class Class

	// Pattern is the regular expression. If it defines a capture group
	// named "target", that group is the reported span rather than the whole
	// match — which lets a rule require surrounding context without
	// redacting it.
	Pattern *regexp.Regexp

	// Confidence is the rule's reliability.
	Confidence Confidence

	// Validate optionally verifies a candidate match structurally: a Luhn
	// check for card numbers, mod-97 for IBANs. A rule with a validator
	// earns ConfidenceExact; one without does not.
	Validate func(string) bool

	// Priority breaks ties when spans overlap. Higher wins. A specific
	// rule must outrank a general one, or a vendor-prefixed token gets
	// reported as a generic high-entropy string.
	Priority int

	// Prefilter is a set of literal substrings, at least one of which must
	// appear in content for Pattern to have any chance of matching. When
	// none is present the pattern is skipped entirely.
	//
	// This is what keeps detection cost from growing linearly with the
	// rule count. A substring search runs at memory bandwidth; a regex
	// scan does not, and most content contains none of the vendor prefixes
	// that most rules look for.
	//
	// A prefilter that is not genuinely implied by the pattern silently
	// disables the rule, which is a security defect rather than a
	// performance regression. TestPrefiltersDoNotSuppressMatches exists to
	// catch that, and any new prefilter must be a literal the pattern
	// cannot match without.
	Prefilter []string

	// PrefilterFold is Prefilter for a case-insensitive pattern: the
	// literals and the content are both case-folded before comparing, the
	// way the (?i) flag folds, so "iGnOrE" cannot slip past a list that
	// spelled out "ignore", "Ignore" and "IGNORE". Either list passing is
	// enough to scan.
	//
	// It exists because the injection rules added in core-2026.09.19 had
	// no prefilter — the case-sensitive kind is how a (?i) rule quietly
	// stops matching — and running them on every byte tripled the cost of
	// scanning ordinary prose. The content is folded once per Scan, and
	// only if some rule carries one of these.
	PrefilterFold []string
}

// Ruleset is a versioned collection of rules.
//
// The version and digest are recorded in every receipt the ruleset
// contributes to. The digest pins the decision to exact rule content rather
// than to a mutable label, so editing a rule without bumping the version is
// still detectable.
type Ruleset struct {
	version string
	rules   []Rule
	digest  string
}

// NewRuleset builds a ruleset and computes its digest.
//
// Rules are sorted by ID first, so the digest depends on rule content alone
// and not on the order they were declared in. Without that, reordering a
// slice would silently change every receipt's ruleset digest.
func NewRuleset(version string, rules []Rule) *Ruleset {
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	h := sha256.New()
	h.Write([]byte(version))
	h.Write([]byte{0})
	for _, r := range sorted {
		h.Write([]byte(r.ID))
		h.Write([]byte{0})
		h.Write([]byte(r.Class))
		h.Write([]byte{0})
		h.Write([]byte(r.Pattern.String()))
		h.Write([]byte{0})
		h.Write([]byte{byte(r.Confidence)})
		h.Write([]byte{0})
	}

	return &Ruleset{
		version: version,
		rules:   sorted,
		digest:  hex.EncodeToString(h.Sum(nil)),
	}
}

// Version returns the ruleset version, for the receipt's detector block.
func (rs *Ruleset) Version() string { return rs.version }

// Digest returns the hex SHA-256 of the ruleset's content.
func (rs *Ruleset) Digest() string { return rs.digest }

// Rules returns a copy of the ruleset's rules.
func (rs *Ruleset) Rules() []Rule {
	out := make([]Rule, len(rs.rules))
	copy(out, rs.rules)
	return out
}

// Scan finds every sensitive span in content.
//
// Overlapping matches are resolved so that exactly one rule claims any
// given byte: higher priority wins, then higher confidence, then the longer
// match. Without this, a GitHub token would be reported both as
// `secret.github_token` and as a generic high-entropy string, and the
// receipt would show two findings where there is one secret.
//
// Results are ordered by position, and Scan is safe for concurrent use.
func (rs *Ruleset) Scan(content []byte) []Span {
	var candidates []Span
	var folded []byte

	for _, rule := range rs.rules {
		if len(rule.PrefilterFold) > 0 && folded == nil {
			folded = foldCase(content)
		}
		if !rule.mayMatch(content, folded) {
			continue
		}
		idx := rule.Pattern.SubexpIndex("target")
		reject := rule.Pattern.SubexpIndex("reject")
		matches := rule.Pattern.FindAllSubmatchIndex(content, -1)
		for _, m := range matches {
			// A "reject" capture group that matched means the context shows
			// this is part of something larger — the first twelve digits of a
			// grouped sixteen-digit number are not an Aadhaar number. RE2 has
			// no lookahead, so the context is matched and then refused.
			if reject > 0 && 2*reject+1 < len(m) && m[2*reject] >= 0 && m[2*reject+1] > m[2*reject] {
				continue
			}
			start, end := m[0], m[1]
			// A "target" capture group narrows the reported span to the
			// sensitive part, leaving required context unredacted.
			if idx > 0 && 2*idx+1 < len(m) && m[2*idx] >= 0 {
				start, end = m[2*idx], m[2*idx+1]
			}
			value := string(content[start:end])

			if rule.Validate != nil && !rule.Validate(value) {
				continue
			}

			candidates = append(candidates, Span{
				Class:      rule.Class,
				Rule:       rule.ID,
				Start:      start,
				End:        end,
				Confidence: rule.Confidence,
				Value:      value,
			})
		}
	}

	return resolveOverlaps(candidates, rs.rules)
}

// mayMatch reports whether the rule's prefilter permits scanning content.
//
// A rule with no prefilter of either kind always scans. folded is content
// passed through foldCase; it is only read when the rule has PrefilterFold.
func (r Rule) mayMatch(content, folded []byte) bool {
	if len(r.Prefilter) == 0 && len(r.PrefilterFold) == 0 {
		return true
	}
	for _, lit := range r.Prefilter {
		if bytes.Contains(content, []byte(lit)) {
			return true
		}
	}
	for _, lit := range r.PrefilterFold {
		if bytes.Contains(folded, foldCase([]byte(lit))) {
			return true
		}
	}
	return false
}

// foldCase maps every character to one representative of its case-folding
// orbit — the smallest code point in it, which is what regexp's (?i) treats
// as equal. Lowercasing would not do: the Kelvin sign folds with "k" under
// (?i) but stays itself under unicode.ToLower, so "Kill" would match a
// pattern for "kill" that a lowercased prefilter had already skipped.
//
// The output may differ in length from the input; it is only ever searched,
// never used for offsets.
func foldCase(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for len(b) > 0 {
		c := b[0]
		if c < utf8.RuneSelf {
			// 'k' and 's' have non-ASCII partners, but their orbit's smallest
			// member is still the ASCII capital, so this agrees with the
			// general case below.
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			out = append(out, c)
			b = b[1:]
			continue
		}
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		if r == utf8.RuneError && size == 1 {
			// Invalid bytes can take part in no case-insensitive match of a
			// literal, so what they become does not matter; they must only
			// not become a letter.
			out = append(out, 0xff)
			continue
		}
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < least {
				least = f
			}
		}
		out = utf8.AppendRune(out, least)
	}
	return out
}

// resolveOverlaps reduces candidates to a non-overlapping set.
func resolveOverlaps(candidates []Span, rules []Rule) []Span {
	if len(candidates) <= 1 {
		return candidates
	}

	priority := make(map[string]int, len(rules))
	for _, r := range rules {
		priority[r.ID] = r.Priority
	}

	// Sort by the winner-selection order: strongest claim first. Ties break
	// on rule ID so the outcome is deterministic for identical rules.
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if pa, pb := priority[a.Rule], priority[b.Rule]; pa != pb {
			return pa > pb
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if a.Len() != b.Len() {
			return a.Len() > b.Len()
		}
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		return a.Rule < b.Rule
	})

	var kept []Span
	for _, c := range candidates {
		overlaps := false
		for _, k := range kept {
			if c.Start < k.End && k.Start < c.End {
				overlaps = true
				break
			}
		}
		if !overlaps {
			kept = append(kept, c)
		}
	}

	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}

// Counts aggregates spans by class, for the receipt's findings block.
//
// Returned sorted by class so that receipts for identical content are
// byte-identical. Map iteration order would otherwise leak into the signed
// payload and make receipts irreproducible.
func Counts(spans []Span) []ClassCount {
	byClass := make(map[Class]int)
	for _, s := range spans {
		byClass[s.Class]++
	}
	out := make([]ClassCount, 0, len(byClass))
	for c, n := range byClass {
		out = append(out, ClassCount{Class: c, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Class < out[j].Class })
	return out
}

// ClassCount is the number of spans found for one class.
type ClassCount struct {
	Class Class
	Count int
}

// HasClassPrefix reports whether class belongs to a family, so a policy can
// address "pii" and match "pii.email".
//
// Matching is on dot boundaries: "pii" matches "pii.email" but not
// "piita.x".
func HasClassPrefix(class Class, family string) bool {
	s := string(class)
	if s == family {
		return true
	}
	return strings.HasPrefix(s, family+".")
}
