package receipt

import "strings"

// Provenance records how the issuer came to know what a receipt describes.
//
// # Why a receipt has to say this
//
// Every field in a receipt answers "what happened". None of them answered
// "how do you know". Those are different questions, and the second one
// decides what the first is worth.
//
// A receipt issued from a gateway describes bytes the issuer handled. A
// receipt issued from an integration describes what another system reported
// afterwards. A receipt issued from a library call describes what the caller
// said they were doing. All three can be signed identically, chained
// identically and logged identically — and they are not equally strong.
//
// Without this field the three are indistinguishable, and the weakest one
// borrows the credibility of the strongest. That is the failure mode this
// whole product exists to refuse, applied to itself.
//
// # Why it is inside the signature
//
// Provenance is a claim about the receipt, so it must be as unforgeable as
// the rest of it. Left outside the signed body, the one field describing how
// much to trust the receipt would be the one field anybody could rewrite.
type Provenance string

const (
	// ProvenanceObserved means the issuer handled the bytes itself: the
	// traffic passed through it, and the action record is first-hand.
	//
	// The strongest form. It is also the only one that can support a claim
	// about completeness, because only a party on the path can know that
	// nothing went round it.
	ProvenanceObserved Provenance = "observed"

	// ProvenanceAttested means another system reported the action and the
	// issuer recorded it.
	//
	// Second-hand. The receipt is exactly as accurate as the report it was
	// built from: if the reporting system logs partially, late, or wrongly,
	// the receipt inherits that and signs it. Naming the reporter in Vantage
	// is what lets a reader judge that risk rather than guess at it.
	ProvenanceAttested Provenance = "attested"

	// ProvenanceAsserted means the caller described its own action.
	//
	// Weakest. It proves the caller's description was governed and has not
	// been altered since. It proves nothing about whether the description
	// was true, or whether other actions went unrecorded.
	ProvenanceAsserted Provenance = "asserted"
)

// Evidence records how the issuer knows what the receipt describes.
type Evidence struct {
	// Provenance is how the action became known.
	Provenance Provenance `json:"provenance"`

	// Vantage names where the issuer stood, or who reported.
	//
	// For an observed receipt, the path the traffic took. For an attested
	// one, the system that reported it. A reader who cannot tell which
	// system produced the underlying record cannot judge how much the
	// receipt is worth, so it is required for both.
	Vantage string `json:"vantage,omitempty"`

	// Reported is what the reporting system says it did, recorded as their
	// claim rather than as ours.
	//
	// This exists because the two are genuinely different facts and
	// flattening them would be a lie in one direction or the other. When a
	// data-loss tool redacts an email and tells us so, we did not redact
	// anything — governance.decision must stay log_only, because that is
	// all this service performed. But refusing to record their action at
	// all would throw away the only interesting part of the report.
	//
	// So the receipt carries both: what we did, and what we were told was
	// done. A reader can see the difference, and an auditor can weigh the
	// second exactly as far as they trust the tool named in Vantage.
	Reported *ReportedAction `json:"reported,omitempty"`
}

// ReportedAction is a second-hand account of enforcement.
type ReportedAction struct {
	// Decision is what the reporting system says it did.
	Decision Decision `json:"decision"`

	// Findings are what it says it found. Counts and classes, never
	// values — the same discipline our own findings keep, applied to
	// somebody else's report.
	Findings []Finding `json:"findings,omitempty"`
}

// validateInto checks a reported action is internally coherent.
func (a *ReportedAction) validateInto(errs *FieldErrors) {
	if !a.Decision.valid() {
		errs.add("evidence.reported.decision", "unrecognised value")
	}
	for i, f := range a.Findings {
		f.validateInto(errs, "evidence.reported.findings", i)
	}
}

// validVantage keeps the field to something that reads as an identifier
// rather than free text, since it appears in signed evidence.
func validVantage(v string) bool {
	if len(v) > 128 {
		return false
	}
	for _, c := range v {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == '/', c == ':':
		default:
			return false
		}
	}
	return true
}

// validateInto checks the evidence block's internal consistency.
func (e *Evidence) validateInto(errs *FieldErrors) {
	if e.Reported != nil {
		// A first-hand receipt has nothing to report second-hand: this
		// service handled the bytes, so its own decision is the whole
		// story and a "reported" block beside it would be two accounts of
		// one event.
		if e.Provenance == ProvenanceObserved {
			errs.add("evidence.reported",
				"must be absent when provenance is observed; a first-hand receipt reports its own decision")
		}
		e.Reported.validateInto(errs)
	}

	switch e.Provenance {
	case ProvenanceObserved, ProvenanceAttested:
		if strings.TrimSpace(e.Vantage) == "" {
			// A first-hand or second-hand claim with no statement of where
			// it came from cannot be assessed. Refusing it is better than
			// emitting evidence whose strength nobody can judge.
			errs.add("evidence.vantage",
				"required when provenance is "+string(e.Provenance))
		} else if !validVantage(e.Vantage) {
			errs.add("evidence.vantage", "is not a valid identifier")
		}
	case ProvenanceAsserted:
		// The issuer was not anywhere, so there is no vantage to give. A
		// value here would suggest a position the issuer did not hold.
		if strings.TrimSpace(e.Vantage) != "" {
			errs.add("evidence.vantage",
				"must be empty when the caller merely asserted the action")
		}
	default:
		errs.add("evidence.provenance", "unrecognised value")
	}
}

// EffectiveProvenance reports how a receipt's contents became known,
// treating an absent block as the weakest possibility.
//
// Receipts issued before this field existed carry no evidence at all. The
// safe reading is that they are asserted: they may well have been observed,
// but nothing in them says so, and quietly promoting an old receipt to the
// strongest claim would be exactly the kind of unearned upgrade the field
// exists to prevent.
func (r *Receipt) EffectiveProvenance() Provenance {
	if r == nil || r.Evidence == nil {
		return ProvenanceAsserted
	}
	return r.Evidence.Provenance
}

// FirstHand reports whether the issuer handled the bytes itself.
func (r *Receipt) FirstHand() bool {
	return r.EffectiveProvenance() == ProvenanceObserved
}
