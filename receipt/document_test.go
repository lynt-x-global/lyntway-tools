package receipt

import "testing"

// A document receipt attests that a file is unchanged. Everything it must not
// say follows from one fact: the artefact arrived complete, and hashing it is
// not the same as having done, watched, or reviewed the work inside it.
//
// This is the subject an accredited assessor's report would use, so each of
// these is a claim somebody would eventually be tempted to make on a receipt
// attached to a penetration test.
func TestADocumentReceiptCannotClaimWorkItDidNotDo(t *testing.T) {
	document := func() *Receipt {
		r := validReceipt()
		r.Content.Subject = SubjectDocument
		return r
	}

	t.Run("cannot claim tokenisation", func(t *testing.T) {
		r := document()
		r.Governance.Decision = DecisionTokenize
		if err := r.Validate(); err == nil {
			t.Error("a document receipt claimed it tokenised a file that arrived complete")
		}
	})

	t.Run("cannot claim redaction", func(t *testing.T) {
		r := document()
		r.Governance.Decision = DecisionRedact
		if err := r.Validate(); err == nil {
			t.Error("a document receipt claimed it redacted a file that arrived complete")
		}
	})

	t.Run("cannot claim it observed the work", func(t *testing.T) {
		// The assessment happened in someone else's engagement, weeks
		// before the file reached us. Observation would say we watched it.
		r := document()
		if r.Evidence == nil {
			r.Evidence = &Evidence{}
		}
		r.Evidence.Provenance = ProvenanceObserved
		if err := r.Validate(); err == nil {
			t.Error("a document receipt claimed first-hand observation of work done elsewhere")
		}
	})

	t.Run("cannot carry findings", func(t *testing.T) {
		// The tempting lie: attest a penetration test report, let the
		// receipt carry its findings, and it reads as though we found
		// them. We hashed a file.
		//
		// The decision is set to log_only first, because the fixture ships
		// with DecisionTokenize and this assertion would otherwise pass on
		// the tokenisation rule without ever reaching the findings rule —
		// green for a reason that has nothing to do with what it claims to
		// test.
		r := document()
		r.Governance.Decision = DecisionLogOnly
		r.Governance.Findings = []Finding{{Class: "pii.email", Count: 1, Decision: DecisionLogOnly}}
		if err := r.Validate(); err == nil {
			t.Error("a document receipt carried findings it never examined anything to produce")
		}
	})

	t.Run("is valid when it claims only integrity", func(t *testing.T) {
		r := document()
		r.Governance.Decision = DecisionLogOnly
		r.Governance.Findings = nil
		if r.Evidence != nil {
			r.Evidence.Provenance = ProvenanceAttested
		}
		if err := r.Validate(); err != nil {
			t.Errorf("a document receipt claiming only that the file is unchanged was refused: %v", err)
		}
	})
}

// An unrecognised subject must read weak, but a document is not unrecognised
// and must not be described as a record about traffic — its digest covers the
// file itself, which is the one strong thing it does say.
func TestADocumentSubjectSurvivesAsItsOwnThing(t *testing.T) {
	r := validReceipt()
	r.Content.Subject = SubjectDocument
	if got := r.EffectiveSubject(); got != SubjectDocument {
		t.Errorf("EffectiveSubject() = %q, want %q", got, SubjectDocument)
	}
}
