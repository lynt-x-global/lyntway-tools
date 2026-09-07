package receipt

import (
	"strings"
	"testing"
	"time"
)

// A hold that released something has to say who released it, and a
// resolution has to match the decision it sits on. These are the rules
// that stop a receipt reading as though a hold was quietly waved through.

func heldReceipt() *Receipt {
	r := validReceipt()
	r.Governance.Decision = DecisionRequireApproval
	r.Governance.Findings = []Finding{{Class: "custom.project", Count: 1, Decision: DecisionRequireApproval}}
	r.Content.OutputDigest = ""
	return r
}

func TestAHeldReceiptReleasesNothingWithoutAnApproval(t *testing.T) {
	r := heldReceipt()
	if err := r.Validate(); err != nil {
		t.Fatalf("a held receipt with no output should validate: %v", err)
	}

	r.Content.OutputDigest = r.Content.InputDigest
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "content.output_digest") {
		t.Fatalf("an output digest on a hold nobody approved was accepted: %v", err)
	}

	r.Governance.Approval = &Approval{
		ID: "apr_1", Outcome: ApprovalApproved, DecidedBy: "ops@acme.test",
		DecidedAt: FormatTime(time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)),
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("an approved release should validate: %v", err)
	}
}

func TestAnApprovalMustMatchTheDecisionItResolves(t *testing.T) {
	at := FormatTime(time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC))

	for name, tc := range map[string]struct {
		shape func(*Receipt)
		want  string
	}{
		"approved on an allow": {
			shape: func(r *Receipt) {
				r.Governance.Decision = DecisionAllow
				r.Governance.Findings = nil
				r.Content.OutputDigest = r.Content.InputDigest
				r.Governance.Approval = &Approval{ID: "apr_1", Outcome: ApprovalApproved, DecidedBy: "x", DecidedAt: at}
			},
			want: "governance.approval.outcome",
		},
		"approved by nobody": {
			shape: func(r *Receipt) {
				r.Governance.Decision = DecisionRequireApproval
				r.Content.OutputDigest = r.Content.InputDigest
				r.Governance.Approval = &Approval{ID: "apr_1", Outcome: ApprovalApproved, DecidedAt: at}
			},
			want: "governance.approval.decided_by",
		},
		"denied without a block": {
			shape: func(r *Receipt) {
				r.Governance.Decision = DecisionRequireApproval
				r.Content.OutputDigest = ""
				r.Governance.Approval = &Approval{ID: "apr_1", Outcome: ApprovalDenied, DecidedBy: "x", DecidedAt: at}
			},
			want: "governance.approval.outcome",
		},
		"denied as a block with no refusal": {
			shape: func(r *Receipt) {
				r.Governance.Decision = DecisionBlock
				r.Content.OutputDigest = ""
				r.Governance.Approval = &Approval{ID: "apr_1", Outcome: ApprovalDenied, DecidedBy: "x", DecidedAt: at}
			},
			want: "governance.approval.outcome",
		},
		"expired without a block": {
			shape: func(r *Receipt) {
				r.Governance.Decision = DecisionRequireApproval
				r.Content.OutputDigest = ""
				r.Governance.Approval = &Approval{ID: "apr_1", Outcome: ApprovalExpired, DecidedAt: at}
			},
			want: "governance.approval.outcome",
		},
		"unknown outcome": {
			shape: func(r *Receipt) {
				r.Governance.Decision = DecisionRequireApproval
				r.Content.OutputDigest = ""
				r.Governance.Approval = &Approval{ID: "apr_1", Outcome: "maybe", DecidedAt: at}
			},
			want: "governance.approval.outcome",
		},
		"no id": {
			shape: func(r *Receipt) {
				r.Governance.Decision = DecisionRequireApproval
				r.Content.OutputDigest = ""
				r.Governance.Approval = &Approval{Outcome: ApprovalExpired, DecidedAt: at}
			},
			want: "governance.approval.id",
		},
		"bad time": {
			shape: func(r *Receipt) {
				r.Governance.Decision = DecisionRequireApproval
				r.Content.OutputDigest = ""
				r.Governance.Approval = &Approval{ID: "apr_1", Outcome: ApprovalExpired, DecidedAt: "yesterday"}
			},
			want: "governance.approval.decided_at",
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := validReceipt()
			tc.shape(r)
			err := r.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a %s error, got %v", tc.want, err)
			}
		})
	}

	// And the shapes that are right.
	denied := validReceipt()
	denied.Governance.Decision = DecisionBlock
	denied.Governance.Refusal = "approval_denied"
	denied.Content.OutputDigest = ""
	denied.Governance.Approval = &Approval{ID: "apr_1", Outcome: ApprovalDenied, DecidedBy: "ops@acme.test", DecidedAt: at}
	if err := denied.Validate(); err != nil {
		t.Errorf("a denial recorded as a refused block should validate: %v", err)
	}
	expired := validReceipt()
	expired.Governance.Decision = DecisionBlock
	expired.Governance.Refusal = "approval_timeout"
	expired.Content.OutputDigest = ""
	expired.Governance.Approval = &Approval{ID: "apr_1", Outcome: ApprovalExpired, DecidedAt: at}
	if err := expired.Validate(); err != nil {
		t.Errorf("an expiry recorded as a refused block should validate: %v", err)
	}
}

// The field is optional and absent on nearly every receipt, so adding it
// must not move a single byte of any receipt that does not carry it. The
// SCITT vectors under testdata/scitt pin this too; this is the direct
// statement of it.
func TestAnAbsentApprovalChangesNoBytes(t *testing.T) {
	r := validReceipt()
	input, err := SigningInput(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(input), "approval") {
		t.Fatalf("an absent approval appeared in the signing input: %s", input)
	}

	// And a present one survives the JSON round trip that verification
	// makes, under the signature.
	signer, keys := testSigner(t)
	held := heldReceipt()
	held.Content.OutputDigest = held.Content.InputDigest
	held.Governance.Approval = &Approval{
		ID: "apr_1", Outcome: ApprovalApproved, DecidedBy: "ops@acme.test",
		DecidedAt: FormatTime(time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)),
	}
	mustSign(t, held, signer)
	signed, _ := SigningInput(held)
	if !strings.Contains(string(signed), `"approval":{"decided_at":"2026-09-07T10:00:00Z","decided_by":"ops@acme.test","id":"apr_1","outcome":"approved"}`) {
		t.Fatalf("the approval is not under the signature in canonical form: %s", signed)
	}
	if _, err := Verify(held, keys, VerifyOptions{Now: held.mustIssuedAt(t)}); err != nil {
		t.Fatalf("verifying a receipt that carries an approval: %v", err)
	}
}
