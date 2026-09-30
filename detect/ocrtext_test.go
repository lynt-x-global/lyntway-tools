package detect

import (
	"strings"
	"testing"
)

// The offset map is the part that can corrupt a document rather than merely
// miss something. A span found in the re-spaced variant carries offsets that
// are wrong for the original by however many spaces were inserted before it,
// and substituting at those offsets overwrites the wrong bytes.
func TestOCRSpansPointAtTheOriginalBytes(t *testing.T) {
	rs := Default()
	const text = "Patientintakeform Contact4111111111111111 seen today"

	spans := ScanOCR(rs, text)
	if len(spans) == 0 {
		t.Fatal("nothing found in glued OCR text")
	}

	for _, sp := range spans {
		if sp.Start < 0 || sp.End > len(text) || sp.Start >= sp.End {
			t.Fatalf("span [%d:%d] is outside the input of %d bytes",
				sp.Start, sp.End, len(text))
		}
		got := text[sp.Start:sp.End]
		if got != sp.Value {
			t.Errorf("span [%d:%d] covers %q but the finding says %q — "+
				"substituting here would overwrite the wrong bytes",
				sp.Start, sp.End, got, sp.Value)
		}
	}
}

// Substituting through the returned offsets must produce text with the value
// gone and everything else intact. This is the property the agent relies on.
func TestSubstitutingThroughOCRSpansIsSafe(t *testing.T) {
	rs := Default()
	const text = "Employeerecord Name Meeralyer ReferenceDE89370400440532013000 Active"

	spans := ScanOCR(rs, text)
	var iban *Span
	for i := range spans {
		if spans[i].Class == "pci.iban" {
			iban = &spans[i]
			break
		}
	}
	if iban == nil {
		t.Fatal("the IBAN glued to its label was not found")
	}

	out := text[:iban.Start] + "<IBAN>" + text[iban.End:]
	if strings.Contains(out, "DE89370400440532013000") {
		t.Error("the IBAN survived substitution at the reported offsets")
	}
	if !strings.HasPrefix(out, "Employeerecord Name Meeralyer Reference") {
		t.Errorf("text before the value was damaged: %q", out)
	}
	if !strings.HasSuffix(out, " Active") {
		t.Errorf("text after the value was damaged: %q", out)
	}
}

// The union must not invent findings. These are the shapes the clean-text
// benchmark counts as hard negatives; re-spacing must not turn any of them
// into a match that the ordinary scan would not have made.
func TestRespacingDoesNotInventFindings(t *testing.T) {
	rs := Default()
	negatives := []string{
		"Order reference ORD4111111111111112 dispatched", // Luhn fails
		"Build v2026.09.30 commit a1b2c3d4e5f6",
		"Invoice total GBP4120.00 due 30 days",
		"Session id 550e8400e29b41d4a716446655440000",
		"Timestamp 20260930T164500Z from host web01",
		"Part number XY123456Z in bin A4",
		"reference DE00000000000000000000 invalid", // IBAN check fails
	}
	for _, neg := range negatives {
		plain := len(rs.Scan([]byte(neg)))
		withOCR := len(ScanOCR(rs, neg))
		if withOCR > plain {
			t.Errorf("re-spacing invented %d finding(s) in %q that a plain "+
				"scan does not make", withOCR-plain, neg)
			for _, sp := range ScanOCR(rs, neg) {
				t.Logf("    %s %q", sp.Class, sp.Value)
			}
		}
	}
}

// The narrowing that made every class reach 1.000: a value's own internal
// uppercase-to-digit transition must survive, or the classes that are
// letters-then-digits are split into fragments matching nothing.
func TestAValueIsNotSplitAtItsOwnInternalBoundary(t *testing.T) {
	cases := []struct{ glued, want string }{
		{"ReferenceDE89370400440532013000", "Reference DE89370400440532013000"},
		{"ContactAAAPZ1234C", "Contact AAAPZ1234C"},
		{"ReferenceAB123456C", "Reference AB123456C"},
		{"Contact4111111111111111", "Contact 4111111111111111"},
		{"Contact+447700900123", "Contact +447700900123"},
	}
	for _, tc := range cases {
		got, _ := respaceOCR(tc.glued)
		if got != tc.want {
			t.Errorf("respace(%q)\n  got  %q\n  want %q", tc.glued, got, tc.want)
		}
	}
}

// Text that needs no repair must come back untouched, so ordinary extracted
// text pays nothing for this and cannot be changed by it.
func TestTextWithItsSpacesIsLeftAlone(t *testing.T) {
	for _, s := range []string{
		"Card number: 4111 1111 1111 1111",
		"Beneficiary IBAN   DE89370400440532013000",
		"plain prose with no values in it at all",
	} {
		got, _ := respaceOCR(s)
		if got != s {
			t.Errorf("respace changed text that needed no repair:\n  %q\n  %q", s, got)
		}
	}
}

func TestScanOCRHandlesEmptyAndNil(t *testing.T) {
	if ScanOCR(nil, "anything") != nil {
		t.Error("a nil ruleset returned findings")
	}
	if ScanOCR(Default(), "") != nil {
		t.Error("empty text returned findings")
	}
}
