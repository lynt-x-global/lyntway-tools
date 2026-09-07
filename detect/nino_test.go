package detect

import "testing"

// UK National Insurance numbers, in the two forms they are written in.
//
// The playground's own sample text carried one — "AB 12 34 56 C" — and it
// passed through untouched, because no tier knew the shape. A product whose
// demo text contains a national identifier it does not detect is making a
// claim on its front page that the engine does not keep.
func TestUKNINODetectionAcrossWrittenForms(t *testing.T) {
	found := []string{
		"AB 12 34 56 C", // as printed on the card and on HMRC letters
		"AB123456C",     // as typed into a form
		"CE 12 34 56 A",
		"JG 10 34 56 D", // final letter D is the last of the four allocated
	}
	for _, nino := range found {
		t.Run(nino, func(t *testing.T) {
			spans := Default().Scan([]byte("Her NI number is " + nino + " and she"))
			if !hasClass(spans, ClassUKNINO) {
				t.Errorf("%q was not detected as a National Insurance number; classes = %v", nino, classesOf(spans))
			}
		})
	}
}

// The structural rules HMRC publishes are what separate a number from any
// two letters, six digits and a letter. Without them the rule would flag
// product codes, and a false positive here is a redaction that corrupts a
// customer's data.
func TestUKNINODetectionLeavesNonNumbersAlone(t *testing.T) {
	missed := []string{
		"GB 12 34 56 A", // prefix never allocated
		"NK123456B",     // prefix never allocated
		"DA 12 34 56 C", // first letter D is never used
		"QQ 12 34 56 C", // HMRC's own example, chosen because Q is never used
		"AO 12 34 56 C", // second letter O is never used
		"AB 12 34 56 E", // suffix beyond A–D
		"AB 12 34 56 Z", // suffix beyond A–D
		"XY987654Z",     // a random nine-character code
		"AB12345C",      // five digits
		"AB1234567C",    // seven digits
		"ab 12 34 56 c", // lower case is not how one is written
	}
	for _, s := range missed {
		t.Run(s, func(t *testing.T) {
			spans := Default().Scan([]byte("reference " + s + " on file"))
			if hasClass(spans, ClassUKNINO) {
				t.Errorf("%q was reported as a National Insurance number", s)
			}
		})
	}
}

// The reported span must be the number alone, so substitution replaces it
// and nothing around it.
func TestUKNINOSpanIsTheNumberAlone(t *testing.T) {
	content := "NI: AB 12 34 56 C."
	spans := Default().Scan([]byte(content))
	for _, s := range spans {
		if s.Class == ClassUKNINO {
			if s.Value != "AB 12 34 56 C" {
				t.Errorf("span = %q, want the number alone", s.Value)
			}
			return
		}
	}
	t.Fatalf("not detected; classes = %v", classesOf(spans))
}
