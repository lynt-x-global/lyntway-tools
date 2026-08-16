package detect

import "testing"

// Phone numbers as people actually write them.
//
// The rule was restricted to unseparated E.164 on the reasoning that loose
// national formats produce false positives. That reasoning is sound and it
// over-corrected: nobody writes an international number without separators.
// Every one of these passed through untouched, which for a redaction
// product is the failure that matters.
func TestPhoneDetectionAcrossWrittenFormats(t *testing.T) {
	found := []string{
		"+919884012345",
		"+91 98840 12345",
		"+91-98840-12345",
		"+1 (415) 555-0132",
		"+1 415 555 0132",
		"+44 20 7946 0958",
		"+49 30 901820",
		"+81 3-1234-5678",
	}
	for _, number := range found {
		t.Run(number, func(t *testing.T) {
			spans := Default().Scan([]byte("call " + number + " today"))
			if !hasClass(spans, ClassPhone) {
				t.Errorf("%q was not detected as a phone number; classes = %v", number, classesOf(spans))
			}
		})
	}
}

// The discipline the original rule was protecting must survive: a leading
// "+" is required context, and ordinary numeric prose is not a phone number.
func TestPhoneDetectionLeavesOrdinaryNumbersAlone(t *testing.T) {
	missed := []string{
		"the total was 1234567890 rupees",
		"version 1.2.3 build 4567",
		"order 2024 0001 5567 for 12 units",
		"coordinates 40.7128 -74.0060",
		"a range of 100 - 200 units",
		"+ 5 degrees",
	}
	for _, text := range missed {
		t.Run(text, func(t *testing.T) {
			if spans := Default().Scan([]byte(text)); hasClass(spans, ClassPhone) {
				t.Errorf("%q was reported as a phone number", text)
			}
		})
	}
}

// An Indian mobile in E.164 is twelve digits beginning 91 — exactly the
// shape of an Aadhaar number, and one in ten passes the Verhoeff check by
// chance. Reporting it as Aadhaar is a false claim about what was found,
// which is the one thing a receipt may never make.
//
// An Aadhaar number is never written with a leading "+". A country code
// always is.
func TestIndianMobileIsNotReportedAsAadhaar(t *testing.T) {
	spans := Default().Scan([]byte("call +919884012345 today"))

	if hasClass(spans, ClassINAadhaar) {
		t.Error("an E.164 mobile number was reported as an Aadhaar number")
	}
	if !hasClass(spans, ClassPhone) {
		t.Errorf("an E.164 mobile number was not reported as a phone number; classes = %v", classesOf(spans))
	}
}

// The fix must not stop Aadhaar being found where it genuinely appears.
//
// 234567890124 carries a valid Verhoeff check digit, which is what makes it
// an Aadhaar candidate rather than any twelve-digit number.
func TestAadhaarIsStillDetected(t *testing.T) {
	for _, text := range []string{
		"aadhaar 2345 6789 0124",
		"aadhaar: 234567890124",
		"234567890124 is the number",
	} {
		t.Run(text, func(t *testing.T) {
			spans := Default().Scan([]byte(text))
			if !hasClass(spans, ClassINAadhaar) {
				t.Errorf("Aadhaar was not detected in %q; classes = %v", text, classesOf(spans))
			}
		})
	}
}

func hasClass(spans []Span, class Class) bool {
	for _, s := range spans {
		if s.Class == class {
			return true
		}
	}
	return false
}

func classesOf(spans []Span) []Class {
	out := []Class{}
	for _, s := range spans {
		out = append(out, s.Class)
	}
	return out
}
