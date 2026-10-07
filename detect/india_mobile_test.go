package detect

import "testing"

// The form a mobile number is actually written in, in India.
//
// phone-international requires a "+" and phone-nanp requires US punctuation.
// Neither covers ten bare digits, which is how every Indian form prints one.
// The label in front is what makes it claimable without claiming every
// ten-digit run in the document.
func TestALabelledIndianMobileIsFound(t *testing.T) {
	rs := Default()
	found := func(s string) string {
		for _, sp := range rs.Scan([]byte(s)) {
			if sp.Class == ClassPhone {
				return s[sp.Start:sp.End]
			}
		}
		return ""
	}

	// The exact line from the registration PDF that prompted the rule. The
	// asterisk is the required-field marker; a separator class of whitespace
	// alone matched the test and missed the document.
	for _, tc := range []struct{ in, want string }{
		{"Mobile No*:                            9951310751", "9951310751"},
		{"Mobile No: 9812345670", "9812345670"},
		{"Phone: 9812345670", "9812345670"},
		{"Telephone 9812345670", "9812345670"},
		{"Contact 9812345670", "9812345670"},
		{"WhatsApp 9812345670", "9812345670"},
		{"Cell # 9812345670", "9812345670"},
		{"mobile number 6012345670", "6012345670"},
	} {
		if got := found(tc.in); got != tc.want {
			t.Errorf("Scan(%q) phone = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// What it must not claim. The judgement that a bare run of ten digits is too
// common to report belongs to phone-international and is not reopened here.
func TestAnUnlabelledTenDigitRunIsStillNotAPhoneNumber(t *testing.T) {
	rs := Default()
	for _, s := range []string{
		"order 9812345670 shipped",
		"invoice total 9812345670 rupees",
		"9812345670",
		// Not an Indian mobile: the range is 6-9.
		"Mobile No 5812345670",
		// Eleven digits is not a ten-digit number with one to spare.
		"Mobile No 98123456701",
		// The label must be a word, not a fragment of one.
		"hotel 9812345670",
		// The gap between label and number is punctuation, not prose.
		"mobile app downloaded 9812345670 times",
		"phone the office and ask for 9812345670 extensions",
	} {
		for _, sp := range rs.Scan([]byte(s)) {
			if sp.Class == ClassPhone {
				t.Errorf("Scan(%q) claimed a phone number %q; this rule must not "+
					"reach an unlabelled or out-of-range run of digits",
					s, s[sp.Start:sp.End])
			}
		}
	}
}

// One number is one finding. "+91 98840 12345" matches the international rule
// and must not also be claimed here.
func TestAnInternationalIndianNumberIsClaimedOnce(t *testing.T) {
	rs := Default()
	n := 0
	for _, sp := range rs.Scan([]byte("Mobile: +91 98840 12345")) {
		if sp.Class == ClassPhone {
			n++
		}
	}
	if n != 1 {
		t.Errorf("got %d phone findings for one number, want 1", n)
	}
}

// The label is context and stays out of the span, so substitution leaves the
// field heading readable. us-routing-number does the same.
func TestTheLabelIsNotRedactedWithTheNumber(t *testing.T) {
	rs := Default()
	in := "Mobile No*: 9951310751"
	for _, sp := range rs.Scan([]byte(in)) {
		if sp.Class != ClassPhone {
			continue
		}
		if got := in[sp.Start:sp.End]; got != "9951310751" {
			t.Errorf("span = %q, want just the digits: a span that swallows the "+
				"label deletes the field heading from the document", got)
		}
	}
}
