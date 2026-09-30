package detect

import "testing"

// Indian identifiers, as an Indian customer writes them.
//
// Probed on production before a demo for an Indian financial institution:
// the spaced Aadhaar and the "+91" mobile were caught, and everything
// written the ordinary Indian way was not — a hyphenated Aadhaar, a PAN in
// lower case, a mobile as "98840 12345", and a UPI ID at all. Worse than any
// miss, an HDFC savings account number was reported as a payment card.
func TestIndianIdentifiersAreFoundAsTheyAreWritten(t *testing.T) {
	rs := Default()
	for _, tc := range []struct {
		content string
		want    Class
		span    string
	}{
		{"Aadhaar 2345 6789 0124 for KYC", ClassINAadhaar, "2345 6789 0124"},
		{"Aadhaar 234567890124 for KYC", ClassINAadhaar, "234567890124"},
		{"Aadhaar 2345-6789-0124 for KYC", ClassINAadhaar, "2345-6789-0124"},
		{"PAN ABCPE1234F on the form", ClassINPAN, "ABCPE1234F"},
		{"my pan is abcpe1234f", ClassINPAN, "abcpe1234f"},
		{"call 98840 12345 after six", ClassPhone, "98840 12345"},
		{"call 98840-12345 after six", ClassPhone, "98840-12345"},
		{"call 098840 12345 after six", ClassPhone, "098840 12345"},
		{"pay to ramesh.k@okhdfcbank today", ClassINUPI, "ramesh.k@okhdfcbank"},
		{"UPI 9884012345@ybl", ClassINUPI, "9884012345@ybl"},
		{"send it to priya@paytm.", ClassINUPI, "priya@paytm"},
		{"RuPay 8112 0000 0000 0008", ClassCreditCard, "8112 0000 0000 0008"},
		{"RuPay 5081000000000001", ClassCreditCard, "5081000000000001"},
	} {
		var got []string
		for _, s := range rs.Scan([]byte(tc.content)) {
			if s.Class == tc.want {
				got = append(got, tc.content[s.Start:s.End])
			}
		}
		if len(got) != 1 || got[0] != tc.span {
			t.Errorf("Scan(%q) found %s %q, want exactly [%q]", tc.content, tc.want, got, tc.span)
		}
	}
}

// The negative half, which on a bank's demo matters more.
func TestIndianLookalikesAreNotReported(t *testing.T) {
	rs := Default()
	for _, tc := range []struct {
		content string
		never   Class
	}{
		// An HDFC savings account: fourteen digits beginning 50100, and
		// Luhn-valid, so it was reported as a Maestro card.
		{"a/c no 50100123456789 HDFC", ClassCreditCard},
		// "+91 98840 12345" is one finding, the international rule's.
		// Checked below; here, the bare ten digits stay the model tier's.
		{"order 9884012345 shipped", ClassPhone},
		// A landline-length or too-short group is not a mobile.
		{"ref 12345 67890 attached", ClassPhone},
		// An ordinary email at a domain that shares a handle's name.
		{"write to x@ybl.com", ClassINUPI},
		// A mention or a handle that is not a PSP's.
		{"thanks @ybl for the help", ClassINUPI},
		{"ping ramesh@example", ClassINUPI},
		// An Aadhaar-shaped tail of a UUID stays excluded with hyphens too.
		{"id 550e8400-e29b-2345-6789-012412345678", ClassINAadhaar},
	} {
		for _, s := range rs.Scan([]byte(tc.content)) {
			if s.Class == tc.never {
				t.Errorf("Scan(%q) reported %s %q", tc.content, tc.never, tc.content[s.Start:s.End])
			}
		}
	}

	// And a real email address stays one finding, an email.
	var emails, upis int
	for _, s := range rs.Scan([]byte("write to x@ybl.com")) {
		switch s.Class {
		case ClassEmail:
			emails++
		case ClassINUPI:
			upis++
		}
	}
	if emails != 1 || upis != 0 {
		t.Errorf("x@ybl.com: %d email, %d UPI findings; want one email", emails, upis)
	}

	// One number is one finding.
	var phones []string
	c := "call +91 98840 12345"
	for _, s := range rs.Scan([]byte(c)) {
		if s.Class == ClassPhone {
			phones = append(phones, c[s.Start:s.End])
		}
	}
	if len(phones) != 1 || phones[0] != "+91 98840 12345" {
		t.Errorf("%q gave phone findings %q, want the whole international number once", c, phones)
	}
}
