package detect

import "testing"

// The same defect, a third and fourth time, in two more rules.
//
// pii.us_ssn matched a hyphen and only a hyphen. pci.iban required capital
// letters while its own validator uppercased before checking, so it could
// never have seen a lowercase one. An evaluator pasted the forms a real
// system emits and watched most of them reach the model untouched:
//
//	078-05-1120   caught          GB82 WEST 1234 5698 7654 32   caught
//	078 05 1120   MISSED          gb82 west 1234 5698 7654 32   MISSED
//	078051120     MISSED
//	078.05.1120   MISSED
//
// This repository has now shipped this shape four times: the IBAN matched
// unspaced and missed spaced, the phone number that needed a leading "+",
// and these two. The rule keeps being right about the value and wrong about
// how a person writes it.
//
// Bare digits stay out. "078051120" is any nine-digit identifier and
// belongs to the model tier, where surrounding context exists. That is the
// same judgement the phone rule makes about "5125550148" and it is still
// the right one.
func TestASocialSecurityNumberIsFoundHoweverItIsPunctuated(t *testing.T) {
	rs := Default()

	for _, tc := range []struct{ content, want string }{
		{"SSN 078-05-1120 on file", "078-05-1120"},
		{"SSN 078 05 1120 on file", "078 05 1120"},
		{"SSN 078.05.1120 on file", "078.05.1120"},
	} {
		var got []string
		for _, s := range rs.Scan([]byte(tc.content)) {
			if s.Class == ClassUSSSN {
				got = append(got, tc.content[s.Start:s.End])
			}
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("Scan(%q) found %q, want exactly [%q]", tc.content, got, tc.want)
		}
	}
}

func TestSocialSecurityNumbersThatAreNotOnes(t *testing.T) {
	rs := Default()

	for _, content := range []string{
		// Bare digits: deliberately still the model tier's problem.
		"order 078051120 shipped",
		// The SSA issues none of these.
		"ref 000-05-1120", "ref 666-05-1120", "ref 900-05-1120",
		"ref 078-00-1120", "ref 078-05-0000",
		// A mixed separator is two adjacent numbers, not one SSN. RE2 has
		// no backreference, so the validator is what holds this.
		"ref 078-05 1120", "ref 078 05.1120", "ref 078.05-1120",
	} {
		for _, s := range rs.Scan([]byte(content)) {
			if s.Class == ClassUSSSN {
				t.Errorf("Scan(%q) claimed %q as a Social Security number",
					content, content[s.Start:s.End])
			}
		}
	}
}

// An IBAN is an IBAN in whatever case it was typed.
//
// Loosening the pattern is safe because ISO 13616's mod-97 check is doing
// the real work: two letters, two digits and a run of alphanumerics is a
// weak shape, and essentially nothing that is not an IBAN survives the
// checksum.
func TestAnIBANIsFoundInLowerCase(t *testing.T) {
	rs := Default()

	for _, tc := range []struct{ content, want string }{
		{"pay to GB82 WEST 1234 5698 7654 32 today", "GB82 WEST 1234 5698 7654 32"},
		{"pay to gb82 west 1234 5698 7654 32 today", "gb82 west 1234 5698 7654 32"},
		{"pay to GB82WEST12345698765432 today", "GB82WEST12345698765432"},
		{"pay to gb82west12345698765432 today", "gb82west12345698765432"},
		{"pay to Gb82 West 1234 5698 7654 32 today", "Gb82 West 1234 5698 7654 32"},
	} {
		var got []string
		for _, s := range rs.Scan([]byte(tc.content)) {
			if s.Class == ClassIBAN {
				got = append(got, tc.content[s.Start:s.End])
			}
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("Scan(%q) found %q, want exactly [%q]", tc.content, got, tc.want)
		}
	}
}

// And the checksum still has to hold, in either case. Without this the
// case-insensitive pattern would be a licence to flag any two letters
// followed by two digits and a run of alphanumerics.
func TestALowerCaseNonIBANIsStillNotAnIBAN(t *testing.T) {
	rs := Default()

	for _, content := range []string{
		// One digit changed: the mod-97 check fails.
		"pay to gb82 west 1234 5698 7654 33 today",
		"pay to GB82 WEST 1234 5698 7654 33 today",
		// Ordinary text that wears the shape.
		"see ticket ab12cdefghijklmn for details",
	} {
		for _, s := range rs.Scan([]byte(content)) {
			if s.Class == ClassIBAN {
				t.Errorf("Scan(%q) claimed %q as an IBAN", content, content[s.Start:s.End])
			}
		}
	}
}
