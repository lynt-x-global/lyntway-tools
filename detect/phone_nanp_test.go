package detect

import (
	"strings"
	"testing"
)

// A North American phone number written the way North Americans write it.
//
// Until 22 September 2026 pii.phone required a leading "+". A healthcare
// evaluator fed the detector a realistic patient line — name, DOB, MRN,
// phone, clinic — and watched "512-555-0148" reach the model untouched
// while the receipt read governance mode "full". Two of eight identifiers
// were caught.
//
// The "+" was a real judgement and it is still right about "5125550148":
// ten loose digits do match order numbers, part numbers and ordinary
// numeric text. What it got wrong is that a SEPARATED number is not ten
// loose digits. "(512) 555-0148" is a punctuation pattern almost nothing
// else wears.
//
// This is the same defect as the IBAN that was matched unspaced and missed
// in the spaced form printed on every invoice. The pair of tests below is
// written so that the negative half carries equal weight: a false finding
// on a receipt claims something crossed the wire that did not, which the
// honesty rule forbids just as firmly as claiming too little.
func TestNANPPhoneNumbersAreDetectedAsPeopleWriteThem(t *testing.T) {
	rs := Default()

	for _, tc := range []struct {
		content string
		want    string // the exact span that must be claimed
	}{
		{"call me on 512-555-0148 today", "512-555-0148"},
		{"call me on (512) 555-0148 today", "(512) 555-0148"},
		{"call me on (512)555-0148 today", "(512)555-0148"},
		{"call me on 512.555.0148 today", "512.555.0148"},
		{"call me on 512 555 0148 today", "512 555 0148"},
		{"call me on 1-512-555-0148 today", "1-512-555-0148"},
		// The form the evaluator actually used, in the shape it arrived.
		{"Patient Maria Gonzalez, phone 512-555-0199, Austin Family Clinic", "512-555-0199"},
		// Start of content: the leading-context branch must not need a
		// character before the number.
		{"512-555-0148 is the clinic", "512-555-0148"},
	} {
		spans := rs.Scan([]byte(tc.content))
		var got []string
		for _, s := range spans {
			if s.Class == ClassPhone {
				got = append(got, tc.content[s.Start:s.End])
			}
		}
		if len(got) != 1 {
			t.Errorf("Scan(%q) found %d phone numbers %q, want exactly 1", tc.content, len(got), got)
			continue
		}
		// The span matters as much as the finding. A span that swallows
		// the preceding character deletes it from the output when the
		// value is tokenised.
		if got[0] != tc.want {
			t.Errorf("Scan(%q) claimed %q, want %q", tc.content, got[0], tc.want)
		}
	}
}

// The negative half. Each of these matched some earlier draft of the
// pattern, which is why they are named individually rather than described.
func TestNANPPhoneDoesNotClaimThingsThatAreNotPhoneNumbers(t *testing.T) {
	rs := Default()

	for _, content := range []string{
		// Unseparated: deliberately still not ours. It belongs to the
		// model tier, where surrounding context is available.
		"order 5125550148 shipped",
		// N11 is reserved for services and is never an area code or an
		// exchange.
		"dial 911 555-0100 for the desk",
		"ext 411-555-0100",
		// An area code or exchange may not begin with 0 or 1.
		"ref 012-555-0148",
		"ref 512-155-0148",
		// Ordinary numeric text that wears the right punctuation.
		"version 1.2.3 released",
		"the range 100-200-3000 units",
		// An IP address must stay an IP address.
		"host 192.168.1.1 is up",
		// Digits either side mean this is a longer run, not a number.
		"id 9512-555-01489 in the export",
	} {
		for _, s := range rs.Scan([]byte(content)) {
			if s.Class == ClassPhone {
				t.Errorf("Scan(%q) claimed %q as a phone number", content, content[s.Start:s.End])
			}
		}
	}
}

// One number is one finding.
//
// "+1 512 555 0148" matches phone-international and phone-nanp both, and
// their spans overlap. The resolver keeps one rule per byte — priority,
// then confidence, then length — and phone-nanp sits at priority 54 so the
// international rule wins. If that ordering is ever reversed, the receipt
// starts reporting two phone numbers where the traffic carried one, and a
// receipt that counts wrong is a receipt that claims wrong.
func TestAnInternationalNumberIsNotAlsoCountedAsANANPNumber(t *testing.T) {
	rs := Default()

	for _, content := range []string{
		"reach me at +1 512 555 0148 any time",
		"reach me at +1 (512) 555-0148 any time",
		"reach me at +1-512-555-0148 any time",
	} {
		var got []string
		for _, s := range rs.Scan([]byte(content)) {
			if s.Class == ClassPhone {
				got = append(got, content[s.Start:s.End])
			}
		}
		if len(got) != 1 {
			t.Errorf("Scan(%q) found %d phone findings %q, want 1", content, len(got), got)
			continue
		}
		// And the winner must be the international rule's span, which
		// includes the "+" and the country code.
		if !strings.HasPrefix(got[0], "+1") {
			t.Errorf("Scan(%q) claimed %q; the international rule should claim the whole "+
				"number including its \"+\", not the national part of it", content, got[0])
		}
	}
}
