package detect

import "testing"

// India's fourteen-digit health identifiers: ABHA for a patient, HPR for a
// practitioner. Added after one went to an AI service inside an uploaded
// registration PDF while Aadhaar and PAN on the same page were both known.
func TestIndianHealthID(t *testing.T) {
	rs := Default()
	has := func(s string, c Class) bool {
		for _, sp := range rs.Scan([]byte(s)) {
			if sp.Class == c {
				return true
			}
		}
		return false
	}

	t.Run("caught", func(t *testing.T) {
		for name, in := range map[string]string{
			"HPR ID, hyphenated": "HPR-ID: 71-1157-5768-1157",
			"ABHA, hyphenated":   "ABHA number 12-3456-7890-1234",
			"spaces instead":     "Health ID 71 1157 5768 1157",
			"bare, no label":     "91-2233-4455-6677",
			"inside a sentence":  "Her registry number is 71-1157-5768-1157 and expires in 2027.",
			"beside other ids":   "PAN ABCPE1234F, Aadhaar 2345 6789 0124, HPR 71-1157-5768-1157",
		} {
			if !has(in, ClassINHealthID) {
				t.Errorf("%s: not detected (%q)", name, in)
			}
		}
	})

	t.Run("the shapes it must not claim", func(t *testing.T) {
		// There is no published check digit, so the grouping is the entire
		// signal. Anything that is merely fourteen digits must stay quiet, or
		// the rule fires on timestamps and order lines all day.
		for name, in := range map[string]string{
			"fourteen bare digits":   "reference 71115757681157",
			"a date":                 "20260101120000",
			"a phone with country":   "+91 98765 43210",
			"a card number":          "4111 1111 1111 1111",
			"an Aadhaar":             "2345 6789 0124",
			"wrong grouping 4-4-4-2": "1234-5678-9012-34",
			"too few groups":         "71-1157-5768",
			"letters in it":          "71-11A7-5768-1157",
		} {
			if has(in, ClassINHealthID) {
				t.Errorf("%s: claimed a health ID where there is none (%q)", name, in)
			}
		}
	})

	t.Run("it does not steal an Aadhaar or a card", func(t *testing.T) {
		// Both are digit groupings on the same forms, and a rule that swallowed
		// them would relabel a known identifier as a weaker one.
		if !has("aadhaar 2345 6789 0124", ClassINAadhaar) {
			t.Error("Aadhaar stopped being detected")
		}
		if !has("card 4111 1111 1111 1111", ClassCreditCard) {
			t.Error("the card number stopped being detected")
		}
	})

	t.Run("it reads as something a person understands", func(t *testing.T) {
		if got := Label(ClassINHealthID); got == "" || got == string(ClassINHealthID) {
			t.Errorf("Label(%s) = %q; a receipt shows this to somebody", ClassINHealthID, got)
		}
	})
}
