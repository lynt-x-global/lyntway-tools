package detect

import "testing"

func TestACardMustBelongToANetwork(t *testing.T) {
	for s, want := range map[string]bool{
		"4111 1111 1111 1111": true,  // Visa
		"5555555555554444":    true,  // Mastercard
		"2223003122003222":    true,  // Mastercard 2-series
		"378282246310005":     true,  // Amex
		"6011111111111117":    true,  // Discover
		"3530111333300000":    true,  // JCB
		"9999884960244227":    true,  // the reserved range tokens use
		"7156703146083437":    false, // Luhn-valid, no network
		"1628880136488025":    false, // UATP is fifteen digits
		"4222222222222":       true,  // Visa, 13
		"41111111111111":      false, // Visa is never 14
	} {
		if got := validCard(s); got != want {
			t.Errorf("validCard(%q) = %v, want %v", s, got, want)
		}
	}
}

func classesIn(s string) []Class {
	var out []Class
	for _, f := range Default().Scan([]byte(s)) {
		out = append(out, f.Class)
	}
	return out
}

func TestPartsOfLongerNumbersAreNotReported(t *testing.T) {
	for _, s := range []string{
		"Card on file ends 5503 2056 1075 2777.",            // a grouped 16-digit number is not an Aadhaar
		"Request id 550e8400-e29b-41d4-a716-907991301131.",  // nor the tail of an identifier
		"Wire to DE56 4254 2357 6931 3625 75 was rejected.", // nor is an IBAN a card when its check fails
	} {
		for _, c := range classesIn(s) {
			if c == ClassINAadhaar || c == ClassCreditCard {
				t.Errorf("%q reported %s", s, c)
			}
		}
	}
	// And the real ones still are.
	if cs := classesIn("Aadhaar 2345 6789 0124 on file."); len(cs) == 0 && validVerhoeff("234567890124") {
		t.Error("a standalone Aadhaar number was missed")
	}
	if cs := classesIn("Pay with 4111 1111 1111 1111 today."); len(cs) != 1 || cs[0] != ClassCreditCard {
		t.Errorf("a card number was missed: %v", cs)
	}
}
