package detect

import "testing"

// Six digits beside the word that makes them an address.
func TestALabelledIndianPINIsFound(t *testing.T) {
	rs := Default()
	found := func(s string) string {
		for _, sp := range rs.Scan([]byte(s)) {
			if sp.Class == ClassINPIN {
				return s[sp.Start:sp.End]
			}
		}
		return ""
	}
	for _, tc := range []struct{ in, want string }{
		{"Postal code:                     533001", "533001"},
		{"PIN Code - 560001", "560001"},
		{"Pincode 400001", "400001"},
		{"Post code: 110001", "110001"},
	} {
		if got := found(tc.in); got != tc.want {
			t.Errorf("Scan(%q) PIN = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, s := range []string{"533001", "Postal code: 033001", "Postal code: 5330011", "pin 1234", "total 533001 units in stock"} {
		if got := found(s); got != "" {
			t.Errorf("Scan(%q) claimed a PIN %q", s, got)
		}
	}
}
