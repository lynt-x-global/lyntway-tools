package tokenize

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// Every shaped token: looks like the value it replaces, can never be a real
// one, is recognised as a token so a second pass does not re-tokenise it,
// and is deterministic.
func TestShapedTokensSitOnReservedRanges(t *testing.T) {
	s := testScope(t)
	cases := []struct {
		class    detect.Class
		original string
		shape    *regexp.Regexp
		never    func(string) bool // true when the token cannot be real
		why      string
	}{
		{detect.ClassUSSSN, "078-05-1120", regexp.MustCompile(`^\d{3}-\d{2}-\d{4}$`),
			func(tok string) bool { a, _ := strconv.Atoi(tok[:3]); return a >= 900 }, "SSA never issues area 900-999"},
		{detect.ClassINAadhaar, "2345 6789 0123", regexp.MustCompile(`^\d{4} \d{4} \d{4}$`),
			func(tok string) bool {
				d := strings.ReplaceAll(tok, " ", "")
				c, ok := detect.VerhoeffCheckDigit(d[:11])
				return d[0] == '0' && ok && d[11] == byte('0'+c)
			}, "UIDAI never issues a number beginning 0; the check digit still validates"},
		{detect.ClassINPAN, "ABCPE1234F", regexp.MustCompile(`^[A-Z]{5}\d{4}[A-Z]$`),
			func(tok string) bool { return strings.HasPrefix(tok, "LYN") && tok[3] == 'P' && tok[4] == 'T' }, "LYN series, holder type kept"},
		{detect.ClassINPAN, "ABCCE1234F", regexp.MustCompile(`^[A-Z]{5}\d{4}[A-Z]$`),
			func(tok string) bool { return tok[3] == 'C' }, "a company PAN stays a company PAN"},
		{detect.ClassIBAN, "DE89 3704 0044 0532 0130 00", regexp.MustCompile(`^GB\d{2}LYNT\d{14}$`),
			func(tok string) bool { return ibanCheckDigits("GB", tok[4:]) == tok[2:4] }, "bank LYNT, mod-97 valid"},
		{detect.ClassINHealthID, "71-2257-5768-1157", regexp.MustCompile(`^\d{2}-\d{4}-\d{4}-\d{4}$`),
			func(tok string) bool { return strings.HasPrefix(tok, "00-") }, "NHA never issues 00"},
		{detect.ClassUKNINO, "QQ 12 34 56 C", regexp.MustCompile(`^ZZ \d{2} \d{2} \d{2} [A-D]$`),
			func(tok string) bool { return strings.HasPrefix(tok, "ZZ") }, "HMRC lists ZZ as never allocated"},
		{detect.ClassINUPI, "ramesh@okhdfcbank", regexp.MustCompile(`^lynt[a-z2-7]{8}@tokenized$`),
			func(tok string) bool { return strings.HasSuffix(tok, "@tokenized") }, "no PSP holds @tokenized"},
		{detect.ClassUSRouting, "021000021", regexp.MustCompile(`^99\d{7}$`),
			func(tok string) bool {
				d := make([]int, 9)
				for i := range tok {
					d[i] = int(tok[i] - '0')
				}
				return (3*(d[0]+d[3]+d[6])+7*(d[1]+d[4]+d[7])+(d[2]+d[5]+d[8]))%10 == 0
			}, "prefix 99 belongs to no district; checksum valid"},
		{detect.ClassBankAccount, "123456789012", regexp.MustCompile(`^9999\d{8}$`),
			func(tok string) bool { return len(tok) == 12 }, "same length, opens 9999"},
		{detect.ClassINPIN, "600017", regexp.MustCompile(`^00\d{4}$`),
			func(tok string) bool { return true }, "India Post issues nothing beginning 0"},
		{detect.ClassPassportNumber, "M1234567", regexp.MustCompile(`^Z9\d{6}$`),
			func(tok string) bool { return true }, "Z9 series"},
		{detect.ClassDateOfBirth, "14/08/1991", regexp.MustCompile(`^\d{2}/\d{2}/\d{4}$`),
			func(tok string) bool { y, _ := strconv.Atoi(tok[6:]); return y < 1940 }, "a date in 1900-1939, same separators"},
		{detect.ClassDateOfBirth, "1991-08-14", regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`),
			func(tok string) bool { return strings.HasPrefix(tok, "19") }, "ISO order kept"},
	}
	for _, c := range cases {
		tok := mustTok(t, s, c.class, c.original)
		if !c.shape.MatchString(tok) {
			t.Errorf("%s: token %q does not have the shape of %q", c.class, tok, c.original)
			continue
		}
		if !c.never(tok) {
			t.Errorf("%s: token %q could be a real value (%s)", c.class, tok, c.why)
		}
		if c.class != detect.ClassDateOfBirth && !IsToken(tok) {
			t.Errorf("%s: token %q is not recognised as a token, so a second pass would tokenise it again", c.class, tok)
		}
		if again := mustTok(t, s, c.class, c.original); again != tok {
			t.Errorf("%s: not deterministic: %q then %q", c.class, tok, again)
		}
		if strings.Contains(tok, strings.ReplaceAll(c.original, " ", "")) {
			t.Errorf("%s: token %q carries the original", c.class, tok)
		}
	}
}

// A shaped token must not be found by the detector as the thing it imitates
// — or, where its validity is the point (IBAN, Aadhaar, routing), the
// detector may find it only as something IsToken already excludes.
func TestShapedTokensAreNotReDetectedAsRealValues(t *testing.T) {
	s := testScope(t)
	rs := detect.Default()
	for _, c := range []struct {
		class detect.Class
		value string
	}{
		{detect.ClassUSSSN, "078-05-1120"}, {detect.ClassINAadhaar, "2345 6789 0123"},
		{detect.ClassIBAN, "DE89 3704 0044 0532 0130 00"}, {detect.ClassUSRouting, "021000021"},
		{detect.ClassUKNINO, "QQ 12 34 56 C"}, {detect.ClassINHealthID, "71-2257-5768-1157"},
	} {
		tok := mustTok(t, s, c.class, c.value)
		for _, sp := range rs.Scan([]byte("Value: " + tok + " noted.")) {
			if !IsToken(sp.Value) {
				t.Errorf("%s: detector found %q (%s) inside the token %q and IsToken does not exclude it", c.class, sp.Value, sp.Class, tok)
			}
		}
	}
}

// Names and addresses have no reserved range; they are plainly nobody's and
// are restored by enumeration, longest first.
func TestNamesAndAddressesAreSyntheticAndRestoreByEnumeration(t *testing.T) {
	s := testScope(t)
	one := mustTok(t, s, detect.ClassPersonName, "Priya")
	two := mustTok(t, s, detect.ClassPersonName, "Priya Sharma")
	three := mustTok(t, s, detect.ClassPersonName, "Ramesh Kumar Venkataraman")
	caps := mustTok(t, s, detect.ClassPersonName, "RAMESH VENKATARAMAN")
	for tok, words := range map[string]int{one: 1, two: 2, three: 3} {
		if len(strings.Fields(tok)) != words {
			t.Errorf("%q should have %d word(s)", tok, words)
		}
	}
	if caps != strings.ToUpper(caps) {
		t.Errorf("an all-capitals name should stay capitals: %q", caps)
	}
	addr := mustTok(t, s, detect.ClassLocation, "14 Example Street, Chennai")
	if !regexp.MustCompile(`^\d{1,3} [A-Z][a-z]+ (Road|Street|Lane|Avenue), [A-Z]`).MatchString(addr) {
		t.Errorf("address token %q is not address-shaped", addr)
	}

	reply := []byte("Dear " + two + ", the certificate for " + three + " at " + addr + " is valid; contact " + one + ".")
	back, n, err := s.RestoreAll(reply)
	if err != nil {
		t.Fatal(err)
	}
	want := "Dear Priya Sharma, the certificate for Ramesh Kumar Venkataraman at 14 Example Street, Chennai is valid; contact Priya."
	if string(back) != want {
		t.Fatalf("restored = %q\nwant       %q", back, want)
	}
	if n != 4 {
		t.Errorf("restored %d substitutions, want 4", n)
	}
}

// RestoreAll also restores the patterned tokens, in the same pass.
func TestRestoreAllCoversPatternedAndEnumeratedTokens(t *testing.T) {
	s := testScope(t)
	ssn := mustTok(t, s, detect.ClassUSSSN, "078-05-1120")
	name := mustTok(t, s, detect.ClassPersonName, "Jane Doe")
	back, n, err := s.RestoreAll([]byte(name + " holds SSN " + ssn + "."))
	if err != nil || string(back) != "Jane Doe holds SSN 078-05-1120." || n != 2 {
		t.Fatalf("RestoreAll = %q, %d, %v", back, n, err)
	}
	// A one-way scope restores nothing and says so by count.
	oneWay, _ := NewScope(make([]byte, KeySize), DiscardStore{})
	tok, _ := oneWay.Tokenize(detect.ClassPersonName, "Jane Doe")
	_, n, _ = oneWay.RestoreAll([]byte(tok))
	if n != 0 {
		t.Errorf("a DiscardStore scope restored %d tokens; it holds nothing to restore from", n)
	}
}
