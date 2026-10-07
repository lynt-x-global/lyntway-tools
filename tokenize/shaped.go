package tokenize

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// Shaped tokens: a substitute that reads like the value it replaces.
//
// A document with <PERSON_NAME> four times and a black box where the PAN
// was is still a document the model cannot do much with, and the reply it
// gives reads oddly to the person who asked. A substitute in the same shape
// keeps the document a document and the reply a reply, and the receipt says
// `tokenize` because that is what happened.
//
// The rule every generator here obeys: the dummy must come from a range that
// can never be a real person's. Not "unlikely" — never, by the issuing
// authority's own rules — and where an authority publishes no reserved range
// (PAN, Indian passports) the token carries a series that marks it as ours
// and the limitation is written down beside the generator. A format-
// preserving substitute that could be somebody else's number is not a
// protection, it is a transfer of risk to a stranger.
//
// Names, addresses and dates have no reserved range and no pattern a regexp
// can pick out of a reply, so they are restored by enumeration of the
// scope's own store (RestoreAll) rather than by tokenPattern.

// SSN: area numbers 900–999 are never issued by the Social Security
// Administration (nor 000 or 666), and the group and serial are never 00
// or 0000.
func ssnToken(sum []byte) string {
	area := 900 + int(sum[0])%100
	group := 1 + int(sum[1])%99
	serial := 1 + (int(sum[2])<<8|int(sum[3]))%9999
	return fmt.Sprintf("%03d-%02d-%04d", area, group, serial)
}

// Aadhaar: UIDAI never issues a number beginning with 0 or 1. The token
// begins with 0, carries a valid Verhoeff check digit so a form's own
// validation accepts it, and is printed in the 4-4-4 groups the card uses.
func aadhaarToken(sum []byte) string {
	var b strings.Builder
	b.WriteByte('0')
	for i := 0; i < 10; i++ {
		b.WriteByte('0' + sum[i]%10)
	}
	body := b.String()
	check, _ := detect.VerhoeffCheckDigit(body)
	full := body + string(rune('0'+check))
	return full[:4] + " " + full[4:8] + " " + full[8:]
}

// PAN: the Income Tax Department publishes no reserved series. The token
// keeps the fourth character — the holder type (P person, C company, …) —
// so the document still says what kind of taxpayer it names, and takes the
// series LYN with T in the surname position, which marks it as ours. This
// is the one shaped token whose "never real" rests on the series being far
// from the sequential allocation rather than on a published rule.
func panToken(sum []byte, original string) string {
	status := byte('P')
	if up := strings.ToUpper(strings.Join(strings.Fields(original), "")); len(up) >= 4 && up[3] >= 'A' && up[3] <= 'Z' {
		status = up[3]
	}
	digits := make([]byte, 4)
	for i := range digits {
		digits[i] = '0' + sum[i]%10
	}
	return "LYN" + string(status) + "T" + string(digits) + string(rune('A'+int(sum[4])%26))
}

// IBAN: a GB IBAN whose bank code is LYNT, which no institution holds, with
// valid ISO 13616 check digits so a payment form's own validation accepts
// it. One country for every token: the shape "an IBAN" is preserved; the
// originating country is not, which is a deliberate loss — a per-country
// generator would be thirty formats to keep right.
func ibanToken(sum []byte) string {
	var b strings.Builder
	for i := 0; i < 14; i++ {
		b.WriteByte('0' + sum[i]%10)
	}
	bban := "LYNT" + b.String()
	return "GB" + ibanCheckDigits("GB", bban) + bban
}

// ibanCheckDigits computes the two check digits that make country+cc+bban
// satisfy the mod-97 rule.
func ibanCheckDigits(country, bban string) string {
	rearranged := bban + country + "00"
	remainder := 0
	for _, r := range rearranged {
		var chunk int
		switch {
		case r >= '0' && r <= '9':
			chunk = int(r - '0')
			remainder = (remainder*10 + chunk) % 97
		case r >= 'A' && r <= 'Z':
			chunk = int(r-'A') + 10
			remainder = (remainder*100 + chunk) % 97
		}
	}
	return fmt.Sprintf("%02d", 98-remainder)
}

// ABHA / HPR health IDs: fourteen digits in 2-4-4-4 groups. The token opens
// with 00, which the National Health Authority never issues.
func healthIDToken(sum []byte) string {
	var b strings.Builder
	b.WriteString("00-")
	for i := 0; i < 12; i++ {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteByte('0' + sum[i]%10)
	}
	return b.String()
}

// UK National Insurance: HMRC lists ZZ among the prefixes never allocated.
// Printed in the spaced groups the card uses, suffix A–D.
func ninoToken(sum []byte) string {
	return fmt.Sprintf("ZZ %02d %02d %02d %c", int(sum[0])%100, int(sum[1])%100, int(sum[2])%100, 'A'+rune(sum[3]%4))
}

// UPI: a VPA whose handle is @tokenized, which NPCI has never assigned to
// a payment service provider.
func upiToken(sum []byte) string {
	return "lynt" + encode(sum[:5]) + "@tokenized"
}

// ABA routing: the first two digits 99 belong to no Federal Reserve
// district or thrift range, and the ninth digit makes the checksum valid.
func routingToken(sum []byte) string {
	d := [9]int{9, 9}
	for i := 2; i < 8; i++ {
		d[i] = int(sum[i]) % 10
	}
	partial := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2] + d[5])
	d[8] = (10 - partial%10) % 10
	var b strings.Builder
	for _, v := range d {
		b.WriteByte('0' + byte(v))
	}
	return b.String()
}

// Bank account: no authority, no checksum. Same length as the original,
// opening 9999 so it sits in no bank's numbering and is recognisable.
func bankAccountToken(sum []byte, length int) string {
	if length < 8 {
		length = 8
	}
	if length > 24 {
		length = 24
	}
	var b strings.Builder
	b.WriteString("9999")
	for i := 0; b.Len() < length; i++ {
		b.WriteByte('0' + sum[i%len(sum)]%10)
	}
	return b.String()
}

// Indian PIN: six digits, and India Post issues nothing beginning with 0.
func pinToken(sum []byte) string {
	return fmt.Sprintf("00%04d", (int(sum[0])<<8|int(sum[1]))%10000)
}

// Passport: Indian passports are a letter and seven digits. The token is
// Z9 and six digits; Z is not a series the Passport Seva programme issues
// to the public, and the second position is never a 9. Like PAN, this
// rests on the issuer's practice rather than a published reservation.
func passportToken(sum []byte) string {
	return fmt.Sprintf("Z9%06d", (int(sum[0])<<16|int(sum[1])<<8|int(sum[2]))%1000000)
}

// dobToken writes a date in the same arrangement as the original — same
// separators, same order — with the day 1–28, the month 1–12 and the year
// in 1900–1939, so the person it describes would be at least 87 and the
// date is plainly a stand-in. A date the pattern cannot read falls back to
// the generic token.
var dateShapes = []*regexp.Regexp{
	regexp.MustCompile(`^(\d{1,2})([./-])(\d{1,2})([./-])(\d{4})$`), // dd/mm/yyyy or mm/dd/yyyy
	regexp.MustCompile(`^(\d{4})([./-])(\d{1,2})([./-])(\d{1,2})$`), // yyyy-mm-dd
}

func dobToken(class detect.Class, sum []byte, original string) string {
	day := 1 + int(sum[0])%28
	month := 1 + int(sum[1])%12
	year := 1900 + int(sum[2])%40
	v := strings.TrimSpace(original)
	if m := dateShapes[0].FindStringSubmatch(v); m != nil {
		return fmt.Sprintf("%02d%s%02d%s%04d", day, m[2], month, m[4], year)
	}
	if m := dateShapes[1].FindStringSubmatch(v); m != nil {
		return fmt.Sprintf("%04d%s%02d%s%02d", year, m[2], month, m[4], day)
	}
	return genericToken(class, sum)
}

// Names are built from syllables rather than drawn from a list of real
// names, so a token cannot land on a colleague, a public figure or another
// person in the same document. The result is pronounceable and shaped like
// a name — "Tavin Morelka" — and is plainly nobody. Word count follows the
// original (one to three words), as does an all-capitals original.
var (
	nameOnsets = []string{"Ta", "Vel", "Ori", "Mar", "Kel", "Sora", "Dan", "Ilo", "Nev", "Ras", "Tev", "Lio", "Ane", "Pel", "Vir", "Ona"}
	nameCodas  = []string{"vin", "ron", "lek", "mir", "dan", "sel", "tor", "nai", "ven", "lar", "din", "mos", "rel", "kai", "sen", "lin"}
	surnameMid = []string{"Mo", "Kal", "Ven", "Tar", "Sel", "Ro", "Ha", "Lin", "Dor", "Mel", "Var", "No", "Pel", "Sa", "Ter", "Ko"}
	surnameEnd = []string{"relka", "vani", "sorin", "deth", "manu", "lkar", "rane", "vith", "sona", "dren", "mire", "tova", "lith", "ndar", "vesk", "rian"}
)

func nameToken(sum []byte, original string) string {
	words := len(strings.Fields(original))
	if words < 1 {
		words = 1
	}
	if words > 3 {
		words = 3
	}
	first := nameOnsets[int(sum[0])%len(nameOnsets)] + nameCodas[int(sum[1])%len(nameCodas)]
	middle := nameOnsets[int(sum[2])%len(nameOnsets)] + nameCodas[int(sum[3])%len(nameCodas)]
	last := surnameMid[int(sum[4])%len(surnameMid)] + surnameEnd[int(sum[5])%len(surnameEnd)]
	var out string
	switch words {
	case 1:
		out = first
	case 2:
		out = first + " " + last
	default:
		out = first + " " + middle + " " + last
	}
	if original == strings.ToUpper(original) && strings.ToUpper(original) != strings.ToLower(original) {
		out = strings.ToUpper(out)
	}
	return out
}

// Addresses keep the shape "number street, town" with a street and a town
// that exist nowhere, so a model can still say "the address on page 2" and
// nobody is sent to a real door.
var (
	streetNames = []string{"Tokenway", "Ledger", "Receipt", "Meridian", "Harbour", "Cedar", "Lantern", "Quill", "Sable", "Vantage", "Orchard", "Beacon", "Granite", "Juniper", "Compass", "Willow"}
	streetKinds = []string{"Road", "Street", "Lane", "Avenue"}
	townNames   = []string{"Lyntpuram", "Tokenpur", "Vaultford", "Signwell", "Receiptham", "Cipherabad", "Hashville", "Ledgerton", "Provence Nagar", "Attestburg", "Sealmore", "Verifield", "Keystone Colony", "Digestpur", "Chainford", "Noncebury"}
)

func addressToken(sum []byte) string {
	num := 1 + int(sum[0])%199
	return fmt.Sprintf("%d %s %s, %s", num,
		streetNames[int(sum[1])%len(streetNames)],
		streetKinds[int(sum[2])%len(streetKinds)],
		townNames[int(sum[3])%len(townNames)])
}

// Enumerator is a Store that can list what it holds. The in-memory store
// can; a token vault behind a database may not, and RestoreAll degrades to
// the pattern-only restore for those.
type Enumerator interface {
	Each(fn func(token, value string) bool)
}

// Each visits every token the memory store holds, in no particular order,
// stopping when fn returns false.
func (s *MemoryStore) Each(fn func(token, value string) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for token, value := range s.m {
		if !fn(token, value) {
			return
		}
	}
}

// RestoreAll puts the original values back for every token this scope has
// issued, including the ones no pattern can find — names, addresses, dates.
// The patterned tokens are restored first, then whatever the store holds is
// replaced longest-first so "Tavin Morelka" is restored before "Tavin".
// Returns the content and how many substitutions were made.
func (s *Scope) RestoreAll(content []byte) ([]byte, int, error) {
	if s == nil {
		return nil, 0, ErrScopeRequired
	}
	out, marks, err := s.RestoreMarking(content)
	if err != nil {
		return nil, 0, err
	}
	n := len(marks)
	en, ok := s.store.(Enumerator)
	if !ok {
		return out, n, nil
	}
	type pair struct{ token, value string }
	var pairs []pair
	en.Each(func(token, value string) bool {
		if len(token) >= 4 && !IsToken(token) {
			pairs = append(pairs, pair{token, value})
		}
		return true
	})
	sort.Slice(pairs, func(i, j int) bool {
		if len(pairs[i].token) != len(pairs[j].token) {
			return len(pairs[i].token) > len(pairs[j].token)
		}
		return pairs[i].token < pairs[j].token
	})
	text := string(out)
	for _, p := range pairs {
		if c := strings.Count(text, p.token); c > 0 {
			text = strings.ReplaceAll(text, p.token, p.value)
			n += c
		}
	}
	return []byte(text), n, nil
}
