package detect

import "sort"

// Grouping the classes the way somebody choosing what to enforce thinks.
//
// The console asks an administrator which kinds of value to act on, and it
// used to ask with a list of fourteen words typed into a React file. Three of
// them — password, passport, biometric — named nothing this ruleset can
// detect, so ticking one promised a protection that did not exist, and the
// agent read none of the fourteen anyway.
//
// The fix is not a better list. It is that the list cannot be written down
// twice: a category exists here only because some rule carries a class in it,
// and TestEveryDetectableClassHasACategory fails the moment a rule arrives
// whose class nobody has placed. A category with nothing behind it cannot be
// offered, because it is never produced.
//
// Deliberately coarse. "Which of these nine things do you care about" is a
// question an administrator can answer; "which of these twenty-six classes"
// is not, and the classes stay visible beside the finding anyway.

// classCategories places each class in the group a person would look for it
// in. Families are handled by prefix below, so only the exceptions are here.
var classCategories = map[Class]string{
	ClassEmail:       "email",
	ClassPhone:       "phone",
	ClassIPv4:        "ip",
	ClassCreditCard:  "card",
	ClassIBAN:        "iban",
	ClassUSSSN:       "ssn",
	ClassINAadhaar:   "aadhaar",
	ClassINHealthID:  "medical",
	ClassINPAN:       "id",
	ClassUKNINO:      "id",
	ClassINUPI:       "financial",
	ClassINPIN:       "address",
	ClassLocation:    "address",
	ClassUSRouting:   "financial",
	ClassBankAccount: "financial",
}

// familyCategories catches a whole family, so a new secret or injection rule
// is categorised the moment it is added rather than the moment somebody
// remembers to categorise it. That asymmetry is deliberate: the families that
// grow are the ones that get a prefix.
var familyCategories = map[string]string{
	"secret":    "key",
	"injection": "injection",
	// A payee redirect or a changed bank detail is a statement about money,
	// and the person choosing what to enforce looks for it beside account
	// numbers, not in a category of its own that nothing else would share.
	"bec": "financial",
}

// Category is the group a class belongs to, or "" when it has none.
//
// An empty answer is not a default group. A class nobody has placed must not
// quietly land in a category an administrator has ticked, because that reads
// as a deliberate choice to enforce it when nobody made one.
func Category(class Class) string {
	if c, ok := classCategories[class]; ok {
		return c
	}
	family, _, found := cutClass(string(class))
	if !found {
		return ""
	}
	return familyCategories[family]
}

// Categories lists every category this ruleset can actually produce, sorted.
//
// Built from the rules rather than declared, so the console cannot offer a
// choice the detector cannot honour.
func (rs *Ruleset) Categories() []string {
	seen := map[string]bool{}
	for _, r := range rs.rules {
		if c := Category(r.Class); c != "" {
			seen[c] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// ClassesIn lists the classes of one category within this ruleset, sorted.
func (rs *Ruleset) ClassesIn(category string) []Class {
	seen := map[Class]bool{}
	for _, r := range rs.rules {
		if Category(r.Class) == category {
			seen[r.Class] = true
		}
	}
	out := make([]Class, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// InCategories reports whether a class is one the given categories select.
//
// An empty selection selects everything. That is the console's own stated
// meaning — "no categories selected, all types will be detected" — and it is
// also the safe reading: a policy that arrived without this field must not
// narrow enforcement to nothing.
func InCategories(class Class, categories []string) bool {
	if len(categories) == 0 {
		return true
	}
	c := Category(class)
	if c == "" {
		// Uncategorised: act on it. The alternative is that a class added
		// without a category is silently exempt from every policy that
		// names categories, which is a hole that opens quietly.
		return true
	}
	for _, want := range categories {
		if want == c {
			return true
		}
	}
	return false
}

// cutClass splits "pii.email" into family and member.
func cutClass(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
