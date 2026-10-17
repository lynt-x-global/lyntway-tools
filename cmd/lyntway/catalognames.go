package main

import (
	"strings"

	"github.com/lynt-x-global/lyntway-tools/catalog"
)

// Naming a key this machine found, using the catalog the console uses.
//
// The seven shapes in dotenv.go are the providers whose keys this tool can
// migrate. They are not the providers a person has. Somebody with a Stripe
// key and a Linear key in the same .env got "2 keys found" and no names,
// and was then expected to go and pick both out of a grid of 385 — which
// is the step the grid exists to save them.
//
// The catalog knows 51 providers by the fixed characters their keys begin
// with, and now lives in a package this command can import. So the finder
// asks it, and the answer is a name the console will agree with because
// it is the same table.
//
// # Why two signals are required
//
// A catalog prefix can be three characters. Matching one anywhere in any
// file would make `lyntway scan` report ordinary strings as credentials,
// and `lyntway scan` gates commits — a false positive there stops somebody
// working, which is the one thing this tool must never do. So the variable
// name has to look like a credential AND the value has to carry a known
// prefix. Two independent signals, neither sufficient alone.
//
// # What is compared
//
// The prefix and nothing else. catalog.ProviderForKey compares against
// fixed strings and returns entries; the value is never logged, stored or
// returned, and what leaves here is a name and the last four characters,
// exactly as every other finding carries.

// credentialNameWords are what a variable is called when it holds a
// secret. Deliberately short: each one added widens what the catalog is
// allowed to be consulted about, and the cost of a wrong guess is a
// commit somebody cannot make.
var credentialNameWords = []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL"}

// looksLikeCredentialName reports whether a variable name says, by itself,
// that its value is a secret.
func looksLikeCredentialName(name string) bool {
	upper := strings.ToUpper(name)
	for _, w := range credentialNameWords {
		if strings.Contains(upper, w) {
			return true
		}
	}
	return false
}

// catalogNaming is what the catalog could say about one value.
type catalogNaming struct {
	// Entry is the single match. Empty when there was none, or when there
	// was more than one.
	Entry string
	// Label is Entry's provider name as it is written.
	Label string
	// Ambiguous is how many entries matched when more than one did.
	// Reported rather than resolved: picking between two providers that
	// share a prefix would send a live credential to one of them, and the
	// person holding it can answer in a second.
	Ambiguous int
}

// nameFromCatalog asks the catalog what a value's prefix belongs to.
//
// An empty naming means the catalog had nothing to say, which is the
// ordinary case: only 51 of the 385 entries fix a prefix at all.
func nameFromCatalog(varName, value string) catalogNaming {
	if !looksLikeCredentialName(varName) {
		return catalogNaming{}
	}
	if len(value) < 8 || looksLikePlaceholder(value) || strings.ContainsAny(value, " <>$") {
		return catalogNaming{}
	}
	matches := catalog.ProviderForKey(value)
	if len(matches) == 0 {
		return catalogNaming{}
	}
	if !randomAfterPrefix(value, matches[0]) {
		return catalogNaming{}
	}
	if len(matches) > 1 {
		return catalogNaming{Ambiguous: len(matches)}
	}
	return catalogNaming{Entry: matches[0].Name, Label: matches[0].Label}
}

// randomAfterPrefix reports whether what follows a provider's prefix looks
// like a credential rather than like English.
//
// It exists because of NOT_A_KEY=re_but_this_is_just_a_word, which this
// found and called a Resend key: the variable is named …KEY and the value
// begins re_, so both signals fired on a sentence. Two signals are not
// enough when one of them is three characters long.
//
// A real key is a random string. The test is that the remainder is long,
// and is not made only of lowercase letters and underscores — which is
// what prose looks like and what no generated credential looks like. A
// lowercase hexadecimal key still passes, because it carries digits.
func randomAfterPrefix(value string, e catalog.Entry) bool {
	rest := value
	for _, p := range e.KeyPrefixes {
		if strings.HasPrefix(value, p) && len(p) > len(value)-len(rest) {
			rest = value[len(p):]
		}
	}
	if len(rest) < 16 {
		return false
	}
	var digit, upper, lowerOrSep int
	for _, r := range rest {
		switch {
		case r >= '0' && r <= '9':
			digit++
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= 'a' && r <= 'z', r == '_', r == '-':
			lowerOrSep++
		}
	}
	// Prose is lowercase and separators and nothing else.
	return digit+upper > 0 && lowerOrSep != len(rest)
}
