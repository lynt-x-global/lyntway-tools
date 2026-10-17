package catalog

import (
	"sort"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// What we already know about the APIs an agent calls.
//
// # Why this is its own package
//
// It began inside httpapi, where only the console could reach it, and the
// console is the half that needs it least: it has a person in front of it
// who can be asked. The CLI has the opposite problem — it walks a disk and
// finds real credentials, and could name seven providers.
//
// So the same key was identified twice, by two tables that did not agree:
// seven upstreams by variable name in cmd/lyntway, and 385 providers by
// prefix in the console's grid. A key the CLI could not name was a key the
// person had to go and find in a list of 385, which is the form this was
// supposed to remove.
//
// Here it is one table, read by both, and the form and the API can no
// longer disagree about what a key is. It is also why this package holds
// nothing but data and the rules for reading it: it is mirrored into the
// public repository, so anything that reached httpapi would take the
// private half with it.

// What we already know about the APIs an agent calls.
//
// # Why this exists
//
// Storing a key for an upstream nobody has configured used to leave the
// key stored and the route missing, so the next call answered 404
// unknown_upstream and the customer was told to go and describe Mailgun to
// us: its address, its surface, the header it reads. Two of those three we
// know, and the third we can look up once rather than asking every
// customer to look it up again.
//
// # Where the entries live
//
// In httpapi/catalog/<vertical>.json, embedded and validated at start by
// catalogload.go. They left this file when the list stopped being sixteen
// long: a file per vertical is a thing two people can fill at once, and
// what a reviewer reads is the entry rather than Go syntax around it.
//
// # The rule the entries are held to
//
// Every entry is either read off that provider's own current
// authentication documentation — the URL is in its doc field, which is
// the evidence, not a courtesy link — or confirmed by lyntway-catalog
// probe, which sends an obviously invalid key to the entry's own address
// in the entry's own scheme and requires a 401 or 403 back. Nothing here
// is from memory. An entry is a promise about where a customer's live
// credential is sent and in what form, and a wrong one sends a real key
// to the wrong address in a shape somebody else might log — worse, not
// better, than having no entry and asking. So a provider we could not
// verify is absent, and absence is the safe answer: the caller is asked
// for the address, which is the one thing we will not guess.
//
// # What is deliberately not here
//
// Payment APIs used to be excluded outright, on the reasoning that
// standing in the payment path makes us a single point of failure for
// money and drags PCI scope across us. That was reversed on 7 September
// 2026, because it left the biggest prize on the table: a payment key is
// the most dangerous secret in anybody's .env, and a developer building a
// finance dashboard on one is an ordinary thing to be. The hazards did not
// go away; they are answered in code instead of by absence, and payments.go
// is where each answer lives.
//
// Nothing whose credential is obtained by OAuth. A token minted for a
// remote server is bound to that server's own address and is refused when
// the request arrives from ours, and nothing here performs the flow on a
// caller's behalf, so listing such a provider would offer something that
// cannot work.
//
// Nothing whose username is per-customer under basic auth. Twilio's is the
// Account SID, which we do not know and must not guess.
//
// A provider whose host carries the customer's own name — Zendesk at
// <theirs>.zendesk.com — is here as a url_template, which is the shape of
// the address plus the name of the one word we are missing. The customer
// supplies that word and it is held to what a DNS label may contain
// before it becomes part of anything. Asking for a word is not guessing
// an address; the first version of this file refused the whole case, and
// the cost was that those customers typed a whole address by hand.

// Entry is an upstream this service can create without asking.
type Entry struct {
	// Name is the path segment, /gw/<name>, and the name a key is stored
	// under.
	Name string `json:"name"`

	// URL is the provider's documented API root. Empty only when
	// URLTemplate is set, because then the address is not ours to know.
	URL string `json:"url,omitempty"`

	// URLTemplate is the address of a provider whose host carries the
	// customer's own name — "https://{subdomain}.zendesk.com/api/v2".
	// The catalog holds the shape; the customer supplies the one word.
	//
	// This is the case the first version of this file refused outright,
	// and refusing it cost more than it saved: Zendesk, Jira and every
	// other per-tenant host fell through to the form, where the customer
	// typed a whole address instead of the one word we were missing.
	// Asking for the word is not guessing the address.
	URLTemplate string `json:"url_template,omitempty"`

	// AuthUserField names a second value the customer must supply, which
	// becomes the basic-auth username. Set only where the provider's
	// username is the customer's own identifier rather than a fixed word:
	// Twilio wants the Account SID, Algolia the Application ID. AuthUser
	// is the opposite case, a constant the provider fixes ("api" at
	// Mailgun), and an entry may name one or the other, never both.
	//
	// It is not a second secret. These identifiers appear in dashboards
	// and URLs, so the console may show one back; only the key is hidden.
	AuthUserField string `json:"auth_user_field,omitempty"`

	// AuthUserHint is what the console asks for, in the provider's own
	// words — "your Account SID, which starts AC".
	AuthUserHint string `json:"auth_user_hint,omitempty"`

	// TemplateField is the placeholder's name — the thing the console
	// asks for, and the key in the request's "template" object.
	TemplateField string `json:"template_field,omitempty"`

	// TemplateHint is how to find that value, in the customer's own
	// terms: "the name in your Zendesk address".
	TemplateHint string `json:"template_hint,omitempty"`

	// Vertical groups the entry in the console's picker: email,
	// messaging, crm, devtools, search, data, docs, support,
	// observability, hr. It is also the name of the file the entry
	// lives in, so a listing and a file are the same set.
	Vertical string `json:"vertical"`

	// Surface is what sits there. Every entry is an ordinary HTTP API;
	// a model provider is configured by the deployment instead.
	Surface receipt.Surface `json:"surface"`

	// AuthScheme, AuthHeader and AuthUser are how the provider's own
	// documentation says the credential is presented.
	AuthScheme string `json:"auth_scheme"`
	AuthHeader string `json:"auth_header,omitempty"`
	AuthUser   string `json:"auth_user,omitempty"`
	AuthPrefix string `json:"auth_prefix,omitempty"`

	// KeyPrefixes are the fixed leading characters this provider's keys
	// carry, when it fixes any — "key-" at Mailgun, "re_" at Resend.
	// Used to recognise a pasted key so the person does not scroll a
	// thousand names looking for one they already have in their hand.
	//
	// Only the prefix is ever compared. The rest of the string is a live
	// credential and never reaches a comparison, a log or a response.
	KeyPrefixes []string `json:"key_prefixes,omitempty"`

	// ProbePath is a path that requires authentication and changes
	// nothing, so an obviously-invalid key sent to it answers 401 or 403
	// and proves the address and scheme are right. Never a write: the
	// probe runs weekly against real providers and a path with a side
	// effect would make this repository a nuisance.
	ProbePath string `json:"probe_path"`

	// Label is the provider's name as it is written, for the console.
	Label string `json:"label"`

	// Note is one honest sentence: what this reaches, and what it does
	// not. The second half is the part that matters — a customer who
	// stores a Mailgun key for an EU domain against this entry gets a 401
	// they cannot explain unless somebody told them first.
	Note string `json:"note"`

	// Doc is the page the entry was verified against, so the next person
	// to touch it can check rather than trust.
	Doc string `json:"doc"`

	// PayloadPolicy says what may be done to a body bound for this
	// provider. Empty is the ordinary case: whatever the tenant's policy
	// decides. "observe" means detect and record but never substitute,
	// because substituting would break the call rather than protect it.
	//
	// See payments.go for the one vertical that uses it and why.
	PayloadPolicy string `json:"payload_policy,omitempty"`

	// EnvPrefixes are the key prefixes that say, by themselves, whether a
	// credential is for the provider's test or live environment. Only
	// where the prefix genuinely carries it: this is read off a pasted key
	// and never asked for, so a guess would put the wrong word beside
	// somebody's key in the console.
	EnvPrefixes *EnvPrefixes `json:"env_prefixes,omitempty"`
}

// EnvPrefixes splits a provider's key prefixes by environment.
//
// A struct rather than a map so an unknown name — "sandbox", "staging",
// a typo — is refused when the catalog loads instead of being kept as a
// third environment nothing in this service knows how to show.
type EnvPrefixes struct {
	Test []string `json:"test,omitempty"`
	Live []string `json:"live,omitempty"`
}

// For returns what we know about a provider by name.
func For(name string) (Entry, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, e := range catalog {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

// All returns every entry, sorted by label, for the console's picker.
//
// A copy, because the caller renders it and a handler that mutated the
// package's own slice would change what every later request is told.
func All() []Entry {
	out := make([]Entry, len(catalog))
	copy(out, catalog)
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}
