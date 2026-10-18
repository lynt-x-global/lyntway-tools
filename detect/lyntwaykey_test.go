package detect

import (
	"strings"
	"testing"
)

// We detect our own credential, or the product does not mean what it says.
//
// A customer who routes through Lyntway holds a lynt_sk_ key. If they paste
// it into a coding agent, the hook that exists to stop exactly that must
// not stay silent; if it lands in a diff, our own Action must not pass it.
// Until 18 October 2026 both did, which made us the only provider in a
// 385-entry catalog whose key this ruleset could not see.

func TestOurOwnIssuedKeyIsDetected(t *testing.T) {
	rs := Default()

	// The shape GenerateAPIKey emits: the prefix plus 20 random bytes in
	// lowercase base32 without padding, which is exactly 32 characters.
	//
	// The body spells out what it is rather than looking random. It still
	// exercises the rule exactly — the prefix, the base32 alphabet and the
	// length are all that rule looks at — and a fixture that reads as a
	// credential is one every scanner, ours included, has to make a
	// judgement about on a public repository.
	const key = "lynt_sk_notarealkeynotarealkeynotarealke"

	for _, c := range []struct {
		name    string
		sample  string
		wantHit bool
	}{
		{"in an env file", "LYNTWAY_API_KEY=" + key, true},
		{"pasted into a prompt", "here is my key " + key + " please fix the route", true},
		{"the prefix with nothing of key length after it", "lynt_sk_short", false},
		{"a key id, which is not a credential", "key_0a1b2c3d4e5f6071", false},
		{"a tenant id, which is not a credential", "t_0a1b2c3d4e5f6071", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			spans := rs.Scan([]byte(c.sample))
			if !c.wantHit {
				if len(spans) != 0 {
					t.Fatalf("found %s, wanted nothing", spans[0].Class)
				}
				return
			}
			if len(spans) == 0 {
				t.Fatal("found nothing — our own key went unseen")
			}
			if spans[0].Class != ClassLyntwayKey {
				t.Errorf("class %s, want %s", spans[0].Class, ClassLyntwayKey)
			}
			// Deterministic tier: no detector name, so the finding is
			// reproducible from the ruleset digest alone.
			if spans[0].Detector != "" {
				t.Errorf("detector %q, want empty", spans[0].Detector)
			}
			// The span must cover the credential and nothing around it,
			// because a tokenising route substitutes exactly this range.
			if got := c.sample[spans[0].Start:spans[0].End]; got != key {
				t.Errorf("span covers %q, want the key itself", got)
			}
		})
	}
}

// The prefix is the contract between the issuer and the ruleset. If one
// moves without the other, we stop seeing our own keys and no test that
// hardcodes a sample would notice.
func TestTheRuleMatchesThePrefixTheIssuerActuallyUses(t *testing.T) {
	var found bool
	for _, r := range Default().Rules() {
		if r.ID != "lyntway-key" {
			continue
		}
		found = true
		for _, p := range r.Prefilter {
			if !strings.HasPrefix(p, "lynt_sk_") {
				t.Errorf("prefilter %q does not match the issued prefix", p)
			}
		}
	}
	if !found {
		t.Fatal("no rule with ID lyntway-key: our own credential is unrecognised")
	}
}
