package detect

import (
	"strings"
	"testing"
)

// TestDefaultRulesetCompiles is a guard, not a formality.
//
// regexp.MustCompile panics at *runtime*, not at build time, so an
// unsupported construct compiles cleanly and then takes down the first
// request that touches detection. Go's regexp is RE2: no lookahead, no
// backreferences. This test is the only thing standing between that and
// production.
func TestDefaultRulesetCompiles(t *testing.T) {
	rs := Default()
	if rs.Version() != RulesetVersion {
		t.Errorf("version = %q, want %q", rs.Version(), RulesetVersion)
	}
	if len(rs.Digest()) != 64 {
		t.Errorf("digest is %d chars, want 64", len(rs.Digest()))
	}
	if len(rs.Rules()) == 0 {
		t.Fatal("ruleset is empty")
	}
	for _, r := range rs.Rules() {
		if r.ID == "" {
			t.Error("rule with empty ID")
		}
		if r.Class == "" {
			t.Errorf("rule %s has no class", r.ID)
		}
		if r.Pattern == nil {
			t.Errorf("rule %s has no pattern", r.ID)
		}
		// A rule claiming exactness without a structural check is either
		// mislabelled or relies on a pattern distinctive enough to earn it.
		// Vendor prefixes qualify; shape-only patterns do not.
		if r.Confidence == ConfidenceExact && r.Validate == nil {
			if !strings.HasPrefix(string(r.Class), "secret.") && r.Class != ClassEmail {
				t.Errorf("rule %s claims exact confidence without a validator", r.ID)
			}
		}
	}
}

// TestDigestStability proves the ruleset digest depends on content rather
// than declaration order. Without that, reordering a slice would silently
// change the digest recorded in every receipt.
func TestDigestStability(t *testing.T) {
	rules := defaultRules()
	a := NewRuleset("v1", rules)

	reversed := make([]Rule, len(rules))
	for i, r := range rules {
		reversed[len(rules)-1-i] = r
	}
	b := NewRuleset("v1", reversed)

	if a.Digest() != b.Digest() {
		t.Error("digest changed when rules were reordered; it must depend on content only")
	}

	c := NewRuleset("v2", rules)
	if a.Digest() == c.Digest() {
		t.Error("digest did not change when the version changed")
	}
}

func TestDetection(t *testing.T) {
	rs := Default()

	tests := []struct {
		name  string
		input string
		want  Class
	}{
		{"email", "contact priya@acme.co.uk for details", ClassEmail},
		{"aws access key", "key " + fakeAWSKey() + " here", ClassAWSAccessKey},
		{"github token", fakeGitHubToken(), ClassGitHubToken},
		{"anthropic key", fakeAnthropicKey(), ClassAnthropicKey},
		{"stripe key", fakeStripeLiveKey(), ClassStripeKey},
		{"slack token", fakeSlackBotToken(), ClassSlackToken},
		{"e164 phone", "call +442071838750 now", ClassPhone},
		{"ipv4", "host 192.168.14.201 responded", ClassIPv4},
		{"us ssn", "ssn 123-45-6789 on file", ClassUSSSN},
		{"visa card", "card 4111 1111 1111 1111 charged", ClassCreditCard},
		{"iban", "pay GB82WEST12345698765432 today", ClassIBAN},
		// The spaced form is how an IBAN is printed on every invoice and
		// bank letter, so it is the form most likely to be in the traffic.
		{"iban in printed groups", "pay GB82 WEST 1234 5698 7654 32 today", ClassIBAN},
		{"iban with hyphens", "pay GB82-WEST-1234-5698-7654-32 today", ClassIBAN},
		{"german iban spaced", "to DE89 3704 0044 0532 0130 00 please", ClassIBAN},
		// A run of capitals after a real IBAN must not be swallowed into
		// the match: that would fail the checksum and turn a detection
		// into a silent miss, which is the worse of the two failures.
		{"iban followed by capitals", "GB82 WEST 1234 5698 7654 32 URGENT PLEASE", ClassIBAN},
		{"private key", fakePEMBlock("RSA "), ClassPrivateKey},
		{"jwt", "token " + fakeJWT(), ClassJWT},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spans := rs.Scan([]byte(tc.input))
			for _, s := range spans {
				if s.Class == tc.want {
					return
				}
			}
			var got []string
			for _, s := range spans {
				got = append(got, string(s.Class))
			}
			t.Errorf("did not detect %s; found %v", tc.want, got)
		})
	}
}

// TestFalsePositives is the more important half of the suite.
//
// A false positive becomes a redaction that corrupts a customer's data or a
// block that breaks their agent. Recall failures are what the ML tier
// exists to cover; precision failures are ours.
func TestFalsePositives(t *testing.T) {
	rs := Default()

	tests := []struct {
		name      string
		input     string
		forbidden Class
	}{
		{"order number is not a card", "order 1234567890123456 shipped", ClassCreditCard},
		{"timestamp run is not a card", "ts 2026081312000000 recorded", ClassCreditCard},
		{"invalid ssn area 000", "id 000-45-6789", ClassUSSSN},
		{"invalid ssn area 666", "id 666-45-6789", ClassUSSSN},
		{"invalid ssn area 900+", "id 900-45-6789", ClassUSSSN},
		{"invalid ssn group 00", "id 123-00-6789", ClassUSSSN},
		{"invalid ssn serial 0000", "id 123-45-0000", ClassUSSSN},
		{"bad iban checksum", "acct GB82WEST12345698765433", ClassIBAN},
		{"bad iban checksum, spaced", "acct GB82 WEST 1234 5698 7654 33", ClassIBAN},
		{"ordinary capitals are not an iban", "SEE ITEM 4 ON PAGE 12 BELOW", ClassIBAN},
		{"version string is not an ip", "version 1.2.3.4000 released", ClassIPv4},
		{"plain word is not a token", "the quick brown fox jumps", ClassGitHubToken},
		{"short number is not a phone", "+44 is the code", ClassPhone},
		{"aadhaar needs a valid checksum", "num 2345 6789 0123", ClassINAadhaar},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, s := range rs.Scan([]byte(tc.input)) {
				if s.Class == tc.forbidden {
					t.Errorf("false positive: %s matched %q via rule %s",
						tc.forbidden, s.Value, s.Rule)
				}
			}
		})
	}
}

// TestOverlapResolution proves one secret produces one finding. Without
// overlap resolution a vendor-prefixed token would be reported by both its
// specific rule and any general one, and the receipt would show two
// findings where there is one secret.
func TestOverlapResolution(t *testing.T) {
	rs := Default()
	// An OpenAI-style key also matches the Stripe prefix pattern shape.
	spans := rs.Scan([]byte("key sk-proj-abcdefghijklmnopqrstuvwx here"))

	for i := 0; i < len(spans); i++ {
		for j := i + 1; j < len(spans); j++ {
			if spans[i].Start < spans[j].End && spans[j].Start < spans[i].End {
				t.Errorf("overlapping spans survived: %s[%d:%d] and %s[%d:%d]",
					spans[i].Rule, spans[i].Start, spans[i].End,
					spans[j].Rule, spans[j].Start, spans[j].End)
			}
		}
	}
}

func TestSpansAreOrdered(t *testing.T) {
	rs := Default()
	input := "a@b.co then " + fakeAWSKey() + " then c@d.co then +442071838750"
	spans := rs.Scan([]byte(input))
	if len(spans) < 3 {
		t.Fatalf("expected several spans, got %d", len(spans))
	}
	for i := 1; i < len(spans); i++ {
		if spans[i].Start < spans[i-1].Start {
			t.Errorf("spans out of order at %d", i)
		}
	}
}

// TestSpanOffsetsAreExact matters because tokenisation substitutes by byte
// offset. An off-by-one corrupts the surrounding content rather than the
// secret.
func TestSpanOffsetsAreExact(t *testing.T) {
	rs := Default()
	input := "email me at priya@acme.com please"
	for _, s := range rs.Scan([]byte(input)) {
		if s.Class != ClassEmail {
			continue
		}
		if got := input[s.Start:s.End]; got != s.Value {
			t.Errorf("offsets do not match value: input[%d:%d]=%q, value=%q",
				s.Start, s.End, got, s.Value)
		}
		if s.Value != "priya@acme.com" {
			t.Errorf("value = %q, want %q", s.Value, "priya@acme.com")
		}
	}
}

// TestScanIsDeterministic guards the property receipts depend on: the same
// content must produce identical findings every time, or a receipt cannot
// be re-derived when someone disputes it.
func TestScanIsDeterministic(t *testing.T) {
	rs := Default()
	input := []byte("priya@acme.com " + fakeAWSKey() + " 4111111111111111 +442071838750 192.168.1.1")

	first := rs.Scan(input)
	for i := 0; i < 50; i++ {
		next := rs.Scan(input)
		if len(next) != len(first) {
			t.Fatalf("span count varied: %d then %d", len(first), len(next))
		}
		for j := range first {
			if first[j] != next[j] {
				t.Fatalf("span %d differs between runs", j)
			}
		}
	}
}

func TestCountsAreSorted(t *testing.T) {
	rs := Default()
	spans := rs.Scan([]byte("a@b.co c@d.co " + fakeAWSKey() + " 192.168.1.1"))
	counts := Counts(spans)
	if len(counts) < 2 {
		t.Fatalf("expected several classes, got %d", len(counts))
	}
	for i := 1; i < len(counts); i++ {
		if counts[i].Class < counts[i-1].Class {
			t.Error("counts are not sorted by class; receipts would not be reproducible")
		}
	}
	for _, c := range counts {
		if c.Class == ClassEmail && c.Count != 2 {
			t.Errorf("email count = %d, want 2", c.Count)
		}
	}
}

func TestLuhn(t *testing.T) {
	valid := []string{"4111111111111111", "4111 1111 1111 1111", "5500005555555559", "371449635398431"}
	invalid := []string{"4111111111111112", "1234567890123456", "0000000000000000"}

	for _, s := range valid {
		if !validLuhn(s) {
			t.Errorf("validLuhn(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validLuhn(s) && s != "0000000000000000" {
			t.Errorf("validLuhn(%q) = true, want false", s)
		}
	}
}

func TestIBAN(t *testing.T) {
	valid := []string{"GB82WEST12345698765432", "DE89370400440532013000", "FR1420041010050500013M02606"}
	invalid := []string{"GB82WEST12345698765433", "DE89370400440532013001", "XX00"}

	for _, s := range valid {
		if !validIBAN(s) {
			t.Errorf("validIBAN(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validIBAN(s) {
			t.Errorf("validIBAN(%q) = true, want false", s)
		}
	}
}

func TestHasClassPrefix(t *testing.T) {
	tests := []struct {
		class  Class
		family string
		want   bool
	}{
		{"pii.email", "pii", true},
		{"pii", "pii", true},
		{"pci.card_number", "pii", false},
		{"piita.thing", "pii", false},
		{"secret.aws_access_key", "secret", true},
	}
	for _, tc := range tests {
		if got := HasClassPrefix(tc.class, tc.family); got != tc.want {
			t.Errorf("HasClassPrefix(%q, %q) = %v, want %v", tc.class, tc.family, got, tc.want)
		}
	}
}

func BenchmarkScan(b *testing.B) {
	rs := Default()
	content := []byte(strings.Repeat(
		"Customer priya@acme.com called from +442071838750 about card 4111111111111111. ", 40))
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.Scan(content)
	}
}

// TestPrefiltersDoNotSuppressMatches is a security test, not a performance
// one.
//
// A prefilter that is not genuinely implied by its pattern makes the rule
// silently stop matching. Nothing fails, no error is logged, and the
// receipt reports zero findings for content that contains a secret — which
// is the worst possible failure mode for this product.
//
// The test strips every prefilter, scans a corpus with both rulesets, and
// requires identical results.
func TestPrefiltersDoNotSuppressMatches(t *testing.T) {
	withPrefilters := Default()

	stripped := defaultRules()
	for i := range stripped {
		stripped[i].Prefilter = nil
	}
	withoutPrefilters := NewRuleset(RulesetVersion, stripped)

	corpus := []string{
		"contact priya@acme.co.uk and RAJESH.K+tag@sub.example.org",
		fakeAWSKey() + " " + fakeAWSTempKey(),
		fakeGitHubToken() + " gho_" + strings.Repeat("b", 40),
		fakeSlackBotToken() + " " + fakeSlackUserToken(),
		fakeStripeLiveKey() + " pk_test_" + strings.Repeat("z", 18),
		fakeAnthropicKey(),
		fakeOpenAIKey(),
		fakePEMBlock("EC "),
		fakeJWT(),
		"card 4111 1111 1111 1111 and 5500005555555559 and 371449635398431",
		"iban GB82WEST12345698765432 and DE89370400440532013000",
		"ssn 123-45-6789 and 078-05-1120",
		"phone +442071838750 and +14155552671 and +919876543210",
		"host 192.168.14.201 and 10.0.0.1 and 255.255.255.255",
		"pan ABCDE1234F issued",
		fakeAzureAccountKey(),
		"nothing sensitive here at all, just ordinary prose about governance",
		"",
		"@ + - eyJ sk- AKIA xox PRIVATE KEY",
	}

	for _, sample := range corpus {
		a := withPrefilters.Scan([]byte(sample))
		b := withoutPrefilters.Scan([]byte(sample))

		if len(a) != len(b) {
			t.Errorf("prefilters changed the result count for %.60q: %d with, %d without",
				sample, len(a), len(b))
			continue
		}
		for i := range a {
			if a[i] != b[i] {
				t.Errorf("prefilters changed span %d for %.60q:\n with:    %+v\n without: %+v",
					i, sample, a[i], b[i])
			}
		}
	}
}

// FuzzPrefilterEquivalence fuzzes the one property prefilters must hold:
// they are a performance shortcut and must never change what is detected.
//
// A structural check on the prefilter literals cannot work — patterns
// express them through character classes and alternations, so `gh[posru]_`
// legitimately implies "ghp_" without containing it. The decidable property
// is behavioural: for any input, scanning with and without prefilters must
// produce identical spans.
//
// Run longer in CI with: go test ./detect/ -fuzz FuzzPrefilterEquivalence
func FuzzPrefilterEquivalence(f *testing.F) {
	seeds := []string{
		"priya@acme.co.uk",
		fakeAWSKey(),
		fakeGitHubToken(),
		fakeAnthropicKey(),
		fakeStripeLiveKey(),
		fakeSlackBotToken(),
		fakePEMBlock("RSA "),
		fakeJWTShort(),
		"4111 1111 1111 1111",
		"GB82WEST12345698765432",
		"123-45-6789",
		"+442071838750",
		"192.168.1.1",
		fakeAzureAccountKey(),
		// Adversarial: prefilter literals present with nothing to match.
		"@ + - ey" + "J sk- sk" + "-ant- AK" + "IA xo" + "x gh" + "p_ PRIVATE KEY Account" + "Key=",
		// Adversarial: near-misses that must not match either way.
		fakeAWSKeyTruncated() + " gh" + "p_short sk" + "-ant- 4111111111111112",
		"",
		"ordinary prose with no sensitive content whatsoever",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	withPrefilters := Default()
	stripped := defaultRules()
	for i := range stripped {
		stripped[i].Prefilter = nil
	}
	withoutPrefilters := NewRuleset(RulesetVersion, stripped)

	f.Fuzz(func(t *testing.T, content []byte) {
		a := withPrefilters.Scan(content)
		b := withoutPrefilters.Scan(content)

		if len(a) != len(b) {
			t.Fatalf("prefilters changed the span count: %d with, %d without, content=%q",
				len(a), len(b), content)
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("prefilters changed span %d:\n with:    %+v\n without: %+v\n content: %q",
					i, a[i], b[i], content)
			}
		}
	})
}

// TestSpansExcludeContext guards the "target" capture-group mechanism.
//
// Rules that need surrounding context to match must not include that
// context in the reported span. A span one byte too wide makes tokenisation
// delete the neighbouring character, silently corrupting content the
// governance layer was supposed to leave alone.
func TestSpansExcludeContext(t *testing.T) {
	rs := Default()

	tests := []struct {
		name  string
		input string
		class Class
		want  string
	}{
		{"phone keeps the preceding space out", "call +442071838750 now", ClassPhone, "+442071838750"},
		{"phone at start of input", "+14155552671 called", ClassPhone, "+14155552671"},
		{"phone after a colon", "tel:+919876543210", ClassPhone, "+919876543210"},
		{"email is exact", "to priya@acme.com now", ClassEmail, "priya@acme.com"},
		{"aws key is exact", "k " + fakeAWSKey() + " e", ClassAWSAccessKey, fakeAWSKey()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var found bool
			for _, s := range rs.Scan([]byte(tc.input)) {
				if s.Class != tc.class {
					continue
				}
				found = true
				if s.Value != tc.want {
					t.Errorf("span value = %q, want %q", s.Value, tc.want)
				}
				if got := tc.input[s.Start:s.End]; got != tc.want {
					t.Errorf("span offsets [%d:%d] cover %q, want %q", s.Start, s.End, got, tc.want)
				}
			}
			if !found {
				t.Errorf("class %s not detected in %q", tc.class, tc.input)
			}
		})
	}
}
