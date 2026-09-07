package tokenize

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// The IPv4 token space is small — a few hundred addresses in reserved
// ranges — and a scope that tokenises more distinct addresses than that
// has to land two of them on the same token. What must never happen is
// the second silently taking the first's token: Restore would then hand
// the second caller the first caller's address, which in a shared vault is
// another customer's data.
func TestDistinctIPsNeverShareAToken(t *testing.T) {
	s := testScope(t)
	const n = 255 // one more than the 254 hosts of a single /24

	values := make([]string, 0, n)
	tokens := make(map[string]string, n) // token -> value it was issued for
	for i := 0; i < n; i++ {
		v := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
		values = append(values, v)
		tok := mustTok(t, s, detect.ClassIPv4, v)
		if prior, taken := tokens[tok]; taken {
			t.Fatalf("value %q was issued %q, which already belongs to %q", v, tok, prior)
		}
		tokens[tok] = v
	}

	// Each token has to come back as its own value, both directly and
	// through the document path a caller actually uses.
	var doc strings.Builder
	for tok, want := range tokens {
		got, ok, err := s.Detokenize(tok)
		if err != nil || !ok {
			t.Fatalf("token %q for %q did not resolve: ok=%v err=%v", tok, want, ok, err)
		}
		if got != want {
			t.Fatalf("token %q resolved to %q, want %q — someone else's address", tok, got, want)
		}
		doc.WriteString(tok + "\n")
	}
	restored, err := s.Restore([]byte(doc.String()))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		if !strings.Contains(string(restored), v+"\n") {
			t.Errorf("%q is missing from the restored document", v)
		}
	}
}

// A value that already has a token keeps it, however many other values are
// tokenised around it. Determinism is the property agent workflows rely on,
// and the collision walk must not trade it away.
func TestAnEarlyTokenSurvivesLaterCollisions(t *testing.T) {
	s := testScope(t)
	first := mustTok(t, s, detect.ClassIPv4, "10.9.9.9")
	for i := 0; i < 500; i++ {
		mustTok(t, s, detect.ClassIPv4, fmt.Sprintf("172.16.%d.%d", i/256, i%256))
	}
	if again := mustTok(t, s, detect.ClassIPv4, "10.9.9.9"); again != first {
		t.Fatalf("token for the same value changed from %q to %q", first, again)
	}
}

// All three RFC 5737 ranges are used before the space runs out, and when
// it does, the failure is an error — never a token that reverses to
// somebody else's value.
func TestIPv4SpaceIsExhaustedLoudly(t *testing.T) {
	s := testScope(t)
	const space = 3 * 254

	ranges := map[string]bool{}
	for i := 0; i < space; i++ {
		v := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		tok := mustTok(t, s, detect.ClassIPv4, v)
		ranges[tok[:strings.LastIndex(tok, ".")]] = true
	}
	for _, want := range []string{"192.0.2", "198.51.100", "203.0.113"} {
		if !ranges[want] {
			t.Errorf("range %s was never used", want)
		}
	}

	_, err := s.Tokenize(detect.ClassIPv4, "10.200.200.200")
	if err == nil {
		t.Fatal("the 763rd address was issued a token in a 762-address space")
	}
	if !errors.Is(err, ErrTokenSpaceExhausted) {
		t.Fatalf("error = %v, want ErrTokenSpaceExhausted", err)
	}
	if got, ok, _ := s.Detokenize("10.200.200.200"); ok {
		t.Fatalf("the refused value was nonetheless recorded as %q", got)
	}
}

// The same rule holds for every format. Phone and card spaces are large
// enough that a real collision is a scale event rather than a test, so this
// seeds the store with a stranger's value under the token a value would
// receive, and checks the value is issued a different token that reverses
// to itself.
func TestACollisionInAnyFormatYieldsAFreshToken(t *testing.T) {
	cases := []struct {
		class detect.Class
		value string
	}{
		{detect.ClassEmail, "priya@acme.com"},
		{detect.ClassPhone, "+44 20 7946 0958"},
		{detect.ClassCreditCard, "4111 1111 1111 1111"},
		{detect.ClassIPv4, "10.1.2.3"},
		{detect.Class("secret.aws_access_key"), "AKIAIOSFODNN7EXAMPLE"},
	}
	for _, c := range cases {
		t.Run(string(c.class), func(t *testing.T) {
			// Learn the natural token from an untouched scope, then occupy
			// it in a fresh one before the value arrives.
			natural := mustTok(t, fixedScope(t), c.class, c.value)

			store := NewMemoryStore()
			if err := store.Put(natural, "somebody-else"); err != nil {
				t.Fatal(err)
			}
			s, err := NewScope(fixedScope(t).key, store)
			if err != nil {
				t.Fatal(err)
			}

			tok := mustTok(t, s, c.class, c.value)
			if tok == natural {
				t.Fatalf("issued %q, which already belongs to somebody else", tok)
			}
			if !tokenPattern.MatchString(tok) {
				t.Fatalf("the alternative token %q is not a shape Restore recognises", tok)
			}
			got, ok, _ := s.Detokenize(tok)
			if !ok || got != c.value {
				t.Fatalf("token %q resolves to %q, want %q", tok, got, c.value)
			}
			if again := mustTok(t, s, c.class, c.value); again != tok {
				t.Fatalf("the alternative token is not stable: %q then %q", tok, again)
			}
			if got, _, _ := s.Detokenize(natural); got != "somebody-else" {
				t.Fatalf("the stranger's mapping was overwritten: %q", got)
			}
		})
	}
}

// The first derivation is byte-for-byte what this package has always
// produced. Vaults hold tokens issued before the collision walk existed,
// and a change to the first attempt would leave every one of them
// unresolvable — silently, because Restore leaves unknown tokens in place.
func TestFirstDerivationIsUnchanged(t *testing.T) {
	s := fixedScope(t)
	for _, c := range []struct {
		class detect.Class
		value string
		want  string
	}{
		{detect.ClassEmail, "priya@acme.com", "lynt-cusdfqze2z4ra@tokenized.invalid"},
		{detect.ClassPhone, "+44 20 7946 0958", "+997735682607"},
		{detect.ClassCreditCard, "4111 1111 1111 1111", "9999502163734022"},
		{detect.ClassIPv4, "10.1.2.3", "192.0.2.41"},
		{detect.ClassIPv4, "203.0.113.7", "192.0.2.91"},
		{detect.Class("secret.aws_access_key"), "AKIAIOSFODNN7EXAMPLE", "LYNT_SECRET_AWS_ACCESS_KEY_fdz65e26ojxrcd6o"},
	} {
		if got := mustTok(t, s, c.class, c.value); got != c.want {
			t.Errorf("%s %q: token %q, want the historical %q", c.class, c.value, got, c.want)
		}
	}
}

// Restore has to recognise tokens in all three reserved ranges, or an
// address that overflowed into the second range would never come back.
func TestTokenPatternCoversEveryIPRange(t *testing.T) {
	for _, tok := range []string{"192.0.2.1", "198.51.100.254", "203.0.113.77"} {
		if !tokenPattern.MatchString(tok) {
			t.Errorf("%q is not recognised as a token", tok)
		}
	}
	for _, not := range []string{"192.0.3.1", "198.51.101.1", "203.0.112.1", "8.8.8.8"} {
		if tokenPattern.MatchString(not) {
			t.Errorf("%q is recognised as a token but is not in a reserved range", not)
		}
	}
}
