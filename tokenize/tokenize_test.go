package tokenize

import (
	"bytes"
	"crypto/rand"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

func testScope(t *testing.T) *Scope {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	s, err := NewScope(key, nil)
	if err != nil {
		t.Fatalf("creating scope: %v", err)
	}
	return s
}

// fixedScope uses a constant key so tokens are comparable across scopes.
func fixedScope(t *testing.T) *Scope {
	t.Helper()
	key := bytes.Repeat([]byte{0x2a}, KeySize)
	s, err := NewScope(key, nil)
	if err != nil {
		t.Fatalf("creating scope: %v", err)
	}
	return s
}

// TestDeterminism is the property that keeps agent workflows alive. If the
// same customer email tokenises differently on two responses, the agent
// cannot correlate them and every multi-step workflow breaks.
// mustTok issues a token and fails the test if the mapping could not be
// recorded — releasing an unrecorded token is the failure this signature
// change exists to prevent.
func mustTok(t *testing.T, s *Scope, class detect.Class, value string) string {
	t.Helper()
	token, err := s.Tokenize(class, value)
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	return token
}

func TestDeterminism(t *testing.T) {
	s := testScope(t)
	for i := 0; i < 100; i++ {
		a := mustTok(t, s, detect.ClassEmail, "priya@acme.com")
		b := mustTok(t, s, detect.ClassEmail, "priya@acme.com")
		if a != b {
			t.Fatalf("token varied between calls: %q then %q", a, b)
		}
	}
	if s.Store().(*MemoryStore).Len() != 1 {
		t.Errorf("scope holds %d entries for one value, want 1", s.Store().(*MemoryStore).Len())
	}
}

// TestStabilityAcrossScopes proves tokens survive a process restart, so
// long as the key does. Without this, every deploy would invalidate every
// token an agent is holding.
func TestStabilityAcrossScopes(t *testing.T) {
	a, b := fixedScope(t), fixedScope(t)
	got1 := mustTok(t, a, detect.ClassEmail, "priya@acme.com")
	got2 := mustTok(t, b, detect.ClassEmail, "priya@acme.com")
	if got1 != got2 {
		t.Errorf("tokens differ across scopes with the same key: %q vs %q", got1, got2)
	}
}

// TestDifferentKeysDifferentTokens proves the key is doing work. Tokens
// travel to the destinations the original value was withheld from, so they
// must not be derivable without the key.
func TestDifferentKeysDifferentTokens(t *testing.T) {
	a, b := testScope(t), testScope(t)
	if mustTok(t, a, detect.ClassEmail, "priya@acme.com") == mustTok(t, b, detect.ClassEmail, "priya@acme.com") {
		t.Error("different keys produced the same token")
	}
}

// TestClassBinding proves the same string under two classes yields
// different tokens, so a token cannot silently carry a type it was not
// issued for.
func TestClassBinding(t *testing.T) {
	s := testScope(t)
	a := mustTok(t, s, detect.ClassEmail, "shared-value")
	b := mustTok(t, s, detect.ClassUSSSN, "shared-value")
	if a == b {
		t.Error("class is not bound into token derivation")
	}
}

func TestRoundTrip(t *testing.T) {
	s := testScope(t)
	original := "priya@acme.com"
	token := mustTok(t, s, detect.ClassEmail, original)

	got, ok, err := s.Detokenize(token)
	if err != nil {
		t.Fatalf("detokenize: %v", err)
	}
	if !ok {
		t.Fatal("token not resolvable in its own scope")
	}
	if got != original {
		t.Errorf("detokenised to %q, want %q", got, original)
	}

	if _, ok, _ := s.Detokenize("lynt-neverissued@tokenized.invalid"); ok {
		t.Error("an unissued token resolved")
	}
}

// TestFormatPreservation is what stops downstream validation from
// rejecting governed content. A token that fails the format check of the
// field it replaces surfaces as a constraint violation, not as governance.
func TestFormatPreservation(t *testing.T) {
	s := testScope(t)

	t.Run("email stays a valid address", func(t *testing.T) {
		token := mustTok(t, s, detect.ClassEmail, "priya@acme.com")
		emailRe := regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
		if !emailRe.MatchString(token) {
			t.Errorf("token %q is not a syntactically valid email", token)
		}
		// RFC 2606 reserves .invalid so the address can never route. A
		// token that accidentally delivers mail defeats the point.
		if !strings.HasSuffix(token, ".invalid") {
			t.Errorf("token %q is not in a guaranteed-unroutable domain", token)
		}
	})

	t.Run("phone stays E.164", func(t *testing.T) {
		token := mustTok(t, s, detect.ClassPhone, "+442071838750")
		e164 := regexp.MustCompile(`^\+[1-9]\d{7,14}$`)
		if !e164.MatchString(token) {
			t.Errorf("token %q is not valid E.164", token)
		}
		if !strings.HasPrefix(token, "+99") {
			t.Errorf("token %q is not in the unassigned +99 country code", token)
		}
	})

	t.Run("card stays Luhn-valid and same length", func(t *testing.T) {
		for _, original := range []string{
			"4111111111111111",    // 16
			"371449635398431",     // 15
			"4111111111111111111", // 19
		} {
			token := mustTok(t, s, detect.ClassCreditCard, original)
			if len(token) != len(original) {
				t.Errorf("token for a %d-digit card is %d digits", len(original), len(token))
			}
			if !luhnValid(token) {
				t.Errorf("token %q is not Luhn-valid; payment paths would reject it", token)
			}
		}
	})

	t.Run("ip stays in the documentation range", func(t *testing.T) {
		token := mustTok(t, s, detect.ClassIPv4, "10.1.2.3")
		if !strings.HasPrefix(token, "192.0.2.") {
			t.Errorf("token %q is not in RFC 5737 documentation space", token)
		}
	})
}

// TestTokensDoNotLeakOriginal is the confidentiality property. Tokens are
// sent to exactly the destinations the value was withheld from.
func TestTokensDoNotLeakOriginal(t *testing.T) {
	s := testScope(t)
	secrets := []struct {
		class detect.Class
		value string
	}{
		{detect.ClassEmail, "priya.sharma@confidential-acme.com"},
		{detect.ClassPhone, "+442071838750"},
		{detect.ClassCreditCard, "4111111111111111"},
		{detect.ClassUSSSN, "123-45-6789"},
		{detect.ClassAWSAccessKey, "AK" + "IA" + "5J7QWMNBZX2LKPRD"},
	}

	for _, sec := range secrets {
		token := mustTok(t, s, sec.class, sec.value)
		if strings.Contains(token, sec.value) {
			t.Errorf("token %q contains the original value", token)
		}
		// No substantial run of the original may survive into the token.
		//
		// Eight characters, not four. A token is format-preserving, so a
		// tokenised phone number is twelve digits drawn from an alphabet of
		// ten, and it shares some four-digit run with the original by
		// chance about once in every hundred and forty runs. That is not a
		// leak — the token is an HMAC of the value and a shared substring
		// carries no information about it — but it failed the build, and a
		// suite that cries wolf is one people stop reading. This whole
		// repository's discipline rests on believing the suite.
		//
		// At eight characters a coincidence is about one in a hundred
		// million, while a genuine fault — a token built by shifting or
		// re-arranging the original rather than deriving it — still shows
		// up immediately.
		const runLength = 8
		for i := 0; i+runLength <= len(sec.value); i++ {
			frag := sec.value[i : i+runLength]
			if strings.ContainsAny(frag, "@.-+") {
				continue // structural characters are expected to recur
			}
			if strings.Contains(token, frag) {
				t.Errorf("token %q leaks fragment %q of %q", token, frag, sec.value)
			}
		}
	}
}

// TestApplyPreservesSurroundingContent is the off-by-one guard.
// Replacement must walk backwards or every span after the first is
// corrupted by the length delta.
func TestApplyPreservesSurroundingContent(t *testing.T) {
	s := testScope(t)
	rs := detect.Default()

	content := []byte("Dear priya@acme.com, your card 4111111111111111 was charged. Call +442071838750.")
	spans := rs.Scan(content)
	if len(spans) < 3 {
		t.Fatalf("expected at least 3 spans, got %d", len(spans))
	}

	out, err := s.Apply(content, spans)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	for _, fixed := range []string{"Dear ", ", your card ", " was charged. Call ", "."} {
		if !bytes.Contains(out, []byte(fixed)) {
			t.Errorf("surrounding text %q was corrupted; got %q", fixed, out)
		}
	}
	for _, span := range spans {
		if bytes.Contains(out, []byte(span.Value)) {
			t.Errorf("original value %q survived tokenisation", span.Value)
		}
	}
}

// TestApplyThenRestore proves the full round trip through real detection:
// govern on the way out, restore on the way back to a trusted destination.
func TestApplyThenRestore(t *testing.T) {
	s := testScope(t)
	rs := detect.Default()

	original := []byte("Contact priya@acme.com or rajesh@acme.com about card 4111111111111111.")
	spans := rs.Scan(original)

	tokenized, err := s.Apply(original, spans)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if bytes.Equal(tokenized, original) {
		t.Fatal("content was unchanged")
	}

	restored, err := s.Restore(tokenized)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !bytes.Equal(restored, original) {
		t.Errorf("round trip did not restore the original:\n got %q\nwant %q", restored, original)
	}
}

// TestApplyIsIdempotentPerValue proves a value appearing twice yields the
// same token both times, which is what lets an agent correlate rows.
func TestApplyIsIdempotentPerValue(t *testing.T) {
	s := testScope(t)
	rs := detect.Default()

	content := []byte("priya@acme.com wrote to priya@acme.com about priya@acme.com")
	out, err := s.Apply(content, rs.Scan(content))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	tokenRe := regexp.MustCompile(`lynt-[a-z2-7]+@tokenized\.invalid`)
	found := tokenRe.FindAllString(string(out), -1)
	if len(found) != 3 {
		t.Fatalf("expected 3 tokens, found %d in %q", len(found), out)
	}
	for _, f := range found[1:] {
		if f != found[0] {
			t.Errorf("the same value produced different tokens: %q and %q", found[0], f)
		}
	}
	if s.Store().(*MemoryStore).Len() != 1 {
		t.Errorf("scope holds %d entries for one repeated value, want 1", s.Store().(*MemoryStore).Len())
	}
}

func TestApplyRejectsOverlappingSpans(t *testing.T) {
	s := testScope(t)
	content := []byte("aaaaaaaaaa")
	spans := []detect.Span{
		{Class: detect.ClassEmail, Start: 0, End: 6, Value: "aaaaaa"},
		{Class: detect.ClassEmail, Start: 4, End: 9, Value: "aaaaa"},
	}
	if _, err := s.Apply(content, spans); err == nil {
		t.Error("overlapping spans were accepted")
	}
}

func TestApplyRejectsOutOfRangeSpan(t *testing.T) {
	s := testScope(t)
	content := []byte("short")
	spans := []detect.Span{{Class: detect.ClassEmail, Start: 0, End: 99, Value: "x"}}
	if _, err := s.Apply(content, spans); err == nil {
		t.Error("out-of-range span was accepted")
	}
}

func TestApplyWithNoSpansCopiesContent(t *testing.T) {
	s := testScope(t)
	content := []byte("nothing sensitive here")
	out, err := s.Apply(content, nil)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !bytes.Equal(out, content) {
		t.Error("content changed when there was nothing to tokenise")
	}
	// The result must be a copy: callers mutate governed output.
	out[0] = 'X'
	if content[0] == 'X' {
		t.Error("Apply returned a slice aliasing the input")
	}
}

func TestKeySizeEnforced(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := NewScope(make([]byte, n), nil); err == nil {
			t.Errorf("NewScope accepted a %d-byte key", n)
		}
	}
}

// TestScopeKeyIsCopied guards against a caller zeroing its key buffer after
// constructing a scope and silently changing every token thereafter.
func TestScopeKeyIsCopied(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, KeySize)
	s, err := NewScope(key, nil)
	if err != nil {
		t.Fatalf("creating scope: %v", err)
	}
	before := mustTok(t, s, detect.ClassEmail, "priya@acme.com")

	for i := range key {
		key[i] = 0
	}
	after := mustTok(t, s, detect.ClassEmail, "priya@acme.com")

	if before != after {
		t.Error("mutating the caller's key buffer changed tokenisation")
	}
}

func TestConcurrentUse(t *testing.T) {
	s := testScope(t)
	values := []string{"a@x.com", "b@x.com", "c@x.com", "d@x.com"}

	done := make(chan string, 200)
	for i := 0; i < 50; i++ {
		go func(i int) {
			v := values[i%len(values)]
			tok, err := s.Tokenize(detect.ClassEmail, v)
			if err != nil {
				t.Errorf("tokenize: %v", err)
				done <- ""
				return
			}
			done <- tok
		}(i)
	}

	seen := make(map[string]int)
	for i := 0; i < 50; i++ {
		seen[<-done]++
	}
	if len(seen) != len(values) {
		t.Errorf("got %d distinct tokens for %d values", len(seen), len(values))
	}
}

func luhnValid(s string) bool {
	sum, double := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		d := int(s[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func BenchmarkTokenize(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	s, _ := NewScope(key, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		//nolint:errcheck // benchmark
		s.Tokenize(detect.ClassEmail, "priya@acme.com")
	}
}

// TestTokensResolveAcrossRestartWithSharedStore is the regression test for
// the gap this Store interface exists to close.
//
// Tokenisation is deterministic, so the forward direction always survived a
// restart. The reverse mapping did not: it lived in a map inside the
// process, so an agent holding a token from before a deploy got a value
// that no longer resolved — and nothing errored, because Restore leaves
// unknown tokens in place. Silent, which is the failure mode this whole
// design exists to avoid.
func TestTokensResolveAcrossRestartWithSharedStore(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, KeySize)
	shared := NewMemoryStore() // stands in for a shared database

	before, err := NewScope(key, shared)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	token, err := before.Tokenize(detect.ClassEmail, "priya@acme.com")
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}

	// A new process, same key, same shared store.
	after, err := NewScope(key, shared)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}

	got, ok, err := after.Detokenize(token)
	if err != nil {
		t.Fatalf("detokenize: %v", err)
	}
	if !ok {
		t.Fatal("token did not resolve after restart; the reverse mapping was lost")
	}
	if got != "priya@acme.com" {
		t.Errorf("resolved to %q", got)
	}
}

// TestRestoreWorksWithoutLocalState proves Restore locates tokens by
// pattern rather than by scanning a local table, so it works against a
// shared store without loading every mapping the deployment ever issued.
func TestRestoreWorksWithoutLocalState(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, KeySize)
	shared := NewMemoryStore()

	issuer, _ := NewScope(key, shared)
	rs := detect.Default()
	original := []byte("Contact priya@acme.com or call +442071838750 about 4111111111111111.")
	tokenized, err := issuer.Apply(original, rs.Scan(original))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	// A different process instance restores.
	restorer, _ := NewScope(key, shared)
	restored, err := restorer.Restore(tokenized)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !bytes.Equal(restored, original) {
		t.Errorf("restore across instances failed:\n got %q\nwant %q", restored, original)
	}
}

// TestUnknownTokensAreLeftAlone proves content that merely looks like a
// token is not mangled.
func TestUnknownTokensAreLeftAlone(t *testing.T) {
	s := testScope(t)
	content := []byte("see lynt-aaaaaaaaaaaaa@tokenized.invalid and +9912345678901 in the docs")
	restored, err := s.Restore(content)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !bytes.Equal(restored, content) {
		t.Errorf("unknown tokens were altered:\n got %q\nwant %q", restored, content)
	}
}

// TestStoreFailurePreventsTokenRelease is the correctness property behind
// the signature change: a token whose mapping could not be recorded must
// never reach the caller, or they hold something they believe is reversible
// and is not.
func TestStoreFailurePreventsTokenRelease(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, KeySize)
	s, err := NewScope(key, failingStore{})
	if err != nil {
		t.Fatalf("scope: %v", err)
	}

	if _, err := s.Tokenize(detect.ClassEmail, "priya@acme.com"); err == nil {
		t.Fatal("a token was released despite the mapping failing to persist")
	}

	rs := detect.Default()
	content := []byte("email priya@acme.com")
	if _, err := s.Apply(content, rs.Scan(content)); err == nil {
		t.Fatal("Apply returned content despite the store failing")
	}
}

type failingStore struct{}

func (failingStore) Put(token, value string) error { return errors.New("store unavailable") }
func (failingStore) Get(token string) (string, bool, error) {
	return "", false, errors.New("store unavailable")
}
