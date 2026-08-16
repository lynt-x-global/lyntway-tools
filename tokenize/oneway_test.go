package tokenize

import (
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

func testKey() []byte {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// One-way tokenisation must still substitute, and still substitute the same
// way. A customer choosing it gives up recovery, not format preservation —
// otherwise it is just redaction with extra steps.
func TestOneWayScopeStillSubstitutesIdentically(t *testing.T) {
	reversible, err := NewScope(testKey(), NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	oneWay, err := NewScope(testKey(), DiscardStore{})
	if err != nil {
		t.Fatal(err)
	}

	a, err := reversible.Tokenize(detect.ClassEmail, "priya@acme.co.in")
	if err != nil {
		t.Fatal(err)
	}
	b, err := oneWay.Tokenize(detect.ClassEmail, "priya@acme.co.in")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("one-way token %q differs from reversible %q; the substitution must not change", b, a)
	}
	if !strings.HasSuffix(b, "@tokenized.invalid") {
		t.Errorf("one-way token %q is not format-preserving", b)
	}
}

func TestOneWayScopeResolvesNothing(t *testing.T) {
	scope, err := NewScope(testKey(), DiscardStore{})
	if err != nil {
		t.Fatal(err)
	}
	token, err := scope.Tokenize(detect.ClassEmail, "priya@acme.co.in")
	if err != nil {
		t.Fatal(err)
	}

	if scope.Reversible() {
		t.Error("a scope backed by DiscardStore reported itself as reversible")
	}
	if _, ok, _ := scope.Detokenize(token); ok {
		t.Error("a one-way scope resolved a token")
	}

	// Restore must leave it in place rather than failing the content.
	restored, err := scope.Restore([]byte("mail " + token + " now"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(restored), token) {
		t.Errorf("Restore altered an unresolvable token: %q", restored)
	}
}

// A namespaced view of a discarding store is still one-way. Checking only
// the outer type would report it reversible — the exact promise this must
// never make wrongly.
func TestNamespacedOneWayScopeIsStillOneWay(t *testing.T) {
	scope, err := NewScope(testKey(), Namespaced(DiscardStore{}, "acme"))
	if err != nil {
		t.Fatal(err)
	}
	if scope.Reversible() {
		t.Error("a namespaced one-way scope reported itself as reversible")
	}
}

// Erasure must reach one tenant's mappings and no further.
func TestErasureIsConfinedToTheTenant(t *testing.T) {
	shared := NewMemoryStore()

	acme, err := NewScope(testKey(), Namespaced(shared, "acme"))
	if err != nil {
		t.Fatal(err)
	}
	globex, err := NewScope(testKey(), Namespaced(shared, "globex"))
	if err != nil {
		t.Fatal(err)
	}

	acmeToken, err := acme.Tokenize(detect.ClassEmail, "priya@acme.co.in")
	if err != nil {
		t.Fatal(err)
	}
	globexToken, err := globex.Tokenize(detect.ClassEmail, "sam@globex.com")
	if err != nil {
		t.Fatal(err)
	}

	removed, supported, err := acme.Erase()
	if err != nil || !supported {
		t.Fatalf("erase: removed=%d supported=%v err=%v", removed, supported, err)
	}
	if removed != 1 {
		t.Errorf("erased %d mappings, want 1", removed)
	}

	if _, ok, _ := acme.Detokenize(acmeToken); ok {
		t.Error("an erased tenant's token still resolves")
	}
	if _, ok, _ := globex.Detokenize(globexToken); !ok {
		t.Error("erasing one tenant destroyed another tenant's mappings")
	}
}

// A store that cannot erase must say so rather than report a success that
// deleted nothing. Erasure is a legal obligation, and an untrue "done" is
// worse than an honest "this deployment cannot".
func TestErasureReportsWhenUnsupported(t *testing.T) {
	scope, err := NewScope(testKey(), readOnlyStore{})
	if err != nil {
		t.Fatal(err)
	}
	removed, supported, err := scope.Erase()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if supported {
		t.Error("a store with no erasure reported that it erased")
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
}

// A namespaced view of a store that cannot erase must report the same.
func TestNamespacedErasureReportsWhenUnsupported(t *testing.T) {
	scope, err := NewScope(testKey(), Namespaced(readOnlyStore{}, "acme"))
	if err != nil {
		t.Fatal(err)
	}
	if _, supported, err := scope.Erase(); supported || err != nil {
		t.Errorf("supported = %v, err = %v; want false, nil", supported, err)
	}
}

type readOnlyStore struct{}

func (readOnlyStore) Put(string, string) error         { return nil }
func (readOnlyStore) Get(string) (string, bool, error) { return "", false, nil }
