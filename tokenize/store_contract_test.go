package tokenize

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// recordingStore captures the keys a wrapper actually writes, so the
// contract below can inspect them rather than infer them.
type recordingStore struct {
	keys   []string
	values map[string]string
}

func newRecordingStore() *recordingStore {
	return &recordingStore{values: map[string]string{}}
}

func (r *recordingStore) Put(token, value string) error {
	r.keys = append(r.keys, token)
	r.values[token] = value
	return nil
}

func (r *recordingStore) Get(token string) (string, bool, error) {
	v, ok := r.values[token]
	return v, ok, nil
}

// A Store key has to survive every backend the interface admits, and the
// backends that matter are text-keyed: a database column, a cache, a file.
//
// This is the test that was missing. Namespacing joined with NUL, which is
// unambiguous and correct in a Go map and rejected outright by Postgres in
// a text column. Both packages were individually correct and individually
// tested; every namespaced write failed in production, and the error
// surfaced two packages from its cause as a character-encoding complaint.
func TestNamespacedKeysAreStorableInATextKeyedStore(t *testing.T) {
	inner := newRecordingStore()
	ns := Namespaced(inner, "t/acme-corp")

	if err := ns.Put("lynt-abc123@tokenized.invalid", "priya@acme.com"); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, _, err := ns.Get("lynt-abc123@tokenized.invalid"); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(inner.keys) == 0 {
		t.Fatal("nothing was written")
	}

	for _, key := range inner.keys {
		if strings.ContainsRune(key, 0) {
			t.Errorf("key %q contains NUL; Postgres rejects it in a text "+
				"column, so every namespaced write would fail", key)
		}
		if !utf8.ValidString(key) {
			t.Errorf("key %q is not valid UTF-8", key)
		}
	}
}

// The separator's whole job is to make one key mean exactly one
// (namespace, token) pair. If it can appear inside either half, two
// different pairs collide — and a collision here means one tenant reading
// another tenant's mapping, which is the failure namespacing exists to
// prevent.
func TestNamespaceSeparatorCannotAppearInEitherHalf(t *testing.T) {
	// Namespaces are built from validated tenant IDs; tokens are generated
	// by this package. Neither alphabet may include the separator.
	namespaces := []string{"t/acme-corp", "t/default", "t/a_b-c9", "t/demo"}
	for _, n := range namespaces {
		if strings.Contains(n, namespaceSeparator) {
			t.Errorf("namespace %q contains the separator", n)
		}
	}

	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	scope, err := NewScope(key, newRecordingStore())
	if err != nil {
		t.Fatalf("scope: %v", err)
	}

	for _, tc := range []struct{ class, value string }{
		{"pii.email", "priya@acme.com"},
		{"pii.phone", "+442071838750"},
		{"pii.credit_card", "4111111111111111"},
		{"pii.ip_address", "203.0.113.9"},
		{"secret.aws_access_key", "AK" + "IA5J7QWMNBZX2LKPRD"},
	} {
		token, err := scope.Tokenize(detect.Class(tc.class), tc.value)
		if err != nil {
			t.Fatalf("tokenizing %s: %v", tc.class, err)
		}
		if strings.Contains(token, namespaceSeparator) {
			t.Errorf("token %q for %s contains the separator", token, tc.class)
		}
		if strings.ContainsRune(token, 0) {
			t.Errorf("token %q for %s contains NUL", token, tc.class)
		}
	}
}

// Two namespaces must not be able to reach each other's mappings, which is
// the property the separator exists to guarantee.
func TestNamespacesRemainIsolatedAfterTheSeparatorChange(t *testing.T) {
	inner := newRecordingStore()
	acme := Namespaced(inner, "t/acme")
	other := Namespaced(inner, "t/other")

	const token = "lynt-shared@tokenized.invalid"
	if err := acme.Put(token, "acme secret"); err != nil {
		t.Fatalf("put: %v", err)
	}

	if _, found, _ := other.Get(token); found {
		t.Error("one tenant resolved another tenant's token")
	}
	v, found, _ := acme.Get(token)
	if !found || v != "acme secret" {
		t.Errorf("the issuing tenant lost its own mapping: %q found=%v", v, found)
	}
}
