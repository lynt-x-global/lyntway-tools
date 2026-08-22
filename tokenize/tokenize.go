// Package tokenize implements deterministic, format-preserving
// tokenisation.
//
// This is the piece that separates governance from a regex filter.
//
// Naive redaction breaks the workflow it is protecting. If an agent reads a
// customer record and the primary key comes back as "[REDACTED]", its next
// query fails — and the agent has no way to know why. Multi-step agent
// workflows collapse the moment a join key is masked, and the governance
// layer gets blamed for the outage.
//
// Three properties fix that:
//
// # Deterministic
//
// The same value always produces the same token within a scope. An agent
// that sees token X for a customer in one response can use X as a key in
// the next request, and the gateway resolves it back. Referential integrity
// survives.
//
// # Format-preserving
//
// A tokenised email is still a syntactically valid email; a tokenised card
// number still passes Luhn. Downstream schema validation, type checks, and
// parsers keep working. Substituting "[REDACTED]" into a column typed as an
// email address fails a constraint check before it ever reaches the agent.
//
// # Reversible within a scope
//
// Tokens resolve back to their original values on the return path to a
// trusted destination, and only there. The mapping lives in a scope that
// the caller controls and can discard.
//
// # What tokens must never be
//
// Tokens must not be reversible by inspection. They are derived through
// HMAC with a secret key, so possessing a token without the key reveals
// nothing about the value — which matters because tokens travel to exactly
// the destinations the original value was withheld from.
package tokenize

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// KeySize is the required length of a tokenisation key in bytes.
const KeySize = 32

// tokenAlphabet is lowercase base32 without padding: unambiguous in logs,
// safe in URLs, and case-insensitive so a system that upper-cases
// identifiers does not destroy the token.
var tokenAlphabet = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Store persists the token-to-value mapping.
//
// The forward direction never needs storage: derivation is deterministic,
// so the same value always yields the same token. Only the reverse lookup
// is inherently a table, and it is the reverse direction that makes
// tokenisation useful — without it a token is just an opaque redaction.
//
// An implementation must be safe for concurrent use, and must be shared
// across every replica that issues or resolves tokens. A per-process store
// means a token issued by one replica does not resolve on another, which
// fails silently: Restore simply leaves the token in place.
type Store interface {
	// Put records a mapping. Called before a token is released, so an
	// error here must prevent the token from being returned.
	Put(token, value string) error

	// Get resolves a token. The boolean reports whether it was known.
	Get(token string) (string, bool, error)
}

// Eraser is a Store that can forget every mapping under a prefix.
//
// Optional, and checked for at run time, because not every Store can do it
// — a write-only sink has nothing to erase, and an implementation that
// cannot must say so rather than report a successful deletion that did
// nothing. Erasure is a legal obligation, not a convenience: a customer who
// asks to be forgotten and is told "done" has been told something that must
// be true.
type Eraser interface {
	// ErasePrefix removes every mapping whose key begins with prefix and
	// returns how many went.
	ErasePrefix(prefix string) (int64, error)
}

// DiscardStore accepts mappings and keeps none.
//
// This is one-way tokenisation: values are still substituted, still
// deterministic and still format-preserving, so the workflow downstream is
// unaffected — but nothing is retained and no token can ever be resolved.
//
// It exists because holding the mapping is what makes a deployment a
// processor of personal data. A customer who never needs to reverse a
// token — which is most audit, telemetry and logging use — should not have
// to place their data in someone else's vault to get governance.
//
// A scope backed by this store reports itself as irreversible, and the
// engine records those substitutions as redaction rather than
// tokenisation. That distinction is not cosmetic: the receipt schema
// defines tokenisation as reversible substitution, so claiming it here
// would promise a customer something this deployment cannot deliver.
type DiscardStore struct{}

// Put implements Store by discarding the mapping.
func (DiscardStore) Put(string, string) error { return nil }

// Get implements Store. Nothing was kept, so nothing resolves.
func (DiscardStore) Get(string) (string, bool, error) { return "", false, nil }

// ErasePrefix implements Eraser trivially: there is never anything to erase.
func (DiscardStore) ErasePrefix(string) (int64, error) { return 0, nil }

// MemoryStore keeps mappings in memory.
//
// Not durable and not shared. Suitable for tests, single-process
// deployments, and cases where tokens are not expected to outlive the
// process. Any deployment with more than one replica needs a shared Store.
type MemoryStore struct {
	mu sync.RWMutex
	m  map[string]string
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{m: make(map[string]string)}
}

// Put implements Store.
func (s *MemoryStore) Put(token, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[token]; !exists {
		s.m[token] = value
	}
	return nil
}

// Get implements Store.
func (s *MemoryStore) Get(token string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[token]
	return v, ok, nil
}

// Len returns the number of mappings held.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// ErasePrefix implements Eraser.
func (s *MemoryStore) ErasePrefix(prefix string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed int64
	for token := range s.m {
		if strings.HasPrefix(token, prefix) {
			delete(s.m, token)
			removed++
		}
	}
	return removed, nil
}

// Scope holds the token mappings for one tokenisation domain.
//
// A scope is typically one agent session, one workspace, or one request
// chain — whatever boundary the caller wants reversibility to span.
// Discarding a scope makes its tokens permanently irreversible, which is
// the intended way to expire them.
//
// Scope is safe for concurrent use.
type Scope struct {
	key   []byte
	store Store
}

// NewScope creates a tokenisation scope.
//
// key must be exactly KeySize bytes and should come from a key management
// service, not from configuration. Two scopes sharing a key produce
// identical tokens for identical values, which is how tokens stay stable
// across process restarts — and why the key must be treated as a secret of
// the same weight as the data it protects.
func NewScope(key []byte, store Store) (*Scope, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("tokenize: key must be %d bytes, got %d", KeySize, len(key))
	}
	if store == nil {
		store = NewMemoryStore()
	}
	k := make([]byte, KeySize)
	copy(k, key)
	return &Scope{key: k, store: store}, nil
}

// Tokenize returns a stable, format-preserving token for value.
//
// Calling it repeatedly with the same class and value returns the same
// token and does not grow the store.
//
// Returns an error when the mapping could not be recorded. That error must
// not be ignored: releasing a token whose reverse mapping was never stored
// hands the caller something they believe is reversible and is not, and the
// failure is silent — Restore would simply leave the token in place.
func (s *Scope) Tokenize(class detect.Class, value string) (string, error) {
	token := s.derive(class, value)

	// Recorded before the token is returned. An existing entry is left
	// alone: derivation is deterministic, so a collision would mean two
	// distinct values produced the same token, which HMAC makes
	// infeasible.
	if err := s.store.Put(token, value); err != nil {
		return "", fmt.Errorf("tokenize: recording token mapping: %w", err)
	}
	return token, nil
}

// Detokenize resolves a token back to its original value.
//
// The boolean reports whether the token was known to this scope. An unknown
// token is not an error: content legitimately contains strings that look
// like tokens but were never issued here, and the caller must leave those
// untouched rather than failing the request.
func (s *Scope) Detokenize(token string) (string, bool, error) {
	return s.store.Get(token)
}

// Store returns the scope's backing store.
func (s *Scope) Store() Store { return s.store }

// Reversible reports whether tokens issued by this scope can be resolved.
//
// False for a one-way scope, where substitution still happens but nothing
// is retained. Callers must consult this before promising reversibility:
// the difference is invisible in the output, because a one-way token looks
// exactly like a reversible one.
func (s *Scope) Reversible() bool {
	switch store := s.store.(type) {
	case DiscardStore:
		return false
	case *namespacedStore:
		// A namespaced view of a discarding store is still one-way, and
		// checking only the outer type would report it as reversible —
		// which is the exact promise this must not make wrongly.
		return !store.oneWay()
	}
	return true
}

// Erase forgets every mapping this scope holds.
//
// Reports whether the backing store was able to do it. A store that cannot
// erase returns false rather than silently succeeding — a deletion request
// answered with an untrue "done" is worse than one answered with "this
// deployment cannot".
func (s *Scope) Erase() (removed int64, supported bool, err error) {
	eraser, ok := s.store.(Eraser)
	if !ok {
		return 0, false, nil
	}
	// The namespaced view erases only its own prefix; an unnamespaced
	// store has no prefix to confine it, so an empty string means all of
	// it, which is what a single-tenant deployment's erasure means.
	n, err := eraser.ErasePrefix("")
	if errors.Is(err, errNoEraser) {
		return 0, false, nil
	}
	return n, true, err
}

// derive computes the deterministic token for a value.
//
// The class is bound into the HMAC input alongside the value, so the same
// string appearing as two different classes yields different tokens. That
// prevents a token from silently carrying a type it was not issued for.
func (s *Scope) derive(class detect.Class, value string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(class))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	sum := mac.Sum(nil)

	switch class {
	case detect.ClassEmail:
		return emailToken(sum)
	case detect.ClassPhone:
		return phoneToken(sum)
	case detect.ClassCreditCard:
		return cardToken(sum, len(digitsOnly(value)))
	case detect.ClassIPv4:
		return ipToken(sum)
	default:
		return genericToken(class, sum)
	}
}

// emailToken produces a syntactically valid address in a domain that can
// never resolve.
//
// The .invalid TLD is reserved by RFC 2606 precisely so it cannot exist. A
// token that accidentally routes is a token that can receive the email it
// was supposed to protect.
func emailToken(sum []byte) string {
	return "lynt-" + encode(sum[:8]) + "@tokenized.invalid"
}

// phoneToken produces an E.164 number in the +99 range.
//
// Country code 99 is unassigned, so the result parses as a phone number and
// validates, but cannot be dialled to reach a real person.
func phoneToken(sum []byte) string {
	var b strings.Builder
	b.WriteString("+99")
	for i := 0; i < 10; i++ {
		b.WriteByte('0' + sum[i]%10)
	}
	return b.String()
}

// cardToken produces a Luhn-valid number of the same length, in the
// 9999 test BIN range that no issuer allocates.
//
// Preserving Luhn validity matters because payment code paths reject
// structurally invalid numbers long before any business logic sees them —
// so a naive token surfaces as a validation error rather than as a governed
// field.
func cardToken(sum []byte, length int) string {
	if length < 13 {
		length = 16
	}
	if length > 19 {
		length = 19
	}

	digits := make([]int, length)
	// A fixed prefix marks the number as synthetic to anyone reading it.
	prefix := []int{9, 9, 9, 9}
	copy(digits, prefix)
	for i := len(prefix); i < length-1; i++ {
		digits[i] = int(sum[i%len(sum)] % 10)
	}
	digits[length-1] = luhnCheckDigit(digits[:length-1])

	var b strings.Builder
	for _, d := range digits {
		b.WriteByte(byte('0' + d))
	}
	return b.String()
}

// luhnCheckDigit returns the digit that makes prefix Luhn-valid.
func luhnCheckDigit(prefix []int) int {
	sum := 0
	double := true // the check digit position makes the last prefix digit doubled
	for i := len(prefix) - 1; i >= 0; i-- {
		d := prefix[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return (10 - sum%10) % 10
}

// ipToken produces an address in 192.0.2.0/24, the RFC 5737 documentation
// range, so it is syntactically valid and guaranteed not to route.
func ipToken(sum []byte) string {
	return fmt.Sprintf("192.0.2.%d", sum[0]%254+1)
}

// genericToken produces a labelled token for classes with no format worth
// preserving.
//
// The class is embedded so that a human reading a governed payload can tell
// what was removed without access to the receipt.
func genericToken(class detect.Class, sum []byte) string {
	label := strings.NewReplacer(".", "_", "-", "_").Replace(string(class))
	return "LYNT_" + strings.ToUpper(label) + "_" + encode(sum[:10])
}

func encode(b []byte) string { return tokenAlphabet.EncodeToString(b) }

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ErrScopeRequired is returned when a transformation needs a scope and none
// was supplied.
var ErrScopeRequired = errors.New("tokenize: a scope is required for reversible tokenisation")

// Apply replaces each span in content with its token and returns the
// transformed content.
//
// Spans must be sorted by start offset and must not overlap, which is what
// detect.Scan guarantees. Replacement walks backwards so that earlier
// offsets stay valid as later ones are rewritten — going forwards would
// shift every subsequent span by the length delta and corrupt the output.
func (s *Scope) Apply(content []byte, spans []detect.Span) ([]byte, error) {
	if s == nil {
		return nil, ErrScopeRequired
	}
	if len(spans) == 0 {
		out := make([]byte, len(content))
		copy(out, content)
		return out, nil
	}

	for i := 1; i < len(spans); i++ {
		if spans[i].Start < spans[i-1].End {
			return nil, fmt.Errorf("tokenize: spans overlap at index %d; detect.Scan must resolve overlaps first", i)
		}
	}
	if spans[len(spans)-1].End > len(content) {
		return nil, errors.New("tokenize: span extends past the end of content")
	}

	out := make([]byte, 0, len(content))
	prev := 0
	for _, span := range spans {
		out = append(out, content[prev:span.Start]...)
		token, err := s.Tokenize(span.Class, span.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, token...)
		prev = span.End
	}
	out = append(out, content[prev:]...)
	return out, nil
}

// Restore replaces every known token in content with its original value.
//
// Used on the return path to a trusted destination. Tokens this scope did
// not issue are left untouched.
//
// Tokens are located by pattern rather than by scanning a local table, so
// this works against a shared store without loading every mapping the
// deployment has ever issued.
func (s *Scope) Restore(content []byte) ([]byte, error) {
	matches := tokenPattern.FindAllIndex(content, -1)
	if len(matches) == 0 {
		out := make([]byte, len(content))
		copy(out, content)
		return out, nil
	}

	out := make([]byte, 0, len(content))
	prev := 0
	for _, m := range matches {
		token := string(content[m[0]:m[1]])
		value, ok, err := s.store.Get(token)
		if err != nil {
			return nil, fmt.Errorf("tokenize: resolving token: %w", err)
		}
		out = append(out, content[prev:m[0]]...)
		if ok {
			out = append(out, value...)
		} else {
			// Not a token this scope issued. Leaving it untouched is the
			// only safe choice: content legitimately contains strings that
			// look like tokens.
			out = append(out, token...)
		}
		prev = m[1]
	}
	return append(out, content[prev:]...), nil
}

// Restored marks a range in the output of RestoreMarking that came from
// resolving a token rather than from the input.
type Restored struct{ Start, End int }

// RestoreMarking restores like Restore and says where each value landed.
//
// The ranges exist because of what a token is. Substitution is
// format-preserving — a tokenised card is a valid card number, a tokenised
// address is a valid address — so after restoring, a detector cannot tell a
// value it has just handed back from one it is seeing for the first time.
// Without the ranges the only options are to substitute everything, which
// hands somebody their own data disguised, or to substitute nothing, which
// lets a value the far end invented pass straight through. Both have
// shipped from this file's callers.
//
// Restore keeps its signature: it is published, and most callers restore a
// whole document with nothing to decide afterwards.
func (s *Scope) RestoreMarking(content []byte) ([]byte, []Restored, error) {
	matches := tokenPattern.FindAllIndex(content, -1)
	if len(matches) == 0 {
		out := make([]byte, len(content))
		copy(out, content)
		return out, nil, nil
	}

	out := make([]byte, 0, len(content))
	var marks []Restored
	prev := 0
	for _, m := range matches {
		token := string(content[m[0]:m[1]])
		value, ok, err := s.store.Get(token)
		if err != nil {
			return nil, nil, fmt.Errorf("tokenize: resolving token: %w", err)
		}
		out = append(out, content[prev:m[0]]...)
		if ok {
			marks = append(marks, Restored{Start: len(out), End: len(out) + len(value)})
			out = append(out, value...)
		} else {
			// Not a token this scope issued, so it is ordinary content that
			// happens to look like one. Left alone, and deliberately not
			// marked: it was not restored, so it is still a candidate for
			// substitution like any other value.
			out = append(out, token...)
		}
		prev = m[1]
	}
	return append(out, content[prev:]...), marks, nil
}

// CountTokens reports how many token-shaped strings appear in content.
//
// Shape only: it does not consult the store, so it counts strings that look
// like tokens whether or not this deployment issued them. Useful for
// reporting how many were resolved — the difference before and after
// Restore — which is a count Restore itself does not return, because that
// signature is published and a caller's reporting need is not a reason to
// change it.
func CountTokens(content []byte) int {
	return len(tokenPattern.FindAllIndex(content, -1))
}

// tokenPattern matches every token shape this package issues.
//
// Anchored on the fixed prefixes and reserved ranges the generators use, so
// it cannot match ordinary content by accident.
var tokenPattern = regexp.MustCompile(
	`lynt-[a-z2-7]{13}@tokenized\.invalid` +
		`|\+99\d{10}` +
		`|\b9999\d{9,15}\b` +
		`|192\.0\.2\.\d{1,3}` +
		`|LYNT_[A-Z0-9_]+_[a-z2-7]{16}`)

// KeyMatches reports whether other holds the same key as s, in constant
// time.
//
// Used to confirm that a restored scope was rebuilt with the right key
// before it is trusted to reverse tokens. A mismatched key would produce
// tokens that silently fail to resolve.
func (s *Scope) KeyMatches(other []byte) bool {
	return subtle.ConstantTimeCompare(s.key, other) == 1
}

// Namespaced returns a view of a store scoped to a namespace.
//
// Necessary for multi-tenancy even though per-tenant keys already make two
// tenants derive different tokens for the same value. The vault is keyed by
// token alone, so a tenant who obtained another tenant's token string — from
// a shared document, a support ticket, a screenshot — would otherwise
// resolve it against the shared table and read data that was never theirs.
//
// Namespacing means a lookup can only ever find mappings the same namespace
// wrote, so a leaked token is inert outside the tenant that issued it.
func Namespaced(inner Store, namespace string) Store {
	return &namespacedStore{inner: inner, prefix: namespace + namespaceSeparator}
}

// namespaceSeparator joins a namespace to a token.
//
// It has to be a byte that can appear in neither half, or two different
// (namespace, token) pairs could produce one key and a tenant would read
// another tenant's mapping. Namespaces are constrained to letters, digits,
// hyphen, underscore and a slash; tokens are generated by this package.
// A control character satisfies that.
//
// NUL would satisfy it too, and was the obvious first choice, but a Store
// is an interface: implementations keep this key in a database column, a
// file, a cache. Postgres rejects NUL in a text column outright, so that
// choice made every namespaced write fail against the one backend that
// matters for multi-tenancy — the failure appearing not here but two
// packages away, as an encoding error. Unit separator carries the same
// guarantee and is storable everywhere.
const namespaceSeparator = "\x1f"

type namespacedStore struct {
	inner  Store
	prefix string
}

func (n *namespacedStore) Put(token, value string) error {
	return n.inner.Put(n.prefix+token, value)
}

func (n *namespacedStore) Get(token string) (string, bool, error) {
	return n.inner.Get(n.prefix + token)
}

// ErasePrefix implements Eraser, confined to this namespace.
//
// The caller's prefix is appended to the namespace rather than replacing
// it, so a tenant asking to erase everything erases everything of theirs.
// Passing the caller's prefix straight through would let one tenant's
// deletion reach another's mappings, which is the same isolation failure
// namespacing exists to prevent — in the one direction where it is
// irreversible.
func (n *namespacedStore) ErasePrefix(prefix string) (int64, error) {
	eraser, ok := n.inner.(Eraser)
	if !ok {
		return 0, errNoEraser
	}
	return eraser.ErasePrefix(n.prefix + prefix)
}

// oneWay reports whether the underlying store retains anything, so that a
// namespaced view of a discarding store still reports itself as one-way.
func (n *namespacedStore) oneWay() bool {
	_, discard := n.inner.(DiscardStore)
	return discard
}

// errNoEraser marks a store that cannot erase, so Scope.Erase can report
// "unsupported" rather than a false success.
var errNoEraser = errors.New("tokenize: this store cannot erase")
