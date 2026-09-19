package receipt

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Withdrawing trust from a key.
//
// A signature says only that whoever held the key signed. Once a key may
// be in somebody else's hands, or has simply been replaced, a verifier has
// to be told — and told in the same place it already gets keys from, so
// that the list travels with the key set rather than depending on a
// service being reachable at the moment of checking.
//
// Two kinds, because they mean different things for old receipts:
//
//   - Retired. The key was replaced in the ordinary course. Receipts it
//     signed before RevokedAt remain exactly as good as they were;
//     anything dated after is refused.
//   - Compromised. Whoever has the key can write any issued_at they like,
//     so the date on a receipt proves nothing about when it was signed.
//     Every receipt the key signed is refused. A receipt that must survive
//     that needs evidence of its time from outside the key — an RFC 3161
//     anchor or a transparency-log inclusion proof — which is checked
//     separately and is why those exist.

// Revocation withdraws trust from one key.
type Revocation struct {
	KeyID string `json:"key_id"`

	// RevokedAt is RFC 3339 UTC.
	RevokedAt string `json:"revoked_at"`

	// Compromised refuses every receipt the key signed, whatever its date.
	Compromised bool `json:"compromised,omitempty"`

	// Reason is for a person reading the list. Advisory.
	Reason string `json:"reason,omitempty"`
}

// RevocationList is the set a verifier consults, by key ID.
type RevocationList map[string]Revocation

// NewRevocationList indexes revocations, refusing malformed ones rather
// than silently trusting the key they were meant to withdraw.
func NewRevocationList(entries []Revocation) (RevocationList, error) {
	list := RevocationList{}
	for _, e := range entries {
		if strings.TrimSpace(e.KeyID) == "" {
			return nil, errors.New("receipt: a revocation names no key")
		}
		if _, err := time.Parse(time.RFC3339, e.RevokedAt); err != nil {
			return nil, fmt.Errorf("receipt: revocation of %q has no valid revoked_at: %w", e.KeyID, err)
		}
		// Compromise is the stronger statement and wins if a key is listed
		// twice; the earlier date wins for the same reason.
		if prior, ok := list[e.KeyID]; ok {
			if prior.Compromised {
				e.Compromised = true
			}
			if prior.RevokedAt < e.RevokedAt {
				e.RevokedAt = prior.RevokedAt
			}
		}
		list[e.KeyID] = e
	}
	return list, nil
}

// ErrKeyRevoked means the receipt was signed, or its key attested, by a key
// that is no longer trusted for it.
var ErrKeyRevoked = errors.New("receipt: key revoked")

// check reports whether a key may be trusted for a receipt issued at t.
func (l RevocationList) check(keyID string, issuedAt time.Time) error {
	rev, ok := l[keyID]
	if !ok {
		return nil
	}
	if rev.Compromised {
		return fmt.Errorf("%w: key %q was reported compromised on %s, so no receipt it signed can be trusted on its own",
			ErrKeyRevoked, keyID, rev.RevokedAt)
	}
	at, err := time.Parse(time.RFC3339, rev.RevokedAt)
	if err != nil {
		// NewRevocationList refuses these; a list built by hand that holds
		// one is treated as the strongest reading.
		return fmt.Errorf("%w: key %q has an unreadable revocation date", ErrKeyRevoked, keyID)
	}
	if !issuedAt.Before(at) {
		return fmt.Errorf("%w: key %q was retired on %s and this receipt is dated %s",
			ErrKeyRevoked, keyID, rev.RevokedAt, issuedAt.UTC().Format(time.RFC3339))
	}
	return nil
}
