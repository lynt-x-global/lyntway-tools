package receipt

import (
	"errors"
	"testing"
	"time"
)

func TestARetiredKeyKeepsItsPast(t *testing.T) {
	s := newTenantSetup(t, "tenant-key", "t_1/")
	r := s.receiptFor(t, "t_1/gw")
	issued, _ := ParseTime(r.IssuedAt)

	after := RevocationList{s.tenant.KeyID(): {KeyID: s.tenant.KeyID(), RevokedAt: issued.Add(time.Hour).Format(time.RFC3339)}}
	if _, err := Verify(r, s.rootsOnly, VerifyOptions{Revoked: after}); err != nil {
		t.Fatalf("a receipt from before retirement was refused: %v", err)
	}
	before := RevocationList{s.tenant.KeyID(): {KeyID: s.tenant.KeyID(), RevokedAt: issued.Add(-time.Hour).Format(time.RFC3339)}}
	if _, err := Verify(r, s.rootsOnly, VerifyOptions{Revoked: before}); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("a receipt dated after retirement: %v, want ErrKeyRevoked", err)
	}
}

func TestACompromisedKeyKeepsNothing(t *testing.T) {
	s := newTenantSetup(t, "tenant-key", "t_1/")
	r := s.receiptFor(t, "t_1/gw")
	issued, _ := ParseTime(r.IssuedAt)
	later := issued.Add(24 * time.Hour).Format(time.RFC3339)

	for name, list := range map[string]RevocationList{
		"signing key": {s.tenant.KeyID(): {KeyID: s.tenant.KeyID(), RevokedAt: later, Compromised: true}},
		"root key":    {s.root.KeyID(): {KeyID: s.root.KeyID(), RevokedAt: later, Compromised: true}},
	} {
		if _, err := Verify(r, s.rootsOnly, VerifyOptions{Revoked: list}); !errors.Is(err, ErrKeyRevoked) {
			t.Errorf("%s compromised: %v, want ErrKeyRevoked", name, err)
		}
	}
}

func TestAnExpiredAttestationStillCoversWhatItSigned(t *testing.T) {
	s := newTenantSetup(t, "tenant-key", "t_1/")
	pub, _ := RawPublicKey(s.tenant)
	now := time.Now().UTC()
	att, err := AttestKeyBetween(s.root, s.tenant.KeyID(), s.tenant.Algorithm(), pub, "t_1/", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	sign := func(at time.Time) *Receipt {
		r := validReceipt()
		r.Chain = Chain{ID: "t_1/gw"}
		r.IssuedAt = at.Format(time.RFC3339)
		r.Issuer = Issuer{KeyID: s.tenant.KeyID(), Name: "Lyntway", KeyAttestation: att}
		if err := Sign(r, s.tenant); err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := sign(now)

	// Verified a year later, long after the attestation ended.
	if _, err := Verify(r, s.rootsOnly, VerifyOptions{Now: now.Add(365 * 24 * time.Hour)}); err != nil {
		t.Fatalf("a receipt signed inside the attestation's period was refused later: %v", err)
	}

	// Signed after the period: refused, whenever it is checked.
	late := sign(now.Add(2 * time.Hour))
	if _, err := Verify(late, s.rootsOnly, VerifyOptions{Now: now.Add(3 * time.Hour)}); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("a receipt dated after the attestation ended: %v, want ErrAttestationInvalid", err)
	}

	if _, err := AttestKeyBetween(s.root, "k", s.tenant.Algorithm(), pub, "t_1/", now, now); err == nil {
		t.Error("an attestation ending when it begins was accepted")
	}
}

func TestAMalformedRevocationIsRefused(t *testing.T) {
	if _, err := NewRevocationList([]Revocation{{KeyID: "k", RevokedAt: "yesterday"}}); err == nil {
		t.Error("a revocation with no usable date was accepted")
	}
	list, err := NewRevocationList([]Revocation{
		{KeyID: "k", RevokedAt: "2026-09-01T00:00:00Z", Compromised: true},
		{KeyID: "k", RevokedAt: "2026-09-10T00:00:00Z"},
	})
	if err != nil || !list["k"].Compromised || list["k"].RevokedAt != "2026-09-01T00:00:00Z" {
		t.Errorf("merged = %+v, %v; want the compromise and the earlier date kept", list["k"], err)
	}
}
