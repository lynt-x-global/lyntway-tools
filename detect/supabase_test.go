package detect

import "testing"

// Supabase publishes two keys and only one of them is a secret. Getting
// that distinction wrong in either direction is a defect: miss the secret
// one and the rule is pointless, flag the public one and people learn to
// ignore the finding that matters.
//
// The rule exists because of what the 2026 incident data actually names.
// A May 2026 scan found roughly 380,000 publicly reachable apps built on
// Lovable, Base44, Replit and Netlify, and the reported failure is a
// builder pasting the secret key where only the publishable one belongs.
// The legacy service_role key was a JWT and the jwt rule already caught
// it; sb_secret_ is not a JWT and matched nothing at all.

func TestSupabaseSecretKeyIsFoundAndThePublishableOneIsNot(t *testing.T) {
	rs := Default()

	for _, c := range []struct {
		name    string
		sample  string
		want    Class
		wantHit bool
	}{
		{
			// Spelled out rather than random-looking: the rule reads the
			// prefix, the alphabet and the length, so nothing is lost, and
			// a credential-shaped fixture on a public repository is one
			// every scanner has to make a judgement about.
			name:    "the secret key, which must never reach a model or a bundle",
			sample:  "SUPABASE_SECRET_KEY=sb_secret_NOTAREALKEYnotarealkey",
			want:    ClassSupabaseKey,
			wantHit: true,
		},
		{
			// Still in wide use, and already covered. Asserted here so that
			// a future narrowing of the jwt rule cannot silently drop it.
			name:    "the legacy service_role key, which is a JWT",
			sample:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE3MDAwMDAwMDB9.dGhpc2lzbm90YXJlYWxzaWduYXR1cmVhdGFsbHh4",
			want:    ClassJWT,
			wantHit: true,
		},
		{
			name:    "the publishable key, which is designed to be public",
			sample:  "NEXT_PUBLIC_SUPABASE_KEY=sb_publishable_9xLmQw2ErTyUiOpAsDfGh",
			wantHit: false,
		},
		{
			name:    "the prefix alone, with nothing of key length after it",
			sample:  "sb_secret_abc",
			wantHit: false,
		},
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
				t.Fatal("found nothing")
			}
			if spans[0].Class != c.want {
				t.Errorf("class %s, want %s", spans[0].Class, c.want)
			}
			// Deterministic tier, so the receipt carries no detector name
			// and a reader can re-derive the finding from the ruleset
			// digest months later.
			if spans[0].Detector != "" {
				t.Errorf("detector %q, want empty: this is a deterministic rule", spans[0].Detector)
			}
		})
	}
}
