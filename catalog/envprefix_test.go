package catalog

// Environment prefixes are read off a pasted key, so they are held to the
// prefixes the picker actually matches on. This sits beside the validation
// it calls rather than in httpapi, which can no longer reach it.

import "testing"

// A live key is labelled from its own prefix or not at all. The catalog is
// where that promise is kept: an env prefix the entry does not otherwise
// recognise would label a key the picker never matched, and a prefix under
// both environments would make one key both at once.
func TestEnvironmentPrefixesAreReadableFromAKeyAlone(t *testing.T) {
	for _, e := range All() {
		if e.EnvPrefixes == nil {
			continue
		}
		if err := e.validateEnvPrefixes(); err != nil {
			t.Errorf("%s: %v", e.Name, err)
			continue
		}
		for _, p := range e.EnvPrefixes.Test {
			if got := e.Environment(p + "0123456789"); got != "test" {
				t.Errorf("%s: a key beginning %q read as %q, want test", e.Name, p, got)
			}
		}
		for _, p := range e.EnvPrefixes.Live {
			if got := e.Environment(p + "0123456789"); got != "live" {
				t.Errorf("%s: a key beginning %q read as %q, want live", e.Name, p, got)
			}
		}
		// Nothing is assumed for a key whose shape does not say.
		if got := e.Environment("0123456789abcdef"); got != "" {
			t.Errorf("%s: a key with no recognised prefix was labelled %q rather than left unlabelled",
				e.Name, got)
		}
	}
}
