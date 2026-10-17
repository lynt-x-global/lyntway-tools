package catalog

import (
	"errors"
	"fmt"
	"strings"
)

// What a payments entry is held to, checked when the catalog loads.
//
// It lives here rather than beside the forwarding rules because it is a
// statement about the data: a payments entry that does not say observe
// would have card numbers substituted on the way to a payment API, which
// turns a valid charge into a failed one and makes it look like the
// provider's fault. Catching that at load means a file that gets it wrong
// stops the build instead of shipping.

// PayloadPolicyObserve means detect and record, never substitute.
//
// The only value defined, and deliberately not a bool: a second reason to
// leave a payload alone will exist one day, and it should arrive as its own
// word rather than as "true" meaning two different things.
const PayloadPolicyObserve = "observe"

// VerticalPayments is the file, the field and the console group. One
// string, so a rule keyed on it cannot drift from the entries it selects.
const VerticalPayments = "payments"

// validatePayments holds a payments entry to the defaults that made the
// vertical admissible. Called from Entry.validate, so a file that
// gets this wrong stops the build rather than shipping.
//
// Refusing to start is the right severity. The failure mode this prevents
// is a payment entry whose card numbers get tokenised — a customer's
// charges failing in production, caused by us, with the receipt reading
// tokenize and therefore looking correct.
func (e Entry) validatePayments() error {
	switch e.PayloadPolicy {
	case "", PayloadPolicyObserve:
	default:
		return fmt.Errorf("payload_policy %q is not a value this service knows; the only one is %q",
			e.PayloadPolicy, PayloadPolicyObserve)
	}
	if e.Vertical == VerticalPayments && e.PayloadPolicy != PayloadPolicyObserve {
		return fmt.Errorf("a payments entry must set payload_policy %q: without it the shipped policy "+
			"substitutes card numbers on the way to a payment API, which turns a valid charge into a "+
			"failed one and makes it look like the provider's fault", PayloadPolicyObserve)
	}
	if e.PayloadPolicy == PayloadPolicyObserve && e.Vertical != VerticalPayments {
		return fmt.Errorf("payload_policy %q on a %s entry: leaving a payload untouched is a payments "+
			"decision, and applying it elsewhere would silently stop substituting for a provider "+
			"nobody agreed to make an exception for", PayloadPolicyObserve, e.Vertical)
	}
	return e.validateEnvPrefixes()
}

// validateEnvPrefixes checks the strings a pasted key's environment is read
// from.
//
// Every one of them must also be a key prefix, because the console offers
// the provider on a prefix match and then labels the key from these: a
// prefix listed here and not there would name an environment for a key the
// picker never recognised. And test and live must not overlap, or the same
// key would be both.
func (e Entry) validateEnvPrefixes() error {
	if e.EnvPrefixes == nil {
		return nil
	}
	known := map[string]bool{}
	for _, p := range e.KeyPrefixes {
		known[p] = true
	}
	seen := map[string]string{}
	for env, prefixes := range map[string][]string{"test": e.EnvPrefixes.Test, "live": e.EnvPrefixes.Live} {
		for _, p := range prefixes {
			if len(p) < 2 {
				return fmt.Errorf("env_prefixes.%s: %q is too short to identify anything", env, p)
			}
			if !known[p] {
				return fmt.Errorf("env_prefixes.%s: %q is not one of this entry's key_prefixes, so a key "+
					"carrying it would be labelled %s by an entry that never recognised the key", env, p, env)
			}
			if other, dup := seen[p]; dup {
				return fmt.Errorf("env_prefixes: %q is listed under both %s and %s, so a key carrying it "+
					"would be both environments at once", p, other, env)
			}
			seen[p] = env
		}
	}
	if len(seen) == 0 {
		return errors.New("env_prefixes is set with nothing in it; leave it out rather than promising " +
			"an environment nothing can be read from")
	}
	return nil
}

// Environment reads test or live off a pasted key's prefix, or returns
// empty.
//
// Empty is the ordinary answer and an honest one. Most providers do not
// encode the environment in the key at all, and a key whose prefix does not
// say is left unlabelled rather than assumed live — a wrong label here
// would be shown beside somebody's credential in the console, where it
// would be believed.
//
// Only the prefix is ever compared. The rest of the argument is a live
// credential and is not sliced, stored, logged or returned.
func (e Entry) Environment(key string) string {
	if e.EnvPrefixes == nil {
		return ""
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	// Longest match wins, for the same reason the provider lookup takes the
	// longest prefix: a provider could one day distinguish "sk_" from
	// "sk_test_", and the more specific string is the better answer.
	best, env := 0, ""
	for _, c := range []struct {
		name     string
		prefixes []string
	}{{"test", e.EnvPrefixes.Test}, {"live", e.EnvPrefixes.Live}} {
		for _, p := range c.prefixes {
			if len(p) > best && strings.HasPrefix(key, p) {
				best, env = len(p), c.name
			}
		}
	}
	return env
}
