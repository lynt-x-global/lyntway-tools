package catalog

import (
	"fmt"
	"strings"
)

// How a credential is presented, and what each way requires.
//
// This vocabulary describes the provider, not the route, which is why it
// sits beside the entries rather than beside the forwarder. A catalog
// entry and a customer's own upstream are described in the same five
// words, and they have to be: when the save path and the forwarder
// disagreed about the same credential, the result was an entry that
// stored cleanly and arrived at the provider in a shape it refused.

// The shapes a credential may take on the way to an upstream.
//
// A closed set, checked when an upstream is saved rather than when it is
// used. An unknown scheme reaching the forwarder would have to be guessed
// at, and a guess about where somebody's key goes is how a real credential
// ends up in the wrong place.
const (
	// AuthSchemeBearer is Authorization: Bearer <key>, the default.
	AuthSchemeBearer = "bearer"

	// AuthSchemeHeader puts the key verbatim in the named AuthHeader.
	AuthSchemeHeader = "header"

	// AuthSchemeBasic is Authorization: Basic base64(<user>:<key>).
	AuthSchemeBasic = "basic"

	// AuthSchemeRaw is Authorization: <key>, with no scheme word. Linear's
	// personal API keys are sent this way and reject a Bearer prefix.
	AuthSchemeRaw = "raw"

	// AuthSchemePrefix is Authorization: <AuthPrefix> <key> — a scheme
	// word that is not "Bearer". Added 7 September 2026, when filling the
	// catalog found more than twenty verified providers that differ from
	// bearer by one word: Gitea and Sourcegraph want "token", PagerDuty
	// "Token token=", Opsgenie "GenieKey", Klaviyo "Klaviyo-API-Key".
	//
	// They were reachable before this existed, by asking the customer to
	// paste "token ghp_xyz" into a field labelled API key and using raw.
	// That is a trap: paste the key alone, which is what the field asks
	// for, and the provider answers 401 as though the key were bad. The
	// word belongs to the provider, so the catalog carries it and the
	// customer pastes only their key.
	AuthSchemePrefix = "prefix"
)

// ValidAuthScheme normalises a scheme and refuses one we cannot honour.
//
// "header" without a header name is refused rather than quietly falling
// back to Bearer: somebody who chose that scheme believes their key is
// going somewhere specific, and sending it as a bearer token instead would
// put a live credential in a place the provider does not read while
// telling nobody.
func ValidAuthScheme(scheme, authHeader string) (string, error) {
	switch s := strings.ToLower(strings.TrimSpace(scheme)); s {
	case "":
		return "", nil
	case AuthSchemeBearer, AuthSchemeBasic, AuthSchemeRaw, AuthSchemePrefix:
		return s, nil
	case AuthSchemeHeader:
		if authHeader == "" {
			return "", fmt.Errorf("the header scheme needs auth_header set to the header name the provider reads")
		}
		return s, nil
	default:
		return "", fmt.Errorf("%q is not an auth scheme this service sends; use bearer, header, basic, raw or prefix", scheme)
	}
}

// ValidAuthPrefix checks the scheme word sent before the key.
//
// It becomes part of the Authorization header verbatim, so it is held to
// what RFC 9110 allows in a field value: visible ASCII and the space, and
// nothing else. Carriage return and line feed are what end a header and
// begin another, so they are the injection this refuses — a value like
// "token\r\nX-Admin: 1" would otherwise arrive at the provider as two
// headers.
//
// A space is deliberately allowed, though the first version of this
// refused one. PagerDuty documents "Authorization: Token token=<key>",
// which contains a space, so banning it meant the save path rejected an
// entry the forwarder placed correctly — the two disagreeing about the
// same credential, which is the bug this file has had before. Leading and
// trailing spaces are still refused: they are always a typo, and they
// change the bytes the provider compares against.
func ValidAuthPrefix(prefix, scheme string) (string, error) {
	if prefix == "" {
		if scheme == AuthSchemePrefix {
			return "", fmt.Errorf("the prefix scheme needs auth_prefix set to the word the provider expects before the key")
		}
		return "", nil
	}
	if scheme != AuthSchemePrefix {
		return "", fmt.Errorf("auth_prefix is only sent with the prefix scheme; set auth_scheme to prefix or leave the prefix out")
	}
	if len(prefix) > 40 {
		return "", fmt.Errorf("the auth prefix must be at most 40 characters")
	}
	if strings.TrimSpace(prefix) != prefix {
		return "", fmt.Errorf("the auth prefix must not begin or end with a space; the space before the key is added when the request is built")
	}
	for _, r := range prefix {
		if r < 0x20 || r > 0x7e {
			return "", fmt.Errorf("the auth prefix must be visible ASCII, because it is sent verbatim in the Authorization header and a control character there would start a second one")
		}
	}
	return prefix, nil
}

// ValidAuthUser checks the username half of basic authentication.
//
// A colon is refused because it is the separator inside the credential:
// "user:extra" and the key would encode as a username "user" and a
// password "extra:<key>", which authenticates as somebody else or as
// nobody. Only meaningful for basic, so anything else must leave it empty
// rather than store a value that is silently never sent.
func ValidAuthUser(user, scheme string) (string, error) {
	if user == "" {
		return "", nil
	}
	if scheme != AuthSchemeBasic {
		return "", fmt.Errorf("auth_user is only sent with the basic scheme; set auth_scheme to basic or leave the user out")
	}
	if len(user) > 200 {
		return "", fmt.Errorf("the auth user must be at most 200 characters")
	}
	for _, r := range user {
		if r < 0x21 || r > 0x7e || r == ':' {
			return "", fmt.Errorf("the auth user must be printable ASCII without a colon")
		}
	}
	return user, nil
}

// ValidAuthHeader checks that a customer-supplied header name is one we
// are willing to set. An unrestricted header name would let a stored
// upstream override Host, Content-Type, or any other header that changes
// what the request means rather than who is sending it.
//
// The allowlist covers headers that carry an API key and nothing else.
// Each is a credential the provider expects in a specific place — adding
// one here is safe as long as no entry can change what the request means
// (routing, encoding, body interpretation) rather than who is sending it.
func ValidAuthHeader(h string) (string, error) {
	if h == "" {
		return "", nil
	}
	lower := strings.ToLower(h)
	switch lower {
	case "x-api-key",
		"x-goog-api-key",
		"api-key",
		// Supabase reads a project key from this, and says in its own
		// documentation that sending it as a bearer token fails: the key
		// is not a JWT and the check rejects it. Without the header there
		// is no way to reach a Supabase project at all.
		"apikey",
		"x-portkey-api-key",
		// Named here because they carry a credential and match no
		// pattern: Postmark's two tokens are the only way to
		// authenticate to it, and neither name ends in -api-key.
		"x-postmark-server-token",
		"x-postmark-account-token",

		// Added 7 September 2026, when the catalog went from 16 entries
		// to several hundred and these were the only thing standing
		// between a verified provider and a customer being able to use
		// it. Every one was read off the vendor's own authentication
		// page and confirmed by sending an invalid key to the real
		// address and getting 401 or 403 back.
		//
		// Each carries a credential and nothing else. None can change
		// where a request goes, how it is encoded, or how its body is
		// read — that is the line this list draws, and a header that
		// crossed it would not belong here however much a provider
		// wanted it. Checkly's X-Checkly-Account was refused on exactly
		// that ground: it selects an account, so it is routing.
		"access-token",           // Pushbullet
		"accesskey",              // Bunny.net
		"anchor-api-key",         // Anchor Browser
		"api_access_token",       // Chatwoot
		"api_token",              // Document360
		"clay-api-key",           // Clay
		"d360-api-key",           // 360dialog
		"dd-api-key",             // Datadog
		"statsig-api-key",        // Statsig
		"steel-api-key",          // Steel
		"x-access-token",         // Dropcontact
		"x-api-token",            // Pipedrive, Mixmax, Scrapeless, Logz.io
		"x-chroma-token",         // Chroma Cloud
		"x-ed-api-token",         // Edge Delta
		"x-figma-token",          // Figma
		"x-honeycomb-team",       // Honeycomb
		"x-richpanel-key",        // Richpanel
		"x-rollbar-access-token", // Rollbar
		"x-subscription-token",   // Brave Search
		"x-tgp-access-token",     // Textline
		"shortcut-token",         // Shortcut
		"x-smarttoken",           // SmartRecruiters
		"x-auth-token",           // BigCommerce; Productsup uses the same name for a
		// client_id:client_secret pair, which is a different credential
		// shape and not one this list makes reachable.
		"x-shopify-access-token", // Shopify Admin
		"xc-token":               // NocoDB
		return lower, nil
	default:
		// Allow any header that looks like a platform-specific API key
		// header, since those carry credentials and nothing else. The
		// x- prefix stopped being required on 7 September 2026: Clay,
		// Steel, Anchor and Statsig all name their header
		// <product>-api-key with no prefix, and listing each by hand
		// taught the list nothing it did not already know.
		if strings.HasSuffix(lower, "-api-key") {
			return lower, nil
		}
		return "", fmt.Errorf("%q is not an auth header this service will set; use x-api-key, x-goog-api-key, api-key, or <provider>-api-key", h)
	}
}

// ValidUpstreamName keeps the path segment predictable.
func ValidUpstreamName(name string) error {
	if name == "" {
		return fmt.Errorf("a name is required: it is what appears in the URL, /gw/<name>")
	}
	if len(name) > 40 {
		return fmt.Errorf("the name must be at most 40 characters")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return fmt.Errorf("the name may contain lowercase letters, digits, hyphen and underscore; %q is not allowed", r)
		}
	}
	return nil
}
