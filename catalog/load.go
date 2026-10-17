package catalog

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// The catalog as data, and the check that keeps it honest.
//
// # Why it left the Go file
//
// Sixteen entries fit in a slice of struct literals. A thousand do not,
// and the ones being written now are being written by people — and
// sessions — who are not touching anything else in this package. A JSON
// file per vertical means two of them can be filled at once without
// meeting in a merge, and it means the thing a reviewer reads is the
// entry rather than Go syntax around the entry.
//
// # Why it is validated rather than trusted
//
// The file is embedded, so a bad entry ships. And an entry is the address
// a live customer credential is sent to: getting one wrong is a credential
// leak we caused. So every field is checked when the package loads, and a
// catalog that fails refuses to start rather than serving a picker that
// sends somebody's Mailgun key to a host nobody verified.
//
// Refusing to start is the right severity because the failure is
// impossible in production and certain in development: the files are
// compiled in, so the first test run after a bad edit fails, and nothing
// bad can reach a customer through this path.

//go:embed data/*.json
var catalogFiles embed.FS

// catalog is the verified set, in no particular order; Catalog sorts.
var catalog = mustLoadCatalog()

// mustLoadCatalog reads the embedded files or stops the program.
func mustLoadCatalog() []Entry {
	sub, err := fs.Sub(catalogFiles, "data")
	if err != nil {
		panic("catalog: the embedded catalog directory is missing: " + err.Error())
	}
	entries, err := LoadCatalog(sub)
	if err != nil {
		panic("catalog: the provider catalog is not usable, so this build must not run:\n" + err.Error())
	}
	return entries
}

// LoadCatalog reads and validates every *.json file at the root of fsys.
//
// Exported because lyntway-catalog checks a working tree with it, before
// the files are embedded and before a build exists. One implementation, so
// what the tool passes is exactly what the server will accept — the last
// time a rule lived in two places, the second copy was found wrong months
// later.
func LoadCatalog(fsys fs.FS) ([]Entry, error) {
	names, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, errors.New("no catalog files: the console would offer nothing and every key would fall through to the address form")
	}
	sort.Strings(names)

	var problems []error
	var all []Entry
	// Where each name was first seen, so a duplicate names both files
	// rather than only the second.
	seen := map[string]string{}

	for _, name := range names {
		vertical := strings.TrimSuffix(path.Base(name), ".json")
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", name, err))
			continue
		}
		var file []Entry
		dec := json.NewDecoder(bytes.NewReader(raw))
		// A misspelt field would otherwise be dropped in silence, and the
		// entry would load with no probe path or no key prefixes while
		// looking complete in the file somebody is reading.
		dec.DisallowUnknownFields()
		if err := dec.Decode(&file); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", name, err))
			continue
		}
		for i, e := range file {
			where := fmt.Sprintf("%s[%d]", name, i)
			if e.Name != "" {
				where = fmt.Sprintf("%s (%s)", e.Name, name)
			}
			if err := e.validate(vertical); err != nil {
				problems = append(problems, fmt.Errorf("%s: %w", where, err))
				continue
			}
			if first, dup := seen[e.Name]; dup {
				problems = append(problems, fmt.Errorf("%s: %q is already in %s; two entries with one name means "+
					"whichever loads second is unreachable and a key stored for it goes to the other's address",
					where, e.Name, first))
				continue
			}
			seen[e.Name] = name
			all = append(all, e)
		}
	}
	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}
	return all, nil
}

// validate checks one entry against everything that can be checked without
// contacting the provider. The probe checks the rest.
func (e Entry) validate(vertical string) error {
	if err := ValidUpstreamName(e.Name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	if e.Label == "" {
		return errors.New("label is missing: it is what the console shows in the picker")
	}
	if e.Note == "" {
		return errors.New("note is missing: it is the sentence somebody reads before handing us a live credential")
	}
	if !strings.HasPrefix(e.Doc, "https://") {
		return fmt.Errorf("doc %q is not a page anybody can check; every entry is read off the provider's own "+
			"authentication documentation and the URL is the evidence", e.Doc)
	}
	if e.Vertical != vertical {
		return fmt.Errorf("vertical is %q in a file named %s.json; the file and the field name the same group "+
			"or the console's grouping disagrees with the listing", e.Vertical, vertical)
	}
	// Two surfaces, and which one an entry may claim is decided by the file
	// it is in rather than by the entry itself.
	//
	// The surface is copied onto every receipt the upstream produces, so it
	// is a claim about what we watched: "mcp" says a tool call crossed us
	// and was read as JSON-RPC, which is the path in gateway.go that governs
	// result.content[].text instead of a model's deltas. An ordinary REST
	// entry that said "mcp" would produce receipts describing tool calls
	// that never happened, and would be relayed by the MCP path, which reads
	// bodies it will not understand.
	//
	// Tying it to the vertical means a person filling email.json cannot
	// reach the MCP surface at all, however the entry is written, and the
	// one file where it is reachable is the one whose entries were each read
	// off a vendor's own remote-MCP page.
	switch {
	case vertical == "mcp" && e.Surface != receipt.SurfaceMCP:
		return fmt.Errorf("surface is %q in mcp.json; an entry here is a vendor's own remote MCP endpoint and "+
			"the receipt has to say so, or a tool call is recorded as an ordinary HTTP request", e.Surface)
	case vertical != "mcp" && e.Surface != receipt.SurfaceHTTP:
		return fmt.Errorf("surface is %q; a catalog entry is an ordinary HTTP API and the receipt has to say so, "+
			"not call it a model call. The MCP surface is reachable from catalog/mcp.json alone", e.Surface)
	}

	// The payments vertical carries defaults nothing else does, and an
	// entry that misses one substitutes card numbers on the way to a
	// payment API. Checked here so a bad entry stops the build.
	if err := e.validatePayments(); err != nil {
		return err
	}
	if err := e.validateAddress(); err != nil {
		return err
	}
	if err := e.validateProbePath(); err != nil {
		return err
	}
	if err := e.validatePrefixes(); err != nil {
		return err
	}

	// The same closed set every customer-supplied upstream is held to. A
	// scheme this service cannot place would become a stored row whose key
	// goes out in a shape nobody chose.
	header, err := ValidAuthHeader(strings.TrimSpace(e.AuthHeader))
	if err != nil {
		// Named explicitly because the fix is not in this file. The
		// allowlist is a security control — an unrestricted header name
		// would let a stored upstream set Host or Content-Type and
		// change what a request means — so a provider with a credential
		// header nobody has seen before needs a reviewed line in
		// validAuthHeader, not a way round it here.
		return fmt.Errorf("auth_header: %w. Adding one is a change to validAuthHeader in "+
			"tenantupstreams.go, and only for a header that carries a credential and nothing else", err)
	}
	scheme, err := ValidAuthScheme(e.AuthScheme, header)
	if err != nil {
		return fmt.Errorf("auth_scheme: %w", err)
	}
	if scheme == "" {
		return errors.New("auth_scheme is missing: an entry says where a credential goes, and an empty scheme " +
			"means the forwarder decides, which is the guess this catalog exists to remove")
	}
	if _, err := ValidAuthUser(strings.TrimSpace(e.AuthUser), scheme); err != nil {
		return fmt.Errorf("auth_user: %w", err)
	}
	if _, err := ValidAuthPrefix(strings.TrimSpace(e.AuthPrefix), scheme); err != nil {
		return fmt.Errorf("auth_prefix: %w", err)
	}
	if err := e.validateAuthUserField(scheme); err != nil {
		return err
	}
	return nil
}

// validateAuthUserField checks the second value a customer supplies for
// providers whose basic-auth username is the customer's own identifier.
//
// Added 7 September 2026. Filling the catalog found that the largest
// group of providers we could not reach was not exotic — it was Twilio,
// Algolia, Mixpanel, Etsy and about a hundred others where the credential
// is a key plus an account identifier. "Paste one key" cannot reach them,
// but the missing half is usually not a second secret: it is an id that
// appears in the provider's own dashboard and URLs.
//
// Both auth_user and auth_user_field would be two answers to one
// question, and nothing would say which the forwarder should send.
func (e Entry) validateAuthUserField(scheme string) error {
	if e.AuthUserField == "" {
		if e.AuthUserHint != "" {
			return errors.New("auth_user_hint with no auth_user_field: the console would have a hint for a " +
				"question it never asks")
		}
		return nil
	}
	if e.AuthUser != "" {
		return errors.New("auth_user and auth_user_field are both set: one says the provider fixes the username " +
			"and the other says the customer supplies it, and nothing decides which is sent")
	}
	if scheme != AuthSchemeBasic {
		return fmt.Errorf("auth_user_field needs auth_scheme basic; %q has no username half for it to fill", scheme)
	}
	if !validTemplateFieldName(e.AuthUserField) {
		return fmt.Errorf("auth_user_field %q may contain lowercase letters, digits and underscore only", e.AuthUserField)
	}
	if e.AuthUserField == e.TemplateField {
		return fmt.Errorf("auth_user_field and template_field are both %q, so one value would have to be both a "+
			"hostname label and a credential and would be checked as neither", e.AuthUserField)
	}
	return nil
}

// validateAddress checks the fixed URL or the template that stands in for
// one. Exactly one of them, because an entry with both would have a
// resolved address and an unresolved one and nothing says which wins.
func (e Entry) validateAddress() error {
	switch {
	case e.URL == "" && e.URLTemplate == "":
		return errors.New("neither url nor url_template is set, so there is no address to send a key to")
	case e.URL != "" && e.URLTemplate != "":
		return errors.New("url and url_template are both set; one entry has one address")
	case e.URLTemplate != "":
		if e.TemplateField == "" {
			return errors.New("url_template with no template_field: the console would have nothing to ask for " +
				"and the address could never be completed")
		}
		if !validTemplateFieldName(e.TemplateField) {
			return fmt.Errorf("template_field %q may contain lowercase letters, digits and underscore only", e.TemplateField)
		}
		placeholder := "{" + e.TemplateField + "}"
		if !strings.Contains(e.URLTemplate, placeholder) {
			return fmt.Errorf("url_template %q does not contain %s, so the value the customer types would be discarded",
				e.URLTemplate, placeholder)
		}
		// Resolved with a value that is legal by the strictest reading, so
		// a template whose shape cannot produce a usable address fails
		// here rather than the first time a customer fills it in.
		example := map[string]string{e.TemplateField: "example"}
		if e.AuthUserField != "" {
			// Resolve refuses a missing field, so an entry that asks for
			// both must be offered both here or a legal entry would fail
			// validation for a reason that has nothing to do with its
			// address.
			example[e.AuthUserField] = "example"
		}
		filled, err := e.Resolve(example)
		if err != nil {
			return fmt.Errorf("url_template: %w", err)
		}
		return checkCatalogURL(filled.URL)
	default:
		return checkCatalogURL(e.URL)
	}
}

// checkCatalogURL holds an address to the rules a customer's own address is
// held to, minus the DNS lookup: this runs at start and in CI, where a
// resolver may not be there and a provider being briefly unresolvable must
// not stop the server.
//
// It used to borrow httpapi's own route parser, which it can no longer
// reach — this package is mirrored into the public repository and anything
// that reached httpapi would take the private half with it. The rules it
// needs are the ones about the address itself and they are written out
// here. The stronger claim, that every entry also parses as a route the
// forwarder will accept, is asserted on the other side of the seam by
// TestEveryCatalogEntryIsAUsableUpstream in httpapi, over every entry. If
// the two ever drift, that test is what says so.
func checkCatalogURL(raw string) error {
	if strings.HasSuffix(raw, "/") {
		// The path is joined onto this, and a trailing slash turns
		// /v3/domains into //v3/domains at providers that route strictly.
		return fmt.Errorf("url %q ends in a slash; write the root without one", raw)
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("url %q is not a URL: %w", raw, err)
	}
	// Plaintext would put the content this product exists to protect on
	// the wire in the clear.
	if parsed.Scheme != "https" {
		return fmt.Errorf("url %q must start with https://, not %q", raw, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("url %q has no host", raw)
	}
	if parsed.User != nil {
		// Credentials in a URL end up in logs, in receipts, and in the
		// console's own display of the upstream.
		return fmt.Errorf("url %q must not contain a username or password", raw)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("url %q carries a query or fragment; the entry is the root the path is joined onto", raw)
	}
	return nil
}

// validateProbePath refuses anything that could change something at the
// provider.
//
// The probe runs weekly against every entry, which will be a thousand
// third-party APIs. A path that writes would make this repository a
// nuisance at best; at worst it would delete something in an account
// belonging to whoever's key last touched it.
func (e Entry) validateProbePath() error {
	if e.ProbePath == "" {
		return errors.New("probe_path is missing: without one the entry can never be checked against the " +
			"provider, and an unchecked address is the whole risk this catalog carries")
	}
	if !strings.HasPrefix(e.ProbePath, "/") {
		return fmt.Errorf("probe_path %q must start with /", e.ProbePath)
	}
	ref, err := url.Parse(e.ProbePath)
	if err != nil {
		return fmt.Errorf("probe_path %q is not a path: %w", e.ProbePath, err)
	}
	if ref.Scheme != "" || ref.Host != "" {
		return fmt.Errorf("probe_path %q names a host; it is a path under the entry's own url, so the probe "+
			"cannot be pointed somewhere the entry does not say", e.ProbePath)
	}
	if ref.Fragment != "" {
		return fmt.Errorf("probe_path %q has a fragment, which is never sent and so cannot be part of it", e.ProbePath)
	}
	if strings.Contains(e.ProbePath, "..") {
		return fmt.Errorf("probe_path %q climbs out of the entry's address", e.ProbePath)
	}
	// A word list, not a proof. It catches the entry written in a hurry
	// against the provider's most convenient endpoint, which is the way
	// a write gets in here; a deliberate one gets past it and gets past a
	// reviewer too, so the reviewer is the real check.
	lower := strings.ToLower(ref.Path)
	for _, verb := range []string{
		"send", "create", "delete", "remove", "update", "revoke", "purge", "destroy",
		"cancel", "refund", "disable", "enable", "invite", "publish", "upload", "import",
		"post", "write", "reset", "archive", "restore", "close", "merge", "deploy",
	} {
		for _, seg := range strings.Split(lower, "/") {
			if seg == verb || strings.HasPrefix(seg, verb+"-") || strings.HasPrefix(seg, verb+"_") {
				return fmt.Errorf("probe_path %q contains %q; the probe must not be able to change anything at "+
					"a provider, so pick a path that only reads", e.ProbePath, verb)
			}
		}
	}
	return nil
}

// validatePrefixes checks the strings a pasted key is matched against.
//
// Only the prefix is ever compared, so a prefix that is too short matches
// keys belonging to somebody else and the console would offer the wrong
// provider for a live credential. Two characters is the shortest any real
// provider uses ("SG." is three; Resend's "re_" is three).
func (e Entry) validatePrefixes() error {
	seen := map[string]bool{}
	for _, p := range e.KeyPrefixes {
		if len(p) < 2 {
			return fmt.Errorf("key prefix %q is too short to identify anything; leave it out rather than "+
				"offering the wrong provider for somebody's key", p)
		}
		if strings.TrimSpace(p) != p || strings.ContainsAny(p, " \t\n") {
			return fmt.Errorf("key prefix %q has whitespace in it", p)
		}
		if seen[p] {
			return fmt.Errorf("key prefix %q is listed twice", p)
		}
		seen[p] = true
	}
	return nil
}

// validTemplateFieldName is the shape a placeholder's name may take. It
// reaches the console as a form field name and the API as a JSON key, so
// it is held to what is safe in both.
func validTemplateFieldName(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}

// Resolve fills in every value the customer has to supply — the one word
// in a templated address, and the username half of a credential where the
// provider's username is the customer's own identifier — and returns an
// entry that names a real host and a complete credential.
//
// Two kinds of value, held to two different rules, and the difference is
// the point.
//
// # The address field is the SSRF boundary
//
// It becomes part of a hostname. Everything the rest of this package does
// to keep a customer from pointing us at the metadata endpoint happens
// after an address exists, so a value carrying a dot, a slash, an at-sign
// or a colon would compose an address those checks never see in the form
// the customer intended. So it is held to [a-z0-9-], what a DNS label may
// contain and nothing else, and the resolved address then takes exactly
// the path a typed one takes.
//
// # The username field is not
//
// It never reaches a hostname; it is base64'd into an Authorization
// header beside the key. Holding it to DNS rules would reject most real
// values — Twilio Account SIDs are mixed case, Algolia Application IDs
// are uppercase — so it takes validAuthUser's rules instead, which refuse
// the colon that would otherwise split the credential and re-aim it at a
// different account.
func (e Entry) Resolve(values map[string]string) (Entry, error) {
	out := e
	wanted := map[string]bool{}
	if e.URLTemplate != "" {
		wanted[e.TemplateField] = true
	}
	if e.AuthUserField != "" {
		wanted[e.AuthUserField] = true
	}
	// Named before anything is filled in, because a value under a name
	// this entry does not have is somebody expecting it to be used. A
	// silently discarded field is how a person ends up certain their key
	// goes to one account when it goes to another.
	for k := range values {
		if !wanted[k] {
			if len(wanted) == 0 {
				return Entry{}, fmt.Errorf("%s needs no %s: its address and credential are complete", e.Name, k)
			}
			return Entry{}, fmt.Errorf("%s has no %s to fill in", e.Name, k)
		}
	}

	if e.URLTemplate != "" {
		value := strings.TrimSpace(values[e.TemplateField])
		if value == "" {
			hint := e.TemplateHint
			if hint == "" {
				hint = "the value that appears in your own " + e.Label + " address"
			}
			return Entry{}, fmt.Errorf("%s needs %s: %s", e.Name, e.TemplateField, hint)
		}
		if err := validTemplateValue(e.TemplateField, value); err != nil {
			return Entry{}, err
		}
		out.URL = strings.ReplaceAll(e.URLTemplate, "{"+e.TemplateField+"}", value)
		out.URLTemplate = ""
	}

	if e.AuthUserField != "" {
		value := strings.TrimSpace(values[e.AuthUserField])
		if value == "" {
			hint := e.AuthUserHint
			if hint == "" {
				hint = "the identifier " + e.Label + " pairs with your key"
			}
			return Entry{}, fmt.Errorf("%s needs %s: %s", e.Name, e.AuthUserField, hint)
		}
		if _, err := ValidAuthUser(value, AuthSchemeBasic); err != nil {
			return Entry{}, fmt.Errorf("%s: %w", e.AuthUserField, err)
		}
		out.AuthUser = value
		out.AuthUserField = ""
	}
	return out, nil
}

// validTemplateValue holds a customer's word to what a DNS label may hold.
//
// Lowercase only, because a hostname is case-insensitive and accepting
// "Acme" would store an address that differs from the one the console
// displays. Leading and trailing hyphens are refused because they are not
// legal in a label and would produce an address that never resolves.
func validTemplateValue(field, value string) error {
	if len(value) > 63 {
		return fmt.Errorf("%s must be at most 63 characters: it is one label of a hostname", field)
	}
	if strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
		return fmt.Errorf("%s must not start or end with a hyphen", field)
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return fmt.Errorf("%s may contain lowercase letters, digits and hyphens only; %q is not allowed. "+
				"It becomes part of the address we send your key to, so nothing else is accepted", field, r)
		}
	}
	return nil
}

// ProviderForKey returns the entries whose key prefixes the pasted key
// carries, longest prefix first.
//
// # Why the prefix and nothing else
//
// The argument is a live credential. It is compared against a handful of
// fixed strings and is never logged, never echoed, never stored and never
// returned; the caller gets entries back, not anything derived from the
// key. Longest first because "pat-" is a HubSpot token and "pat" would be
// an Airtable one, and the more specific match is the better guess.
//
// Several matches is a real answer, not a failure to resolve: the caller
// asks rather than picking, because picking wrong sends the key to the
// wrong provider.
func ProviderForKey(key string) []Entry {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	type match struct {
		entry Entry
		width int
	}
	var found []match
	for _, e := range catalog {
		best := 0
		for _, p := range e.KeyPrefixes {
			if len(p) > best && strings.HasPrefix(key, p) {
				best = len(p)
			}
		}
		if best > 0 {
			found = append(found, match{e, best})
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].width != found[j].width {
			return found[i].width > found[j].width
		}
		return found[i].entry.Label < found[j].entry.Label
	})
	out := make([]Entry, 0, len(found))
	for _, m := range found {
		out = append(out, m.entry)
	}
	return out
}
