package catalog

import (
	"strings"
	"testing"
	"testing/fstest"
)

// A malformed catalog must never load. Every case here is an entry that
// would otherwise become a stored row pointing a live customer credential
// somewhere nobody verified, or a route that can never be called.
func TestAnUnusableEntryStopsTheWholeCatalogLoading(t *testing.T) {
	// The entry every case starts from: valid, so a failure below is
	// caused by the one field the case changes and nothing else.
	const good = `{"name":"acme","label":"Acme","vertical":"email","url":"https://api.acme.com",
		"surface":"http","auth_scheme":"bearer","probe_path":"/v1/me",
		"doc":"https://acme.example/docs","note":"Acme's API."}`

	cases := []struct {
		name string
		file string
		want string
	}{
		{"an address we cannot send to", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"http://api.acme.com","surface":"http","auth_scheme":"bearer","probe_path":"/v1/me",
			"doc":"https://acme.example/docs","note":"n"}]`, "https"},
		{"no address at all", `[{"name":"acme","label":"Acme","vertical":"email",
			"surface":"http","auth_scheme":"bearer","probe_path":"/v1/me",
			"doc":"https://acme.example/docs","note":"n"}]`, "neither url nor url_template"},
		{"a template with nothing to ask for", `[{"name":"acme","label":"Acme","vertical":"email",
			"url_template":"https://{sub}.acme.com","surface":"http","auth_scheme":"bearer","probe_path":"/v1/me",
			"doc":"https://acme.example/docs","note":"n"}]`, "template_field"},
		{"a template whose field is never substituted", `[{"name":"acme","label":"Acme","vertical":"email",
			"url_template":"https://acme.com","template_field":"sub","surface":"http","auth_scheme":"bearer",
			"probe_path":"/v1/me","doc":"https://acme.example/docs","note":"n"}]`, "does not contain {sub}"},
		{"a probe path that writes", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"https://api.acme.com","surface":"http","auth_scheme":"bearer","probe_path":"/v3/messages/send",
			"doc":"https://acme.example/docs","note":"n"}]`, "must not be able to change anything"},
		{"no probe path", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"https://api.acme.com","surface":"http","auth_scheme":"bearer",
			"doc":"https://acme.example/docs","note":"n"}]`, "probe_path is missing"},
		{"a probe path naming another host", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"https://api.acme.com","surface":"http","auth_scheme":"bearer",
			"probe_path":"https://evil.example/v1","doc":"https://acme.example/docs","note":"n"}]`, "must start with /"},
		{"a scheme we cannot place", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"https://api.acme.com","surface":"http","auth_scheme":"magic","probe_path":"/v1/me",
			"doc":"https://acme.example/docs","note":"n"}]`, "auth_scheme"},
		{"no scheme at all", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"https://api.acme.com","surface":"http","probe_path":"/v1/me",
			"doc":"https://acme.example/docs","note":"n"}]`, "auth_scheme is missing"},
		{"a header the allowlist refuses", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"https://api.acme.com","surface":"http","auth_scheme":"header","auth_header":"host",
			"probe_path":"/v1/me","doc":"https://acme.example/docs","note":"n"}]`, "validAuthHeader"},
		{"a surface that is not http", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"https://api.acme.com","surface":"model","auth_scheme":"bearer","probe_path":"/v1/me",
			"doc":"https://acme.example/docs","note":"n"}]`, "surface"},
		{"a vertical that disagrees with its file", `[{"name":"acme","label":"Acme","vertical":"crm",
			"url":"https://api.acme.com","surface":"http","auth_scheme":"bearer","probe_path":"/v1/me",
			"doc":"https://acme.example/docs","note":"n"}]`, "vertical is"},
		{"no evidence anybody can check", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"https://api.acme.com","surface":"http","auth_scheme":"bearer","probe_path":"/v1/me",
			"doc":"","note":"n"}]`, "doc"},
		{"a key prefix too short to identify anything", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"https://api.acme.com","surface":"http","auth_scheme":"bearer","probe_path":"/v1/me",
			"key_prefixes":["a"],"doc":"https://acme.example/docs","note":"n"}]`, "too short"},
		{"a field nobody reads", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"https://api.acme.com","surface":"http","auth_scheme":"bearer","probe_path":"/v1/me",
			"probepath":"/v1/me","doc":"https://acme.example/docs","note":"n"}]`, "unknown field"},
		{"an address that ends in a slash", `[{"name":"acme","label":"Acme","vertical":"email",
			"url":"https://api.acme.com/","surface":"http","auth_scheme":"bearer","probe_path":"/v1/me",
			"doc":"https://acme.example/docs","note":"n"}]`, "ends in a slash"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadCatalog(fstest.MapFS{"email.json": &fstest.MapFile{Data: []byte(c.file)}})
			if err == nil {
				t.Fatalf("this loaded, so it would ship: %s", c.file)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal does not say %q, so nobody could fix it: %v", c.want, err)
			}
			if !strings.Contains(err.Error(), "email.json") {
				t.Errorf("the refusal does not name the file: %v", err)
			}
		})
	}

	// And the entry the cases are derived from does load, so every failure
	// above is the change and not the baseline.
	if _, err := LoadCatalog(fstest.MapFS{
		"email.json": &fstest.MapFile{Data: []byte("[" + good + "]")},
	}); err != nil {
		t.Fatalf("the baseline entry does not load, so the cases above prove nothing: %v", err)
	}
}

// Two entries with one name means whichever loads second is unreachable,
// and a key stored for it goes to the other one's address.
func TestADuplicateNameAcrossFilesIsRefusedAndNamesBothFiles(t *testing.T) {
	entry := func(vertical string) string {
		return `[{"name":"acme","label":"Acme","vertical":"` + vertical + `","url":"https://api.acme.com",
			"surface":"http","auth_scheme":"bearer","probe_path":"/v1/me",
			"doc":"https://acme.example/docs","note":"n"}]`
	}
	_, err := LoadCatalog(fstest.MapFS{
		"crm.json":   &fstest.MapFile{Data: []byte(entry("crm"))},
		"email.json": &fstest.MapFile{Data: []byte(entry("email"))},
	})
	if err == nil {
		t.Fatal("two entries named acme loaded")
	}
	if !strings.Contains(err.Error(), "crm.json") || !strings.Contains(err.Error(), "email.json") {
		t.Errorf("the refusal has to name both files, or the second author cannot find the first: %v", err)
	}
}

// An empty directory would serve a picker with nothing in it and send
// every customer to the address form, which is the failure the catalog
// exists to remove — silently.
func TestAnEmptyCatalogDirectoryIsRefused(t *testing.T) {
	if _, err := LoadCatalog(fstest.MapFS{}); err == nil {
		t.Error("no catalog files loaded as a valid empty catalog")
	}
}

// --- The value that becomes a hostname ---------------------------------------

// The SSRF boundary. Everything else in this package that keeps a customer
// from pointing us at the metadata endpoint runs on an address that
// already exists; this runs on the word before there is one.
func TestATemplateValueIsHeldToWhatADNSLabelMayContain(t *testing.T) {
	entry := Entry{
		Name: "zed", Label: "Zed", TemplateField: "subdomain",
		URLTemplate: "https://{subdomain}.zed.example/api/v2",
	}

	refused := []struct {
		value string
		why   string
	}{
		{"acme.evil.example", "a dot moves the address to another domain entirely"},
		{"acme/../..", "a slash escapes the host into the path"},
		{"acme:8080", "a colon changes the port"},
		{"user@evil.example", "an at-sign makes the whole host a userinfo section"},
		{"ACME", "an uppercase label stores an address that differs from the one displayed"},
		{"169.254.169.254", "a dot again, this time at the metadata endpoint"},
		{"acme%2eevil", "a percent escape is not a label"},
		{"-acme", "a leading hyphen is not legal in a label"},
		{"acme-", "a trailing hyphen is not legal in a label"},
		{"", "nothing at all"},
		{"acme evil", "a space"},
		{strings.Repeat("a", 64), "longer than a label may be"},
	}
	for _, c := range refused {
		if _, err := entry.Resolve(map[string]string{"subdomain": c.value}); err == nil {
			t.Errorf("%q was accepted into a hostname: %s", c.value, c.why)
		}
	}

	got, err := entry.Resolve(map[string]string{"subdomain": "acme-corp2"})
	if err != nil {
		t.Fatalf("an ordinary label was refused: %v", err)
	}
	if got.URL != "https://acme-corp2.zed.example/api/v2" {
		t.Errorf("resolved to %q", got.URL)
	}
	if got.URLTemplate != "" {
		t.Error("the resolved entry still carries a template, so it would be resolved twice")
	}

	// A value for a field the entry does not have would be silently
	// dropped, and the person would believe they had set something.
	if _, err := entry.Resolve(map[string]string{"region": "eu"}); err == nil {
		t.Error("a value for an unknown field was accepted")
	}
	// And a fixed-address entry must refuse one rather than ignore it.
	fixed := Entry{Name: "acme", URL: "https://api.acme.com"}
	if _, err := fixed.Resolve(map[string]string{"subdomain": "acme"}); err == nil {
		t.Error("a template value was accepted for an entry whose address is fixed")
	}
}

// --- Recognising a key by its shape ------------------------------------------

func TestProviderForKeyMatchesOnThePrefixAndNothingElse(t *testing.T) {
	if got := ProviderForKey("re_0123456789abcdef"); len(got) != 1 || got[0].Name != "resend" {
		t.Errorf("a Resend key resolved to %v", names(got))
	}
	if got := ProviderForKey("nothing-in-particular"); len(got) != 0 {
		t.Errorf("an unrecognisable key claimed %v", names(got))
	}
	if got := ProviderForKey(""); len(got) != 0 {
		t.Errorf("an empty string matched %v", names(got))
	}
	// Longest first: an entry claiming "pat-" is a better answer than one
	// claiming "pat" for a key that begins pat-.
	long := Entry{Name: "long", KeyPrefixes: []string{"pat-na1-"}}
	short := Entry{Name: "short", KeyPrefixes: []string{"pat-"}}
	restore := catalog
	catalog = []Entry{short, long}
	defer func() { catalog = restore }()
	got := ProviderForKey("pat-na1-000")
	if len(got) != 2 || got[0].Name != "long" {
		t.Errorf("longest prefix did not come first: %v", names(got))
	}
}

func names(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return out
}

// --- Through the API, on the real handlers -----------------------------------

func TestResolveFillsTheCustomersIdentifierAndRefusesOneThatSplitsTheCredential(t *testing.T) {
	entry := Entry{
		Name: "twilio", Label: "Twilio", URL: "https://api.twilio.com",
		AuthScheme: AuthSchemeBasic, AuthUserField: "account_sid",
		AuthUserHint: "your Account SID",
	}

	got, err := entry.Resolve(map[string]string{"account_sid": "AC0123456789abcdef"})
	if err != nil {
		t.Fatalf("a legal Account SID was refused: %v", err)
	}
	if got.AuthUser != "AC0123456789abcdef" {
		t.Errorf("AuthUser = %q, want the SID the customer supplied", got.AuthUser)
	}
	// Cleared once filled, so nothing downstream asks for it a second time
	// and no console renders a field that has already been answered.
	if got.AuthUserField != "" {
		t.Errorf("AuthUserField = %q after resolving, want it cleared", got.AuthUserField)
	}

	for _, tc := range []struct {
		name   string
		values map[string]string
	}{
		// "AC123:token" would encode as username "AC123" and password
		// "token:<key>", which authenticates as a different account or as
		// nobody, and looks like the customer's key is wrong.
		{"a colon moves the credential boundary", map[string]string{"account_sid": "AC123:token"}},
		{"missing entirely", map[string]string{}},
		{"blank", map[string]string{"account_sid": "   "}},
		{"a field this entry never asked for", map[string]string{"account_sid": "AC1", "region": "eu"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if out, err := entry.Resolve(tc.values); err == nil {
				t.Errorf("Resolve(%v) = %+v, want an error", tc.values, out.AuthUser)
			}
		})
	}
}

func TestAnEntryCannotFixAUsernameAndAskForOne(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry Entry
	}{
		{"both fixed and asked for", Entry{
			AuthScheme: AuthSchemeBasic, AuthUser: "api", AuthUserField: "account_sid"}},
		{"asked for without a username half to fill", Entry{
			AuthScheme: AuthSchemeBearer, AuthUserField: "account_sid"}},
		{"one value would be both a hostname and a credential", Entry{
			AuthScheme: AuthSchemeBasic, AuthUserField: "subdomain", TemplateField: "subdomain"}},
		{"a hint for a question never asked", Entry{
			AuthScheme: AuthSchemeBasic, AuthUserHint: "your Account SID"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.entry.validateAuthUserField(tc.entry.AuthScheme); err == nil {
				t.Error("the entry was accepted, want it refused")
			}
		})
	}
}
