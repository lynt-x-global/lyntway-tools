package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Keys with a real prefix and an unmistakably fake body.
//
// The first version of these was shaped like the real thing all the way
// through — `sk_live_51H8x…`, which is the exact form Stripe issues — on
// the reasoning that a test passing on a string no provider would accept
// is not passing on much. GitHub's push protection refused the mirror
// over it, and it was right to: these files ship in a public repository,
// and a public repository full of `sk_live_` strings teaches every reader
// and every scanner to ignore exactly the thing this tool exists to
// notice.
//
// What the code under test actually needs is the prefix, which is what
// the catalog matches on, and a body that does not read as prose, which
// is what randomAfterPrefix checks. Neither needs the body to be
// plausible. So the prefixes are real and the rest says EXAMPLE and
// NOTAREAL in capitals — the convention AWS uses in its own docs.
//
// Stripe's is `sk_test_` rather than `sk_live_`, which is both a real
// catalog prefix and the truthful one: this is a test key. It exercises
// the same catalog entry and the same rule.
//
// They say NOTAREAL and FAKE and not EXAMPLE, which was the second
// attempt and found nothing at all: "example" is in looksLikePlaceholder,
// so the scanner skipped every line of the fixture and four tests failed
// for the right reason. A fixture has to be obviously fake to a person
// and not obviously fake to the heuristic, which is a narrower target
// than it sounds.
const (
	openAIKey = "sk-proj-NOTAREAL0000FAKE0000NOTAREAL4f9a"
	stripeKey = "sk_test_NOTAREAL0000FAKE0000STRIPE"
	resendKey = "re_NOTAREAL0000FAKE0000RESEND"
	linearKey = "lin_api_NOTAREAL0000FAKE0000LINEAR"
)

func projectWithKeys(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	body := "OPENAI_API_KEY=" + openAIKey + "\n" +
		"STRIPE_SECRET_KEY=" + stripeKey + "\n" +
		"RESEND_API_KEY=" + resendKey + "\n" +
		"LINEAR_API_KEY=" + linearKey + "\n" +
		"DATABASE_URL=postgres://localhost/app\n" +
		"NOT_A_KEY=re_but_this_is_just_a_word\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The invariant that matters most here, and the one this got wrong first:
// connect must never show fewer keys than `lyntway scan` found. It
// bucketed by Upstream and Catalog and silently dropped anything with
// neither, so a live Stripe key — recognised by the gateway's own rules —
// was in the scan and not on the screen somebody agrees to.
func TestConnectShowsEveryKeyTheScannerFound(t *testing.T) {
	dir := projectWithKeys(t)

	scanned, _, err := scanPaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	f := takeConnectFindings(dir)

	if got, want := len(f.Migratable)+len(f.Named), len(scanned); got != want {
		t.Fatalf("connect shows %d keys, the scanner found %d", got, want)
	}
	for _, h := range scanned {
		found := false
		for _, c := range append(append([]keyHit{}, f.Migratable...), f.Named...) {
			if c.Last4 == h.Last4 {
				found = true
			}
		}
		if !found {
			t.Errorf("%s (…%s) is in the scan and not in connect", h.Label, h.Last4)
		}
	}
}

func TestConnectNamesProvidersTheSevenShapesCannot(t *testing.T) {
	f := takeConnectFindings(projectWithKeys(t))

	var buf bytes.Buffer
	prevOut := stdout
	stdout = &buf
	defer func() { stdout = prevOut }()
	printConnectFindings(f)
	out := buf.String()

	// Named from the catalog, which is the whole point of it having moved
	// into a package this command can import.
	for _, want := range []string{"Stripe key", "Resend key", "Linear key"} {
		if !strings.Contains(out, want) {
			t.Errorf("the catalog did not name %q:\n%s", want, out)
		}
	}
	// Only the OpenAI key is one this tool can actually move. Offering to
	// move a Stripe key would be a promise nothing here can keep.
	if len(f.Migratable) != 1 || f.Migratable[0].Upstream != "openai" {
		t.Errorf("migratable should be the OpenAI key alone, got %+v", f.Migratable)
	}
	for _, h := range f.Named {
		if h.Upstream != "" {
			t.Errorf("%s is in the not-moved list with an upstream set", h.Label)
		}
	}
}

// `lyntway scan` gates commits, and a false positive there stops somebody
// working. A catalog prefix can be three characters, so prose beginning
// "re_" must not become a Resend key.
func TestProseIsNotAKeyHoweverItIsNamed(t *testing.T) {
	for _, value := range []string{
		"re_but_this_is_just_a_word",
		"key_this_is_a_description_of_something",
		"pat_the_name_of_a_person_here",
	} {
		if n := nameFromCatalog("SOME_API_KEY", value); n.Entry != "" || n.Ambiguous > 0 {
			t.Errorf("%q was named %q by the catalog", value, n.Entry)
		}
	}
	// And the real one still is.
	if n := nameFromCatalog("RESEND_API_KEY", resendKey); n.Entry != "resend" {
		t.Errorf("a real Resend key was named %q", n.Entry)
	}
}

// Both signals are required. Either alone names something that is not a
// credential, or misses one that is.
func TestTheCatalogIsOnlyConsultedAboutAVariableThatHoldsASecret(t *testing.T) {
	if n := nameFromCatalog("SOME_PUBLIC_URL", resendKey); n.Entry != "" {
		t.Errorf("a variable that does not hold a secret was named %q", n.Entry)
	}
	if n := nameFromCatalog("RESEND_API_KEY", "nothing-shaped-like-a-key-at-all"); n.Entry != "" {
		t.Errorf("a value with no known prefix was named %q", n.Entry)
	}
}

// Routing signs receipts with a key that is not on the machine being
// recorded, so it needs an account. Saying that with the list already on
// screen is the difference between an answer and a sign-up wall.
func TestConnectWithoutAnAccountStillReportsAndThenExplains(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	dir := projectWithKeys(t)
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(prev)

	var buf bytes.Buffer
	prevOut := stdout
	stdout = &buf
	defer func() { stdout = prevOut }()

	if err := connectCommand(nil); err != nil {
		t.Fatalf("connect refused to run without an account: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Stripe key") {
		t.Fatalf("the findings were withheld until sign-in:\n%s", out)
	}
	if !strings.Contains(out, "Routing needs an account") {
		t.Fatalf("it did not say why routing stopped:\n%s", out)
	}
	// It must not have changed anything on the way to saying so.
	body, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), openAIKey) {
		t.Fatal("the .env was rewritten by a command that had not been agreed to")
	}
}

// Nothing connect does is its own: every change is init or keys migrate,
// which undo already reverses. A new mutation here would be a new thing
// for undo to miss.
func TestConnectOwnsNoChangesOfItsOwn(t *testing.T) {
	body, err := os.ReadFile("connect.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"os.WriteFile", "os.Remove", "os.Rename", "os.Create"} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("connect.go calls %s directly; every change here must go through "+
				"init or keys migrate, which undo knows how to reverse", forbidden)
		}
	}
}
