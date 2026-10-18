package detect

import "testing"

// A password in a URL is the most common secret in a repository, and
// nothing here caught it until 17 October 2026: `lyntway scan` reported
// "No provider keys" over a .env holding three production database
// passwords, which a reader takes to mean there was nothing to find.
//
// The cases below are split into what must be caught and what must not.
// The second list is the one that matters most: this rule runs in a
// pre-commit hook, and a scanner that blocks a commit over a compose-file
// default is a scanner somebody switches off, after which it catches
// nothing at all.

func scanOne(t *testing.T, text string) []Span {
	t.Helper()
	var out []Span
	for _, s := range Default().Scan([]byte(text)) {
		if s.Class == ClassURLPassword {
			out = append(out, s)
		}
	}
	return out
}

func TestURLPasswordIsFound(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"postgres", "DATABASE_URL=postgres://appuser:S3cretPassw0rd@db.internal:5432/prod", "S3cretPassw0rd"},
		{"postgresql scheme", "postgresql://analytics:Wq8zTrV2mKx@warehouse:5432/sales", "Wq8zTrV2mKx"},
		{"mongodb+srv", "mongodb+srv://admin:T0pS3kr1t99@cluster0.abcd.mongodb.net/app", "T0pS3kr1t99"},
		{"redis, no username", "REDIS_URL=redis://:C4cheP4ssw0rd@cache.internal:6379", "C4cheP4ssw0rd"},
		{"amqp", "amqp://svc:Rabb1tMQpw9@broker:5672/vhost", "Rabb1tMQpw9"},
		{"https basic auth", "https://svcaccount:Bas1cAuthPw7@api.internal/v1", "Bas1cAuthPw7"},
		// An OKF concept document's resource field, which is exactly where
		// the format invites somebody to put a connection location.
		{"okf resource", "resource: postgresql://analytics:Wr3housePw22@warehouse.acme.internal:5432/sales", "Wr3housePw22"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scanOne(t, c.text)
			if len(got) != 1 {
				t.Fatalf("want 1 finding, got %d in %q", len(got), c.text)
			}
			// The span is the password alone. The host is context and
			// stays readable; a substitution leaves a URL still shaped
			// like a URL.
			if got[0].Value != c.want {
				t.Errorf("span is %q, want %q — the span must be the password, not the whole URL", got[0].Value, c.want)
			}
		})
	}
}

func TestURLPasswordIsNotFound(t *testing.T) {
	cases := []struct{ name, text string }{
		{"no credential at all", "postgres://appuser@db.internal:5432/prod"},
		{"plain url", "See https://docs.example.com/guide for the schema."},
		{"markdown link with an at sign", "[mail the team](https://acme.com/contact/hello@acme.com)"},
		{"scp-style git remote", "git@github.com:lynt-x-global/lyntway-core.git"},
		{"shell variable", "postgres://user:${DB_PASSWORD}@db.internal:5432/prod"},
		{"bare shell variable", "postgres://user:$DB_PASSWORD@db.internal:5432/prod"},
		{"template", "postgres://user:{{ db_password }}@db.internal/prod"},
		{"angle placeholder", "postgres://user:<your-password>@db.internal/prod"},
		{"windows variable", "postgres://user:%DB_PASS%@db.internal/prod"},
		{"compose default", "postgres://postgres:postgres@localhost:5432/dev"},
		{"documented example", "postgres://user:password@localhost:5432/mydb"},
		{"changeme", "mongodb://root:changeme@localhost:27017"},
		{"a port, not a password", "postgres://user:5432@db.internal/prod"},
		{"too short", "redis://:abc@cache"},
		{"redacted in a log", "postgres://user:REDACTED@db.internal/prod"},
		{"xxxx", "postgres://user:xxxxxxxx@db.internal/prod"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := scanOne(t, c.text); len(got) != 0 {
				t.Errorf("reported %q in %q — this would block a commit over something that is not a credential",
					got[0].Value, c.text)
			}
		})
	}
}

// The words that are only a placeholder when they are the WHOLE password.
// "test" as a substring rejects Greatest123 and "fake" rejects
// Breakfast99, which are real passwords somebody chose. A rule that
// silently drops a real credential is worse than one that never ran.
func TestURLPasswordRejectsPlaceholdersOnlyWhole(t *testing.T) {
	for _, pw := range []string{"Greatest123", "Breakfast99", "Sampler4Life", "Rootkit88x"} {
		t.Run(pw, func(t *testing.T) {
			text := "postgres://user:" + pw + "@db.internal/prod"
			if got := scanOne(t, text); len(got) != 1 {
				t.Errorf("missed %q — a real password containing a placeholder word as a substring", pw)
			}
		})
	}
}

// A vendor token written into a URL stays that vendor's token. Reporting
// it as a generic URL password would lose the one thing that matters
// operationally: where to go and revoke it.
func TestVendorTokenInAURLOutranksTheGenericRule(t *testing.T) {
	text := "https://oauth2:ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + "@github.com/org/repo.git"
	var classes []Class
	for _, s := range Default().Scan([]byte(text)) {
		classes = append(classes, s.Class)
	}
	for _, c := range classes {
		if c == ClassGitHubToken {
			return
		}
	}
	t.Errorf("classes were %v, want a GitHub token — a revocable token must not be reported as a generic URL password", classes)
}

// The mislabel this rule was really written for.
//
// The userinfo of a URL ends in @host, so "S3cretPassw0rd@db.internal" is
// a well-formed email address to a pattern. Before 17 October 2026 every
// database password followed by a dotted hostname was reported as
// pii.email — and that is worse than missing it. On a route that tokenises
// email the password would have been substituted, the connection string
// broken, and the receipt would have said an email address was protected.
//
// A receipt must never claim more than actually happened, and it must not
// claim something different either.
func TestAPasswordIsNotReportedAsAnEmailAddress(t *testing.T) {
	const text = "DATABASE_URL=postgres://appuser:S3cretPassw0rd@db.internal:5432/prod"
	var classes []Class
	for _, s := range Default().Scan([]byte(text)) {
		classes = append(classes, s.Class)
		if s.Class == ClassEmail {
			t.Errorf("reported %q as %s — it is a database password", s.Value, s.Class)
		}
	}
	found := false
	for _, c := range classes {
		if c == ClassURLPassword {
			found = true
		}
	}
	if !found {
		t.Errorf("classes were %v, want %s", classes, ClassURLPassword)
	}
}

// And a real email address in prose is still an email address. The rule
// above must not have eaten the one it outranks.
func TestARealEmailIsStillAnEmail(t *testing.T) {
	for _, text := range []string{
		"Contact sathya@example.com about the invoice.",
		"from: alerts@monitoring.acme.co.uk",
	} {
		var found bool
		for _, s := range Default().Scan([]byte(text)) {
			if s.Class == ClassEmail {
				found = true
			}
			if s.Class == ClassURLPassword {
				t.Errorf("reported %q as a URL password in %q", s.Value, text)
			}
		}
		if !found {
			t.Errorf("no email found in %q", text)
		}
	}
}
