package detect

import "testing"

// A URI's userinfo is a username, not a person.
//
// The email rule matched scheme://user@host and reported pii.email, so a
// Sentry DSN, a postgres URL, an AMQP broker URL and a Redis URL each
// carried a personal-data finding. Two things followed from that, and both
// are worse than a noisy report. Under redact mode the match was
// substituted with a dummy address, which leaves a connection string that
// still looks like one and no longer works — the failure mode
// TestFalsePositives calls "a redaction that corrupts a customer's data".
// And on the receipt it claimed personal data had passed where none had,
// which is the one thing a receipt may never do.
//
// The rule next door already stated half of this: "postgres://user@host
// carries no credential and must not be reported as one". That was true of
// secrets, and this rule reported it as PII instead.
func TestURIUserinfoIsNotAPersonsAddress(t *testing.T) {
	rs := Default()

	for _, c := range []struct {
		name   string
		text   string
		want   bool // want an email finding
		expect string
	}{
		{"sentry dsn", "SENTRY_DSN=https://abc123def456abc123def456abc123de@o12345.ingest.sentry.io/6789", false, ""},
		{"postgres url with a user and no password", "DATABASE_URL=postgres://appuser@db.internal.example.com:5432/app", false, ""},
		{"mongodb+srv url", "mongodb+srv://admin@cluster0.ab1cd.mongodb.net/test", false, ""},
		{"amqp broker url", "BROKER=amqp://worker@rabbit.example.org:5672/", false, ""},
		{"redis url", "REDIS_URL=redis://default@redis.example.net:6379", false, ""},
		{"a ci job's token url", "https://oauth2@github.com/org/repo.git", false, ""},

		// The SSH remote has no scheme, so the pattern guard cannot reach
		// it; a denylist of code hosts' own logins does.
		{"git ssh remote", "git clone git@github.com:lynt-x-global/lyntway-core.git", false, ""},
		{"gitlab ssh remote", "git@gitlab.com:group/project.git", false, ""},

		// And everything that is an address still is.
		{"prose", "please contact ramesh.venkataraman@example.com today", true, "ramesh.venkataraman@example.com"},
		{"mailto", "mailto:support@example.com", true, "support@example.com"},
		{"a query string, where it is a real person's", "GET https://app.example.com/u?email=ramesh@example.com&x=1", true, "ramesh@example.com"},
		{"a url path, which is not userinfo", "https://site.example.com/contact/ramesh@example.com", true, "ramesh@example.com"},
		{"after a url on the same line", "see https://example.com/docs then write to ops@example.com", true, "ops@example.com"},
		{"a person at a code host is still a person", "ramesh@github.com", true, "ramesh@github.com"},
		{"json", `{"email":"ramesh@example.com","id":7}`, true, "ramesh@example.com"},
		{"a header with angle brackets", "From: Ramesh <ramesh@example.com>", true, "ramesh@example.com"},
		{"a sentence ending in a full stop", "Mail ramesh@example.com.", true, "ramesh@example.com"},
		{"followed by a colon", "ramesh@example.com: see above", true, "ramesh@example.com"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var found []string
			for _, s := range rs.Scan([]byte(c.text)) {
				if s.Class == ClassEmail {
					found = append(found, s.Value)
				}
			}
			if !c.want {
				if len(found) != 0 {
					t.Fatalf("reported %v as a person's address; under redact mode that value is replaced and whatever it configures stops working", found)
				}
				return
			}
			if len(found) == 0 {
				t.Fatalf("did not find %q, so narrowing the rule lost a real address", c.expect)
			}
			if found[0] != c.expect {
				t.Errorf("reported %q, want %q", found[0], c.expect)
			}
		})
	}
}

// The password in a URL is still the reported span, and the host and
// username around it stay readable. Guarding the email rule must not have
// moved what the url-password rule reports.
func TestAPasswordInAURLIsStillTheOnlyThingReported(t *testing.T) {
	rs := Default()
	spans := rs.Scan([]byte("DATABASE_URL=postgres://appuser:s3cretpw@db.example.com:5432/app"))
	if len(spans) != 1 {
		t.Fatalf("got %d findings, want exactly the password: %+v", len(spans), spans)
	}
	if spans[0].Class != ClassURLPassword {
		t.Errorf("class is %s, want %s", spans[0].Class, ClassURLPassword)
	}
	if spans[0].Value != "s3cretpw" {
		t.Errorf("reported %q; a substitution must leave the URL shaped like a URL", spans[0].Value)
	}
}
