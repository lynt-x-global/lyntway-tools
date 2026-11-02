package detect

import "testing"

// A password with a character reserved in a URI has to be percent-encoded
// to appear in the userinfo at all, so the encoded form is the form a real
// DSN takes. These were all silently clean until 1 Nov 2026.
func TestAPercentEncodedDSNPasswordIsFound(t *testing.T) {
	for _, tc := range []struct {
		name string
		dsn  string
	}{
		{"an at sign in the password", `postgres://admin:S3cr3tP%40ss@db.internal:5432/app`},
		{"an ampersand", `postgres://admin:Tr0ub4dor%263@db.internal:5432/app`},
		{"two encoded characters", `mysql://root:p%40ssw0rd%21X9@10.0.0.4:3306/prod`},
		{"a lowercase hex pair", `redis://:k9%2fLm2Qp@cache.internal:6379`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !hasClass(Default().Scan([]byte(tc.dsn)), ClassURLPassword) {
				t.Errorf("no url_password reported in %s; a real credential in a real DSN went out unflagged", tc.dsn)
			}
		})
	}
}

// The placeholders the percent rule was written for must still be refused,
// including the one the hex test alone cannot see: %DB_PASSWORD% opens with
// %DB, and D and B are both hex digits.
func TestAVariableReferenceIsStillNotACredential(t *testing.T) {
	for _, dsn := range []string{
		`postgres://admin:%DB_PASSWORD%@db.internal:5432/app`,
		`postgres://admin:%PGPASS%@db.internal:5432/app`,
		`postgres://admin:${DB_PASS}@db.internal:5432/app`,
		`postgres://admin:{{ password }}@db.internal:5432/app`,
		`postgres://admin:<password>@db.internal:5432/app`,
		// A stray percent encoding nothing: prose, not a DSN password.
		`postgres://admin:save50%off@db.internal:5432/app`,
	} {
		if hasClass(Default().Scan([]byte(dsn)), ClassURLPassword) {
			t.Errorf("%s was reported as a credential; on a blocking route that refuses a request over a value nobody ever set", dsn)
		}
	}
}

// An unencoded password still has to be found, which is the case that
// worked before and must not regress.
func TestAPlainDSNPasswordIsStillFound(t *testing.T) {
	if !hasClass(Default().Scan([]byte(`postgres://admin:xK9fLm2Qp7Rt@db.internal:5432/app`)), ClassURLPassword) {
		t.Error("a plain DSN password is no longer reported")
	}
}
