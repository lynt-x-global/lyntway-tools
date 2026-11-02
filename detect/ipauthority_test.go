package detect

import "testing"

// A host is where the data is going, not a person.
//
// The url-password rule's own comment calls the host context rather than a
// secret, and the email rule already refuses a userinfo for the same
// reason. The IP rule did neither, so a connection string to a numeric
// host put pii.ip_address on the receipt — and under redact mode would
// have substituted the host, breaking the connection and claiming personal
// data had been protected.
func TestAnAddressInsideAURIAuthorityIsNotReported(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"a mysql dsn", `mysql://root:p%40ssw0rd%21X9@10.0.0.4:3306/prod`},
		{"a postgres dsn", `postgres://admin:xK9fLm2Qp7Rt@192.168.1.50:5432/app`},
		{"a plain https host", `https://10.2.3.4/health`},
		{"no userinfo at all", `http://172.16.9.1:8080/metrics`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if hasClass(Default().Scan([]byte(tc.text)), ClassIPv4) {
				t.Errorf("the host in %s was reported as personal data", tc.text)
			}
		})
	}
}

// Everywhere else an address still means what it always did. Narrowing a
// rule is only safe if the cases it was right about keep working, and a
// query string is the case most easily lost to a guard on "://".
func TestAnAddressOutsideAnAuthorityIsStillReported(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"in a log line", `the client connected from 203.0.113.77 at 09:14`},
		{"in a query string", `https://example.com/lookup?ip=203.0.113.77`},
		{"on its own", `203.0.113.77`},
		{"in a path, after the authority", `https://example.com/hosts/203.0.113.77`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !hasClass(Default().Scan([]byte(tc.text)), ClassIPv4) {
				t.Errorf("no address reported in %s; the guard reaches past the authority", tc.text)
			}
		})
	}
}

// The password in those same strings is still found. This is the pairing
// that was wrong on 1 Nov 2026 — host reported, secret missed — and it is
// worth one assertion that both halves are now the right way round.
func TestTheSecretIsFoundAndTheHostIsNot(t *testing.T) {
	spans := Default().Scan([]byte(`mysql://root:p%40ssw0rd%21X9@10.0.0.4:3306/prod`))
	if !hasClass(spans, ClassURLPassword) {
		t.Error("the password was not reported")
	}
	if hasClass(spans, ClassIPv4) {
		t.Error("the host was reported as personal data")
	}
}
