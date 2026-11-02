package detect

import "testing"

// Nothing the scanner is handed may make it panic.
//
// This runs on every request the gateway serves, so a panic here is the
// service going down on content somebody chose.
func FuzzScanDoesNotPanic(f *testing.F) {
	for _, seed := range []string{
		"", "\x00", "sk-proj-", "4111 1111 1111 1111",
		"postgres://u:p@h/db", "https://hooks.slack.com/services/",
		"AIza", "-----BEGIN PRIVATE KEY-----", "%", "%%%%", "%4",
		"\xff\xfe\x00\x00", "a@b.c", "+999", "​​​",
		"sk-ant-" + "x", "AKIA", "dp.pt.", "SG.",
	} {
		f.Add(seed)
	}
	rs := Default()
	f.Fuzz(func(t *testing.T, s string) {
		spans := rs.Scan([]byte(s))
		// Every span must be inside the input, or a caller slicing by it
		// panics instead.
		for _, sp := range spans {
			if sp.Start < 0 || sp.End > len(s) || sp.Start > sp.End {
				t.Fatalf("span %d:%d is outside an input of %d bytes (class %s)", sp.Start, sp.End, len(s), sp.Class)
			}
		}
	})
}
