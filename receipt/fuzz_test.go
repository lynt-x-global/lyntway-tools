package receipt

import "testing"

// A receipt is handed to you by the party you are checking up on.
//
// VerifyJSON is the one function in this repository whose input is
// chosen by somebody with a reason to want it to misbehave — and
// lyntway-verify runs it on whatever a stranger pastes. It may return
// any error it likes; it may not panic.
func FuzzVerifyJSONDoesNotPanic(f *testing.F) {
	for _, seed := range []string{
		"", "{}", "[]", "null", `{"signature":{}}`,
		`{"receipt_id":"a","chain":{"id":"c","sequence":1}}`,
		`{"signature":{"alg":"ed25519","key_id":"k","value":"!!!"}}`,
		`{"evidence":{"provenance":"observed"},"governance":{"mode":"full"}}`,
		`{"chain":{"sequence":-1}}`,
		`{"findings":[{"class":"x","count":99999999999999}]}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		// No resolver: every signature check fails, which is the point —
		// what is being exercised is the parsing and shape handling that
		// runs before any key is consulted.
		_, _ = VerifyJSON(raw, nil, VerifyOptions{})
	})
}
