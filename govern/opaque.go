package govern

import "github.com/lynt-x-global/lyntway-tools/receipt"

// Content this engine could not read.
//
// Detection works on text. A vision request carries its image as base64
// inside JSON, a file upload can carry a document the same way, and to a
// rule-based scanner those are a long run of harmless characters. Nothing
// is found, and until now the receipt said so in a way that reads as "this
// content was clean" rather than "part of this content was not text".
//
// That is the same fault as the stream nobody could parse: not a missed
// detection, which is ordinary and honest, but a claim to have examined
// something that was never examined. A reader comparing two receipts has
// no way to tell an empty scan from an unread one.
//
// So a substantial encoded run is reported as a component that did not run.
// The mode drops to degraded, which is what degraded means — some of it did
// not happen — and the component says which part.
//
// Deliberately not decoded here. Decoding and scanning is worth doing and
// is a larger piece of work: a decoded PDF is not text either, substituting
// inside it means re-encoding, and a scanner fed arbitrary binary produces
// findings nobody can act on. Saying plainly that it was not read is the
// honest position in the meantime, and remains correct afterwards for
// whatever still cannot be decoded.

// ComponentEncodedContent names the capability that is missing when a
// payload carries something this engine cannot read as text.
const ComponentEncodedContent = "encoded-content"

// minimumOpaqueRun is how long a base64 run must be before it is treated as
// carried content rather than an identifier.
//
// Tokens, signatures, request ids and trace headers are short and appear in
// ordinary payloads constantly; reporting those as unread content would
// mark almost every receipt degraded and teach a reader to ignore the
// field. A kilobyte is well past anything incidental and far below the
// smallest real image.
const minimumOpaqueRun = 1024

// carriesUnreadableContent reports whether content holds an encoded run
// long enough to be something rather than an identifier.
//
// Scanned rather than matched with a regular expression: Go caps a repeat
// count at 1000, which is below the threshold that makes this useful, and a
// single pass over the bytes is cheaper than a pattern for the same answer.
func carriesUnreadableContent(content []byte) bool {
	if len(content) < minimumOpaqueRun {
		return false
	}
	run := 0
	for _, c := range content {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '+', c == '/', c == '_', c == '-':
			run++
			if run >= minimumOpaqueRun {
				return true
			}
		default:
			run = 0
		}
	}
	return false
}

// withUnreadableContent adds the missing-capability component and lowers
// health, leaving an already worse state alone.
func withUnreadableContent(components []receipt.Component, health receipt.Health) ([]receipt.Component, receipt.Health) {
	components = append(components, receipt.Component{
		Name:   ComponentEncodedContent,
		Health: receipt.HealthUnavailable,
	})
	if health == receipt.HealthHealthy {
		return components, receipt.HealthDegraded
	}
	return components, health
}
