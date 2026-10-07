package detect

import (
	"strings"
	"unicode"
)

// Scanning text that came out of an OCR engine.
//
// OCR does not return the text on the page. It returns its best guess, and one
// of the ways the guess differs is that engines drop the spaces inside a line
// they detected as a single box. OCR engines do this: a form line
// reading
//
//	Contact   4111 1111 1111 1111
//
// comes back as "Contact4111111111111111". Every digit is correct. The value is
// intact. And the ruleset does not fire, because almost every rule requires a
// word boundary before the value and there is now a letter where the boundary
// used to be.
//
// Measured before this existed: recall on a scanned page was 0.783 on a clean
// render, 0.652 on a light scan and 0.522 on a poor one — against 1.000 for the
// same values in a text PDF. Half the sensitive values on a photographed
// statement were invisible to us, and nothing said so, because a miss looks
// exactly like clean content.
//
// # Why this is not fixed in the rules
//
// Dropping the word-boundary requirement would find "Contact4111111111111111"
// and also find the last sixteen digits of a twenty-digit order reference. The
// boundary is doing real work on ordinary text, and ordinary text is most of
// what we scan.
//
// # Why it is not fixed by re-spacing the text either
//
// The obvious repair — insert a space between a letter and a digit — breaks the
// classes that are deliberately letters-then-digits. An Indian PAN is ABCDE1234F,
// a UK NINO is AB123456C, an IBAN is DE89370400440532013000. Re-spacing those
// turns a match into three fragments that match nothing.
//
// So the re-spacing is narrowed to the transition that a dropped space actually
// creates — a lowercase label running into a capital, a digit or a plus — and
// even then ScanOCR does not choose between the two forms. It scans both and
// takes the union, so a rule that suits the raw text and a rule that suits the
// re-spaced text both get the form they need. This costs one extra pass over
// text that has already been through an OCR model, and it applies only to OCR
// output: clean text never takes this path, so nothing here can affect the
// precision figures measured on it.

// ScanOCR finds values in text produced by an OCR engine.
//
// Use it wherever the text came from a scan or a photograph. For text read out
// of a document's own text layer, use Ruleset.Scan: that text has its spaces.
//
// Spans are reported against the text as given. A span found only in the
// re-spaced variant is mapped back, so offsets remain usable for substitution.
func ScanOCR(rs *Ruleset, text string) []Span {
	if rs == nil || text == "" {
		return nil
	}

	spans := rs.Scan([]byte(text))

	respaced, offsets := respaceOCR(text)
	if respaced == text {
		return spans
	}

	seen := make(map[[2]int]bool, len(spans))
	for _, sp := range spans {
		seen[[2]int{sp.Start, sp.End}] = true
	}

	for _, sp := range rs.Scan([]byte(respaced)) {
		// Back to offsets in the original, so a caller substituting by
		// position edits the bytes it was given rather than a variant it
		// never saw.
		start := offsets[sp.Start]
		end := offsets[sp.End]
		if seen[[2]int{start, end}] {
			continue
		}
		seen[[2]int{start, end}] = true
		sp.Start, sp.End = start, end
		spans = append(spans, sp)
	}
	return spans
}

// RespaceOCR returns text with the spaces an OCR engine dropped put back.
//
// Exported because the model tier needs it too, and that was measured rather
// than assumed: Presidio misses "PriyaRaghunathan" and finds it once the
// spaces are restored (ai-sidecar/test_modelbench.py). The entity models want
// word boundaries for the same reason the rules do, and they get the text
// second-hand through the sidecar, so somebody has to hand them the repaired
// form.
//
// ScanOCR is the right entry point for finding values in Go. This is for the
// callers that only need the string, because they are about to send it
// somewhere else.
func RespaceOCR(text string) string {
	out, _ := respaceOCR(text)
	return out
}

// respaceOCR inserts a space at each boundary a dropped space would have
// created (see boundaryBetween), and returns a map from each offset in the
// result back to the offset in the input.
//
// The map is what makes the union safe to substitute against. Without it a span
// found in the variant would carry offsets that are wrong for the original by
// however many spaces were inserted before it, and tokenising at those offsets
// would corrupt the surrounding text rather than replace the value.
func respaceOCR(text string) (string, []int) {
	var b strings.Builder
	b.Grow(len(text) + 16)

	// offsets is indexed by position in the output and holds the position in
	// the input. It is one longer than the output so an end offset pointing
	// just past the last byte resolves.
	offsets := make([]int, 0, len(text)+17)

	runes := []rune(text)
	inPos := 0
	var prev rune
	for i, r := range runes {
		if i > 0 && boundaryBetween(prev, r) {
			b.WriteByte(' ')
			offsets = append(offsets, inPos)
		}
		b.WriteRune(r)
		for range []byte(string(r)) {
			offsets = append(offsets, inPos)
		}
		inPos += len(string(r))
		prev = r
	}
	offsets = append(offsets, inPos)
	return b.String(), offsets
}

// boundaryBetween reports whether a space belongs between two adjacent runes
// that OCR may have joined.
//
// The transition is lowercase-to-something, and the something is an uppercase
// letter, a digit or a plus. That is narrow on purpose, and the narrowness was
// arrived at by measuring.
//
// Splitting at every letter/digit transition was the first attempt. It lifted
// card numbers from 0.600 to 1.000 and broke the three classes that are
// themselves letters-then-digits: "ReferenceDE89370400440532013000" became
// "Reference DE 89370400440532013000", and an IBAN split at its own country
// code matches nothing. Same for a PAN (ABCDE1234F) and a NINO (AB123456C).
//
// What actually creates the glue is an engine dropping the space between two
// tokens. The left token is a label and English labels end in lowercase; the
// right token is the value, and a value begins with a capital, a digit or a
// plus. Inside a value the transitions are uppercase-to-digit, which this
// leaves alone — so "Contact" separates from "AAAPZ1234C" and the PAN stays
// whole.
func boundaryBetween(a, b rune) bool {
	if !isASCIILower(a) {
		return false
	}
	return isASCIIUpper(b) || unicode.IsDigit(b) || b == '+'
}

func isASCIILower(r rune) bool { return r >= 'a' && r <= 'z' }
func isASCIIUpper(r rune) bool { return r >= 'A' && r <= 'Z' }
