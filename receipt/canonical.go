package receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize serialises v as canonical JSON per RFC 8785 (JCS).
//
// Canonical serialisation is what makes a signature portable. Two
// implementations that serialise the same receipt differently will produce
// different signatures over what is logically identical data, and neither
// will be able to verify the other. JCS removes that ambiguity by fixing
// key order, whitespace, and string escaping.
//
// # Numbers
//
// RFC 8785 requires numbers to be formatted per ECMAScript's
// Number::toString, which is the single largest source of cross-language
// canonicalisation bugs — it involves shortest-round-trip float formatting
// that few standard libraries expose directly.
//
// This implementation sidesteps that hazard rather than reimplementing it:
// the receipt schema contains no floating-point fields, and Canonicalize
// rejects any non-integral number it encounters. Integers have exactly one
// correct decimal representation in both JSON and ECMAScript, so the two
// agree trivially.
//
// The consequence is a deliberate restriction: do not add float fields to
// the receipt schema. Express fractional quantities as integers in a fixed
// unit (milliseconds, basis points, bytes) or as strings.
func Canonicalize(v any) ([]byte, error) {
	// Round-tripping through encoding/json first means struct tags,
	// omitempty, and custom marshallers are all honoured exactly as they
	// would be on the wire. UseNumber preserves the literal number text so
	// we can reject non-integers without ever converting through float64
	// and losing the evidence.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Grow(len(raw) + len(raw)/8)
	if err := writeCanonical(&buf, generic, "$"); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonical emits the canonical form of v. path is carried for error
// reporting only.
func writeCanonical(buf *bytes.Buffer, v any, path string) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil

	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil

	case string:
		writeCanonicalString(buf, t)
		return nil

	case json.Number:
		return writeCanonicalNumber(buf, t, path)

	case []any:
		buf.WriteByte('[')
		for i, elem := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, elem, path+"["+itoa(i)+"]"); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil

	case map[string]any:
		return writeCanonicalObject(buf, t, path)

	default:
		// Unreachable for values that came through encoding/json with
		// UseNumber, but an explicit failure beats a silent wrong
		// serialisation in code that guards a signature.
		return &CanonicalizationError{
			Path:   path,
			Reason: "unsupported value type in decoded JSON",
		}
	}
}

// writeCanonicalObject emits an object with keys sorted per RFC 8785.
func writeCanonicalObject(buf *bytes.Buffer, obj map[string]any, path string) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}

	// RFC 8785 sorts member names by their UTF-16 code units, not by code
	// point and not by UTF-8 bytes. The three orders agree for ASCII and
	// diverge above U+FFFF: a supplementary character encodes as a
	// surrogate pair beginning at 0xD800, which sorts *before* characters
	// in U+E000..U+FFFF, whereas by code point it would sort after.
	//
	// Receipt keys are ASCII today, so this can never bite in practice —
	// which is exactly why it would go unnoticed until an extension field
	// carried an emoji and interop silently broke. Sort correctly now.
	sort.Slice(keys, func(i, j int) bool {
		return lessUTF16(keys[i], keys[j])
	})

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeCanonicalString(buf, k)
		buf.WriteByte(':')
		if err := writeCanonical(buf, obj[k], path+"."+k); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// lessUTF16 reports whether a sorts before b when both are compared as
// sequences of UTF-16 code units.
func lessUTF16(a, b string) bool {
	// Fast path: while both strings are pure ASCII, UTF-16 order, code
	// point order, and byte order coincide. Almost every comparison takes
	// this path and never allocates.
	if isASCII(a) && isASCII(b) {
		return a < b
	}
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// writeCanonicalNumber emits a number, rejecting anything non-integral.
func writeCanonicalNumber(buf *bytes.Buffer, n json.Number, path string) error {
	s := n.String()

	// Reject the ECMAScript-formatting hazard explicitly rather than
	// guessing at a representation that another implementation might not
	// reproduce byte for byte.
	if strings.ContainsAny(s, ".eE") {
		return &CanonicalizationError{
			Path: path,
			Reason: "non-integral number " + s + ": the receipt schema forbids floating-point " +
				"values because RFC 8785 number formatting is not reproducible across " +
				"implementations; use an integer in a fixed unit, or a string",
		}
	}

	// Normalise the integer's text. Encoding/json will not emit "+7" or
	// "007", but a caller supplying a hand-built json.Number could, and a
	// signature must not depend on incidental formatting.
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		buf.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	if u, err := strconv.ParseUint(s, 10, 64); err == nil {
		buf.WriteString(strconv.FormatUint(u, 10))
		return nil
	}
	return &CanonicalizationError{
		Path:   path,
		Reason: "integer " + s + " does not fit in 64 bits",
	}
}

// hexDigits is used for \u escapes, which RFC 8785 requires in lowercase.
const hexDigits = "0123456789abcdef"

// writeCanonicalString emits a JSON string per RFC 8785 section 3.2.2.2.
//
// The escaping rules are narrower than encoding/json's defaults: exactly
// seven characters take two-character escapes, every other control
// character takes a lowercase \u00xx escape, and everything else is emitted
// literally as UTF-8. In particular <, >, and & are NOT escaped, where
// encoding/json escapes them by default for HTML safety. That difference
// alone would break interop, which is why this does not delegate to
// encoding/json for strings.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[(r>>4)&0xF])
				buf.WriteByte(hexDigits[r&0xF])
				continue
			}
			// utf8.RuneError from decoding invalid input is written as the
			// replacement character, matching what encoding/json produced
			// upstream. Receipts are built from validated fields, so this
			// is a defensive path rather than an expected one.
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

// SigningInput returns the exact bytes a signature covers.
//
// Two fields are excluded:
//
//   - Signature, because a signature cannot cover itself.
//   - Anchors, because they are obtained after signing. An RFC 3161 or
//     OpenTimestamps proof commits to the signed receipt; if the receipt
//     also committed to the anchor, neither could be produced first.
//
// Excluding anchors means they are not tamper-evident under this signature.
// That is correct: an anchor is independently verifiable against the
// receipt digest it commits to, so it carries its own integrity and does
// not need ours.
func SigningInput(r *Receipt) ([]byte, error) {
	// Copy by value, then clear the excluded fields. The copy is shallow,
	// but nothing reachable through the remaining pointers is mutated, and
	// the caller's receipt is left untouched.
	unsigned := *r
	unsigned.Signature = nil
	unsigned.Anchors = nil
	return Canonicalize(&unsigned)
}

// Digest returns the lowercase hex SHA-256 of a receipt's signing input.
//
// This is the value a successor receipt records as its PrevHash, and the
// value an external timestamp anchor commits to. It is computed over the
// signing input rather than the full receipt so that attaching an anchor
// after the fact does not change a receipt's identity — otherwise anchoring
// would retroactively break every chain link after it.
func Digest(r *Receipt) (string, error) {
	input, err := SigningInput(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:]), nil
}

// DigestContent returns the lowercase hex SHA-256 of arbitrary content, for
// populating Content.InputDigest and Content.OutputDigest.
//
// Callers hash content and discard it. Nothing in this package retains a
// reference to the bytes passed here.
func DigestContent(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SigningInputFromJSON derives the signing input from a receipt exactly as
// it arrived, rather than from a parsed struct.
//
// This is what makes a verifier survive the schema growing.
//
// SigningInput marshals a Go value, so any field the verifier's build does
// not know about is dropped before canonicalisation — and the bytes it
// hashes are not the bytes that were signed. A verifier compiled last year
// therefore reports NOT VERIFIED for a receipt carrying a field added since,
// which is the worst possible false alarm: it reads as tampering.
//
// That failure mode is fatal to the promise this whole package exists for.
// An auditor is handed a receipt and a binary and told the two work together
// offline, indefinitely, with nobody's cooperation. A format that quietly
// breaks that every time it gains a field is not evidence, it is a version
// dependency wearing a signature.
//
// So canonicalisation happens over the parsed JSON document, where unknown
// members survive into the hash. The caller still parses the receipt for its
// meaning; only the bytes under the signature come from here.
func SigningInputFromJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("receipt: reading the receipt document: %w", err)
	}
	document, ok := generic.(map[string]any)
	if !ok {
		return nil, errors.New("receipt: a receipt must be a JSON object")
	}

	// The same two exclusions SigningInput makes, for the same reasons: a
	// signature cannot cover itself, and an anchor attaches afterwards.
	delete(document, "signature")
	delete(document, "anchors")

	var buf bytes.Buffer
	buf.Grow(len(raw))
	if err := writeCanonical(&buf, document, "$"); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnknownFields reports top-level members a build of this package does not
// recognise.
//
// A verifier that checks a signature it cannot fully interpret must say so.
// The signature proves the document is intact; it says nothing about whether
// the reader understood every claim in it, and a receipt carrying an
// unrecognised field could be carrying the one that matters.
func UnknownFields(raw []byte) ([]string, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("receipt: reading the receipt document: %w", err)
	}

	known := map[string]bool{
		"version": true, "id": true, "issued_at": true, "issuer": true,
		"action": true, "actor": true, "content": true, "governance": true,
		"evidence": true, "chain": true, "signature": true, "anchors": true,
	}

	var unknown []string
	for field := range document {
		if !known[field] {
			unknown = append(unknown, field)
		}
	}
	sort.Strings(unknown)
	return unknown, nil
}
