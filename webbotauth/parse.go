package webbotauth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// A focused parser for the three headers Web Bot Auth uses, rather than a
// general RFC 8941 structured field implementation.
//
// The narrow scope is deliberate. A general parser is a large surface for a
// verifier to carry, and every additional construct is another place for a
// disagreement about serialisation to become a signature that verifies when
// it should not. What is parsed here is exactly what the profile defines.

// signatureInput is one entry from the Signature-Input header.
type signatureInput struct {
	// label identifies this signature within the header dictionary.
	label string

	// components are the covered component identifiers, in order, each
	// with any parameters retained verbatim.
	components []component

	// params are the signature parameters: created, expires, keyid, alg,
	// tag, nonce.
	params map[string]string

	// raw is the exact text of the inner list and its parameters as
	// received.
	//
	// Retained because the signature base's @signature-params line must
	// reproduce this byte for byte. Re-serialising a parsed structure
	// risks differing from what the signer produced — a different quoting
	// choice, a dropped parameter, a reordered list — and the signature
	// would fail for reasons that look like tampering.
	raw string
}

// component is one covered component identifier.
type component struct {
	name string
	// params is the verbatim parameter text, including the leading
	// semicolon, or empty.
	params string
}

// covers reports whether a component is in the covered set.
func (s *signatureInput) covers(name string) bool {
	for _, c := range s.components {
		if c.name == name {
			return true
		}
	}
	return false
}

func (s *signatureInput) componentNames() []string {
	out := make([]string, len(s.components))
	for i, c := range s.components {
		out[i] = c.name
	}
	return out
}

// parseSignatureInput parses the Signature-Input header.
//
// The header is a dictionary of labels to inner lists with parameters:
//
//	sig1=("@authority" "signature-agent");created=1735689600;keyid="...";tag="web-bot-auth"
func parseSignatureInput(raw string) ([]*signatureInput, error) {
	var out []*signatureInput

	for _, entry := range splitDictionary(raw) {
		label, value, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("%w: Signature-Input entry %q has no value", ErrMalformed, entry)
		}
		label = strings.TrimSpace(label)
		value = strings.TrimSpace(value)

		if !strings.HasPrefix(value, "(") {
			return nil, fmt.Errorf("%w: Signature-Input %q does not start with a component list", ErrMalformed, label)
		}
		close := strings.Index(value, ")")
		if close < 0 {
			return nil, fmt.Errorf("%w: Signature-Input %q has an unterminated component list", ErrMalformed, label)
		}

		components, err := parseComponents(value[1:close])
		if err != nil {
			return nil, err
		}
		params, err := parseParams(value[close+1:])
		if err != nil {
			return nil, err
		}

		out = append(out, &signatureInput{
			label:      label,
			components: components,
			params:     params,
			raw:        value,
		})
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%w: Signature-Input is empty", ErrMalformed)
	}
	return out, nil
}

// parseComponents parses the inner list of covered component identifiers.
func parseComponents(inner string) ([]component, error) {
	var out []component

	for _, token := range splitOutsideQuotes(inner, ' ') {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if !strings.HasPrefix(token, `"`) {
			return nil, fmt.Errorf("%w: component %q is not a quoted string", ErrMalformed, token)
		}
		endQuote := strings.Index(token[1:], `"`)
		if endQuote < 0 {
			return nil, fmt.Errorf("%w: component %q is unterminated", ErrMalformed, token)
		}
		out = append(out, component{
			name:   strings.ToLower(token[1 : endQuote+1]),
			params: token[endQuote+2:],
		})
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%w: signature covers no components", ErrMalformed)
	}
	return out, nil
}

// parseParams parses trailing ;key=value parameters.
func parseParams(raw string) (map[string]string, error) {
	params := make(map[string]string)

	for _, part := range splitOutsideQuotes(raw, ';') {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			// A boolean parameter, which the profile does not use but
			// which is valid structured field syntax.
			params[strings.TrimSpace(key)] = ""
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		params[key] = strings.Trim(value, `"`)
	}

	return params, nil
}

// parseSignatureHeader parses the Signature header: a dictionary of labels
// to byte sequences delimited by colons.
func parseSignatureHeader(raw string) (map[string][]byte, error) {
	out := make(map[string][]byte)

	for _, entry := range splitDictionary(raw) {
		label, value, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("%w: Signature entry %q has no value", ErrMalformed, entry)
		}
		label = strings.TrimSpace(label)
		value = strings.TrimSpace(value)

		if len(value) < 2 || !strings.HasPrefix(value, ":") || !strings.HasSuffix(value, ":") {
			return nil, fmt.Errorf("%w: Signature %q is not a byte sequence", ErrMalformed, label)
		}
		encoded := value[1 : len(value)-1]

		// Structured fields specify standard base64. Some implementations
		// emit base64url, so both are accepted: rejecting a signature over
		// an encoding choice would be a needless interoperability failure,
		// and the decoded bytes are identical either way.
		decoded, err := decodeBase64Either(encoded)
		if err != nil {
			return nil, fmt.Errorf("%w: Signature %q is not valid base64", ErrMalformed, label)
		}
		out[label] = decoded
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%w: Signature is empty", ErrMalformed)
	}
	return out, nil
}

func decodeBase64Either(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("not valid base64")
}

// signatureBase builds the RFC 9421 signature base for a request.
//
// Each covered component contributes a line of the form
//
//	"name";params: value
//
// and the final line is @signature-params with the inner list and
// parameters exactly as received. Lines are separated by newlines with no
// trailing newline after the last.
func signatureBase(r *http.Request, input *signatureInput) ([]byte, error) {
	var b strings.Builder

	for _, c := range input.components {
		value, err := componentValue(r, c)
		if err != nil {
			return nil, err
		}
		b.WriteByte('"')
		b.WriteString(c.name)
		b.WriteByte('"')
		b.WriteString(c.params)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteByte('\n')
	}

	b.WriteString(`"@signature-params": `)
	// The raw text rather than a re-serialisation, so the base matches what
	// the signer produced.
	b.WriteString(input.raw)

	return []byte(b.String()), nil
}

// componentValue resolves one covered component against the request.
func componentValue(r *http.Request, c component) (string, error) {
	switch c.name {
	case "@authority":
		// The Host header, lowercased, with any default port removed. This
		// is the value that binds the signature to the origin it was sent
		// to.
		return strings.ToLower(authority(r)), nil

	case "@method":
		return strings.ToUpper(r.Method), nil

	case "@target-uri":
		return targetURI(r), nil

	case "@path":
		// The path as it appeared on the request line, percent-encoding
		// intact. RFC 9421 defines @path as the target URI's path
		// component, and a signer sees only the encoded form — the SDKs
		// sign urlsplit(url).path, which is exactly what was sent. Go's
		// URL.Path is the decoded form, so "/v1/a%2Fb" would be
		// reconstructed as "/v1/a/b" and every signature over an encoded
		// path would fail as if tampered with. EscapedPath returns the
		// original bytes whenever they were a valid encoding, and the
		// canonical re-encoding otherwise, which is what a signer that
		// normalised would have produced.
		return requestPath(r), nil

	case "@query":
		if r.URL == nil || r.URL.RawQuery == "" {
			return "?", nil
		}
		return "?" + r.URL.RawQuery, nil

	case "@scheme":
		return scheme(r), nil

	default:
		if strings.HasPrefix(c.name, "@") {
			// An unknown derived component cannot be reconstructed, and
			// guessing would produce a base that silently fails to match.
			return "", fmt.Errorf("%w: unsupported derived component %q", ErrMalformed, c.name)
		}
		values := r.Header.Values(http.CanonicalHeaderKey(c.name))
		if len(values) == 0 {
			return "", fmt.Errorf("%w: signature covers header %q which is not present",
				ErrMalformed, c.name)
		}
		// RFC 9421 joins repeated field values with ", " after trimming
		// each. Obtaining this wrong is invisible until an agent sends a
		// repeated header.
		trimmed := make([]string, len(values))
		for i, v := range values {
			trimmed[i] = strings.TrimSpace(v)
		}
		return strings.Join(trimmed, ", "), nil
	}
}

func authority(r *http.Request) string {
	if r.Host != "" {
		return stripDefaultPort(r.Host, scheme(r))
	}
	if r.URL != nil {
		return stripDefaultPort(r.URL.Host, scheme(r))
	}
	return ""
}

func stripDefaultPort(host, scheme string) string {
	switch {
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		return strings.TrimSuffix(host, ":443")
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

func scheme(r *http.Request) string {
	// Behind a reverse proxy — which is how this service runs — the
	// original scheme survives only in a forwarded header. TLS being nil
	// on the inner request says nothing about how the client connected.
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		return strings.ToLower(strings.TrimSpace(strings.Split(v, ",")[0]))
	}
	if r.TLS != nil {
		return "https"
	}
	if r.URL != nil && r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	return "http"
}

// requestPath is the encoded path, "/" when the request has none.
func requestPath(r *http.Request) string {
	if r.URL == nil {
		return "/"
	}
	if p := r.URL.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

func targetURI(r *http.Request) string {
	uri := scheme(r) + "://" + authority(r) + requestPath(r)
	if r.URL != nil && r.URL.RawQuery != "" {
		uri += "?" + r.URL.RawQuery
	}
	return uri
}

// splitDictionary splits a structured field dictionary on commas that are
// outside quoted strings and byte sequences.
func splitDictionary(raw string) []string {
	var (
		out     []string
		current strings.Builder
		inQuote bool
		inBytes bool
	)
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		switch {
		case ch == '"' && !inBytes:
			inQuote = !inQuote
		case ch == ':' && !inQuote:
			inBytes = !inBytes
		case ch == ',' && !inQuote && !inBytes:
			out = append(out, strings.TrimSpace(current.String()))
			current.Reset()
			continue
		}
		current.WriteByte(ch)
	}
	if s := strings.TrimSpace(current.String()); s != "" {
		out = append(out, s)
	}
	return out
}

// splitOutsideQuotes splits on a separator that is not inside a quoted
// string.
func splitOutsideQuotes(raw string, sep byte) []string {
	var (
		out     []string
		current strings.Builder
		inQuote bool
	)
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch == '"' {
			inQuote = !inQuote
		}
		if ch == sep && !inQuote {
			out = append(out, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(ch)
	}
	out = append(out, current.String())
	return out
}

func parseUnix(raw string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
}
