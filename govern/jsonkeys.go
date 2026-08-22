package govern

import (
	"bytes"
	"encoding/json"
	"io"
)

// Object keys are structure, not content.
//
// Detection runs over raw bytes and has no idea it is looking at JSON, so a
// key name can be reported as a finding like anything else. Acting on that
// finding rewrites the key — and a message whose key was replaced is still
// valid JSON while no longer being the thing it was.
//
// That is not hypothetical. The model tier read "jsonrpc" as a person's
// name, the tokeniser replaced the key, and every MCP server this gateway
// spoke to answered "Parse error: Invalid JSON-RPC message". The payload
// parsed; the protocol was gone. No test noticed, because the output was
// syntactically fine.
//
// So a span touching a key is still counted — the receipt should say what
// was seen — and is never substituted. Nobody has ever wanted the name of a
// field protected; they want the value under it protected.

// keyRange is the byte range of one object key, quotes included.
type keyRange struct{ start, end int }

// jsonObjectKeys returns the byte ranges of every object key in content.
//
// Returns nil when content is not JSON, which is the common case and costs
// one byte to establish.
func jsonObjectKeys(content []byte) []keyRange {
	trimmed := bytes.TrimLeft(content, " \t\r\n")
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil
	}

	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()

	var (
		ranges []keyRange
		// depthIsObject tracks, per nesting level, whether we are inside an
		// object. Only objects have keys, and inside an array a string is
		// always a value.
		depthIsObject []bool
		expectKey     bool
	)

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Not parseable. Returning nil rather than a partial answer:
			// half a set of key ranges would protect half the keys, which
			// is worse than the honest "this is not JSON".
			return nil
		}

		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				depthIsObject = append(depthIsObject, true)
				expectKey = true
			case '[':
				depthIsObject = append(depthIsObject, false)
				expectKey = false
			case '}', ']':
				if len(depthIsObject) > 0 {
					depthIsObject = depthIsObject[:len(depthIsObject)-1]
				}
				expectKey = len(depthIsObject) > 0 && depthIsObject[len(depthIsObject)-1]
			}
		case string:
			if expectKey {
				if r, ok := stringTokenRange(content, int(dec.InputOffset())); ok {
					ranges = append(ranges, r)
				}
				expectKey = false
				continue
			}
			expectKey = len(depthIsObject) > 0 && depthIsObject[len(depthIsObject)-1]
		default:
			expectKey = len(depthIsObject) > 0 && depthIsObject[len(depthIsObject)-1]
		}
	}
	return ranges
}

// stringTokenRange locates the string literal ending at end.
//
// The decoder reports where a token finished, not where it began, and the
// decoded value cannot be measured against the raw bytes because escapes
// make the two different lengths. So the opening quote is found by walking
// back, counting the backslashes before each quote: an odd number means the
// quote is escaped and is not the opening one.
func stringTokenRange(content []byte, end int) (keyRange, bool) {
	if end <= 0 || end > len(content) || content[end-1] != '"' {
		return keyRange{}, false
	}
	for i := end - 2; i >= 0; i-- {
		if content[i] != '"' {
			continue
		}
		slashes := 0
		for j := i - 1; j >= 0 && content[j] == '\\'; j-- {
			slashes++
		}
		if slashes%2 == 0 {
			return keyRange{start: i, end: end}, true
		}
	}
	return keyRange{}, false
}

// withinKey reports whether [start,end) touches any object key.
func withinKey(start, end int, keys []keyRange) bool {
	for _, k := range keys {
		if start < k.end && k.start < end {
			return true
		}
	}
	return false
}
