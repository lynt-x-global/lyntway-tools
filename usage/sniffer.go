package usage

import "bytes"

// Sniffer reads a provider's usage figure out of a stream as it passes,
// without holding the stream.
//
// It sits on a TeeReader beside the relay rather than inside it, so the
// governed path is not changed by accounting: the relay sees exactly the
// bytes it saw before, and the sniffer sees a copy. It keeps only the
// current line, and only looks at data lines that mention usage, so a long
// generation costs it nothing.
//
// # Merging across events
//
// Each provider reports usage more than once and in more than one place.
// Anthropic opens with message_start carrying the input count and a
// placeholder output of 1, then closes with message_delta carrying the
// final output count. OpenAI sends usage:null on every chunk and the
// figure on a final chunk with no choices, when the caller asked for it
// with stream_options.include_usage. Gemini repeats usageMetadata on every
// chunk, cumulatively.
//
// Every one of those reports a running or final total, never an increment,
// so the largest value seen per field is the provider's final word.
// Summing would double Anthropic's input and inflate Gemini's by the
// number of chunks.
type Sniffer struct {
	line  []byte
	usage TokenUsage
	model string
	found bool
}

// maxSniffedLine bounds the line the sniffer will assemble. Mirrors the
// relay's own scanner limit; a line past it is dropped rather than held.
const maxSniffedLine = 1 << 20

func NewSniffer() *Sniffer { return &Sniffer{} }

// Write implements io.Writer for the TeeReader. It never fails: the relay
// must not be broken by the accounting beside it.
func (u *Sniffer) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		nl := bytes.IndexByte(p, '\n')
		if nl < 0 {
			u.take(p)
			break
		}
		u.take(p[:nl])
		u.consumeLine()
		p = p[nl+1:]
	}
	return n, nil
}

func (u *Sniffer) take(b []byte) {
	if len(u.line)+len(b) > maxSniffedLine {
		// Past the bound the line is not one a provider writes; whatever
		// it is, it is not read.
		u.line = u.line[:0]
		return
	}
	u.line = append(u.line, b...)
}

func (u *Sniffer) consumeLine() {
	line := u.line
	u.line = u.line[:0]
	if !bytes.HasPrefix(line, []byte("data:")) {
		return
	}
	payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
	seen, ok := Parse(payload)
	if !ok {
		return
	}
	// Read the model off the same event that carried the figure. Taking
	// it from any event would let a later one that names nothing — or a
	// provider that echoes a requested alias mid-stream — overwrite the
	// name of the model that actually answered.
	if u.model == "" {
		u.model = Model(payload)
	}
	u.found = true
	if seen.Input > u.usage.Input {
		u.usage.Input = seen.Input
	}
	if seen.Output > u.usage.Output {
		u.usage.Output = seen.Output
	}
}

// Model is the model the stream said answered, or empty when it named
// none. Valid once the stream has ended.
func (u *Sniffer) Model() string {
	if u == nil {
		return ""
	}
	return u.model
}

// Result reports what the stream said, once it has ended.
func (u *Sniffer) Result() (TokenUsage, bool) {
	if u == nil || !u.found {
		return TokenUsage{}, false
	}
	out := u.usage
	out.ReportedBy = ReportedByProvider
	return out, true
}
