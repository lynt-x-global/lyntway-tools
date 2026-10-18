package usage

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// Token figures are the provider's, and every test here checks two things
// about them: that the number carried is the one the provider wrote, and
// that it is labelled as the provider's wherever it appears.
//
// The fixtures are captured responses, not hand-written JSON. A parser
// tested against what we imagine a provider sends passes forever and
// fails in production on the first field we imagined wrong.

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return raw
}

// The buffered shapes, as each provider actually writes them.
func TestProviderUsageIsReadFromCapturedResponses(t *testing.T) {
	cases := []struct {
		file          string
		input, output int64
		counted       bool
	}{
		{"openai_chat_completion.json", 57, 19, true},
		{"openai_responses.json", 36, 87, true},
		// Embeddings produce no completion; the provider reports none and
		// zero is what it said, not what was assumed.
		{"openai_embeddings.json", 8, 0, true},
		{"anthropic_messages.json", 2095, 503, true},
		// Google reports thinking tokens apart from the answer and bills
		// both as output.
		{"gemini_generate_content.json", 11, 16, true},
		// An error body carries no usage and is not counted as tokens.
		{"provider_error.json", 0, 0, false},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			got, ok := FromBody(fixture(t, c.file), receipt.SurfaceModel)
			if ok != c.counted {
				t.Fatalf("counted=%v, want %v (got %+v)", ok, c.counted, got)
			}
			if !ok {
				return
			}
			if got.Input != c.input || got.Output != c.output {
				t.Errorf("got in=%d out=%d, want in=%d out=%d", got.Input, got.Output, c.input, c.output)
			}
			if got.ReportedBy != "provider" {
				t.Errorf("reported_by must say provider, got %q", got.ReportedBy)
			}
		})
	}
}

// A tool result is arbitrary JSON. One that happens to carry a usage
// object of its own must not be recorded as tokens somebody was billed for.
func TestOnlyAModelSurfaceIsReadForTokens(t *testing.T) {
	if _, ok := FromBody(fixture(t, "openai_chat_completion.json"), receipt.SurfaceMCP); ok {
		t.Fatal("an MCP surface must not be read for token usage")
	}
}

// The streamed shapes, fed to the sniffer in awkward pieces so a usage
// line split across two writes is still assembled and read.
func TestStreamedUsageIsSniffedAcrossWrites(t *testing.T) {
	cases := []struct {
		file          string
		input, output int64
	}{
		// message_start says input 25 and a placeholder output of 1;
		// message_delta says output 15. The larger wins per field.
		{"anthropic_messages_stream.sse", 25, 15},
		// usage:null on every chunk, the figure on the last, when the
		// caller asked for it.
		{"openai_chat_completion_stream.sse", 57, 4},
	}
	for _, c := range cases {
		for _, chunk := range []int{1, 7, 100, 1 << 16} {
			t.Run(fmt.Sprintf("%s/chunk=%d", c.file, chunk), func(t *testing.T) {
				raw := fixture(t, c.file)
				sniff := NewSniffer()
				for i := 0; i < len(raw); i += chunk {
					end := i + chunk
					if end > len(raw) {
						end = len(raw)
					}
					n, err := sniff.Write(raw[i:end])
					if err != nil || n != end-i {
						t.Fatalf("Write returned n=%d err=%v for %d bytes", n, err, end-i)
					}
				}
				got, ok := sniff.Result()
				if !ok {
					t.Fatal("no usage found in the stream")
				}
				if got.Input != c.input || got.Output != c.output {
					t.Errorf("got in=%d out=%d, want in=%d out=%d", got.Input, got.Output, c.input, c.output)
				}
				if got.ReportedBy != "provider" {
					t.Errorf("reported_by must say provider, got %q", got.ReportedBy)
				}
			})
		}
	}
}

// A stream the caller did not ask to include usage in reports nothing,
// and nothing is what is recorded.
func TestAStreamWithoutUsageReportsNone(t *testing.T) {
	sniff := NewSniffer()
	_, _ = sniff.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\ndata: [DONE]\n\n"))
	if _, ok := sniff.Result(); ok {
		t.Fatal("usage:null must not count as a figure")
	}
	var nilSniffer *Sniffer
	if _, ok := nilSniffer.Result(); ok {
		t.Fatal("a nil sniffer reports nothing")
	}
	// A usage object with none of the fields any provider writes is not
	// a figure either, buffered or streamed.
	if _, ok := Parse([]byte(`{"choices":[],"usage":{}}`)); ok {
		t.Fatal("an empty usage object must not count as a figure of zero")
	}
}

// The model that answered is the one that was billed, and it is read from
// the provider's reply rather than the caller's request: an alias resolves
// to a dated build, and a router or a fallback can serve a model the
// caller never named.
func TestTheModelThatAnsweredIsReadFromTheProvidersReply(t *testing.T) {
	for _, c := range []struct {
		file string
		want string
	}{
		{"openai_chat_completion.json", "gpt-4o-mini-2024-07-18"},
		{"anthropic_messages.json", "claude-sonnet-4-5-20250929"},
		{"gemini_generate_content.json", "gemini-2.5-flash"},
	} {
		t.Run(c.file, func(t *testing.T) {
			if got := Model(fixture(t, c.file)); got != c.want {
				t.Errorf("model %q, want %q", got, c.want)
			}
		})
	}

	// A body that names none is empty, not a guess.
	if got := Model([]byte(`{"ok":true}`)); got != "" {
		t.Errorf("model %q from a body that named none", got)
	}
}

// A streamed reply names its model in the same event that carries the
// opening figure, and that is where it must be read: a later event naming
// nothing, or echoing the alias the caller asked for, would otherwise
// overwrite the name of the model that actually answered.
func TestAStreamsModelIsTakenFromTheEventThatCarriedTheFigure(t *testing.T) {
	for _, c := range []struct {
		file string
		want string
	}{
		{"anthropic_messages_stream.sse", "claude-sonnet-4-5-20250929"},
		{"openai_chat_completion_stream.sse", "gpt-4o-mini-2024-07-18"},
	} {
		t.Run(c.file, func(t *testing.T) {
			sniff := NewSniffer()
			if _, err := sniff.Write(fixture(t, c.file)); err != nil {
				t.Fatal(err)
			}
			if got := sniff.Model(); got != c.want {
				t.Errorf("model %q, want %q", got, c.want)
			}
		})
	}

	var nilSniffer *Sniffer
	if got := nilSniffer.Model(); got != "" {
		t.Errorf("a nil sniffer named %q", got)
	}
}
