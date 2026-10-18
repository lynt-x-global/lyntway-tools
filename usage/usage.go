// Package usage carries what a provider said a call cost.
//
// # Whose number this is
//
// Nothing here counts tokens. It cannot: the tokenizer is the provider's,
// and a count made on this side would be a guess dressed as a measurement.
// What this does is read the figure the provider put in its own response
// — usage.prompt_tokens, usage.input_tokens, usageMetadata — and carry it
// unaltered.
//
// So every figure is labelled ReportedBy: provider. It is not observed,
// because nothing here observed it; it is what the other side said. A
// reader deciding whether to trust it is deciding whether to trust the
// provider's invoice, which is the same decision they were already making.
//
// # Why it is its own package
//
// It was inside the service, which meant the gateway could account for a
// call and `lyntway guard` — watching the same request on a laptop —
// could not. A second copy in the CLI would have been two parsers for one
// set of provider shapes, drifting apart on the first provider that
// changed a field name. This package is in the module the public tools are
// built from, so there is one parser and both sides read it.
//
// # Calls with no figure
//
// A provider that reported nothing — an error body, a stream the caller
// did not ask to include usage in, an upstream that speaks no shape
// recognised here — is a call and not tokens. Zero would read as "free",
// and absent is the honest value.
package usage

import (
	"bytes"
	"encoding/json"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// TokenUsage is what a provider said one call cost it, in its own units.
type TokenUsage struct {
	Input  int64 `json:"input"`
	Output int64 `json:"output"`

	// ReportedBy says whose count this is. Always "provider": the field
	// is written out so a reader of the JSON is told rather than left to
	// assume this measured something.
	ReportedBy string `json:"reported_by"`
}

// ReportedByProvider is the only value ReportedBy takes today.
const ReportedByProvider = "provider"

// Note is repeated on every surface that carries a token figure, because
// each is read on its own.
const Note = "Token counts are what the provider reported in its own response. This service did not count them and cannot vouch for them. " +
	"Calls whose response carried no usage figure are counted as calls and not as tokens."

// FromBody reads a provider's usage figure out of a buffered response.
//
// Only a model surface is read. A tool result is arbitrary JSON, and a
// tool that happened to return a "usage" object of its own would be
// recorded as tokens somebody was billed for.
func FromBody(body []byte, surface receipt.Surface) (TokenUsage, bool) {
	if surface != receipt.SurfaceModel || len(body) == 0 {
		return TokenUsage{}, false
	}
	return Parse(body)
}

// Parse is FromBody without the surface guard, for the stream sniffer,
// which is only ever attached to a model surface.
//
// Three shapes cover the providers this is used with, and they are told
// apart by field name rather than by which upstream answered: a tenant's
// own Azure OpenAI resource, a vLLM server and a proxy in front of a model
// all answer in one of the same three, and a parse keyed on the upstream's
// name would miss all of them.
//
//   - OpenAI chat, completions, embeddings: usage.prompt_tokens and
//     usage.completion_tokens (absent on embeddings, which produce none).
//   - OpenAI Responses and Anthropic Messages: usage.input_tokens and
//     usage.output_tokens.
//   - Gemini: usageMetadata.promptTokenCount and candidatesTokenCount,
//     plus thoughtsTokenCount, which Google bills as output and reports
//     apart from it.
//
// Cached-input and cache-creation counts are not folded into Input. Each
// provider prices them differently from a fresh input token, and adding
// them would make an estimate wrong in the direction of charging more.
// What is reported is the plain input figure, which is what every provider
// means by it.
func Parse(raw []byte) (TokenUsage, bool) {
	// A quick reject before a full decode: a body that never mentions
	// usage cannot carry it, and the buffered path reads every response.
	if !bytes.Contains(raw, []byte("usage")) {
		return TokenUsage{}, false
	}

	var env struct {
		Usage *struct {
			PromptTokens     *int64 `json:"prompt_tokens"`
			CompletionTokens *int64 `json:"completion_tokens"`
			InputTokens      *int64 `json:"input_tokens"`
			OutputTokens     *int64 `json:"output_tokens"`
		} `json:"usage"`
		UsageMetadata *struct {
			PromptTokenCount     *int64 `json:"promptTokenCount"`
			CandidatesTokenCount *int64 `json:"candidatesTokenCount"`
			ThoughtsTokenCount   *int64 `json:"thoughtsTokenCount"`
		} `json:"usageMetadata"`
		// The Anthropic stream opens with the usage nested inside the
		// message object of a message_start event.
		Message *struct {
			Usage *struct {
				InputTokens  *int64 `json:"input_tokens"`
				OutputTokens *int64 `json:"output_tokens"`
			} `json:"usage"`
		} `json:"message"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return TokenUsage{}, false
	}

	out := TokenUsage{ReportedBy: ReportedByProvider}
	found := false
	take := func(into *int64, from *int64) {
		if from != nil && *from >= 0 {
			*into += *from
			found = true
		}
	}
	switch {
	case env.Usage != nil && (env.Usage.PromptTokens != nil || env.Usage.CompletionTokens != nil):
		take(&out.Input, env.Usage.PromptTokens)
		take(&out.Output, env.Usage.CompletionTokens)
	case env.Usage != nil:
		take(&out.Input, env.Usage.InputTokens)
		take(&out.Output, env.Usage.OutputTokens)
	case env.UsageMetadata != nil:
		take(&out.Input, env.UsageMetadata.PromptTokenCount)
		take(&out.Output, env.UsageMetadata.CandidatesTokenCount)
		take(&out.Output, env.UsageMetadata.ThoughtsTokenCount)
	case env.Message != nil && env.Message.Usage != nil:
		take(&out.Input, env.Message.Usage.InputTokens)
		take(&out.Output, env.Message.Usage.OutputTokens)
	}
	if !found {
		return TokenUsage{}, false
	}
	return out, true
}
