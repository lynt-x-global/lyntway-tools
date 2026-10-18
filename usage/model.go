package usage

import (
	"bytes"
	"encoding/json"
)

// Model reads the model a provider named in its own response.
//
// The provider's answer is used rather than the request's, because they
// differ in ways that matter to anyone pricing a session: an alias like
// "claude-sonnet-4-5" or "gpt-4o" resolves to a dated build, a router
// picks a model the caller never named, and a fallback silently serves a
// different one. What was billed is what answered.
//
// Empty when the response named none, which is a state and not a failure:
// the tokens are still the provider's figure, and a line that said
// "unknown model" would be more honest than one that guessed from the
// request.
func Model(raw []byte) string {
	if !bytes.Contains(raw, []byte(`"model"`)) {
		return ""
	}
	var env struct {
		Model string `json:"model"`
		// Anthropic's stream carries it inside the message of the opening
		// message_start event, where the usage is too.
		Message *struct {
			Model string `json:"model"`
		} `json:"message"`
		// Gemini names it beside the usage rather than at the top.
		ModelVersion string `json:"modelVersion"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return ""
	}
	switch {
	case env.Model != "":
		return env.Model
	case env.Message != nil && env.Message.Model != "":
		return env.Message.Model
	}
	return env.ModelVersion
}
