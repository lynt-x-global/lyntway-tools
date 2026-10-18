package detect

import "testing"

// The rule that stopped a developer working.
//
// On 19 October 2026 `lyntway guard -- claude` blocked Claude Code's own
// startup request inside this repository. CLAUDE.md documents a
// development key as sk-local-test-0123456789, Claude Code loads
// CLAUDE.md into its context and sends it, and the rule below matched it
// as an OpenAI key at high confidence — which the default policy blocks.
// The agent read the 403 as an auth failure and asked the user to sign in
// again.
//
// Every case here is about the two ways that rule can be wrong, and they
// are not symmetric. A missed key is a leak and is the worse one, so the
// negative cases below are deliberately narrow: a real key is random, and
// a random body is not allowed to be waved through because four of its
// characters happened to spell a word.

func TestARealOpenAIKeyIsStillCaught(t *testing.T) {
	rs := Default()
	for _, c := range []struct{ name, sample string }{
		// The legacy shape: sk- and 48 characters.
		{"legacy", "OPENAI_API_KEY=sk-" + "Qw3rTy7UiOp1AsDfGh4JkLzXcVbN8mQ2wE5rT9yU0iOp"},
		// A project key, which is longer again.
		{"project", "OPENAI_API_KEY=sk-proj-" + "Qw3rTy7UiOp1AsDfGh4JkLzXcVbN8mQ2wE5rT9yU0iOpQw3rTy7UiOp1AsDfGh4J"},
		// A random body that happens to contain the letters of a
		// placeholder word without them being a segment of their own.
		{"random body containing the letters t-e-s-t", "sk-" + "Qw3rTy7UiOtestp1AsDfGh4JkLzXcVbN8mQ2wE5rT9yU"},
	} {
		t.Run(c.name, func(t *testing.T) {
			spans := rs.Scan([]byte(c.sample))
			if len(spans) == 0 {
				t.Fatal("a real OpenAI key went unflagged — this is the failure that matters")
			}
			if spans[0].Class != ClassOpenAIKey {
				t.Errorf("class %s, want %s", spans[0].Class, ClassOpenAIKey)
			}
		})
	}
}

func TestADocumentedExampleDoesNotStopSomebodyWorking(t *testing.T) {
	rs := Default()
	for _, c := range []struct{ name, sample string }{
		// The exact line from this repository's CLAUDE.md.
		{"our own CLAUDE.md", "LYNTWAY_DEV=1 LYNTWAY_API_KEYS=sk-" + "local-test-0123456789"},
		// Too short to be anything OpenAI issues.
		{"short", "sk-" + "abc123def456ghi789jkl"},
		// Long enough to look real, and spelling out that it is not.
		{"a long example", "sk-proj-" + "example-0123456789abcdefghijklmnopqrstuvwxyz0123"},
		{"a long test key", "sk-" + "test-0123456789abcdefghijklmnopqrstuvwxyz012345"},
		{"a dev key", "sk-" + "dev-0123456789abcdefghijklmnopqrstuvwxyz0123456"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, sp := range rs.Scan([]byte(c.sample)) {
				if sp.Class == ClassOpenAIKey {
					t.Errorf("flagged %q as an OpenAI key; an agent reading a file like this is stopped from working",
						c.sample[sp.Start:sp.End])
				}
			}
		})
	}
}

// Anthropic's own credential must never be reported as somebody else's.
// The OAuth token a subscription sends begins sk-ant-, which the OpenAI
// pattern also matches; only the priority ordering keeps them apart, and
// a reader told their Anthropic token is an OpenAI key has been given a
// fact they cannot act on.
func TestAnAnthropicTokenIsNotCalledAnOpenAIKey(t *testing.T) {
	rs := Default()
	for _, sample := range []string{
		"sk-ant-oat01-" + "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLL",
		"sk-ant-api03-" + "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLL",
	} {
		spans := rs.Scan([]byte(sample))
		if len(spans) == 0 {
			t.Fatal("an Anthropic key went unflagged")
		}
		if spans[0].Class != ClassAnthropicKey {
			t.Errorf("class %s, want %s", spans[0].Class, ClassAnthropicKey)
		}
	}
}
