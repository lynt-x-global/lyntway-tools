package detect

import "strings"

// Synthetic credential fixtures, assembled at runtime.
//
// These values must match the detection patterns, which means they look
// exactly like real credentials to a secret scanner. Written as literals
// they would trip gitleaks on every commit.
//
// The alternative — allowlisting `_test.go` paths in the scanner
// configuration — is worse. Test files are precisely where someone pastes a
// real key "just to check something", and a path allowlist would make that
// invisible. Assembling fixtures from fragments keeps the scanner at full
// strength across the entire repository, including here.
//
// Rule for anyone adding a fixture: build it from parts, never paste a
// working credential, and never widen the scanner configuration instead.

// fakeAWSKey returns a synthetic AWS access key ID.
func fakeAWSKey() string { return "AK" + "IA" + "5J7QWMNBZX2LKPRD" }

// fakeAWSTempKey returns a synthetic AWS temporary access key ID.
func fakeAWSTempKey() string { return "AS" + "IA" + "5J7QWMNBZX2LKPRD" }

// fakeAWSKeyTruncated returns a key one character short, for negative tests.
func fakeAWSKeyTruncated() string { return "AK" + "IA" + "5J7QWMNBZX2LKPR" }

// fakeJWT returns a synthetic JWT with a well-formed header segment.
func fakeJWT() string {
	header := "ey" + "JhbGciOiJIUzI1NiJ9"
	payload := "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0"
	return header + "." + payload + ".dozjgNryP4J3jVmNHl0w5N"
}

// fakeJWTShort returns a shorter synthetic JWT.
func fakeJWTShort() string {
	return "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiIxIn0.abcdefghij"
}

// fakeGitHubToken returns a synthetic GitHub personal access token.
func fakeGitHubToken() string { return "gh" + "p_" + strings.Repeat("a", 36) }

// fakeGitHubOAuthToken returns a synthetic GitHub OAuth token.
func fakeGitHubOAuthToken() string { return "gh" + "o_" + strings.Repeat("b", 40) }

// fakeSlackBotToken returns a synthetic Slack bot token.
func fakeSlackBotToken() string { return "xo" + "xb-1234567890-abcdefghij" }

// fakeSlackUserToken returns a synthetic Slack user token.
func fakeSlackUserToken() string { return "xo" + "xp-9876543210-zyxwvutsrq" }

// fakeStripeLiveKey returns a synthetic Stripe live secret key.
func fakeStripeLiveKey() string { return "sk" + "_live_" + strings.Repeat("9", 20) }

// fakeStripeTestKey returns a synthetic Stripe publishable test key.
func fakeStripeTestKey() string { return "pk" + "_test_" + strings.Repeat("z", 18) }

// fakeAnthropicKey returns a synthetic Anthropic API key.
func fakeAnthropicKey() string { return "sk" + "-ant-" + strings.Repeat("x", 24) }

// fakeOpenAIKey returns a synthetic OpenAI project key.
func fakeOpenAIKey() string { return "sk" + "-proj-" + strings.Repeat("q", 22) }

// fakePEMBlock returns a synthetic private key block of the given type.
func fakePEMBlock(kind string) string {
	return "-----BE" + "GIN " + kind + "PRIVATE KEY-----\nMIIBOgIBAAJB\n-----EN" + "D " + kind + "PRIVATE KEY-----"
}

// fakeAzureAccountKey returns a synthetic Azure storage connection fragment.
func fakeAzureAccountKey() string { return "Account" + "Key=" + strings.Repeat("A", 64) + "==" }
