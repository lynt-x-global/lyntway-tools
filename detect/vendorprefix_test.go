package detect

import (
	"strings"
	"testing"
)

// Each vendor prefix, with a body of the shape that vendor issues.
//
// Assembled from fragments so no literal here resembles a live
// credential, for the reason fixtures_test.go gives.
var vendorSamples = []struct {
	class Class
	text  string
}{
	{ClassGoogleAPIKey, "GEMINI_API_KEY=AIza" + "SyD4kL9mQp2XvN7bRt3WsZc8Ff0Jg1Lu5A"},
	{ClassXAIKey, "XAI_API_KEY=xai-" + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu5Ae2Bn7PxQ9Zm"},
	{ClassNPMToken, "//registry.npmjs.org/:_authToken=npm_" + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu5A"},
	{ClassSendGridKey, "SENDGRID_API_KEY=SG." + "kR7bQp2XvN4mZc8Td1Wy.6Hs3Ff0Jg9Lu5Ae2Bn7PxQ9ZmKd4Vt8Nr2Yc6Xb"},
	{ClassDigitalOceanKey, "DO_TOKEN=dop_v1_" + "7f3a9c2e5b8d1046af23e7c9b50d8a1f6e4c2b97d05a8f3e1c6b4927da50f8e3"},
	{ClassShopifyToken, "SHOPIFY_TOKEN=shpat_" + "7f3a9c2e5b8d1046af23e7c9b50d8a1f"},
	{ClassHuggingFaceKey, "HF_TOKEN=hf_" + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu5A"},
	{ClassGroqKey, "GROQ_API_KEY=gsk_" + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu5Ae2Bn7PxQ9Zm"},
	{ClassResendKey, "RESEND_API_KEY=re_" + "kR7bQp2X_vN4mZc8Td1Wy6Hs3Ff0Jg9"},
	{ClassReplicateKey, "REPLICATE_API_TOKEN=r8_" + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu5A"},
	{ClassLinearKey, "LINEAR_API_KEY=lin_api_" + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu5A"},
	{ClassDockerToken, "DOCKER_PAT=dckr_pat_" + "kR7bQp2XvN4mZc8Td1Wy6Hs3"},
	{ClassPlanetScaleKey, "DB_TOKEN=pscale_tkn_" + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu5A"},
	{ClassNewRelicKey, "NEW_RELIC_LICENSE_KEY=NRAK-" + "KR7BQP2XVN4MZC8TD1WY6HS3FF"},
	{ClassAtlassianToken, "JIRA_TOKEN=ATATT3xFfGF0" + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu5Ae2Bn7PxQ9Zm"},
	{ClassSentryToken, "SENTRY_AUTH_TOKEN=sntrys_" + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu5Ae2Bn7PxQ9Zm"},
	{ClassGrafanaToken, "GRAFANA_TOKEN=glsa_" + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu_abcd1234"},
	{ClassDopplerToken, "DOPPLER_TOKEN=dp.pt." + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu5A"},
	{ClassSquareToken, "SQUARE_TOKEN=sq0atp-" + "kR7bQp2XvN4mZc8Td1Wy6A"},
	{ClassFigmaToken, "FIGMA_TOKEN=figd_" + "kR7bQp2XvN4mZc8Td1Wy6Hs3Ff0Jg9Lu5Ae2Bn7P"},
}

func TestEveryVendorPrefixIsFound(t *testing.T) {
	for _, s := range vendorSamples {
		t.Run(string(s.class), func(t *testing.T) {
			if !hasClass(Default().Scan([]byte(s.text)), s.class) {
				t.Errorf("no %s reported in %q", s.class, s.text)
			}
		})
	}
}

// Every class a rule can emit needs a human name and somewhere to revoke
// it, or a finding tells a reader what happened and not what to do.
func TestEveryVendorPrefixClassIsNamed(t *testing.T) {
	for _, v := range vendorPrefixRules {
		if Label(v.Class) == string(v.Class) {
			t.Errorf("%s has no label; a receipt would print the identifier at the reader", v.Class)
		}
	}
}

// The span must not swallow the character before the key.
//
// Without a target group the leading context is part of the match, and a
// substitution rewrites `KEY="value"` into `KEY=<dummy>"` — a line that
// no longer parses, in a file the tool was asked to make safe.
func TestTheVendorSpanIsTheCredentialAlone(t *testing.T) {
	text := `GROQ_API_KEY="gsk_` + strings.Repeat("Ab3", 16) + `"`
	spans := Default().Scan([]byte(text))
	for _, s := range spans {
		if s.Class != ClassGroqKey {
			continue
		}
		got := text[s.Start:s.End]
		if !strings.HasPrefix(got, "gsk_") {
			t.Errorf("span = %q; it starts before the credential", got)
		}
		if strings.ContainsAny(got, `"=`) {
			t.Errorf("span = %q; it swallowed punctuation around the value", got)
		}
		return
	}
	t.Fatal("no Groq key reported")
}

// The documented examples must not be findings. A README is not a leak,
// and a scanner that says it is gets switched off.
func TestVendorPlaceholdersAreNotCredentials(t *testing.T) {
	for _, text := range []string{
		"GROQ_API_KEY=gsk_your-api-key-here-replace-this-value",
		"NPM_TOKEN=npm_example0000000000000000000000000",
		"HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"GEMINI_API_KEY=AIzaSy-your-placeholder-key-goes-here",
	} {
		for _, s := range Default().Scan([]byte(text)) {
			if HasClassPrefix(s.Class, "secret") {
				t.Errorf("%s reported in %q, which is a placeholder", s.Class, text)
			}
		}
	}
}

// Prose that happens to start with a prefix is not a credential.
func TestOrdinaryTextIsNotAVendorKey(t *testing.T) {
	for _, text := range []string{
		"the re_ prefix is how Resend names its keys",
		"see the npm_ prefixed tokens in the docs",
		"NRAK-STYLE identifiers are documented upstream",
		"hf_ tokens begin with that prefix",
	} {
		for _, s := range Default().Scan([]byte(text)) {
			if HasClassPrefix(s.Class, "secret") {
				t.Errorf("%s reported in prose: %q", s.Class, text)
			}
		}
	}
}
