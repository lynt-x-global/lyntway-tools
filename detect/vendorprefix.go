package detect

import (
	"regexp"
	"strconv"
	"strings"
)

// Credentials identified by a prefix their issuer allocated and nobody
// else may use.
//
// One table rather than twenty near-identical rule blocks, because they
// share one argument and the differences between them are data: the
// prefix, the alphabet the body is drawn from, and how short a body may
// be before it stops being plausible.
//
// # The length floor is the only judgement in here
//
// Too high and a vendor shortening its tokens goes silently undetected;
// too low and an ordinary sentence beginning with the prefix matches.
// Each is set below the shortest form the vendor currently issues rather
// than at it, so a format change costs precision rather than recall — a
// false positive is noticed and argued about, and a miss is not noticed
// at all.
//
// # What is deliberately not here
//
// A Sentry DSN. Its public key is meant to be in client-side code and
// shipped to browsers, so reporting it would be reporting a published
// value as a secret — the same mistake the Stripe rule made with pk_
// keys until it was narrowed to sk_ and rk_.
var vendorPrefixRules = []struct {
	ID       string
	Class    Class
	Prefixes []string
	// Body is the character class the value's tail is drawn from,
	// written as it appears inside a regexp character set.
	Body string
	Min  int
}{
	// Google issues one shape for Maps, Gemini and every other API key.
	{"google-api-key", ClassGoogleAPIKey, []string{"AIza"}, `A-Za-z0-9_\-`, 30},
	{"xai-key", ClassXAIKey, []string{"xai-"}, `A-Za-z0-9`, 30},
	{"npm-token", ClassNPMToken, []string{"npm_"}, `A-Za-z0-9`, 30},
	// SendGrid's is three dot-separated parts. The first two are enough
	// to be unmistakable and the third varies in length.
	{"sendgrid-key", ClassSendGridKey, []string{"SG."}, `A-Za-z0-9_\-\.`, 30},
	{"digitalocean-token", ClassDigitalOceanKey, []string{"dop_v1_", "doo_v1_", "dor_v1_"}, `a-f0-9`, 32},
	{"shopify-token", ClassShopifyToken, []string{"shpat_", "shpss_", "shppa_", "shpca_"}, `a-fA-F0-9`, 24},
	{"huggingface-token", ClassHuggingFaceKey, []string{"hf_"}, `A-Za-z0-9`, 28},
	{"groq-key", ClassGroqKey, []string{"gsk_"}, `A-Za-z0-9`, 40},
	{"resend-key", ClassResendKey, []string{"re_"}, `A-Za-z0-9_`, 24},
	{"replicate-token", ClassReplicateKey, []string{"r8_"}, `A-Za-z0-9`, 28},
	{"linear-key", ClassLinearKey, []string{"lin_api_"}, `A-Za-z0-9`, 28},
	{"docker-token", ClassDockerToken, []string{"dckr_pat_", "dckr_oat_"}, `A-Za-z0-9_\-`, 20},
	{"planetscale-token", ClassPlanetScaleKey, []string{"pscale_tkn_", "pscale_pw_"}, `A-Za-z0-9_\-\.`, 28},
	{"newrelic-key", ClassNewRelicKey, []string{"NRAK-", "NRJS-", "NRII-", "NRAA-"}, `A-Z0-9`, 20},
	// The fixed preamble after ATATT is what keeps this off ordinary
	// capitalised words.
	{"atlassian-token", ClassAtlassianToken, []string{"ATATT3xFfGF0"}, `A-Za-z0-9_\-=`, 30},
	{"sentry-token", ClassSentryToken, []string{"sntrys_", "sntryu_"}, `A-Za-z0-9_\-=\.`, 30},
	{"grafana-token", ClassGrafanaToken, []string{"glsa_", "glc_", "glr_", "gle_"}, `A-Za-z0-9_`, 28},
	{"doppler-token", ClassDopplerToken, []string{"dp.pt.", "dp.st.", "dp.sa.", "dp.ct.", "dp.scim."}, `A-Za-z0-9`, 28},
	{"square-token", ClassSquareToken, []string{"sq0atp-", "sq0csp-"}, `A-Za-z0-9_\-`, 20},
	{"figma-token", ClassFigmaToken, []string{"figd_", "figu_", "figoa_"}, `A-Za-z0-9_\-`, 28},
}

// vendorPrefixRuleset turns that table into rules.
//
// Every one is Exact at priority 100, the same as the hand-written vendor
// rules: a prefix nobody else may mint leaves nothing to be uncertain
// about, and nothing weaker may claim the span first.
//
// notAPlaceholderKey rejects the documented examples that would otherwise
// match, for the reason it was written — a README is not a leak, and a
// scanner that says it is gets switched off.
func vendorPrefixRuleset() []Rule {
	out := make([]Rule, 0, len(vendorPrefixRules))
	for _, v := range vendorPrefixRules {
		quoted := make([]string, 0, len(v.Prefixes))
		for _, p := range v.Prefixes {
			quoted = append(quoted, regexp.QuoteMeta(p))
		}
		// The leading group is required context and must not be part of
		// the span, so the credential is captured in "target". Without it
		// a substitution swallows the character before the key — the
		// quote or the equals sign — and rewrites the line into something
		// that no longer parses.
		//
		// The prefix itself is inside the span: it is part of the
		// credential, and leaving it behind would publish which vendor
		// the removed value belonged to.
		pattern := `(?:^|[^A-Za-z0-9_\-\.])(?P<target>(?:` + strings.Join(quoted, "|") + `)[` + v.Body + `]{` + strconv.Itoa(v.Min) + `,})`
		out = append(out, Rule{
			ID:         v.ID,
			Class:      v.Class,
			Pattern:    regexp.MustCompile(pattern),
			Confidence: ConfidenceExact,
			Validate:   notAPlaceholderKey,
			Prefilter:  append([]string(nil), v.Prefixes...),
			Priority:   100,
		})
	}
	return out
}
