package agentsecrets

import "github.com/lynt-x-global/lyntway-tools/detect"

// Where each kind of credential is revoked.
//
// A report that names a problem and leaves the reader to find the page is
// most of the way to useless: the fix for a key in a transcript is to
// revoke it, the file cannot be edited out of every backup that already
// copied it, and the only thing standing between the reader and that fix
// is knowing where to click.
//
// These are console pages, deliberately, not API endpoints and not
// deep links into a specific key — we do not know which key it is and
// cannot find out without sending the value somewhere, which is the one
// thing this package promises not to do. A page that lists the reader's
// own keys is as far as honesty reaches.
//
// A class with no entry prints no link rather than a guess. A wrong
// rotation URL in a security tool sends somebody to the wrong console to
// revoke the wrong thing.
var rotateAt = map[detect.Class]string{
	detect.ClassAWSAccessKey: "https://console.aws.amazon.com/iam/home#/security_credentials",
	detect.ClassAWSSecretKey: "https://console.aws.amazon.com/iam/home#/security_credentials",
	detect.ClassGitHubToken:  "https://github.com/settings/tokens",
	detect.ClassSlackToken:   "https://api.slack.com/apps",
	detect.ClassSlackWebhook: "https://api.slack.com/apps",
	detect.ClassStripeKey:    "https://dashboard.stripe.com/apikeys",
	detect.ClassOpenAIKey:    "https://platform.openai.com/api-keys",
	detect.ClassAnthropicKey: "https://console.anthropic.com/settings/keys",
	detect.ClassSupabaseKey:  "https://supabase.com/dashboard/project/_/settings/api-keys",
	detect.ClassLyntwayKey:   "https://lyntway.com/app/keys",
	detect.ClassAzureConnStr: "https://portal.azure.com",

	// The prefixed vendor credentials. Each points at the page that lists
	// the reader's own keys, never a deep link into one: we do not know
	// which key it is and cannot find out without sending the value
	// somewhere, which this package does not do.
	detect.ClassGoogleAPIKey:    "https://console.cloud.google.com/apis/credentials",
	detect.ClassXAIKey:          "https://console.x.ai",
	detect.ClassNPMToken:        "https://www.npmjs.com/settings/~/tokens",
	detect.ClassSendGridKey:     "https://app.sendgrid.com/settings/api_keys",
	detect.ClassDigitalOceanKey: "https://cloud.digitalocean.com/account/api/tokens",
	detect.ClassShopifyToken:    "https://admin.shopify.com/settings/apps",
	detect.ClassHuggingFaceKey:  "https://huggingface.co/settings/tokens",
	detect.ClassGroqKey:         "https://console.groq.com/keys",
	detect.ClassResendKey:       "https://resend.com/api-keys",
	detect.ClassReplicateKey:    "https://replicate.com/account/api-tokens",
	detect.ClassLinearKey:       "https://linear.app/settings/api",
	detect.ClassDockerToken:     "https://app.docker.com/settings/personal-access-tokens",
	detect.ClassPlanetScaleKey:  "https://app.planetscale.com/settings",
	detect.ClassNewRelicKey:     "https://one.newrelic.com/admin-portal/api-keys/home",
	detect.ClassAtlassianToken:  "https://id.atlassian.com/manage-profile/security/api-tokens",
	detect.ClassSentryToken:     "https://sentry.io/settings/account/api/auth-tokens/",
	detect.ClassGrafanaToken:    "https://grafana.com/profile/api-keys",
	detect.ClassDopplerToken:    "https://dashboard.doppler.com",
	detect.ClassSquareToken:     "https://developer.squareup.com/apps",
	detect.ClassFigmaToken:      "https://www.figma.com/developers/api#access-tokens",

	// Deliberately absent, each for a reason:
	//
	//   private_key   — a PEM block is a key for something we cannot
	//                   identify from the key itself. Where it is
	//                   revoked depends on what trusts it.
	//   jwt           — a session token is not revoked at a URL; it is
	//                   invalidated by the service that issued it, and
	//                   which service that is is not in the token's
	//                   shape.
	//   url_password  — the console for a database password is whoever
	//                   runs the database, which may be nobody but the
	//                   reader.
	//   discord_webhook,
	//   teams_webhook — both are configured per channel by whoever owns
	//                   that channel, and there is no account-wide page
	//                   that lists them. Slack has one, so Slack gets a
	//                   link and these two do not; sending a reader to
	//                   discord.com to revoke a webhook they can only
	//                   remove from the channel it posts to would be the
	//                   wrong console, which is what this table refuses
	//                   to do.
}

// RotateURL returns the page where a credential of this class is revoked,
// or "" when naming one would be a guess.
func RotateURL(class detect.Class) string { return rotateAt[class] }

// RotationAdvice returns one line per distinct provider in the result,
// ordered by how many credentials of that provider were found, so the
// reader works down the list by weight rather than by alphabet.
//
// It is built from the credentials rather than from the class list: a
// page for a provider nobody has a key for is noise in a report whose
// whole job is to be short enough to act on.
func RotationAdvice(creds []Credential) []string {
	type row struct {
		label string
		url   string
		n     int
	}
	seen := map[string]*row{}
	var order []*row
	for _, c := range creds {
		url := RotateURL(detect.Class(c.Class))
		if url == "" {
			continue
		}
		r, ok := seen[url]
		if !ok {
			r = &row{label: c.Label, url: url}
			seen[url] = r
			order = append(order, r)
		}
		r.n++
	}
	// Insertion order is the credential order, which Credentials()
	// already sorted by sighting count, so the heaviest provider leads.
	out := make([]string, 0, len(order))
	for _, r := range order {
		out = append(out, r.label+" — "+r.url)
	}
	return out
}
