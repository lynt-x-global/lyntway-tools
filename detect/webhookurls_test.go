package detect

import "testing"

// An incoming webhook URL is a bearer token spelled as a URL: whoever has
// it can post as the integration. None of the three was matched until
// 1 Nov 2026, when a drill sent a Slack webhook through /v1/govern and was
// told the request carried nothing.
func TestAWebhookURLIsACredential(t *testing.T) {
	for _, tc := range []struct {
		name  string
		class Class
		text  string
	}{
		{
			"slack incoming webhook", ClassSlackWebhook,
			`post it to https://hooks.slack.com/services/T000AAAA/B111BBBB/xxxxxxxxxxxxxxxxxxxxxxxx`,
		},
		{
			"slack workflow trigger", ClassSlackWebhook,
			`https://hooks.slack.com/triggers/T000AAAA/7788991122334/abcdef0123456789abcdef0123456789`,
		},
		{
			"discord webhook", ClassDiscordWebhook,
			`curl -X POST https://discord.com/api/webhooks/123456789012345678/AbCdEf-0123456789_abcdefghijklmnopqrstuvwxyzABCD`,
		},
		{
			"discord on the old host", ClassDiscordWebhook,
			`https://discordapp.com/api/webhooks/123456789012345678/AbCdEf-0123456789_abcdefghijklmnopqrstuvwxyzABCD`,
		},
		{
			"teams connector", ClassTeamsWebhook,
			`https://contoso.webhook.office.com/webhookb2/a1b2c3d4-0000-1111-2222-333344445555@6677/IncomingWebhook/abc123`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !hasClass(Default().Scan([]byte(tc.text)), tc.class) {
				t.Errorf("no %s reported in %s", tc.class, tc.text)
			}
		})
	}
}

// The span has to be the whole URL. A redact rule that replaced only part
// of it would leave a working webhook on the wire, which is worse than not
// matching at all because the receipt would say the value was protected.
func TestTheWholeWebhookURLIsTheSpan(t *testing.T) {
	url := `https://hooks.slack.com/services/T000AAAA/B111BBBB/xxxxxxxxxxxxxxxxxxxxxxxx`
	text := `alerts go to ` + url + ` every morning`
	for _, s := range Default().Scan([]byte(text)) {
		if s.Class != ClassSlackWebhook {
			continue
		}
		if got := text[s.Start:s.End]; got != url {
			t.Errorf("span = %q, want the whole URL %q", got, url)
		}
		return
	}
	t.Fatal("no slack webhook reported")
}

// Ordinary URLs on those vendors' other hosts are not credentials, and
// neither is the documentation page that describes the feature.
func TestAnOrdinaryVendorURLIsNotAWebhook(t *testing.T) {
	for _, text := range []string{
		`see https://api.slack.com/messaging/webhooks for the setup`,
		`https://slack.com/services/T000AAAA`,
		`https://discord.com/channels/123456789012345678/987654321098765432`,
		`https://docs.microsoft.com/webhookb2/overview`,
		`https://example.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789`,
	} {
		for _, s := range Default().Scan([]byte(text)) {
			switch s.Class {
			case ClassSlackWebhook, ClassDiscordWebhook, ClassTeamsWebhook:
				t.Errorf("%s reported in %q, which carries no credential", s.Class, text)
			}
		}
	}
}

// Every class a rule can emit needs a human name, or a console and a
// receipt print a dotted identifier at the reader.
func TestTheWebhookClassesAreNamed(t *testing.T) {
	for _, c := range []Class{ClassSlackWebhook, ClassDiscordWebhook, ClassTeamsWebhook} {
		if got := Label(c); got == string(c) {
			t.Errorf("no label for %s", c)
		}
	}
}
