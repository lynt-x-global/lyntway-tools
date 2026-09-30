package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Where the tools on a machine are configured to send, and what is left
// behind when the agent reads the files that say so.
//
// The fixtures here plant a key beside every endpoint, because that is
// the failure this feature could have: a base URL with a token in its
// query string is the one field in a device report most likely to carry a
// secret, and a rule that trimmed instead of refusing would keep it on
// the odd day it did not match.

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func endpointsByApp(apps []aiApp) map[string][]aiAppEndpoint {
	out := map[string][]aiAppEndpoint{}
	for _, a := range apps {
		out[a.Name] = a.Endpoints
	}
	return out
}

// A shell profile that redirects a tool is found, and everything else in
// that profile stays on the machine.
func TestAShellProfileRedirectIsReportedAsAHostAndNothingElse(t *testing.T) {
	h := fixtureHost(t, "darwin")
	write(t, filepath.Join(h.Home, ".zshrc"), strings.Join([]string{
		"# >>> lyntway >>>",
		`export OPENAI_API_KEY="sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`,
		`export OPENAI_BASE_URL="https://gw.acme.test/gw/openai/v1?trace=abc"`,
		"export ANTHROPIC_BASE_URL=https://gw.acme.test/gw/anthropic",
		"# export OLLAMA_HOST=127.0.0.1:99999",
		"alias k='kubectl'",
		"# <<< lyntway <<<",
	}, "\n"))

	got := configuredEndpoints(h)

	codex := got["Codex CLI"]
	if len(codex) != 1 || codex[0].Host != "gw.acme.test" {
		t.Fatalf("Codex CLI = %+v, want the host alone", codex)
	}
	if codex[0].Source != endpointFromShell || codex[0].Setting != "OPENAI_BASE_URL" {
		t.Errorf("Codex CLI = %+v, want it attributed to the variable it came from", codex[0])
	}
	if claude := got["Claude Code"]; len(claude) != 1 || claude[0].Host != "gw.acme.test" {
		t.Errorf("Claude Code = %+v", claude)
	}
	// A commented-out line is not configuration this machine has.
	if _, ok := got["Ollama"]; ok {
		t.Errorf("a commented-out export was reported as configuration: %+v", got["Ollama"])
	}

	// Nothing from that file but the host may exist anywhere in the
	// endpoints: not the key, not the query string, not the alias.
	for app, list := range got {
		for _, e := range list {
			for _, leak := range []string{"sk-proj-", "trace=abc", "/gw/openai", "kubectl", "?"} {
				if strings.Contains(e.Host+e.Setting+e.Source, leak) {
					t.Fatalf("%s carried %q out of the profile: %+v", app, leak, e)
				}
			}
		}
	}
}

// A value that is resolved somewhere else is not a host this machine has.
//
// The interesting one is the third: a URL whose host is a variable parses
// perfectly well and yields "$gateway_host", a string that looks like a
// finding and names nothing. That is the case this refuses.
func TestAnUnresolvedReferenceIsNotReportedAsAnEndpoint(t *testing.T) {
	h := fixtureHost(t, "linux")
	write(t, filepath.Join(h.Home, ".bashrc"), strings.Join([]string{
		`export OPENAI_API_BASE="$GATEWAY_URL/v1"`,
		"export ANTHROPIC_BASE_URL=${ANTHROPIC_PROXY}",
		`export OPENAI_BASE_URL="https://$GATEWAY_HOST/v1"`,
		"export OLLAMA_HOST=${OLLAMA_ADDR}",
	}, "\n"))

	if got := configuredEndpoints(h); len(got) != 0 {
		t.Fatalf("endpoints = %+v, want none: not one of those values names a host this can see", got)
	}
}

// An application's own settings file beats a shell, and a bare address
// with no scheme is still a host.
func TestASettingsFileEndpointAndABareAddressAreBothRead(t *testing.T) {
	h := fixtureHost(t, "darwin")
	write(t, filepath.Join(h.Home, ".claude", "settings.json"),
		`{"env":{"ANTHROPIC_BASE_URL":"https://gw.acme.test/gw/anthropic","ANTHROPIC_AUTH_TOKEN":"sk-ant-AAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`)
	write(t, filepath.Join(h.Home, ".zshrc"), "export OLLAMA_HOST=127.0.0.1:11434\n")

	got := configuredEndpoints(h)

	claude := got["Claude Code"]
	if len(claude) != 1 || claude[0].Host != "gw.acme.test" || claude[0].Source != endpointFromConfig {
		t.Fatalf("Claude Code = %+v, want the settings file's host", claude)
	}
	if claude[0].Setting != "env.ANTHROPIC_BASE_URL" {
		t.Errorf("setting = %q, want the key it was read from", claude[0].Setting)
	}
	if ollama := got["Ollama"]; len(ollama) != 1 || ollama[0].Host != "127.0.0.1:11434" {
		t.Errorf("Ollama = %+v, want the bare address", ollama)
	}
	for _, e := range claude {
		if strings.Contains(e.Host, "sk-ant") || strings.Contains(e.Setting, "sk-ant") {
			t.Fatalf("the token beside the base URL travelled with it: %+v", e)
		}
	}
}

// An endpoint exists only for software that is on the machine: a variable
// set for a tool nobody installed is a fact about a variable.
func TestAnEndpointIsOnlyAttachedToSoftwareThatIsThere(t *testing.T) {
	endpoints := map[string][]aiAppEndpoint{
		"Codex CLI": {{Host: "gw.acme.test", Source: endpointFromShell, Setting: "OPENAI_BASE_URL"}},
		"Continue":  {{Host: "models.acme.test", Source: endpointFromConfig, Setting: "models.apiBase"}},
	}
	apps := withEndpoints([]aiApp{
		{Name: "Cursor", Kind: "desktop"},
		{Name: "Continue in VS Code", Kind: "desktop"},
	}, endpoints)

	got := endpointsByApp(apps)
	if len(got["Cursor"]) != 0 {
		t.Errorf("Cursor = %+v, want nothing: no endpoint was found for it", got["Cursor"])
	}
	// An extension is inventoried as "<extension> in <editor>", and its
	// own config names it by the extension alone.
	if list := got["Continue in VS Code"]; len(list) != 1 || list[0].Host != "models.acme.test" {
		t.Errorf("Continue in VS Code = %+v", list)
	}
	if len(apps) != 2 {
		t.Errorf("withEndpoints changed the inventory: %+v", apps)
	}
}

// The last look before a report leaves drops an endpoint the service
// would refuse, so one odd row costs that row and not the report.
func TestSanitiseDropsAnEndpointThatIsNotAHost(t *testing.T) {
	r := deviceReport{
		DeviceID: "dev_abcdefghijklmnopqrstuv", Kind: "laptop", OS: "macos",
		Hostname: "laptop", Agent: "lyntway-agent/test", WindowSeconds: 60,
		AIApps: []aiApp{{Name: "Codex CLI", Kind: "cli", Endpoints: []aiAppEndpoint{
			{Host: "api.openai.com/v1?api_key=sk-proj-AAAA", Source: endpointFromShell, Setting: "OPENAI_BASE_URL"},
			{Host: "https://api.openai.com", Source: endpointFromShell, Setting: "OPENAI_BASE_URL"},
			{Host: "gw.acme.test", Source: "guessed", Setting: "OPENAI_BASE_URL"},
			{Host: "gw.acme.test", Source: endpointFromShell, Setting: "read from line 42 of ~/.zshrc"},
			{Host: "gw.acme.test", Source: endpointFromShell, Setting: "OPENAI_BASE_URL"},
		}}},
		Destinations: []destination{},
	}

	sanitiseReport(&r)

	kept := r.AIApps[0].Endpoints
	if len(kept) != 1 || kept[0].Host != "gw.acme.test" {
		t.Fatalf("endpoints = %+v, want only the one that is a host with a known source and a name", kept)
	}
	if looksSecret(kept[0].Host + kept[0].Setting) {
		t.Errorf("a secret survived sanitising: %+v", kept[0])
	}
}
