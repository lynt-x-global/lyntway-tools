package main

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

// Where the AI tools on this machine are configured to send.
//
// # Why this is worth reading files for
//
// Knowing Cursor is installed says little. Knowing a shell profile on the
// machine sets OPENAI_BASE_URL to somebody's own gateway, or that nothing
// does, is the difference between an estate that is routed and one that is
// not — and it is the only way to learn it without watching traffic,
// which this agent does not do.
//
// # The rule that makes it shippable
//
// Only a host leaves. A base URL is the field in a configuration most
// likely to carry a token in its query string, so the value is reduced to
// its host before it is kept, and everything else the file holds — keys,
// arguments, the rest of the settings — is read, used to find the host,
// and dropped. aiAppEndpoint has three fields and none of them can hold a
// value: the host, which kind of place it came from, and the name of the
// variable or key. A name, never a value. The same guard the MCP reader
// uses, for the same reason.
//
// # What a finding here is, exactly
//
// "A shell profile on this machine sets OPENAI_BASE_URL to that host."
// That is a fact about the machine. Which applications read that variable
// is a documented mapping, not something the agent watched, and the source
// travels with the row so a reader can see which of the two they are
// looking at. It is never a claim that the tool ran, that it was started
// from that shell, or that it sent anything anywhere.

// aiAppEndpoint is one address an application is configured to reach.
type aiAppEndpoint struct {
	Host    string `json:"host"`
	Source  string `json:"source"`
	Setting string `json:"setting,omitempty"`
}

// The two sources, as the service's contract names them.
const (
	endpointFromShell  = "shell"
	endpointFromConfig = "config"
)

// maxEndpointsPerApp is the service's limit, applied here so an odd
// machine loses the surplus rows rather than the whole report.
const maxEndpointsPerApp = 8

// baseURLVars are the environment variables that redirect an AI tool, and
// the tools documented to read each one.
//
// Deliberately short. A longer table is a table that goes stale, and a
// wrong entry here would attribute an endpoint to software that never
// reads it — which is precisely the kind of overclaim this product exists
// not to make. A variable no tool in the inventory reads is not listed:
// reporting it would be reporting a fact about no application.
var baseURLVars = []struct {
	Name string
	Apps []string
}{
	{"OPENAI_BASE_URL", []string{"Codex CLI"}},
	{"OPENAI_API_BASE", []string{"Aider"}},
	{"ANTHROPIC_BASE_URL", []string{"Claude Code"}},
	{"OLLAMA_HOST", []string{"Ollama"}},
}

// shellProfiles are the login files read for those variables. Read for
// assignments of those four names and nothing else: the rest of the file
// is somebody's shell, and none of it is the agent's business.
var shellProfiles = []string{
	".zshrc", ".zshenv", ".zprofile", ".bashrc", ".bash_profile", ".profile",
	filepath.Join(".config", "fish", "config.fish"),
}

// maxProfileBytes bounds a profile read. A shell profile is a few
// kilobytes; a megabyte of one is not a profile.
const maxProfileBytes = 1 << 20

// assignment matches "export NAME=value", "NAME=value" and fish's
// "set -gx NAME value". The value is taken up to whitespace or a comment,
// and unquoted here — endpointHost does the rest, and refuses anything
// that is not a host.
//
// Anchored at the start of a line, which is also what keeps a
// commented-out export from counting as configuration this machine has:
// "# export X=…" cannot match, because the first thing after the indent
// is not a name. A comment stripper stood here too, until it was
// deliberately broken and no test noticed — which is how a second guard
// announces that it was never a guard.
var assignment = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+|set[ \t]+-[gxlUe]+[ \t]+|setenv[ \t]+)?([A-Z][A-Z0-9_]*)[ \t]*(?:=|[ \t])[ \t]*("[^"\n]*"|'[^'\n]*'|[^\s#]+)`)

// configuredEndpoints returns, per application name, where the machine
// says that application is configured to send.
//
// Keyed by the name the inventory uses, so an application that is not
// installed contributes nothing: a base URL set for software that is not
// there is a fact about a variable, not about an AI tool, and the report
// has no row to put it on.
func configuredEndpoints(h agentHost) map[string][]aiAppEndpoint {
	out := map[string][]aiAppEndpoint{}
	add := func(app string, e aiAppEndpoint) {
		if app == "" || e.Host == "" {
			return
		}
		for _, have := range out[app] {
			if have == e {
				return
			}
		}
		if len(out[app]) >= maxEndpointsPerApp {
			return
		}
		out[app] = append(out[app], e)
	}

	for name, value := range shellBaseURLs(h) {
		for _, v := range baseURLVars {
			if v.Name != name {
				continue
			}
			host := endpointHost(value)
			for _, app := range v.Apps {
				add(app, aiAppEndpoint{Host: host, Source: endpointFromShell, Setting: name})
			}
		}
	}

	// Claude Code's own settings file carries an env block, which beats
	// any shell: it applies however the tool was started.
	if body, err := readLocal(h.join(".claude", "settings.json"), maxProfileBytes); err == nil {
		var doc struct {
			Env map[string]string `json:"env"`
		}
		if json.Unmarshal(body, &doc) == nil {
			if host := endpointHost(doc.Env["ANTHROPIC_BASE_URL"]); host != "" {
				add("Claude Code", aiAppEndpoint{Host: host, Source: endpointFromConfig, Setting: "env.ANTHROPIC_BASE_URL"})
			}
		}
	}

	// Continue's config names a base URL per model. The extension is in
	// the inventory as "Continue in <editor>", so the endpoint is
	// attached under that prefix by the caller.
	if body, err := readLocal(h.join(".continue", "config.json"), maxProfileBytes); err == nil {
		var doc struct {
			Models []struct {
				APIBase string `json:"apiBase"`
			} `json:"models"`
		}
		if json.Unmarshal(body, &doc) == nil {
			for _, m := range doc.Models {
				if host := endpointHost(m.APIBase); host != "" {
					add("Continue", aiAppEndpoint{Host: host, Source: endpointFromConfig, Setting: "models.apiBase"})
				}
			}
		}
	}

	// Zed names one address per provider in its settings.
	if body, err := readLocal(h.zedSettings(), maxProfileBytes); err == nil {
		var doc struct {
			LanguageModels map[string]struct {
				APIURL string `json:"api_url"`
			} `json:"language_models"`
		}
		if json.Unmarshal(stripJSONC(body), &doc) == nil {
			for provider, m := range doc.LanguageModels {
				host := endpointHost(m.APIURL)
				if host == "" || !settingName.MatchString(provider) {
					continue
				}
				add("Zed", aiAppEndpoint{Host: host, Source: endpointFromConfig,
					Setting: "language_models." + provider + ".api_url"})
			}
		}
	}

	return out
}

// deviceSettingPattern is the service's rule for a setting name, repeated
// here so a row that would be refused at the other end is dropped on this
// side instead — one odd setting must not cost a whole report.
var deviceSettingPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// settingName is the same rule applied to the one part of a setting name
// that comes out of somebody else's file — a provider key in Zed's
// settings — before it is joined into a longer name.
var settingName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,40}$`)

// shellBaseURLs reads the login profiles for the variables in
// baseURLVars, and returns the last assignment of each: a profile read top
// to bottom leaves the last one in force.
func shellBaseURLs(h agentHost) map[string]string {
	wanted := map[string]bool{}
	for _, v := range baseURLVars {
		wanted[v.Name] = true
	}
	found := map[string]string{}
	for _, rel := range shellProfiles {
		path := h.join(rel)
		if path == "" {
			continue
		}
		body, err := readLocal(path, maxProfileBytes)
		if err != nil {
			continue
		}
		for _, m := range assignment.FindAllStringSubmatch(string(body), -1) {
			if wanted[m[1]] {
				found[m[1]] = m[2]
			}
		}
	}
	return found
}

// endpointHost reduces a configured value to a bare host, and returns ""
// for anything that is not one.
//
// Three refusals matter. A value holding a shell expansion or a template
// reference is resolved somewhere this cannot see, so reporting a host
// from it would be reporting a guess. A URL's path and query are dropped
// before anything is kept, because that is where a token rides. And a
// value that is not a host in the shape the service accepts is dropped
// whole rather than trimmed into one, since a trimmed value is a value
// that was nearly something else.
func endpointHost(raw string) string {
	v := strings.TrimSpace(raw)
	v = strings.Trim(v, `"'`)
	if v == "" || strings.ContainsAny(v, "$`{}*") {
		return ""
	}
	if host := hostOnly(v); host != "" {
		return host
	}
	// OLLAMA_HOST and its kind are written as a bare address, with no
	// scheme. Accepted only in exactly the shape the report contract
	// takes, which has no room for a path or a query string.
	v = strings.ToLower(strings.TrimSuffix(v, "/"))
	if len(v) <= 253 && deviceHostPattern.MatchString(v) {
		return v
	}
	return ""
}

// endpointWhere names a source in the words a person would use for it.
func endpointWhere(source string) string {
	if source == endpointFromShell {
		return "a shell profile"
	}
	return "its settings file"
}

// appsWithEndpoint counts the applications that name at least one.
func appsWithEndpoint(apps []aiApp) int {
	n := 0
	for _, a := range apps {
		if len(a.Endpoints) > 0 {
			n++
		}
	}
	return n
}

// withEndpoints attaches the configured endpoints to the applications the
// inventory found.
//
// An application that is not installed gets nothing, and an endpoint whose
// application is not installed is dropped: this reports where the AI on
// this machine is pointed, not what variables the machine happens to set.
// An editor extension is named "<extension> in <editor>", so its endpoints
// are matched on the extension's own name.
func withEndpoints(apps []aiApp, endpoints map[string][]aiAppEndpoint) []aiApp {
	if len(endpoints) == 0 {
		return apps
	}
	for i := range apps {
		name := apps[i].Name
		if found, ok := endpoints[name]; ok {
			apps[i].Endpoints = append(apps[i].Endpoints, found...)
			continue
		}
		if base, _, ok := strings.Cut(name, " in "); ok {
			if found, ok := endpoints[base]; ok {
				apps[i].Endpoints = append(apps[i].Endpoints, found...)
			}
		}
	}
	return apps
}
