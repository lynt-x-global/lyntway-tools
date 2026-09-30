package main

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// Coverage, and the last look at a report before it leaves.
//
// Each detail is one sentence of at most maxCoverageDetail characters,
// because that is what the report endpoint accepts. The sentences are
// written to fit, caveats included; the clamp in sanitiseReport exists so
// an unforeseen error message cannot get a whole report refused, and a test
// holds the worst case under the limit so the clamp never has to cut a
// caveat off in practice.

const maxCoverageDetail = 240

// buildCoverage states, per surface, the weakest level that is true.
func buildCoverage(in coverageInputs) []coverageEntry {
	var out []coverageEntry

	// Desktop apps: never more than metadata. Knowing an app is installed
	// says nothing about what it sent.
	apps := coverageEntry{Surface: "desktop_apps", Level: "metadata"}
	if in.ProcErr != nil {
		apps.Detail = fmt.Sprintf("%d AI app%s found in app and extension folders; the process list could not be read (%s), so none is marked running.",
			len(in.Apps), pluralS(len(in.Apps)), shortErr(in.ProcErr))
	} else {
		apps.Detail = fmt.Sprintf("%d AI app%s found from app folders, editor extensions and process names; names and versions only, nothing they send is seen.",
			len(in.Apps), pluralS(len(in.Apps)))
	}
	// Said here rather than left to the console to infer from the rows:
	// an endpoint is where a file says the app would send, and the
	// surface that carries it must not read as one that saw it go.
	if n := appsWithEndpoint(in.Apps); n > 0 {
		apps.Detail += fmt.Sprintf(" %d name a configured endpoint, from a settings file or a shell profile: configuration, not traffic.", n)
	}
	out = append(out, apps)

	// MCP: configuration, not traffic.
	m := coverageEntry{Surface: "mcp", Level: "metadata"}
	m.Detail = fmt.Sprintf("%d MCP server%s in %d client config file%s; name, transport and host only, never a command, argument or secret, and no tool call is seen",
		len(in.MCP.Servers), pluralS(len(in.MCP.Servers)), in.MCP.Read, pluralS(in.MCP.Read))
	if n := len(in.MCP.Unreadable); n > 0 {
		m.Detail += fmt.Sprintf("; %d file%s could not be parsed", n, pluralS(n))
	}
	if n := in.MCP.NotLocal; n > 0 {
		m.Detail += fmt.Sprintf("; %d in cloud storage, not read", n)
	}
	m.Detail += "."
	out = append(out, m)

	out = append(out, localModelCoverage(in.Local, in.Destinations))

	se := coverageEntry{Surface: "server_env", Level: "none",
		Detail: "Files are not scanned for keys on this device; the agent does that with --server or --scan."}
	if in.Scan != nil {
		se.Level = "metadata"
		// The roots are counted, not listed: a list of paths has no
		// length limit, and the detail does.
		se.Detail = fmt.Sprintf("%d file%s under %d scanned folder%s checked for provider keys; class and path reported, never the value",
			in.Scan.Files, pluralS(in.Scan.Files), len(in.ScanRoots), pluralS(len(in.ScanRoots)))
		if in.Scan.Truncated {
			se.Detail += fmt.Sprintf("; stopped at the %d-file limit, the rest unread", defaultServerLimits.MaxFiles)
		}
		if n := in.Scan.NotLocal; n > 0 {
			se.Detail += fmt.Sprintf("; %d in cloud storage, not read", n)
		}
		se.Detail += "."
	}
	out = append(out, se)

	ob := coverageEntry{Surface: "outbound", Level: "metadata"}
	if in.Samples == 0 {
		ob.Level = "none"
		reason := "no sample was taken"
		if in.SampleErr != nil {
			reason = shortErr(in.SampleErr)
		}
		ob.Detail = fmt.Sprintf("Open connections could not be read (%s), so where AI traffic went is unknown.", reason)
	} else {
		ob.Detail = fmt.Sprintf("TCP connections sampled %d time%s over %s, matched to AI hosts by address; no content, shorter connections than %s missed, shared addresses named by address",
			in.Samples, pluralS(in.Samples), in.Window.Round(time.Second), in.Interval)
		if in.Failures > 0 {
			ob.Detail += fmt.Sprintf("; %d sample%s failed", in.Failures, pluralS(in.Failures))
		}
		if in.GOOS == "darwin" && !in.Elevated {
			ob.Detail += "; only this user's processes seen"
		}
		ob.Detail += "."
	}
	out = append(out, ob)
	return out
}

// localModelCoverage is "content" only while the proxy is in front of a
// local model server and nothing was seen going around it.
func localModelCoverage(s localModelState, dests []destination) coverageEntry {
	e := coverageEntry{Surface: "local_models"}
	bypass := 0
	for _, d := range dests {
		if (d.Host == "localhost:11434" || d.Host == "localhost:1234") && d.App != "lyntway" {
			bypass += d.Connections
		}
	}
	switch {
	case len(s.Servers) == 0 && !s.ProxyRunning:
		e.Level = "none"
		e.Detail = "No local model server is answering on this machine, so there is nothing here to cover."
	case len(s.Servers) == 0 && s.ProxyRunning:
		e.Level = "none"
		e.Detail = "lyntway proxy is running but no local model server answers behind it, so no local prompt is inspected."
	case !s.ProxyRunning:
		e.Level = "metadata"
		e.Detail = fmt.Sprintf("%s with nothing in front, so its prompts are not inspected; run `lyntway proxy` or install the agent with --proxy.", strings.Join(s.Servers, " and "))
	case bypass > 0:
		e.Level = "metadata"
		e.Detail = fmt.Sprintf("lyntway proxy fronts %s, but %d connection%s went straight to the model server, uninspected.", s.ProxyUpstream, bypass, pluralS(bypass))
	default:
		e.Level = "content"
		e.Detail = fmt.Sprintf("lyntway proxy on %s inspects prompts and replies here for apps pointed at it, and none went around it; only classes and counts leave.", defaultProxyListen)
	}
	return e
}

func shortErr(err error) string {
	return oneLine(err.Error(), 80)
}

// oneLine makes s a single line of at most max characters: control
// characters become spaces, and an over-long value is cut with an
// ellipsis. The endpoint refuses multi-line or over-long fields, and one
// odd field should cost that field, not the report.
func oneLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	return strings.TrimSpace(string(runes[:max-1])) + "…"
}

// withheldName replaces a name that is itself shaped like a credential.
const withheldName = "(withheld: shaped like a credential)"

// looksSecret asks the gateway's rules, and the scanner's provider shapes,
// whether a string holds a credential or a card number.
func looksSecret(s string) bool {
	for _, sp := range credentialRules.Scan([]byte(s)) {
		if detect.HasClassPrefix(sp.Class, "secret") || detect.HasClassPrefix(sp.Class, "pci") {
			return true
		}
	}
	return len(findKeys(s, 1)) > 0
}

// sanitiseReport is the last look before a report leaves. Every string
// is made a bounded single line; a host the endpoint would refuse is
// dropped; and any name that is itself shaped like a key — somebody
// called an MCP server by the token it uses — is withheld. Without this, a
// single such field gets the whole report refused by the service, which
// scans for exactly that; with it, the field is lost and the device still
// reports.
func sanitiseReport(r *deviceReport) {
	field := func(s string, max int) string {
		s = oneLine(s, max)
		if looksSecret(s) {
			return withheldName
		}
		return s
	}
	r.Hostname = field(r.Hostname, 253)
	r.OSVersion = field(r.OSVersion, 64)
	r.User = field(r.User, 254)
	r.Agent = oneLine(r.Agent, 64)
	if r.WindowSeconds < 1 {
		// A single sample is still a window of something; the endpoint
		// counts from one.
		r.WindowSeconds = 1
	}
	for i := range r.Coverage {
		r.Coverage[i].Detail = field(r.Coverage[i].Detail, maxCoverageDetail)
	}
	for i := range r.AIApps {
		r.AIApps[i].Name = field(r.AIApps[i].Name, 100)
		r.AIApps[i].Version = field(r.AIApps[i].Version, 64)
		// An endpoint that is not exactly a host, a known source and a
		// name-shaped setting is dropped, not repaired. The endpoint is
		// the field most likely to arrive carrying a whole URL, and a URL
		// carries a query string; a rule that trimmed one into a host
		// would be a rule that sometimes kept the part it meant to lose.
		kept := r.AIApps[i].Endpoints[:0]
		for _, e := range r.AIApps[i].Endpoints {
			e.Host = strings.ToLower(strings.TrimSpace(e.Host))
			if len(e.Host) > 253 || !deviceHostPattern.MatchString(e.Host) {
				continue
			}
			if e.Source != endpointFromShell && e.Source != endpointFromConfig {
				continue
			}
			if e.Setting != "" && !deviceSettingPattern.MatchString(e.Setting) {
				continue
			}
			if len(kept) >= maxEndpointsPerApp {
				break
			}
			kept = append(kept, e)
		}
		r.AIApps[i].Endpoints = kept
	}
	for i := range r.MCPServers {
		m := &r.MCPServers[i]
		m.Name = field(m.Name, 100)
		m.Host = strings.ToLower(m.Host)
		if m.Host != "" && (len(m.Host) > 253 || !deviceHostPattern.MatchString(m.Host)) {
			m.Host = ""
		}
	}
	kept := r.Destinations[:0]
	for _, d := range r.Destinations {
		d.Host = strings.ToLower(d.Host)
		if len(d.Host) > 253 || !deviceHostPattern.MatchString(d.Host) {
			continue
		}
		d.App = field(d.App, 100)
		kept = append(kept, d)
	}
	r.Destinations = kept
}
