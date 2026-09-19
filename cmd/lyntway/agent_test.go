package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The agent's seam tests run the whole of runOnce — inventory, MCP
// discovery, connection attribution, the server-mode scan, the report and
// the send — against a fixture machine and a fake receiver. The machine's
// live state is the only thing replaced: the process list and connection
// table come from fixtures, and the local-model probes answer as told.

const testAgentKey = "lw_test_agentkey_0123456789abcdef"

// receiver is a fake Lyntway that records what the agent sends.
type receiver struct {
	mu       sync.Mutex
	reports  [][]byte
	attests  [][]byte
	auth     []string
	requests int
}

func (rc *receiver) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		defer rc.mu.Unlock()
		rc.requests++
		rc.auth = append(rc.auth, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/report":
			rc.reports = append(rc.reports, body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"next_report_seconds": 300}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/attest":
			rc.attests = append(rc.attests, body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"receipt": {"id": "rcpt_x"}}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// agentFixture is a machine: a home with MCP configs holding planted
// credentials, a server directory with keys in files, a process list and
// a connection table.
type agentFixture struct {
	host    agentHost
	scanDir string
	state   string
}

func newAgentFixture(t *testing.T) agentFixture {
	t.Helper()
	h := fixtureHost(t, "darwin")
	t.Setenv("HOME", h.Home)
	project := filepath.Join(h.Root, "work", "app")
	_ = os.MkdirAll(project, 0o700)
	for name, rel := range mcpFixturePaths["darwin"] {
		plantFixture(t, name, filepath.Join(h.Home, filepath.FromSlash(rel)), project)
	}
	for name, rel := range mcpCommonPaths {
		plantFixture(t, name, filepath.Join(h.Home, filepath.FromSlash(rel)), project)
	}

	// Applications: one bundle with a readable version, and an editor
	// extension folder.
	bundle := filepath.Join(h.Root, "Applications", "ChatGPT.app", "Contents")
	_ = os.MkdirAll(bundle, 0o755)
	_ = os.WriteFile(filepath.Join(bundle, "Info.plist"), []byte(`<?xml version="1.0"?><plist><dict>
<key>CFBundleShortVersionString</key>
<string>1.2025.300</string></dict></plist>`), 0o644)
	_ = os.MkdirAll(filepath.Join(h.Home, ".vscode", "extensions", "github.copilot-chat-0.31.0"), 0o755)

	// A server's worth of files.
	scan := filepath.Join(h.Root, "srv", "api")
	_ = os.MkdirAll(filepath.Join(scan, "node_modules", "dep"), 0o755)
	write := func(rel, body string) {
		p := filepath.Join(scan, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".env", "PORT=8080\nOPENAI_API_KEY="+tOpenAI+"\nMISTRAL_API_KEY="+tMistral+"\n")
	write("worker/settings.py", "ANTHROPIC_KEY = '"+tAnthropic+"'\nBASE = 'https://api.anthropic.com'\n")
	write("requirements.txt", "openai==1.40.0\nanthropic>=0.30\nrequests\n")
	// A dependency's own fixture is somebody else's business.
	write("node_modules/dep/test.env", "OPENAI_API_KEY="+tOpenAI+"\n")

	return agentFixture{host: h, scanDir: scan, state: filepath.Join(h.Root, "state")}
}

// stubMachine replaces live readings with fixtures for the test's life.
func stubMachine(t *testing.T, ollama, proxy bool) {
	t.Helper()
	prevP, prevC, prevL, prevX, prevT := listProcessesFn, sampleConnectionsFn, probeLocalModel, probeAgentProxy, stdinIsTerminal
	t.Cleanup(func() {
		listProcessesFn, sampleConnectionsFn, probeLocalModel, probeAgentProxy, stdinIsTerminal = prevP, prevC, prevL, prevX, prevT
	})
	listProcessesFn = func(string) ([]procInfo, error) { return parsePS(readNetFixture(t, "ps.txt")), nil }
	sampleConnectionsFn = func(string) ([]tcpConn, error) { return parseLsof(readNetFixture(t, "lsof.txt")), nil }
	probeLocalModel = func(url string) bool { return ollama && strings.Contains(url, ":11434") }
	probeAgentProxy = func(string) (map[string]any, bool) {
		if !proxy {
			return nil, false
		}
		return map[string]any{"tool": proxyTool, "upstream": "http://127.0.0.1:11434"}, true
	}
	stdinIsTerminal = func() bool { return false }
}

func newTestAgent(t *testing.T, fx agentFixture, opts agentOptions) *agent {
	t.Helper()
	opts.StateDir = fx.state
	if opts.Interval == 0 {
		opts.Interval = 5 * time.Millisecond
		opts.Window = 12 * time.Millisecond
	}
	a, err := newAgent(opts)
	if err != nil {
		t.Fatal(err)
	}
	a.host = fx.host
	a.log = io.Discard
	a.resolver, _ = fakeResolver(map[string][]string{
		"api2.cursor.sh": {"104.18.1.1"}, "api.anthropic.com": {"2607:6bc0::10"},
		"api.openai.com": {"104.18.2.2"}, "chatgpt.com": {"104.18.2.2"},
	}, nil)
	return a
}

func captureStdout(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = prev })
	return &buf
}

// contractReport is the device report contract, decoded strictly: a field
// the contract does not name fails the test.
type contractReport struct {
	DeviceID  string `json:"device_id"`
	Kind      string `json:"kind"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	OSVersion string `json:"os_version"`
	Agent     string `json:"agent"`
	User      string `json:"user"`
	Coverage  []struct {
		Surface string `json:"surface"`
		Level   string `json:"level"`
		Detail  string `json:"detail"`
	} `json:"coverage"`
	AIApps []struct {
		Name    string `json:"name"`
		Kind    string `json:"kind"`
		Running bool   `json:"running"`
		Version string `json:"version"`
	} `json:"ai_apps"`
	MCPServers []struct {
		Client         string `json:"client"`
		Name           string `json:"name"`
		Transport      string `json:"transport"`
		Host           string `json:"host"`
		HasCredentials bool   `json:"has_credentials"`
	} `json:"mcp_servers"`
	Destinations []struct {
		Host        string `json:"host"`
		App         string `json:"app"`
		Connections int    `json:"connections"`
	} `json:"destinations"`
	WindowSeconds *int   `json:"window_seconds"`
	ReportedAt    string `json:"reported_at"`
}

func decodeContract(t *testing.T, body []byte) contractReport {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var r contractReport
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("the report does not match the contract: %v\n%s", err, body)
	}
	oneOf := func(field, v string, allowed ...string) {
		t.Helper()
		for _, a := range allowed {
			if v == a {
				return
			}
		}
		t.Errorf("%s = %q, not one of %v", field, v, allowed)
	}
	if !deviceIDPattern.MatchString(r.DeviceID) {
		t.Errorf("device_id %q does not match dev_<22-40 [a-z0-9]>", r.DeviceID)
	}
	oneOf("kind", r.Kind, "laptop", "server")
	oneOf("os", r.OS, "macos", "windows", "linux", "other")
	if !strings.HasPrefix(r.Agent, "lyntway-agent/") {
		t.Errorf("agent = %q", r.Agent)
	}
	surfaces := map[string]bool{}
	for _, c := range r.Coverage {
		oneOf("coverage.surface", c.Surface, "desktop_apps", "local_models", "mcp", "server_env", "outbound")
		oneOf("coverage.level", c.Level, "content", "metadata", "none")
		if c.Detail == "" {
			t.Errorf("coverage for %s has no detail", c.Surface)
		}
		surfaces[c.Surface] = true
	}
	if len(surfaces) != 5 {
		t.Errorf("coverage names %d surfaces, want all 5", len(surfaces))
	}
	for _, a := range r.AIApps {
		oneOf("ai_apps.kind", a.Kind, "desktop", "cli", "sdk", "local_model")
	}
	for _, m := range r.MCPServers {
		oneOf("mcp_servers.client", m.Client, "claude-desktop", "cursor", "vscode", "windsurf", "other")
		oneOf("mcp_servers.transport", m.Transport, "stdio", "http")
		if m.Host != "" && !deviceHostPattern.MatchString(m.Host) {
			t.Errorf("mcp host %q is not a bare host", m.Host)
		}
	}
	for _, d := range r.Destinations {
		if !deviceHostPattern.MatchString(d.Host) {
			t.Errorf("destination host %q is not a bare host", d.Host)
		}
	}
	for _, c := range r.Coverage {
		if n := len([]rune(c.Detail)); n > maxCoverageDetail || strings.ContainsAny(c.Detail, "\n\r") {
			t.Errorf("coverage detail for %s is %d characters or multi-line: %q", c.Surface, n, c.Detail)
		}
	}
	if r.WindowSeconds == nil || *r.WindowSeconds < 1 {
		t.Error("window_seconds missing or below 1")
	}
	if looksSecret(string(body)) {
		t.Error("the endpoint's own secret scan would refuse this report")
	}
	if _, err := time.Parse(time.RFC3339, r.ReportedAt); err != nil {
		t.Errorf("reported_at %q is not RFC 3339", r.ReportedAt)
	}
	for _, list := range []string{`"ai_apps":null`, `"mcp_servers":null`, `"destinations":null`, `"coverage":null`} {
		if bytes.Contains(bytes.ReplaceAll(body, []byte(" "), nil), []byte(list)) {
			t.Errorf("%s: an empty list must be [], not null", list)
		}
	}
	return r
}

func TestAgentOnceSendsTheContractAndNoCredential(t *testing.T) {
	fx := newAgentFixture(t)
	stubMachine(t, true, false)
	rc := &receiver{}
	srv := httptest.NewServer(rc.handler(t))
	defer srv.Close()
	t.Setenv("LYNTWAY_API_KEY", testAgentKey)
	t.Setenv("LYNTWAY_URL", srv.URL)
	out := captureStdout(t)

	a := newTestAgent(t, fx, agentOptions{Once: true, Scan: []string{fx.scanDir}})
	if err := a.runOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(rc.reports) != 1 {
		t.Fatalf("%d reports sent, want 1", len(rc.reports))
	}
	for _, h := range rc.auth {
		if h != "Bearer "+testAgentKey {
			t.Errorf("Authorization = %q", h)
		}
	}
	r := decodeContract(t, rc.reports[0])
	if r.Kind != "laptop" || r.User != "someone" {
		t.Errorf("kind %q, user %q", r.Kind, r.User)
	}

	// What was found, so the absence checks below are about a report that
	// had the credentials within reach.
	var creds int
	for _, m := range r.MCPServers {
		if m.HasCredentials {
			creds++
		}
	}
	if creds != 7 {
		t.Errorf("%d MCP servers flagged as holding a credential, want 7", creds)
	}
	apps := map[string]bool{}
	for _, app := range r.AIApps {
		apps[app.Name+"@"+app.Version] = app.Running
	}
	if _, ok := apps["ChatGPT@1.2025.300"]; !ok {
		t.Errorf("ChatGPT and its bundle version missing: %v", apps)
	}
	if running, ok := apps["GitHub Copilot Chat in VS Code@0.31.0"]; !ok || running {
		t.Errorf("an installed extension in an editor that is not running: %v", apps)
	}
	if !apps["Claude Code@"] && !apps["Claude Code@2.1.277"] {
		t.Errorf("Claude Code should be running: %v", apps)
	}
	cov := map[string]string{}
	for _, c := range r.Coverage {
		cov[c.Surface] = c.Level
	}
	if cov["local_models"] != "metadata" || cov["server_env"] != "metadata" || cov["outbound"] != "metadata" {
		t.Errorf("coverage: %v", cov)
	}

	// The keys went to /v1/attest as classes and counts, by file.
	if len(rc.attests) != 2 {
		t.Fatalf("%d attestations, want one per file with a key (2): %s", len(rc.attests), bytes.Join(rc.attests, []byte("\n")))
	}
	var att keyAttestation
	if err := json.Unmarshal(rc.attests[0], &att); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, att.OccurredAt); err != nil {
		t.Errorf("occurred_at %q: every attestation carries when the finding was made", att.OccurredAt)
	}
	if shared, err := os.ReadFile(filepath.Join(fx.host.Home, ".lyntway", "device_id")); err != nil || strings.TrimSpace(string(shared)) != r.DeviceID {
		t.Errorf("the device id was not published at ~/.lyntway/device_id for the extension to read (%v)", err)
	}
	if att.Tool != "lyntway-agent" || att.ChainID != "device:"+r.DeviceID || att.Reference != r.DeviceID {
		t.Errorf("attestation identity: %+v", att)
	}
	if att.Action.Target != filepath.ToSlash(filepath.Join(fx.scanDir, ".env")) || len(att.Findings) != 2 {
		t.Errorf("attestation for .env: %+v", att)
	}
	for _, body := range rc.attests {
		if bytes.Contains(body, []byte("node_modules")) {
			t.Error("a dependency's file was reported")
		}
	}

	// The bytes on disk are the bytes that were sent.
	saved, err := os.ReadFile(filepath.Join(fx.state, "last-report.json"))
	if err != nil || !bytes.Equal(saved, rc.reports[0]) {
		t.Errorf("last-report.json differs from what was sent (%v)", err)
	}

	// And no credential, planted anywhere this read, is in anything that
	// left or was printed or was kept.
	attested, _ := os.ReadFile(filepath.Join(fx.state, "attested.json"))
	everything := string(bytes.Join(append(append(rc.reports, rc.attests...), saved, attested, out.Bytes()), []byte("\n")))
	assertNoValue(t, everything)
	if strings.Contains(out.String(), testAgentKey) || strings.Contains(string(saved), testAgentKey) {
		t.Error("the Lyntway key was printed or saved in the report")
	}
	if !strings.Contains(out.String(), "OPENAI_BASE_URL="+srv.URL+"/gw/openai/v1") {
		t.Errorf("the routing change was not printed:\n%s", out)
	}

	// A second run with nothing changed reports the device again and the
	// same keys not again.
	a2 := newTestAgent(t, fx, agentOptions{Once: true, Scan: []string{fx.scanDir}})
	if err := a2.runOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rc.reports) != 2 || len(rc.attests) != 2 {
		t.Errorf("after a second run: %d reports, %d attestations; want 2 and 2", len(rc.reports), len(rc.attests))
	}
	var r2 contractReport
	_ = json.Unmarshal(rc.reports[1], &r2)
	if r2.DeviceID != r.DeviceID {
		t.Errorf("the device id changed between runs: %s then %s", r.DeviceID, r2.DeviceID)
	}
}

func TestAgentDryRunSendsAndWritesNothing(t *testing.T) {
	fx := newAgentFixture(t)
	stubMachine(t, false, false)
	rc := &receiver{}
	srv := httptest.NewServer(rc.handler(t))
	defer srv.Close()
	t.Setenv("LYNTWAY_API_KEY", testAgentKey)
	t.Setenv("LYNTWAY_URL", srv.URL)
	out := captureStdout(t)

	a := newTestAgent(t, fx, agentOptions{DryRun: true, Scan: []string{fx.scanDir}})
	if err := a.runOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rc.requests != 0 {
		t.Errorf("--dry-run made %d requests", rc.requests)
	}
	if _, err := os.Stat(fx.state); !os.IsNotExist(err) {
		t.Errorf("--dry-run created its state directory (%v)", err)
	}
	text := out.String()
	start := strings.Index(text, "\n{\n")
	end := strings.Index(text, "\n}\n")
	if start < 0 || end < 0 {
		t.Fatalf("the report was not printed:\n%s", text)
	}
	decodeContract(t, []byte(text[start+1:end+2]))
	if !strings.Contains(text, "would go to /v1/attest") {
		t.Error("the findings that would be attested were not shown")
	}
	assertNoValue(t, text)
}

func TestAgentWithoutAKeyNeedsDryRun(t *testing.T) {
	fx := newAgentFixture(t)
	t.Setenv("LYNTWAY_API_KEY", "")
	if _, err := newAgent(agentOptions{Once: true, StateDir: fx.state}); err == nil || !strings.Contains(err.Error(), "LYNTWAY_API_KEY") {
		t.Errorf("err = %v", err)
	}
	if _, err := newAgent(agentOptions{DryRun: true, StateDir: fx.state}); err != nil {
		t.Errorf("--dry-run should need no key: %v", err)
	}
}

func TestAgentRefusesAKeyOnTheCommandLine(t *testing.T) {
	err := agentCommand([]string{"--dry-run", "--key", testAgentKey})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), testAgentKey) {
		t.Error("the refusal repeated the key")
	}
}

func TestAgentReportsAServerThatDoesNotAcceptReportsYet(t *testing.T) {
	fx := newAgentFixture(t)
	stubMachine(t, false, false)
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	t.Setenv("LYNTWAY_API_KEY", testAgentKey)
	t.Setenv("LYNTWAY_URL", srv.URL)
	captureStdout(t)
	a := newTestAgent(t, fx, agentOptions{Once: true})
	err := a.runOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "does not accept device reports yet") {
		t.Errorf("err = %v", err)
	}
}

func TestLocalModelCoverageIsContentOnlyBehindTheProxy(t *testing.T) {
	ollama := []string{"Ollama on 127.0.0.1:11434"}
	cases := []struct {
		name  string
		s     localModelState
		dests []destination
		want  string
	}{
		{"nothing running", localModelState{}, nil, "none"},
		{"unfronted", localModelState{Servers: ollama}, nil, "metadata"},
		{"fronted", localModelState{Servers: ollama, ProxyRunning: true}, []destination{{Host: "localhost:11435", App: "Cursor", Connections: 2}, {Host: "localhost:11434", App: "lyntway", Connections: 2}}, "content"},
		{"fronted but bypassed", localModelState{Servers: ollama, ProxyRunning: true}, []destination{{Host: "localhost:11434", App: "Cursor", Connections: 1}}, "metadata"},
		{"proxy with nothing behind it", localModelState{ProxyRunning: true}, nil, "none"},
	}
	for _, c := range cases {
		if got := localModelCoverage(c.s, c.dests); got.Level != c.want {
			t.Errorf("%s: level %q, want %q (%s)", c.name, got.Level, c.want, got.Detail)
		}
	}
}

func TestOutboundCoverageSaysWhatItCouldNotSee(t *testing.T) {
	none := buildCoverage(coverageInputs{GOOS: "darwin"})
	if none[4].Surface != "outbound" || none[4].Level != "none" {
		t.Errorf("no samples must read none: %+v", none[4])
	}
	some := buildCoverage(coverageInputs{GOOS: "darwin", Samples: 3, Interval: 30 * time.Second, Window: 90 * time.Second})
	if some[4].Level != "metadata" || !strings.Contains(some[4].Detail, "only this user's processes") {
		t.Errorf("an unelevated macOS sample must say it saw only this user: %+v", some[4])
	}
	root := buildCoverage(coverageInputs{GOOS: "darwin", Elevated: true, Samples: 3})
	if strings.Contains(root[4].Detail, "only this user's") {
		t.Errorf("root sees everyone: %+v", root[4])
	}
	for _, c := range some {
		if c.Surface == "desktop_apps" && c.Level != "metadata" {
			t.Errorf("an inventory is never more than metadata: %+v", c)
		}
	}
}

func TestDeviceIDIsMadeOnceAndKept(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	id, stored, err := loadDeviceID(dir, false)
	if err != nil || stored || !deviceIDPattern.MatchString(id) {
		t.Fatalf("dry run: %q %v %v", id, stored, err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("a dry run wrote the device id")
	}
	first, stored, err := loadDeviceID(dir, true)
	if err != nil || !stored {
		t.Fatal(err)
	}
	again, _, _ := loadDeviceID(dir, true)
	if again != first {
		t.Errorf("the id changed: %s then %s", first, again)
	}
	if info, _ := os.Stat(filepath.Join(dir, "device_id")); info.Mode().Perm() != 0o600 {
		t.Errorf("device_id mode %v", info.Mode().Perm())
	}
	_ = os.WriteFile(filepath.Join(dir, "device_id"), []byte("dev_NOT-VALID\n"), 0o600)
	replaced, _, _ := loadDeviceID(dir, true)
	if replaced == first || !deviceIDPattern.MatchString(replaced) {
		t.Errorf("a corrupted id was kept or replaced badly: %q", replaced)
	}
}

func TestKeyAttestationsCarryNoValueAndChangeWithTheFile(t *testing.T) {
	s := serverScan{
		Keys: []keyAtRest{
			{File: "/srv/app/.env", Class: "secret.openai_key", Upstream: "openai"},
			{File: "/srv/app/.env", Class: "secret.openai_key", Upstream: "openai"},
			{File: "/srv/app/.env", Class: "provider.mistral", Upstream: "mistral"},
		},
		Modified: map[string]time.Time{"/srv/app/.env": time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)},
	}
	atts := keyAttestations(s, "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa", "web-1")
	if len(atts) != 1 || len(atts[0].Findings) != 2 || atts[0].Findings[1].Count != 2 {
		t.Fatalf("%+v", atts)
	}
	if atts[0].Action.Destination != "file://web-1/srv/app/.env#modified=2026-09-01T10:00:00Z" {
		t.Errorf("destination %q", atts[0].Action.Destination)
	}
	s.Modified["/srv/app/.env"] = s.Modified["/srv/app/.env"].Add(time.Hour)
	later := keyAttestations(s, "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa", "web-1")
	if later[0].Action.Destination == atts[0].Action.Destination {
		t.Error("a changed file must not reuse the destination the receipt id is derived from")
	}
	if later[0].fingerprint() == atts[0].fingerprint() {
		t.Error("a changed file must be reported again")
	}
	// The same file found the same way tomorrow is not a new finding.
	s.ScannedAt = s.ScannedAt.Add(24 * time.Hour)
	tomorrow := keyAttestations(s, "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa", "web-1")
	if tomorrow[0].OccurredAt == later[0].OccurredAt || tomorrow[0].fingerprint() != later[0].fingerprint() {
		t.Error("the finding's time must be sent but must not make an unchanged file new")
	}
}

func TestRoutingAdviceNamesTheChangeAndNotTheKey(t *testing.T) {
	s := serverScan{
		Keys: []keyAtRest{{File: "/srv/app/.env", Class: "secret.openai_key", Upstream: "openai"}},
		SDKs: []sdkUse{{Name: "anthropic", Upstream: "anthropic", Dir: "/srv/worker"}},
	}
	dests := []destination{
		{Host: "api.groq.com", App: "python3", Connections: 3},
		{Host: "api.anthropic.com", App: "node", Connections: 2},
		{Host: "160.79.104.10", App: "node", Connections: 5},
		{Host: "bedrock-runtime.us-east-1.amazonaws.com", App: "java", Connections: 1},
		{Host: "chatgpt.com", App: "python3", Connections: 1},
		{Host: "api2.cursor.sh", App: "Cursor", Connections: 4},
	}
	got := routingAdvice("https://lyntway.example", s, dests)
	for _, unwanted := range []string{"chatgpt.com", "cursor.sh", "160.79.104.10"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("no setting on a server reaches %s, so nothing may be advised for it:\n%s", unwanted, got)
		}
	}
	for _, want := range []string{
		"2 connections to api.anthropic.com from node",
		"bedrock-runtime.us-east-1.amazonaws.com (1 connection from java)",
		"The LiteLLM callback",
		"OPENAI_BASE_URL=https://lyntway.example/gw/openai/v1",
		"OPENAI_API_KEY=<your Lyntway key>~<your OpenAI key>",
		"lyntway keys migrate /srv/app",
		"ANTHROPIC_BASE_URL=https://lyntway.example/gw/anthropic",
		"ANTHROPIC_AUTH_TOKEN=<your Lyntway key>",
		"api.groq.com (3 connections from python3)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("advice lacks %q:\n%s", want, got)
		}
	}
}

func TestServiceDefinitionsCarryNoKey(t *testing.T) {
	t.Setenv("LYNTWAY_API_KEY", testAgentKey)
	for _, goos := range []string{"darwin", "linux", "windows"} {
		for _, system := range []bool{false, true} {
			spec := serviceSpec{GOOS: goos, System: system, Exe: "/opt/lyntway/bin/lyntway", StateDir: "/var/lib/lyntway",
				Args: agentServiceArgs("/var/lib/lyntway", true, false, []string{"/srv/my app"}), LogPath: "/var/lib/lyntway/agent.log", User: "someone"}
			path, body, cmds := serviceDefinition(spec)
			text := string(body)
			if goos == "windows" {
				if !bytes.HasPrefix(body, []byte{0xFF, 0xFE}) {
					t.Errorf("%s: the task XML must be UTF-16 with a BOM", goos)
				}
				text = taskXML(spec)
				if !strings.Contains(text, "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>") {
					t.Errorf("%s: without PT0S the task stops after 72 hours", goos)
				}
			}
			if strings.Contains(text, testAgentKey) || strings.Contains(strings.Join(cmds[len(cmds)-1], " "), testAgentKey) {
				t.Errorf("%s system=%v: the key is in the service definition", goos, system)
			}
			if !strings.Contains(text, "--server") || !strings.Contains(text, "/var/lib/lyntway") {
				t.Errorf("%s system=%v: arguments missing from %s:\n%s", goos, system, path, text)
			}
			if goos == "linux" {
				if system != strings.Contains(text, "ProtectSystem=strict") {
					t.Errorf("linux system=%v: sandboxing belongs to the system unit only", system)
				}
				if !strings.Contains(text, `"/srv/my app"`) {
					t.Errorf("a path with a space must be quoted in ExecStart:\n%s", text)
				}
				if system == strings.Contains(strings.Join(cmds[0], " "), "--user") {
					t.Errorf("linux system=%v: wrong systemctl scope %v", system, cmds)
				}
			}
			if goos == "darwin" && system != strings.HasPrefix(path, "/Library/LaunchDaemons/") {
				t.Errorf("darwin system=%v: plist at %s", system, path)
			}
		}
	}
}

func TestReadmeCarriesTheExplanation(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil || !bytes.Contains(mod, []byte("lyntway-core")) {
		t.Skip("not the lyntway-core repository; the public mirror's README is generated")
	}
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if os.IsNotExist(err) {
		// The image build copies the tree without *.md (.dockerignore).
		// The CI test job has the README and holds it to the text there.
		t.Skip("README.md is not in this build context")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), agentExplanation) {
		t.Error("README.md's agent section has drifted from `lyntway agent --explain`; paste agentExplanation into it")
	}
}
