package main

import (
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The report endpoint refuses a report whole for one bad field: an
// over-long detail, a host that is not a bare host, anything shaped like a
// secret. These tests hold the agent to the same rules before it sends.

func TestCoverageFitsTheEndpointInTheWorstCase(t *testing.T) {
	long := errors.New(strings.Repeat("an error message from an operating system tool that goes on ", 5))
	in := coverageInputs{
		GOOS: "darwin", ProcErr: long, Apps: make([]aiApp, 123),
		MCP:       mcpDiscovery{Servers: make([]mcpServerInfo, 499), Read: 199, Unreadable: make([]string, 17), NotLocal: 12},
		Local:     localModelState{Servers: []string{"Ollama on 127.0.0.1:11434", "LM Studio on 127.0.0.1:1234"}},
		Scan:      &serverScan{Files: 50000, Truncated: true, NotLocal: 1234},
		ScanRoots: defaultServerRoots, Samples: 30, Failures: 29, SampleErr: long,
		Interval: 30 * time.Second, Window: 15 * time.Minute,
	}
	worst := buildCoverage(in)
	in.Samples = 0
	for _, cov := range [][]coverageEntry{worst, buildCoverage(in)} {
		for _, c := range cov {
			if n := len([]rune(c.Detail)); n > maxCoverageDetail {
				t.Errorf("%s: %d characters", c.Surface, n)
			}
			// The clamp is a safety net. A sentence written to fit keeps
			// its caveats, so the worst case must fit without being cut.
			if strings.HasSuffix(c.Detail, "…") {
				t.Errorf("%s was cut to fit: %q", c.Surface, c.Detail)
			}
		}
	}
	for _, c := range worst {
		if c.Surface == "server_env" && (!strings.Contains(c.Detail, "50000-file limit") || !strings.Contains(c.Detail, "cloud storage")) {
			t.Errorf("a caveat was lost: %q", c.Detail)
		}
	}
}

func TestSanitiseReportWithholdsWhatTheEndpointWouldRefuse(t *testing.T) {
	r := deviceReport{
		Hostname: "web-1\nsecond line", Agent: "lyntway-agent/dev", WindowSeconds: 0,
		Coverage: []coverageEntry{{Surface: "mcp", Level: "metadata", Detail: strings.Repeat("x", 400)}},
		AIApps:   []aiApp{{Name: "Claude", Kind: "desktop"}},
		MCPServers: []mcpServerInfo{
			{Client: "other", Name: tGitHub, Transport: "stdio"},
			{Client: "cursor", Name: "ok", Transport: "http", Host: "Bad Host/path"},
		},
		Destinations: []destination{
			{Host: "api.openai.com", App: "python3", Connections: 1},
			{Host: "api.openai.com or chatgpt.com", App: "x", Connections: 1},
			{Host: "[2607:6bc0::10]", App: "node", Connections: 2},
		},
	}
	sanitiseReport(&r)
	if r.MCPServers[0].Name != withheldName {
		t.Errorf("an MCP server named by its token kept the name")
	}
	if r.MCPServers[1].Host != "" {
		t.Errorf("an invalid host was kept: %q", r.MCPServers[1].Host)
	}
	if len(r.Destinations) != 2 || r.Destinations[1].Host != "[2607:6bc0::10]" {
		t.Errorf("destinations: %+v", r.Destinations)
	}
	if r.WindowSeconds != 1 || strings.Contains(r.Hostname, "\n") || len([]rune(r.Coverage[0].Detail)) > maxCoverageDetail {
		t.Errorf("bounds not applied: %+v", r)
	}
	body := agentJSON(r)
	assertNoValue(t, string(body))
	if looksSecret(string(body)) {
		t.Error("the sanitised report would still be refused")
	}
}

func TestAReportThatWouldBeRefusedIsNotSent(t *testing.T) {
	rc := &receiver{}
	srv := httptest.NewServer(rc.handler(t))
	defer srv.Close()
	a := &agent{c: config{Origin: srv.URL, Key: testAgentKey}, client: srv.Client(), opts: agentOptions{StateDir: t.TempDir()}}
	_, err := a.send([]byte(`{"hostname":"` + tOpenAI + `"}`))
	if err == nil || rc.requests != 0 {
		t.Fatalf("a body carrying a key was sent (err %v, %d requests)", err, rc.requests)
	}
	if strings.Contains(err.Error(), tOpenAI) {
		t.Error("the refusal repeated the value")
	}
	if _, statErr := os.Stat(filepath.Join(a.opts.StateDir, "last-report.json")); !os.IsNotExist(statErr) {
		t.Error("a refused report was written to disk as though it had been sent")
	}
}

func TestAnAmbiguousAddressIsReportedAsTheAddress(t *testing.T) {
	r, _ := fakeResolver(map[string][]string{
		"api.anthropic.com": {"160.79.104.10", "2607:6bc0::10"},
		"claude.ai":         {"160.79.104.10", "2607:6bc0::10"},
	}, nil)
	r.refresh()
	if got := r.name(ap("160.79.104.10:443").Addr(), true); got != "160.79.104.10" {
		t.Errorf("v4: %q", got)
	}
	if got := r.name(ap("[2607:6bc0::10]:443").Addr(), true); got != "[2607:6bc0::10]" || !deviceHostPattern.MatchString(got) {
		t.Errorf("v6: %q", got)
	}
}
