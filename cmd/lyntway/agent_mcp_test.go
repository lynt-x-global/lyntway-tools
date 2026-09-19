package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The fixtures carry {{NAME}} placeholders rather than key-shaped values,
// so the repository's secret scanner has nothing to find in testdata; the
// values are the scan tests' constants, planted at run time.
func plantedValues() map[string]string {
	return map[string]string{
		"{{OPENAI}}": tOpenAI, "{{ANTHROPIC}}": tAnthropic, "{{GEMINI}}": tGemini,
		"{{XAI}}": tXAI, "{{MISTRAL}}": tMistral, "{{GITHUB}}": tGitHub,
	}
}

// plantFixture copies testdata/agent/mcp/<name> to dst with the values
// planted. project is written JSON-escaped wherever {{PROJECT}} appears.
func plantFixture(t *testing.T, name, dst, project string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "agent", "mcp", name))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for k, v := range plantedValues() {
		text = strings.ReplaceAll(text, k, v)
	}
	esc, _ := json.Marshal(project)
	text = strings.ReplaceAll(text, `"{{PROJECT}}"`, string(esc))
	if strings.Contains(text, "{{") {
		t.Fatalf("%s: a placeholder was not planted", name)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fixtureHost builds an agentHost for goos rooted in a temp directory. The
// Windows AppData layout is the real one relative to the home directory.
func fixtureHost(t *testing.T, goos string) agentHost {
	t.Helper()
	root := t.TempDir()
	h := agentHost{GOOS: goos, Home: filepath.Join(root, "home"), Root: root, User: "someone"}
	if goos == "windows" {
		h.AppData = filepath.Join(h.Home, "AppData", "Roaming")
		h.LocalAppData = filepath.Join(h.Home, "AppData", "Local")
	}
	return h
}

// Where each client keeps its file, written out per OS by hand rather
// than derived from mcpSources — the test is of those paths.
var mcpFixturePaths = map[string]map[string]string{
	"darwin": {
		"claude_desktop_config.json": "Library/Application Support/Claude/claude_desktop_config.json",
		"vscode_mcp.jsonc":           "Library/Application Support/Code/User/mcp.json",
		"vscode_settings.jsonc":      "Library/Application Support/Code/User/settings.json",
	},
	"windows": {
		"claude_desktop_config.json": "AppData/Roaming/Claude/claude_desktop_config.json",
		"vscode_mcp.jsonc":           "AppData/Roaming/Code/User/mcp.json",
		"vscode_settings.jsonc":      "AppData/Roaming/Code/User/settings.json",
	},
	"linux": {
		"claude_desktop_config.json": ".config/Claude/claude_desktop_config.json",
		"vscode_mcp.jsonc":           ".config/Code/User/mcp.json",
		"vscode_settings.jsonc":      ".config/Code/User/settings.json",
	},
}

// The same on every OS.
var mcpCommonPaths = map[string]string{
	"cursor_mcp.json":          ".cursor/mcp.json",
	"windsurf_mcp_config.json": ".codeium/windsurf/mcp_config.json",
	"claude.json":              ".claude.json",
}

func TestMCPDiscoveryReadsEveryClientOnEveryOS(t *testing.T) {
	want := []mcpServerInfo{
		{Client: "claude-desktop", Name: "filesystem", Transport: "stdio"},
		{Client: "claude-desktop", Name: "github", Transport: "stdio", HasCredentials: true},
		{Client: "claude-desktop", Name: "linear", Transport: "stdio", Host: "mcp.linear.app", HasCredentials: true},
		{Client: "cursor", Name: "figma", Transport: "http", Host: "127.0.0.1:3845"},
		{Client: "cursor", Name: "postgres", Transport: "stdio", HasCredentials: true},
		{Client: "cursor", Name: "stripe", Transport: "http", Host: "mcp.stripe.com", HasCredentials: true},
		{Client: "other", Name: "context7", Transport: "http", Host: "mcp.context7.com"},
		{Client: "other", Name: "sequential-thinking", Transport: "stdio"},
		{Client: "other", Name: "supabase", Transport: "stdio", HasCredentials: true},
		{Client: "vscode", Name: "github-remote", Transport: "http", Host: "api.githubcopilot.com"},
		{Client: "vscode", Name: "memory", Transport: "stdio"},
		{Client: "vscode", Name: "playwright", Transport: "stdio"},
		{Client: "vscode", Name: "sentry", Transport: "http", Host: "mcp.sentry.dev:8443", HasCredentials: true},
		{Client: "windsurf", Name: "brave-search", Transport: "stdio", HasCredentials: true},
		{Client: "windsurf", Name: "notion", Transport: "http", Host: "mcp.notion.com"},
	}
	for _, goos := range []string{"darwin", "windows", "linux"} {
		t.Run(goos, func(t *testing.T) {
			h := fixtureHost(t, goos)
			project := filepath.Join(h.Root, "work", "app")
			if err := os.MkdirAll(project, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, rel := range mcpFixturePaths[goos] {
				plantFixture(t, name, filepath.Join(h.Home, filepath.FromSlash(rel)), project)
			}
			for name, rel := range mcpCommonPaths {
				plantFixture(t, name, filepath.Join(h.Home, filepath.FromSlash(rel)), project)
			}
			plantFixture(t, "project_mcp.json", filepath.Join(project, ".mcp.json"), project)
			plantFixture(t, "project_cursor_mcp.json", filepath.Join(project, ".cursor", "mcp.json"), project)
			plantFixture(t, "project_vscode_mcp.jsonc", filepath.Join(project, ".vscode", "mcp.json"), project)

			// The project is found the way it is on a real machine: from
			// Claude Code's own record of it.
			roots := projectRoots(h)
			if len(roots) != 1 || roots[0] != project {
				t.Fatalf("project roots = %v, want [%s]", roots, project)
			}

			d := discoverMCP(mcpSources(h, roots))
			got := append([]mcpServerInfo(nil), d.Servers...)
			sort.Slice(got, func(i, j int) bool {
				if got[i].Client != got[j].Client {
					return got[i].Client < got[j].Client
				}
				return got[i].Name < got[j].Name
			})
			if len(got) != len(want) {
				t.Fatalf("found %d servers, want %d:\n%+v", len(got), len(want), got)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("server %d:\n got %+v\nwant %+v", i, got[i], want[i])
				}
			}
			if d.Read != 9 || len(d.Unreadable) != 0 {
				t.Errorf("read %d files, %d unreadable; want 9 and 0", d.Read, len(d.Unreadable))
			}

			out, _ := json.Marshal(d.Servers)
			assertNoValue(t, string(out))
			for _, frag := range []string{"session=", "/sse", "/v1", "token=", "app:", "npx", "--access-token", "Documents"} {
				if strings.Contains(string(out), frag) {
					t.Errorf("%q reached the report: %s", frag, out)
				}
			}
		})
	}
}

func TestMCPDiscoveryCountsAFileItCannotParse(t *testing.T) {
	h := fixtureHost(t, "linux")
	path := filepath.Join(h.Home, ".cursor", "mcp.json")
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(`{"mcpServers": {`), 0o600)
	d := discoverMCP(mcpSources(h, nil))
	if len(d.Unreadable) != 1 || d.Read != 0 {
		t.Fatalf("unreadable = %v, read = %d", d.Unreadable, d.Read)
	}
	cov := buildCoverage(coverageInputs{MCP: d, Samples: 1})
	if !strings.Contains(cov[1].Detail, "1 file could not be parsed") {
		t.Errorf("coverage does not admit the unparsed file: %s", cov[1].Detail)
	}
}

func TestHostOnlyDropsEverythingButTheHost(t *testing.T) {
	cases := map[string]string{
		"https://mcp.example.com/sse?token=abc#frag":     "mcp.example.com",
		"https://user:pass@mcp.example.com:443/x":        "mcp.example.com",
		"http://127.0.0.1:3845/sse":                      "127.0.0.1:3845",
		"HTTPS://MCP.Example.COM/":                       "mcp.example.com",
		"https://[2001:db8::1]:8443/mcp":                 "[2001:db8::1]:8443",
		"postgresql://app:secret@db.internal:5432/app":   "",
		"@modelcontextprotocol/server-github":            "",
		"https://mcp.example.com/path/with/secret/value": "mcp.example.com",
	}
	for in, want := range cases {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksLikeCredential(t *testing.T) {
	cases := []struct {
		name, value string
		want        bool
	}{
		{"GITHUB_PERSONAL_ACCESS_TOKEN", tGitHub, true},
		{"Authorization", "Bearer " + tAnthropic, true},
		{"Authorization", "Bearer abcdefgh12345678", true},
		{"X-Api-Key", "0123456789abcdef", true},
		{"ANYTHING", tOpenAI, true}, // a known key shape needs no name
		{"Authorization", "Bearer ${input:gh-token}", false},
		{"API_KEY", "${env:MEMORY_KEY}", false},
		{"API_KEY", "$MEMORY_KEY", false},
		{"TOKEN", "{{ secrets.TOKEN }}", false},
		{"API_KEY", "%API_KEY%", false},
		{"API_KEY", "your-key-here", false},
		{"API_KEY", "", false},
		{"TOKEN", "short", false},
		{"AUTH_REQUIRED", "true", false},
		{"GITHUB_OAUTH_CLIENT_ID", "Iv1.0123456789abcdef", false},
		{"AUTH_URL", "https://auth.example.com/authorize", false},
		{"MEMORY_FILE_PATH", "/tmp/memory.json", false},
	}
	for _, c := range cases {
		if got := looksLikeCredential(c.name, c.value); got != c.want {
			t.Errorf("looksLikeCredential(%q, %q) = %v, want %v", c.name, c.value, got, c.want)
		}
	}
}

func TestStripJSONCLeavesStringsAlone(t *testing.T) {
	in := `{
  // comment
  "a": "https://x//y", /* block
  comment */ "b": "// not a comment",
  "c": [1, 2,],
  "d": {"e": "\"quoted // still a string\"",},
}`
	var got map[string]any
	if err := json.Unmarshal(stripJSONC([]byte(in)), &got); err != nil {
		t.Fatalf("%v\n%s", err, stripJSONC([]byte(in)))
	}
	if got["a"] != "https://x//y" || got["b"] != "// not a comment" {
		t.Errorf("strings were altered: %v", got)
	}
	if d := got["d"].(map[string]any); d["e"] != `"quoted // still a string"` {
		t.Errorf("escaped quote mishandled: %v", d["e"])
	}
}
