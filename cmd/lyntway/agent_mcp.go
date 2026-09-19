package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Which MCP servers the AI clients on this machine are configured to start
// or reach.
//
// # What is read, and what is kept of it
//
// Each client keeps a JSON file naming its servers. From each entry four
// facts survive: the server's name, whether it runs as a local process or
// is reached over HTTP, the host it reaches (never the path, never the
// query string, never user information), and whether a credential is sitting
// in the file beside it. The command line, the arguments, the environment
// and the headers are read so those facts can be established and are then
// dropped. The type that leaves this file, mcpServerInfo, has no field that
// could hold any of them, which is the guard: a value cannot be reported by
// a struct with nowhere to put it.
//
// # Why has_credentials matters and a value never does
//
// A token pasted into claude_desktop_config.json is readable by every
// process running as that person, synced by whatever backs up their home
// directory, and invisible to the security team. That it is there is the
// finding. What it is would turn this agent into the leak it reports.
//
// # What it does not see
//
// A server added through a client's settings screen that stores it
// somewhere other than these files; a server a client fetches from its
// vendor's cloud; and whatever the servers actually do when called. This
// is configuration, not traffic.

// mcpServerInfo is one configured server, as reported. Nothing else about
// a server leaves the machine.
type mcpServerInfo struct {
	Client         string `json:"client"`
	Name           string `json:"name"`
	Transport      string `json:"transport"`
	Host           string `json:"host"`
	HasCredentials bool   `json:"has_credentials"`
}

// mcpSource is one file a client reads its servers from.
type mcpSource struct {
	// Client is the contract's name: claude-desktop, cursor, vscode,
	// windsurf, or other. Claude Code, Gemini CLI and Zed are "other"
	// because the report contract names no more; Label keeps the truth
	// for the person reading the local output.
	Client string
	Label  string
	Path   string
	// Keys is where the server map lives inside the file, tried in
	// order: "mcpServers" for most, "servers" for VS Code, "mcp.servers"
	// for VS Code's older settings.json form.
	Keys []string
	// JSONC means the file allows comments and trailing commas, as VS Code
	// and Zed settings do.
	JSONC bool
}

// mcpSources lists every file this looks at for one user.
//
// projects are directories somebody has opened in an editor or in Claude
// Code; each can carry its own server list, and those are as real as the
// global ones.
func mcpSources(h agentHost, projects []string) []mcpSource {
	var out []mcpSource
	add := func(client, label, path string, jsonc bool, keys ...string) {
		if path == "" {
			return
		}
		out = append(out, mcpSource{Client: client, Label: label, Path: path, Keys: keys, JSONC: jsonc})
	}

	// Claude Desktop keeps its file in the platform's application
	// support directory.
	add("claude-desktop", "Claude Desktop", h.appSupport("Claude", "claude_desktop_config.json"), false, "mcpServers")

	// Cursor: one global file, one per project.
	add("cursor", "Cursor", h.join(".cursor", "mcp.json"), false, "mcpServers")

	// VS Code (and Insiders): the dedicated mcp.json, and the settings
	// file that held servers before it existed.
	for _, product := range []string{"Code", "Code - Insiders"} {
		add("vscode", "VS Code", h.appSupport(product, "User", "mcp.json"), true, "servers")
		add("vscode", "VS Code", h.appSupport(product, "User", "settings.json"), true, "mcp.servers")
	}

	// Windsurf keeps its file under Codeium's directory on every OS.
	add("windsurf", "Windsurf", h.join(".codeium", "windsurf", "mcp_config.json"), false, "mcpServers")

	// Claude Code: user and per-project servers in ~/.claude.json, plus
	// the settings file the CLI's own init reads.
	add("other", "Claude Code", h.join(".claude.json"), false, "mcpServers")
	add("other", "Claude Code", h.join(".claude", "settings.json"), false, "mcpServers")

	// Others that are common enough to be worth a stat.
	add("other", "Gemini CLI", h.join(".gemini", "settings.json"), false, "mcpServers")
	add("other", "Zed", h.zedSettings(), true, "context_servers")

	for _, p := range projects {
		add("cursor", "Cursor (project)", filepath.Join(p, ".cursor", "mcp.json"), false, "mcpServers")
		add("vscode", "VS Code (project)", filepath.Join(p, ".vscode", "mcp.json"), true, "servers")
		add("other", "Claude Code (project)", filepath.Join(p, ".mcp.json"), false, "mcpServers")
	}
	return out
}

// mcpDiscovery is what reading every source produced.
type mcpDiscovery struct {
	Servers []mcpServerInfo
	// Read counts files that existed and parsed; Unreadable names the ones
	// that existed and did not, so "no servers" is never said about a file
	// this could not read.
	Read       int
	Unreadable []string
	// NotLocal counts files that exist only in cloud storage; they are not
	// fetched, and so not read.
	NotLocal int
	// Labels maps a reported server back to the client's real name, for
	// local output only.
	Labels map[mcpServerInfo]string
}

// discoverMCP reads every source and returns what they configure.
func discoverMCP(sources []mcpSource) mcpDiscovery {
	d := mcpDiscovery{Labels: map[mcpServerInfo]string{}}
	seen := map[mcpServerInfo]bool{}
	for _, src := range sources {
		body, err := readLocal(src.Path, 16<<20)
		if errors.Is(err, errNotLocal) {
			d.NotLocal++
			continue
		}
		if err != nil {
			continue
		}
		servers, projects, err := parseMCPFile(body, src)
		if err != nil {
			d.Unreadable = append(d.Unreadable, src.Path)
			continue
		}
		d.Read++
		for _, s := range append(servers, projects...) {
			if seen[s] {
				continue
			}
			seen[s] = true
			d.Servers = append(d.Servers, s)
			d.Labels[s] = src.Label
		}
	}
	sort.Slice(d.Servers, func(i, j int) bool {
		a, b := d.Servers[i], d.Servers[j]
		if a.Client != b.Client {
			return a.Client < b.Client
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Host < b.Host
	})
	return d
}

// parseMCPFile reads one client file. The second return is servers found
// under ~/.claude.json's per-project entries, which carry the same shape a
// level down.
func parseMCPFile(body []byte, src mcpSource) ([]mcpServerInfo, []mcpServerInfo, error) {
	if src.JSONC {
		body = stripJSONC(body)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, err
	}
	var out []mcpServerInfo
	for _, key := range src.Keys {
		raw := lookupRaw(doc, key)
		if raw == nil {
			continue
		}
		out = append(out, serversFrom(raw, src.Client)...)
	}

	// Claude Code keeps "local" servers under projects/<path>/mcpServers.
	var projects []mcpServerInfo
	if raw, ok := doc["projects"]; ok && src.Label == "Claude Code" {
		var byPath map[string]map[string]json.RawMessage
		if json.Unmarshal(raw, &byPath) == nil {
			for _, p := range byPath {
				if servers, ok := p["mcpServers"]; ok {
					projects = append(projects, serversFrom(servers, src.Client)...)
				}
			}
		}
	}
	return out, projects, nil
}

// lookupRaw follows a dotted key, and also accepts the key whole: VS Code's
// settings.json spells the nested object "mcp": {"servers": …} in some
// versions and uses the flat key "mcp.servers" in none, but a user can.
func lookupRaw(doc map[string]json.RawMessage, key string) json.RawMessage {
	if raw, ok := doc[key]; ok {
		return raw
	}
	head, rest, nested := strings.Cut(key, ".")
	if !nested {
		return nil
	}
	var inner map[string]json.RawMessage
	if json.Unmarshal(doc[head], &inner) != nil {
		return nil
	}
	return lookupRaw(inner, rest)
}

// mcpEntry is everything a client may say about a server. Read in full so
// the facts can be established; never reported.
type mcpEntry struct {
	Command   string         `json:"command"`
	Args      []string       `json:"args"`
	Env       map[string]any `json:"env"`
	Headers   map[string]any `json:"headers"`
	URL       string         `json:"url"`
	ServerURL string         `json:"serverUrl"` // Windsurf
	HTTPURL   string         `json:"httpUrl"`   // Gemini CLI
	Type      string         `json:"type"`
	Transport string         `json:"transport"`
}

func serversFrom(raw json.RawMessage, client string) []mcpServerInfo {
	var entries map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	var out []mcpServerInfo
	for name, body := range entries {
		var e mcpEntry
		if json.Unmarshal(body, &e) != nil {
			continue
		}
		// Zed nests the command one level down.
		if e.Command == "" {
			var zed struct {
				Command struct {
					Path string            `json:"path"`
					Args []string          `json:"args"`
					Env  map[string]string `json:"env"`
				} `json:"command"`
			}
			if json.Unmarshal(body, &zed) == nil && zed.Command.Path != "" {
				e.Command, e.Args = zed.Command.Path, zed.Command.Args
				e.Env = map[string]any{}
				for k, v := range zed.Command.Env {
					e.Env[k] = v
				}
			}
		}
		out = append(out, describeServer(name, client, e))
	}
	return out
}

// describeServer reduces one entry to what may be reported.
func describeServer(name, client string, e mcpEntry) mcpServerInfo {
	info := mcpServerInfo{Client: client, Name: name, Transport: "stdio"}

	remote := firstNonEmpty(e.URL, e.ServerURL, e.HTTPURL)
	kind := strings.ToLower(firstNonEmpty(e.Type, e.Transport))
	if remote != "" || kind == "http" || kind == "sse" || kind == "streamable-http" || kind == "streamablehttp" {
		info.Transport = "http"
	}
	if remote != "" {
		info.Host = hostOnly(remote)
	} else {
		// A local process that bridges to a remote server — mcp-remote,
		// supergateway, our own shim — still sends its traffic to that
		// host, and the host is the thing a reader wants.
		for _, a := range e.Args {
			if h := hostOnly(a); h != "" {
				info.Host = h
				break
			}
		}
	}

	info.HasCredentials = entryHoldsCredential(e, remote)
	return info
}

// hostOnly returns the host (and a non-default port) of an http(s) URL,
// and "" for anything else. Userinfo, path, query and fragment are all
// dropped: a query string is where people put tokens.
func hostOnly(raw string) string {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		return host
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// entryHoldsCredential reports whether a credential is written into the
// entry itself: an environment value, a header, a URL's query or userinfo,
// or an argument.
func entryHoldsCredential(e mcpEntry, remote string) bool {
	for k, v := range e.Env {
		if s, ok := v.(string); ok && looksLikeCredential(k, s) {
			return true
		}
	}
	for k, v := range e.Headers {
		if s, ok := v.(string); ok && looksLikeCredential(k, s) {
			return true
		}
	}
	for _, u := range append([]string{remote}, e.Args...) {
		if urlHoldsCredential(u) {
			return true
		}
	}
	// "--api-key sk-…", "--token=…": an argument named for a secret and the
	// value after it, or a bare value that is shaped like a known key.
	for i, a := range e.Args {
		name, value, joined := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if joined && strings.HasPrefix(a, "-") && looksLikeCredential(name, value) {
			return true
		}
		if strings.HasPrefix(a, "-") && !joined && i+1 < len(e.Args) && looksLikeCredential(name, e.Args[i+1]) {
			return true
		}
		if valueShapedLikeKey(a) {
			return true
		}
	}
	return false
}

// credentialName matches a variable, header or flag named for a secret.
var credentialName = regexp.MustCompile(`(?i)(api[_-]?key|apikey|token|secret|passw(or)?d|passwd|credential|auth|bearer|cookie|session|private[_-]?key|access[_-]?key|\bpat\b|_pat$)`)

// notSecretName is a name that matched credentialName for a word it
// contains but names something public: GITHUB_OAUTH_CLIENT_ID, AUTH_URL.
// Reporting those would say a credential is in the file when it is not.
var notSecretName = regexp.MustCompile(`(?i)(_id|_url|_uri|_host|_endpoint|_user|_username|_region|_type|_mode|_scope|_scopes)$`)

// looksLikeCredential decides whether a named value is a credential held
// in the file.
//
// A reference is not: "${input:token}", "${env:GITHUB_TOKEN}", "$TOKEN" and
// "{{secrets.X}}" are all resolved at run time from somewhere else, and
// reporting them as a credential in the file would send somebody hunting
// for a key that is not there.
func looksLikeCredential(name, value string) bool {
	v := strings.TrimSpace(value)
	bare := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "Bearer "), "Basic "))
	if bare == "" || isReference(bare) {
		return false
	}
	if valueShapedLikeKey(v) {
		return true
	}
	if !credentialName.MatchString(name) || notSecretName.MatchString(name) {
		return false
	}
	// "true", "none", "********": configuration, not a secret.
	if len(bare) < 8 || looksLikePlaceholder(bare) || strings.Trim(bare, "*•x") == "" {
		return false
	}
	switch strings.ToLower(bare) {
	case "true", "false", "none", "null", "required", "optional":
		return false
	}
	return true
}

func isReference(v string) bool {
	return strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$") && !strings.ContainsAny(v[1:], " /:") ||
		strings.HasPrefix(v, "{{") || strings.HasPrefix(v, "%") && strings.HasSuffix(v, "%") && len(v) > 2
}

// valueShapedLikeKey asks the same rules `lyntway scan` and the gateway use
// whether a bare value is a known kind of key.
func valueShapedLikeKey(v string) bool {
	for _, h := range findKeys(v, 1) {
		if h.Class != "" {
			return true
		}
	}
	return false
}

// urlHoldsCredential reports a password in a URL's userinfo, or a query
// parameter named for a secret. Any scheme: a postgresql:// connection
// string handed to a database server is where a password most often sits.
func urlHoldsCredential(raw string) bool {
	if !strings.Contains(raw, "://") {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if u.User != nil {
		if p, ok := u.User.Password(); ok && p != "" && !isReference(p) {
			return true
		}
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			if looksLikeCredential(k, v) {
				return true
			}
		}
	}
	return false
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// stripJSONC removes // and /* */ comments outside strings, and a comma
// that is followed only by whitespace and a closing bracket. VS Code's and
// Zed's settings files are JSON with both, and encoding/json refuses them.
func stripJSONC(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inString, escaped := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			if i < len(in) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++
		case c == ',':
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\t' || in[j] == '\n' || in[j] == '\r') {
				j++
			}
			if j < len(in) && (in[j] == '}' || in[j] == ']') {
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// projectRoots lists directories somebody has opened, from the places the
// tools themselves record them: Claude Code's project map, and the
// workspace records Cursor, VS Code and Windsurf keep. Bounded, because a
// long-lived editor has opened thousands.
func projectRoots(h agentHost) []string {
	const limit = 200
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = filepath.Clean(p)
		if p == "." || p == string(filepath.Separator) || seen[p] || len(out) >= limit {
			return
		}
		if info, err := os.Stat(p); err != nil || !info.IsDir() {
			return
		}
		seen[p] = true
		out = append(out, p)
	}

	if body, err := readLocal(h.join(".claude.json"), 64<<20); err == nil {
		var doc struct {
			Projects map[string]json.RawMessage `json:"projects"`
		}
		if json.Unmarshal(body, &doc) == nil {
			keys := make([]string, 0, len(doc.Projects))
			for k := range doc.Projects {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				add(k)
			}
		}
	}

	for _, product := range []string{"Cursor", "Code", "Windsurf"} {
		dir := h.appSupport(product, "User", "workspaceStorage")
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			body, err := readLocal(filepath.Join(dir, e.Name(), "workspace.json"), 1<<20)
			if err != nil {
				continue
			}
			var ws struct {
				Folder string `json:"folder"`
			}
			if json.Unmarshal(body, &ws) != nil || !strings.HasPrefix(ws.Folder, "file://") {
				continue
			}
			u, err := url.Parse(ws.Folder)
			if err != nil {
				continue
			}
			p := u.Path
			if h.GOOS == "windows" {
				p = strings.TrimPrefix(p, "/")
				p = filepath.FromSlash(p)
			}
			add(p)
		}
	}
	return out
}
