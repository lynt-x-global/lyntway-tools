package main

// An MCP tool server over stdio.
//
// MCP is JSON-RPC 2.0 over stdin/stdout. This file implements just
// enough of the protocol for a host (Claude Code, Claude Desktop) to
// discover the tools and call them. No third-party dependencies: the
// protocol is small and the Go stdlib handles it.
//
// stdout discipline: the MCP transport owns stdout. Every tool function
// in this codebase prints to the `stdout` variable (main.go line 59),
// so before calling a tool we redirect `stdout` to a buffer and restore
// it afterwards. The buffer becomes the tool's text result.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lynt-x-global/lyntway-tools/agentsecrets"
)

// The tools this server offers, for the usage message.
const mcpServerUsage = `lyntway mcp-server — MCP tool server for AI agents

Usage:
  lyntway mcp-server          speak MCP over stdio; an editor starts this, not a person

Tools offered:
  lyntway_status       whether Lyntway is configured here, and what is not covered
  lyntway_setup        sign in; with an API key, saves it immediately
  lyntway_scan         find .env files in a directory and report which carry keys
  lyntway_history      the credentials this machine's coding agents have already seen
  lyntway_migrate      move provider keys out of .env files and into Lyntway
  lyntway_init         detect the AI tools installed here and route them
  lyntway_full_setup   sign in, scan, migrate and route, in one call
  lyntway_receipts     list recent local receipts from ~/.lyntway/receipts
  lyntway_watch        watch a directory's .env files for new provider keys

It reads JSON-RPC on stdin and writes it on stdout, so running it by hand
looks like nothing happening — that is the protocol, not a fault. Put it in
an editor's MCP configuration instead, which ` + "`lyntway init`" + ` does.

It takes no argument.
`

func mcpServer(args []string) error {
	// Arguments are refused rather than ignored.
	//
	// They used to be dropped on the floor, so `lyntway mcp-server --help`
	// printed nothing and sat waiting on stdin — which to the person
	// running it is indistinguishable from a hang. Every other command
	// here answers --help, and the database gateway refuses an
	// unrecognised flag for the same reason: starting on a typo is worse
	// than printing this.
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			fmt.Fprint(stdout, mcpServerUsage)
			return nil
		default:
			return fmt.Errorf("mcp-server takes no argument, and got %q. "+
				"It speaks MCP over stdio and is started by an editor; `lyntway mcp-server --help` explains", a)
		}
	}

	reader := bufio.NewReader(os.Stdin)
	writer := os.Stdout
	var writeMu sync.Mutex

	// The watcher context lives as long as the server. Cancelled on exit
	// so the goroutine does not leak.
	watchCtx, watchCancel := context.WithCancel(context.Background())
	defer watchCancel()

	// Track the active watcher so lyntway_watch can replace it.
	var activeWatcher *envWatcher
	_ = activeWatcher // used in tool dispatch below

	startWatcher := func(dir string) {
		watchCancel() // stop any previous watcher
		watchCtx, watchCancel = context.WithCancel(context.Background())
		lk := ""
		var extra []string
		if c, err := loadConfig(); err == nil {
			lk = c.Key
			// Fetch custom upstream names so the watcher can match
			// variables like PORTKEY_API_KEY against user-added
			// upstreams, not only the hardcoded provider list.
			if ups, err := serverUpstreams(c); err == nil {
				extra = ups
			}
		}
		activeWatcher = newEnvWatcher(dir, 30*time.Second, lk, extra, writer, &writeMu)
		go activeWatcher.run(watchCtx)
	}

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			writeMu.Lock()
			writeJSONRPC(writer, nil, nil, &jsonRPCError{Code: -32700, Message: "Parse error"})
			writeMu.Unlock()
			continue
		}

		writeMu.Lock()
		switch req.Method {
		case "initialize":
			writeJSONRPC(writer, req.ID, mcpInitResult(), nil)
			writeMu.Unlock()
			// Start watching the working directory for .env changes.
			cwd, _ := os.Getwd()
			if cwd != "" {
				startWatcher(cwd)
			}
		case "notifications/initialized":
			writeMu.Unlock()
			// Client acknowledgement; nothing to do.
		case "tools/list":
			writeJSONRPC(writer, req.ID, mcpToolsList(), nil)
			writeMu.Unlock()
		case "tools/call":
			result, rpcErr := mcpToolsCall(req.Params, startWatcher)
			writeJSONRPC(writer, req.ID, result, rpcErr)
			writeMu.Unlock()
		default:
			writeJSONRPC(writer, req.ID, nil, &jsonRPCError{Code: -32601, Message: "Method not found"})
			writeMu.Unlock()
		}
	}
}

// --- JSON-RPC types ---

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeJSONRPC(w io.Writer, id json.RawMessage, result any, rpcErr *jsonRPCError) {
	resp := jsonRPCResponse{JSONRPC: "2.0", ID: id, Result: result, Error: rpcErr}
	body, _ := json.Marshal(resp)
	body = append(body, '\n')
	_, _ = w.Write(body)
}

// --- MCP protocol responses ---

func mcpInitResult() map[string]any {
	return map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]any{
			"tools":   map[string]any{},
			"logging": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    "lyntway",
			"version": version,
		},
	}
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema mcpInputSchema `json:"inputSchema"`
}

type mcpInputSchema struct {
	Type       string             `json:"type"`
	Properties map[string]mcpProp `json:"properties,omitempty"`
	Required   []string           `json:"required,omitempty"`
}

type mcpProp struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

var mcpTools = []mcpTool{
	{
		Name:        "lyntway_status",
		Description: "Check whether Lyntway is configured on this machine and what is covered. Returns the sign-in state and the routing status of each detected tool.",
		InputSchema: mcpInputSchema{Type: "object"},
	},
	{
		Name:        "lyntway_setup",
		Description: "Sign in to Lyntway. With an API key, saves it immediately. Without one, starts a device link flow that opens a browser for approval.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: map[string]mcpProp{
				"api_key": {Type: "string", Description: "An API key from the Lyntway console. If omitted, a browser-based device link flow is started."},
				"url":     {Type: "string", Description: "The Lyntway server URL. Defaults to https://lyntway.com."},
			},
		},
	},
	{
		Name:        "lyntway_scan",
		Description: "Find .env files in a directory and report which ones contain provider API keys (OpenAI, Anthropic, Gemini, xAI, Mistral, etc.). Shows the variable name, upstream, and last 4 characters of each key. Never shows the full key value.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: map[string]mcpProp{
				"directory": {Type: "string", Description: "The directory to scan. Defaults to the current working directory."},
			},
		},
	},
	{
		Name: "lyntway_history",
		Description: "Report the credentials this machine's AI coding agents have already seen: the keys in their " +
			"transcripts, prompt histories, pasted buffers, shell snapshots and MCP configuration. Reads local files " +
			"only and sends nothing. Never shows a key's value — a label, the last four characters and a fingerprint. " +
			"Changes no file. One key seen in many files is reported as one credential, because the count is the " +
			"number of things to revoke. Some findings are test fixtures or documented examples the agent read " +
			"rather than live keys; say so when reporting, and never print a value back to the user.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: map[string]mcpProp{
				"project": {Type: "string", Description: "Also read the agent files kept inside this project directory, such as a committed .mcp.json. Optional."},
			},
		},
	},
	{
		Name:        "lyntway_migrate",
		Description: "Move provider keys from .env files to Lyntway. Without confirm, shows the plan: which keys will be moved and what will change. With confirm: true, executes the migration. Every file is backed up first; undo with `lyntway undo`.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: map[string]mcpProp{
				"directory": {Type: "string", Description: "The project directory containing .env files. Defaults to the current working directory."},
				"confirm":   {Type: "boolean", Description: "Set to true to execute the migration. Without this, only the plan is shown."},
				"replace":   {Type: "boolean", Description: "Set to true only after the user has agreed to replace a provider key Lyntway already stores for the same provider. That key may be in use by other applications. Without this, a stored key is left as it is and that variable is not migrated."},
			},
		},
	},
	{
		Name:        "lyntway_init",
		Description: "Detect AI tools installed on this machine (Claude Desktop, Claude Code, shell, Cursor, Continue) and route them through Lyntway. Without confirm, shows the plan. With confirm: true, applies the changes. Every file is backed up first.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: map[string]mcpProp{
				"confirm": {Type: "boolean", Description: "Set to true to apply the changes. Without this, only the plan is shown."},
			},
		},
	},
	{
		Name:        "lyntway_full_setup",
		Description: "Full setup: sign in, scan .env for provider keys, migrate them, route tools. Without confirm, shows the plan (login state, keys found, tools detected). With confirm: true, executes login, migration and routing with --yes.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: map[string]mcpProp{
				"api_key":   {Type: "string", Description: "An API key from the console. If omitted, a browser-based device link is started."},
				"directory": {Type: "string", Description: "Project directory to scan for .env files. Defaults to the current working directory."},
				"confirm":   {Type: "boolean", Description: "Set to true to execute the full setup. Without this, only the plan is shown."},
			},
		},
	},
	{
		Name:        "lyntway_receipts",
		Description: "List recent local receipts from ~/.lyntway/receipts/. Shows receipt IDs, timestamps and filenames.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: map[string]mcpProp{
				"limit": {Type: "string", Description: "Maximum number of receipts to return. Defaults to 10."},
			},
		},
	},
	{
		Name:        "lyntway_watch",
		Description: "Watch .env files in a directory for new provider keys. The MCP server polls the directory and sends a notification when new keys appear. Call lyntway_migrate to secure them.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: map[string]mcpProp{
				"directory": {Type: "string", Description: "The directory to watch. Defaults to the current working directory."},
			},
		},
	},
}

func mcpToolsList() map[string]any {
	return map[string]any{"tools": mcpTools}
}

// --- Tool dispatch ---

// looseBool unmarshals both JSON true and "true". Claude Code and other
// MCP hosts sometimes send boolean arguments as strings, and Go's
// json.Unmarshal does not coerce "true" to bool — so confirm: "true"
// silently stays false, and the tool returns a dry-run plan forever.
type looseBool bool

func (b *looseBool) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	*b = looseBool(s == "true" || s == "1")
	return nil
}

type mcpCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type mcpToolResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError,omitempty"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func mcpToolsCall(params json.RawMessage, startWatcher func(string)) (any, *jsonRPCError) {
	var call mcpCallParams
	if err := json.Unmarshal(params, &call); err != nil {
		return nil, &jsonRPCError{Code: -32602, Message: "Invalid params"}
	}

	var text string
	var toolErr error

	switch call.Name {
	case "lyntway_status":
		text, toolErr = mcpToolStatus()
	case "lyntway_setup":
		text, toolErr = mcpToolSetup(call.Arguments)
	case "lyntway_history":
		text, toolErr = mcpToolHistory(call.Arguments)
	case "lyntway_scan":
		text, toolErr = mcpToolScan(call.Arguments)
	case "lyntway_migrate":
		text, toolErr = mcpToolMigrate(call.Arguments)
	case "lyntway_init":
		text, toolErr = mcpToolInit(call.Arguments)
	case "lyntway_full_setup":
		text, toolErr = mcpToolFullSetup(call.Arguments)
	case "lyntway_receipts":
		text, toolErr = mcpToolReceipts(call.Arguments)
	case "lyntway_watch":
		text, toolErr = mcpToolWatch(call.Arguments, startWatcher)
	default:
		return nil, &jsonRPCError{Code: -32602, Message: fmt.Sprintf("Unknown tool: %s", call.Name)}
	}

	if toolErr != nil {
		return mcpToolResult{
			Content: []mcpContent{{Type: "text", Text: toolErr.Error()}},
			IsError: true,
		}, nil
	}
	return mcpToolResult{
		Content: []mcpContent{{Type: "text", Text: text}},
	}, nil
}

// captureTool runs fn with stdout redirected to a buffer and returns
// what was printed. This keeps tool output off the JSON-RPC transport.
func captureTool(fn func() error) (string, error) {
	var buf bytes.Buffer
	prev := stdout
	stdout = &buf
	input = nil
	err := fn()
	stdout = prev
	return buf.String(), err
}

// --- Individual tools ---

func mcpToolStatus() (string, error) {
	text, err := captureTool(func() error { return status() })
	if err != nil {
		return "", err
	}

	// Append a scan of the working directory so the agent sees unmigrated
	// keys without a separate call. The status alone tells the agent about
	// routing; this tells it about the project.
	cwd, _ := os.Getwd()
	if cwd != "" {
		if c, err := loadConfig(); err == nil {
			extra, _ := serverUpstreams(c)
			if cands, err := findCandidates(cwd, extra, c.Key); err == nil && len(cands) > 0 {
				var lines []string
				for _, c := range cands {
					if c.Skip != "" {
						continue
					}
					lines = append(lines, fmt.Sprintf("  %s (%s) …%s", c.Var, c.Upstream, c.last4()))
				}
				if len(lines) > 0 {
					text += "\n\nUnmigrated provider keys in " + cwd + ":\n" +
						strings.Join(lines, "\n") +
						"\n\nCall lyntway_migrate to secure them."
				}
			}
		}
	}
	return text, nil
}

func mcpToolSetup(args json.RawMessage) (string, error) {
	var p struct {
		APIKey string `json:"api_key"`
		URL    string `json:"url"`
	}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &p)
	}

	var loginArgs []string
	if p.URL != "" {
		loginArgs = append(loginArgs, "--url", p.URL)
	}
	if p.APIKey != "" {
		loginArgs = append(loginArgs, "--key", p.APIKey)
	}

	text, err := captureTool(func() error { return login(loginArgs) })
	if err != nil {
		return "", err
	}
	return text, nil
}

// mcpToolHistory lets an agent ask what it has already seen.
//
// The one tool here that reports on the agent calling it. Written so the
// answer is actionable without being dangerous: the agent is told what
// to revoke and where it was, never the value — a tool result becomes
// part of the next prompt, so returning a key here would put it straight
// back into the model this exists to keep it away from.
func mcpToolHistory(args json.RawMessage) (string, error) {
	var p struct {
		Project string `json:"project"`
	}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &p)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("this machine has no home directory to look in: %w", err)
	}
	sources := agentsecrets.Sources(agentsecrets.Host{
		GOOS:         runtime.GOOS,
		Home:         home,
		AppData:      os.Getenv("APPDATA"),
		LocalAppData: os.Getenv("LOCALAPPDATA"),
	})
	if p.Project != "" {
		abs, err := filepath.Abs(p.Project)
		if err != nil {
			return "", err
		}
		sources = append(sources, agentsecrets.ProjectSources(abs)...)
	}

	res := agentsecrets.Scan(sources, agentsecrets.DefaultRules())
	allow, err := agentsecrets.LoadAllow(filepath.Join(home, ".lyntway"))
	if err != nil {
		return "", fmt.Errorf("reading the judged list: %w", err)
	}
	res = res.Excluding(allow)
	creds := res.Credentials()

	var sb strings.Builder
	fmt.Fprintf(&sb, "Read %d file%s (%d MB) across %d location%s.\n",
		res.Files, pluralS(res.Files), res.Bytes>>20, res.Sources, pluralS(res.Sources))
	if !res.Complete() {
		// Said first, because an agent summarising this will lead with
		// the count and a count over a partial read is not a verdict.
		fmt.Fprintf(&sb, "INCOMPLETE: %d file%s could not be read, so this is not a clean result. "+
			"Report that before any number.\n", len(res.Unread), pluralS(len(res.Unread)))
	}
	if res.Allowed > 0 {
		fmt.Fprintf(&sb, "%d finding%s already judged by the user and not listed.\n", res.Allowed, pluralS(res.Allowed))
	}
	if len(creds) == 0 {
		sb.WriteString("\nNo credentials found in what the agents here have written.\n")
		return sb.String(), nil
	}

	fmt.Fprintf(&sb, "\n%d credential%s, %d sighting%s:\n\n",
		len(creds), pluralS(len(creds)), len(res.Findings), pluralS(len(res.Findings)))
	for _, c := range creds {
		kinds := make([]string, 0, 4)
		for _, k := range c.Kinds() {
			kinds = append(kinds, string(k))
		}
		fmt.Fprintf(&sb, "  %s ending %s (%s) — %d sighting%s in %s\n",
			c.Label, c.Last4, c.Fingerprint, len(c.Seen), pluralS(len(c.Seen)), strings.Join(kinds, ", "))
	}
	sb.WriteString("\nSome of these may be test fixtures or documented examples rather than live keys: " +
		"a fixture is built to have the shape of the real thing. Tell the user that, and never print a value.\n" +
		"A key in a transcript cannot be rotated out of the file — nobody edits it and every backup has a copy — " +
		"so the remedy is to revoke the credential. `lyntway history --allow` retires the ones they have judged.\n")
	return sb.String(), nil
}

func mcpToolScan(args json.RawMessage) (string, error) {
	var p struct {
		Directory string `json:"directory"`
	}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &p)
	}
	dir := p.Directory
	if dir == "" {
		dir = "."
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}

	c, err := loadConfig()
	if err != nil {
		// Not signed in — scan without the Lyntway key so existing
		// keys are not filtered as "already routed".
		c = config{}
	}
	extra, _ := serverUpstreams(c)

	found, err := findCandidates(dir, extra, c.Key)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Scanning %s\n\n", dir)
	if len(found) == 0 {
		sb.WriteString("No provider keys found in .env files.\n")
		return sb.String(), nil
	}
	for _, it := range found {
		if it.Skip != "" {
			fmt.Fprintf(&sb, "  %s  %-24s  %s\n", filepath.Base(it.File), it.Var, it.Skip)
		} else {
			fmt.Fprintf(&sb, "  %s  %-24s  %-12s  ...%s\n", filepath.Base(it.File), it.Var, it.Upstream, it.last4())
		}
	}
	return sb.String(), nil
}

func mcpToolMigrate(args json.RawMessage) (string, error) {
	var p struct {
		Directory string    `json:"directory"`
		Confirm   looseBool `json:"confirm"`
		Replace   looseBool `json:"replace"`
	}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &p)
	}
	dir := p.Directory
	if dir == "" {
		dir = "."
	}

	if !p.Confirm {
		// Plan mode: show what would be migrated without changing anything.
		return mcpMigratePlan(dir)
	}

	// Execute without prompting — the MCP transport owns stdin, so any
	// question that reads from it hangs. That question has two answers,
	// and confirm is not one of them: confirm agrees to the plan, not to
	// overwriting a key another project stored for the same provider. So
	// a stored key is kept unless replace was passed as well.
	answer := "--keep"
	if p.Replace {
		answer = "--replace"
	}
	cmdArgs := []string{"--yes", answer, dir}
	text, err := captureTool(func() error { return keysMigrate(cmdArgs) })
	if err != nil {
		return "", err
	}
	return text, nil
}

func mcpMigratePlan(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}

	c, err := loadConfig()
	if err != nil {
		return "", err
	}
	extra, _ := serverUpstreams(c)
	// What the server already holds decides whether a line is a move or a
	// replacement, and a replacement reaches every application using that
	// stored key — so it is shown here, before anybody confirms anything.
	stored, storedErr := storedProviderKeys(c)

	found, err := findCandidates(dir, extra, c.Key)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Migration plan for %s\n\n", dir)
	if len(found) == 0 {
		sb.WriteString("No provider keys to migrate.\n")
		return sb.String(), nil
	}

	var moves, held int
	for _, it := range found {
		// The same test keysMigrate applies, so the plan cannot call a line
		// a move that the migration then treats as a stored key.
		have, isHeld := stored[it.Upstream]
		switch {
		case it.Skip != "":
			fmt.Fprintf(&sb, "  skip  %-24s  %s\n", it.Var, it.Skip)
		case isHeld:
			fmt.Fprintf(&sb, "  held  %-24s  %-12s  ...%s  (Lyntway already stores a %s key ending %s)\n",
				it.Var, it.Upstream, it.last4(), it.Upstream, have.Last4)
			held++
		default:
			fmt.Fprintf(&sb, "  move  %-24s  %-12s  ...%s\n", it.Var, it.Upstream, it.last4())
			moves++
		}
	}
	fmt.Fprintf(&sb, "\n%d key(s) would be moved to Lyntway.\n", moves)
	if held > 0 {
		fmt.Fprintf(&sb, "%d key(s) are for a provider Lyntway already stores a key for. With confirm alone they are left as they are, "+
			"and those variables keep their current value. To replace the stored key instead — for every application that uses it — "+
			"ask the user, and call again with confirm: true and replace: true.\n", held)
	}
	if storedErr != nil {
		sb.WriteString("Could not check which keys Lyntway already stores, so a stored key may be affected; with confirm alone it is kept.\n")
	}
	sb.WriteString("Call again with confirm: true to execute.\n")
	return sb.String(), nil
}

func mcpToolInit(args json.RawMessage) (string, error) {
	var p struct {
		Confirm looseBool `json:"confirm"`
	}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &p)
	}

	if !p.Confirm {
		// Plan mode: show what would be configured.
		return mcpInitPlan()
	}

	// Execute: pass --yes so it does not prompt.
	text, err := captureTool(func() error { return initialise([]string{"--yes"}) })
	if err != nil {
		return "", err
	}
	return text, nil
}

func mcpInitPlan() (string, error) {
	_, err := loadConfig()
	if err != nil {
		return "", err
	}

	targets := scan()
	var sb strings.Builder
	sb.WriteString("Init plan — what would be configured:\n\n")
	var actionable int
	for _, t := range targets {
		switch {
		case t.Found && t.Kind != kindManual:
			fmt.Fprintf(&sb, "  route   %s\n", t.Name)
			actionable++
		case t.Found && t.Kind == kindManual:
			fmt.Fprintf(&sb, "  manual  %s — %s\n", t.Name, t.Why)
		default:
			reason := t.Why
			if reason == "" {
				reason = "not installed"
			}
			fmt.Fprintf(&sb, "  skip    %s — %s\n", t.Name, reason)
		}
	}
	if actionable == 0 {
		sb.WriteString("\nNothing can be configured automatically.\n")
	} else {
		fmt.Fprintf(&sb, "\n%d tool(s) would be routed through Lyntway.\n", actionable)
		sb.WriteString("Call again with confirm: true to apply.\n")
	}
	return sb.String(), nil
}

func mcpToolReceipts(args json.RawMessage) (string, error) {
	var p struct {
		Limit int `json:"limit"`
	}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &p)
	}
	if p.Limit <= 0 {
		p.Limit = 10
	}

	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find home directory: %w", err)
	}
	dir := filepath.Join(h, ".lyntway", "receipts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "No receipts directory found. No receipts have been recorded on this machine.\n", nil
		}
		return "", err
	}

	// Collect .json and .jsonl files, sorted by modification time (newest first).
	type entry struct {
		name    string
		modTime string
		size    int64
	}
	var receipts []entry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		receipts = append(receipts, entry{
			name:    name,
			modTime: info.ModTime().UTC().Format("2006-01-02 15:04:05"),
			size:    info.Size(),
		})
	}
	sort.Slice(receipts, func(i, j int) bool {
		return receipts[i].modTime > receipts[j].modTime
	})

	if len(receipts) == 0 {
		return "No receipts found in " + dir + "\n", nil
	}

	if len(receipts) > p.Limit {
		receipts = receipts[:p.Limit]
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Recent receipts in %s:\n\n", dir)
	for _, r := range receipts {
		fmt.Fprintf(&sb, "  %s  %6d bytes  %s\n", r.modTime, r.size, r.name)
	}
	fmt.Fprintf(&sb, "\n%d receipt(s) shown.\n", len(receipts))
	return sb.String(), nil
}

func mcpToolWatch(args json.RawMessage, startWatcher func(string)) (string, error) {
	var p struct {
		Directory string `json:"directory"`
	}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &p)
	}
	dir := p.Directory
	if dir == "" {
		dir = "."
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	startWatcher(dir)
	return fmt.Sprintf("Watching %s for .env changes. You will be notified when new provider keys appear.\n", dir), nil
}

func mcpToolFullSetup(args json.RawMessage) (string, error) {
	var p struct {
		APIKey    string    `json:"api_key"`
		Directory string    `json:"directory"`
		Confirm   looseBool `json:"confirm"`
	}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &p)
	}

	if !p.Confirm {
		return mcpFullSetupPlan(p.APIKey, p.Directory)
	}

	// Execute: run setup with --yes so nothing prompts.
	cliCommand = "mcp-server"
	setupArgs := []string{"--yes"}
	if p.APIKey != "" {
		setupArgs = append(setupArgs, "--key", p.APIKey)
	}
	text, err := captureTool(func() error {
		if p.Directory != "" {
			if err := os.Chdir(p.Directory); err != nil {
				return err
			}
		}
		return setup(setupArgs)
	})
	if err != nil {
		return "", err
	}
	return text, nil
}

func mcpFullSetupPlan(apiKey, dir string) (string, error) {
	var sb strings.Builder
	sb.WriteString("Full setup plan:\n\n")

	// 1. Login state.
	c, err := loadConfig()
	if err != nil || c.Key == "" {
		sb.WriteString("  login: not signed in — will start device link")
		if apiKey != "" {
			sb.WriteString(" (api_key provided)")
		}
		sb.WriteString("\n")
	} else {
		ok, reason := validateKey(c)
		switch {
		case ok:
			prefix := c.Key
			if len(prefix) > 12 {
				prefix = prefix[:12]
			}
			fmt.Fprintf(&sb, "  login: signed in to %s (%s…)\n", c.Origin, prefix)
		case reason == "revoked":
			sb.WriteString("  login: key revoked — will sign in again\n")
		default:
			fmt.Fprintf(&sb, "  login: %s — will sign in again\n", reason)
		}
	}

	// 2. Keys.
	scanDir := dir
	if scanDir == "" {
		scanDir = "."
	}
	scanDir, _ = filepath.Abs(scanDir)
	lk := ""
	if c.Key != "" {
		lk = c.Key
	}
	extra, _ := serverUpstreams(c)
	found, scanErr := findCandidates(scanDir, extra, lk)
	if scanErr != nil {
		fmt.Fprintf(&sb, "  keys:  %v\n", scanErr)
	} else {
		var actionable int
		for _, it := range found {
			if it.Skip == "" {
				fmt.Fprintf(&sb, "  move   %-24s %-12s …%s\n", it.Var, it.Upstream, it.last4())
				actionable++
			}
		}
		if actionable == 0 {
			sb.WriteString("  keys:  no provider keys to migrate\n")
		} else {
			fmt.Fprintf(&sb, "  keys:  %d key(s) would be migrated\n", actionable)
		}
	}

	// 3. Tools.
	targets := scan()
	var routable int
	for _, t := range targets {
		switch {
		case t.Found && t.Kind != kindManual:
			fmt.Fprintf(&sb, "  route  %s\n", t.Name)
			routable++
		case t.Found && t.Kind == kindManual:
			fmt.Fprintf(&sb, "  manual %s — %s\n", t.Name, t.Why)
		}
	}
	if routable == 0 {
		sb.WriteString("  tools: nothing to route automatically\n")
	} else {
		fmt.Fprintf(&sb, "  tools: %d tool(s) would be routed\n", routable)
	}

	// 4. Ollama.
	if ollamaRunning() {
		sb.WriteString("  ollama: running on 127.0.0.1:11434 — front with `lyntway proxy`\n")
	}

	sb.WriteString("\nCall again with confirm: true to execute.\n")
	return sb.String(), nil
}
