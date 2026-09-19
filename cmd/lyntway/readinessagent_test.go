package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func init() { agentPause = 0 }

// fakeMCP is a server whose manners each test chooses.
type fakeMCP struct {
	token       string // required bearer token; "" means open
	www         string // WWW-Authenticate on refusal
	tools       []map[string]any
	pageSize    int  // 0: one page
	loopCursor  bool // hand back the same cursor forever
	sse         bool
	rateHeaders bool
	methodCode  int    // code for an unknown method; 0 means -32601
	toolReply   string // "error", "iserror", "vague", "success"

	mu       sync.Mutex
	methods  []string
	called   []string
	authSeen []string
	deletes  int
}

func (f *fakeMCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
	f.mu.Unlock()
	if r.Method == http.MethodDelete {
		f.mu.Lock()
		f.deletes++
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if f.token != "" && r.Header.Get("Authorization") != "Bearer "+f.token {
		if f.www != "" {
			w.Header().Set("WWW-Authenticate", f.www)
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var msg struct {
		ID     any            `json:"id"`
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &msg)
	f.mu.Lock()
	f.methods = append(f.methods, msg.Method)
	f.mu.Unlock()
	if f.rateHeaders {
		w.Header().Set("RateLimit-Policy", `"default";q=100;w=60`)
	}
	w.Header().Set("Mcp-Session-Id", "sess-1")

	if msg.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	reply := map[string]any{"jsonrpc": "2.0", "id": msg.ID}
	switch msg.Method {
	case "initialize":
		reply["result"] = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{"name": "fake", "version": "1.0"}}
	case "tools/list":
		cursor, _ := msg.Params["cursor"].(string)
		start := 0
		fmt.Sscanf(cursor, "c%d", &start)
		end := len(f.tools)
		next := ""
		if f.pageSize > 0 && start+f.pageSize < len(f.tools) {
			end = start + f.pageSize
			next = fmt.Sprintf("c%d", end)
		}
		if f.loopCursor {
			next = "c0"
			end = len(f.tools)
			start = 0
		}
		res := map[string]any{"tools": f.tools[start:end]}
		if next != "" {
			res["nextCursor"] = next
		}
		reply["result"] = res
	case "tools/call":
		name, _ := msg.Params["name"].(string)
		f.mu.Lock()
		f.called = append(f.called, name)
		f.mu.Unlock()
		switch f.toolReply {
		case "iserror":
			reply["result"] = map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "Unknown tool: " + name}}}
		case "vague":
			reply["result"] = map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "something went wrong"}}}
		case "success":
			reply["result"] = map[string]any{"content": []any{map[string]any{"type": "text", "text": "ok"}}}
		default:
			reply["error"] = map[string]any{"code": -32602, "message": "Tool not found: " + name}
		}
	default:
		code := f.methodCode
		if code == 0 {
			code = -32601
		}
		reply["error"] = map[string]any{"code": code, "message": "Method not found"}
	}
	out, _ := json.Marshal(reply)
	if f.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		// A server notification first, as a real stream may send, so the
		// reader has to find the answer rather than take the first event.
		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\n")
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", out)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func tool(name, desc string, schema map[string]any, ann map[string]any) map[string]any {
	t := map[string]any{"name": name, "description": desc, "inputSchema": schema}
	if ann != nil {
		t["annotations"] = ann
	}
	return t
}

func objSchema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func goodTools() []map[string]any {
	return []map[string]any{
		tool("list_issues", "List the issues in a project, newest first.",
			objSchema(map[string]any{"project": map[string]any{"type": "string", "description": "The project key."}}, "project"),
			map[string]any{"readOnlyHint": true}),
		tool("create_issue", "Create an issue in a project and return its key.",
			objSchema(map[string]any{"title": map[string]any{"type": "string", "description": "A one-line title."}}, "title"),
			map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false}),
		tool("delete_issue", "Delete an issue permanently. It cannot be restored.",
			objSchema(map[string]any{"key": map[string]any{"type": "string", "description": "The issue key."}}, "key"),
			map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": true}),
	}
}

func statuses(t agentTarget) map[string]string {
	out := map[string]string{}
	for _, c := range t.Checks {
		out[c.ID] = c.Status
	}
	return out
}

func checkByID(t agentTarget, id string) agentCheck {
	for _, c := range t.Checks {
		if c.ID == id {
			return c
		}
	}
	return agentCheck{}
}

// A server built the way an agent needs passes every check it can be
// asked, over an event stream and across pages.
func TestAWellBuiltServerPassesEveryCheck(t *testing.T) {
	t.Setenv("FAKE_MCP_TOKEN", "tok-secret-123")
	f := &fakeMCP{token: "tok-secret-123", www: `Bearer realm="fake"`, tools: goodTools(), pageSize: 2, sse: true, rateHeaders: true, toolReply: "iserror"}
	srv := httptest.NewServer(f)
	defer srv.Close()

	got := checkMCP(srv.URL, "tok-secret-123")
	for _, c := range got.Checks {
		if c.Status != checkPass {
			t.Errorf("%s: %s — %s", c.ID, c.Status, c.Evidence)
		}
	}
	if len(got.Checks) != len(mcpDefs) {
		t.Errorf("%d checks reported, want every one of %d", len(got.Checks), len(mcpDefs))
	}
	if got.Server != "fake 1.0" || !got.ToolsRead || len(got.Tools) != 3 {
		t.Errorf("what the server said of itself was not kept: %+v", got)
	}
	if f.deletes != 1 {
		t.Errorf("the session was ended %d times, want once", f.deletes)
	}
}

// The first request is the stranger's. A token supplied for reading the
// tool list must not ride on the one request that asks what a stranger
// gets, or the answer would be about us.
func TestTheFirstRequestNeverCarriesTheToken(t *testing.T) {
	f := &fakeMCP{token: "tok-secret-123", www: `Bearer realm="fake"`, tools: goodTools()}
	srv := httptest.NewServer(f)
	defer srv.Close()

	got := checkMCP(srv.URL, "tok-secret-123")
	if len(f.authSeen) < 2 || f.authSeen[0] != "" {
		t.Fatalf("first request carried %q; it must carry nothing", f.authSeen[0])
	}
	if f.authSeen[1] != "Bearer tok-secret-123" {
		t.Errorf("the second request did not use the token: %q", f.authSeen[1])
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "tok-secret-123") {
		t.Error("the token appears in the result, which becomes a signed report")
	}
}

// The whole safety argument: no tool the server lists is ever called.
func TestNoListedToolIsEverCalled(t *testing.T) {
	f := &fakeMCP{tools: goodTools(), sse: true}
	srv := httptest.NewServer(f)
	defer srv.Close()

	checkMCP(srv.URL, "")
	if len(f.called) != 1 {
		t.Fatalf("tools/call was sent %d times, want exactly once: %v", len(f.called), f.called)
	}
	for _, tl := range goodTools() {
		if f.called[0] == tl["name"] {
			t.Fatalf("a listed tool, %s, was called", f.called[0])
		}
	}
	if !strings.HasPrefix(f.called[0], "lyntway_readiness_no_such_tool_") {
		t.Errorf("the one call named %q, not the made-up tool", f.called[0])
	}
	allowed := map[string]bool{"initialize": true, "notifications/initialized": true, "tools/list": true,
		"tools/call": true, "lyntway/readiness_no_such_method": true}
	for _, m := range f.methods {
		if !allowed[m] {
			t.Errorf("sent %q, which is not in the fixed list of what this check sends", m)
		}
	}
}

// A server that gets everything wrong fails each check for its own
// reason, and says which tools.
func TestABadlyBuiltServerFailsForEachReason(t *testing.T) {
	bad := []map[string]any{
		// Labelled read-only, named like a write.
		tool("delete_everything", "Deletes every record in the account.", objSchema(map[string]any{}), map[string]any{"readOnlyHint": true}),
		// No description, no annotations, an untyped and undescribed input,
		// and a required field that is not defined.
		tool("run", "", objSchema(map[string]any{"q": map[string]any{}}, "missing"), nil),
		// A name clients will refuse.
		tool("send email", "Sends an email to anyone at all.", objSchema(map[string]any{}), map[string]any{"readOnlyHint": false}),
	}
	f := &fakeMCP{tools: bad, methodCode: -32602, toolReply: "success"}
	srv := httptest.NewServer(f)
	defer srv.Close()

	got := checkMCP(srv.URL, "")
	st := statuses(got)
	for _, id := range []string{"mcp.auth", "mcp.tools_described", "mcp.tools_schema", "mcp.tool_names", "mcp.effects_labelled",
		"mcp.idempotency_declared", "mcp.error_unknown_tool", "mcp.error_unknown_method", "mcp.rate_limits_stated"} {
		if st[id] != checkFail {
			t.Errorf("%s is %s, want fail: %s", id, st[id], checkByID(got, id).Evidence)
		}
	}
	if st["mcp.tools_paging"] != checkInconclusive {
		t.Errorf("paging on a one-page list is %s; it was never exercised, so it cannot pass", st["mcp.tools_paging"])
	}
	eff := checkByID(got, "mcp.effects_labelled").Evidence
	if !strings.Contains(eff, "abelled read-only but named like a write: delete_everything") {
		t.Errorf("the contradicted label was not named: %s", eff)
	}
	sch := checkByID(got, "mcp.tools_schema").Evidence
	for _, want := range []string{"run.q has no type", "run.q has no description", `run requires "missing"`} {
		if !strings.Contains(sch, want) {
			t.Errorf("schema evidence does not say %q: %s", want, sch)
		}
	}
	if auth := checkByID(got, "mcp.auth").Evidence; !strings.Contains(auth, "not labelled read-only") {
		t.Errorf("an open server exposing writes was not described as such: %s", auth)
	}
}

// Every check carries its criterion and its limit, pass or fail, and a
// run that stops early still names every check rather than omitting some.
func TestEveryCheckCarriesItsCriterionAndItsLimit(t *testing.T) {
	f := &fakeMCP{token: "x", www: `Bearer resource_metadata="https://auth.example/.well-known/oauth-protected-resource"`}
	srv := httptest.NewServer(f)
	defer srv.Close()

	got := checkMCP(srv.URL, "")
	if len(got.Checks) != len(mcpDefs) {
		t.Fatalf("%d checks, want %d even though the server refused", len(got.Checks), len(mcpDefs))
	}
	for _, c := range got.Checks {
		if c.Criterion == "" || c.NotProven == "" || c.Evidence == "" {
			t.Errorf("%s is missing its criterion, its limit or its evidence: %+v", c.ID, c)
		}
		if c.ID != "mcp.auth" && c.Status != checkInconclusive {
			t.Errorf("%s is %s although the tools were never read", c.ID, c.Status)
		}
	}
	auth := checkByID(got, "mcp.auth")
	if auth.Status != checkPass || !strings.Contains(auth.Evidence, "cannot front") {
		t.Errorf("an OAuth refusal was not read as one: %+v", auth)
	}
	if !strings.Contains(checkByID(got, "mcp.tools_described").Evidence, "--mcp-token-env") {
		t.Error("the run did not say how to let it read the tools")
	}
}

// A 401 with nothing to act on leaves a client stuck.
func TestARefusalWithNoWayForwardFails(t *testing.T) {
	srv := httptest.NewServer(&fakeMCP{token: "x"})
	defer srv.Close()
	if c := checkByID(checkMCP(srv.URL, ""), "mcp.auth"); c.Status != checkFail {
		t.Errorf("a 401 with no WWW-Authenticate was %s: %s", c.Status, c.Evidence)
	}
}

// An open server whose every tool is labelled read-only is allowed to be
// open; the same server with one unlabelled tool is not.
func TestAnOpenServerIsJudgedByWhatItExposes(t *testing.T) {
	ro := []map[string]any{goodTools()[0]}
	srv := httptest.NewServer(&fakeMCP{tools: ro})
	defer srv.Close()
	if c := checkByID(checkMCP(srv.URL, ""), "mcp.auth"); c.Status != checkPass {
		t.Errorf("open and read-only was %s: %s", c.Status, c.Evidence)
	}

	withWrite := append(ro, tool("update_thing", "Updates a thing somewhere.", objSchema(map[string]any{}), nil))
	srv2 := httptest.NewServer(&fakeMCP{tools: withWrite})
	defer srv2.Close()
	if c := checkByID(checkMCP(srv2.URL, ""), "mcp.auth"); c.Status != checkFail || !strings.Contains(c.Evidence, "update_thing") {
		t.Errorf("open with an unlabelled tool was %s: %s", c.Status, c.Evidence)
	}

	// No label at all is not read-only, whatever the name suggests: the
	// specification's default is false, and a client assuming otherwise
	// runs a write without asking.
	unlabelled := append(ro, tool("lookup", "Looks a thing up somewhere.", objSchema(map[string]any{}), nil))
	srv4 := httptest.NewServer(&fakeMCP{tools: unlabelled})
	defer srv4.Close()
	if c := checkByID(checkMCP(srv4.URL, ""), "mcp.auth"); c.Status != checkFail || !strings.Contains(c.Evidence, "lookup") {
		t.Errorf("open with a tool carrying no label was %s: %s", c.Status, c.Evidence)
	}

	// A read-only label on a delete is not taken at its word.
	liar := append(ro, tool("delete_all", "Deletes every record there is.", objSchema(map[string]any{}), map[string]any{"readOnlyHint": true}))
	srv3 := httptest.NewServer(&fakeMCP{tools: liar})
	defer srv3.Close()
	if c := checkByID(checkMCP(srv3.URL, ""), "mcp.auth"); c.Status != checkFail || !strings.Contains(c.Evidence, "delete_all") {
		t.Errorf("open with a delete labelled read-only was %s: %s", c.Status, c.Evidence)
	}
}

// A cursor that comes back again means a client paging to the end never
// gets there.
func TestACursorThatLoopsFailsPaging(t *testing.T) {
	srv := httptest.NewServer(&fakeMCP{tools: goodTools(), loopCursor: true})
	defer srv.Close()
	got := checkMCP(srv.URL, "")
	if c := checkByID(got, "mcp.tools_paging"); c.Status != checkFail || !strings.Contains(c.Evidence, "already followed") {
		t.Errorf("a looping cursor was %s: %s", c.Status, c.Evidence)
	}
}

// An error that does not name what was wrong is no help to an agent.
func TestAnErrorThatDoesNotNameTheToolFails(t *testing.T) {
	srv := httptest.NewServer(&fakeMCP{tools: goodTools(), toolReply: "vague"})
	defer srv.Close()
	if c := checkByID(checkMCP(srv.URL, ""), "mcp.error_unknown_tool"); c.Status != checkFail {
		t.Errorf("a vague error was %s: %s", c.Status, c.Evidence)
	}
}

// Nothing leaves the machine that should not: a token never crosses plain
// http to another host, and only http(s) is accepted at all.
func TestATokenNeverCrossesPlainHTTP(t *testing.T) {
	if _, err := validateAgentTarget("http://mcp.example.com/mcp", true); err == nil {
		t.Error("a token would have been sent over plain http to another host")
	}
	if _, err := validateAgentTarget("http://127.0.0.1:9/mcp", true); err != nil {
		t.Errorf("plain http to this machine was refused: %v", err)
	}
	if _, err := validateAgentTarget("http://mcp.example.com/mcp", false); err != nil {
		t.Errorf("plain http with no token was refused: %v", err)
	}
	if _, err := validateAgentTarget("file:///etc/passwd", false); err == nil {
		t.Error("a non-http scheme was accepted")
	}
}

func TestTheTokenIsReadFromTheEnvironmentOnly(t *testing.T) {
	t.Setenv("EMPTY_TOKEN_VAR", "")
	if _, err := runAgentChecks([]string{"https://mcp.example.com/mcp"}, nil, "EMPTY_TOKEN_VAR", true); err == nil ||
		!strings.Contains(err.Error(), "EMPTY_TOKEN_VAR") {
		t.Errorf("an empty token variable was not refused by name: %v", err)
	}
}

// The name of a tool decides whether a read-only label contradicts it.
func TestWriteNamesAreRecognisedInEveryCase(t *testing.T) {
	for name, want := range map[string]bool{
		"delete_issue": true, "createPage": true, "issue-update": true, "files.write": true,
		"list_issues": false, "getUser": false, "search": false, "settings_get": false,
	} {
		if namedLikeAWrite(name) != want {
			t.Errorf("namedLikeAWrite(%q) = %v, want %v", name, !want, want)
		}
	}
}

// A redirect from an API endpoint is not an open endpoint. Followed, the
// sign-in page's 200 read as "answered without a credential".
func TestARedirectToSignInIsNotReadAsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer srv.Close()
	got := probeEndpoint(probeResult{Endpoint: "GET /v1/orders", Host: "test", Detail: "GET " + srv.URL + "/v1/orders"})
	if got.Verdict == verdictOpen {
		t.Fatal("a redirect to a sign-in page was reported as an endpoint that answers without a credential")
	}
	if got.Status != http.StatusFound || !strings.Contains(describeResult(got), "redirected to /login") {
		t.Errorf("the redirect was not reported as one: %+v", got)
	}
}

// robots.txt: the fetchers that act for a person are what decides; a site
// that keeps training crawlers out is making a different, legitimate choice.
func TestRobotsIsJudgedByTheFetchersThatActForAPerson(t *testing.T) {
	onlyTraining := "User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nAllow: /\n"
	if b := blockedAgents(onlyTraining, userFetchers); len(b) != 0 {
		t.Errorf("keeping GPTBot out was read as blocking %v", b)
	}
	if b := blockedAgents(onlyTraining, trainingCrawlers); len(b) != 1 || b[0] != "GPTBot" {
		t.Errorf("the training crawler kept out was not reported: %v", b)
	}
	everyone := "User-agent: *\nDisallow: /\n"
	if b := blockedAgents(everyone, userFetchers); len(b) != len(userFetchers) {
		t.Errorf("a site closed to everyone was read as letting %v in", b)
	}
	ownGroup := "User-agent: *\nDisallow: /\n\nUser-agent: Claude-User\nAllow: /\n"
	if b := blockedAgents(ownGroup, []string{"Claude-User"}); len(b) != 0 {
		t.Errorf("an agent with its own permissive group was read as blocked: %v", b)
	}
}

func TestDocsChecksReadWhatTheSiteServes(t *testing.T) {
	long := strings.Repeat("Send a message with one request. ", 30)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, "<html><body><p>%s</p><a href=\"/spec/openapi.json\">spec</a></body></html>", long)
		case "/llms.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "# Docs\n- [Quickstart](/quickstart)\n")
		case "/robots.txt":
			fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	got := checkDocs(srv.URL + "/")
	st := statuses(got)
	// httptest serves plain http, which is itself a finding.
	if st["docs.readable_without_js"] != checkFail || !strings.Contains(checkByID(got, "docs.readable_without_js").Evidence, "http") {
		t.Errorf("plain http docs were %s", st["docs.readable_without_js"])
	}
	if st["docs.llms_txt"] != checkPass || st["docs.openapi_findable"] != checkPass {
		t.Errorf("llms.txt %s, openapi %s; both are served", st["docs.llms_txt"], st["docs.openapi_findable"])
	}
	if st["docs.agents_allowed"] != checkFail {
		t.Errorf("robots.txt closed to everyone was %s", st["docs.agents_allowed"])
	}
	if strings.Contains(visibleText("<script>var x = 'hidden words'</script><p>seen</p>"), "hidden") {
		t.Error("script text was counted as visible")
	}
}
