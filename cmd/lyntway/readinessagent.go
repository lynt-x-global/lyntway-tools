package main

// Asks an MCP server whether an agent could use it, and use it safely.
//
// # Where this came from
//
// XitOK, folded into Lyntway on 17 September 2026, measured agent readiness
// by sending real coding agents at an API and grading what they managed.
// That needs model keys, sandboxes and money per run, and it answers "can
// an agent finish this task", which is a different question from the one a
// readiness check answers. What moved across is narrower and cheaper: the
// facts about a server that decide whether an agent's client can reach it,
// understand it, and tell a harmless call from a harmful one — each read
// from what the server itself returns, each with a stated pass condition
// and a stated limit.
//
// XitOK graded its docs checks into a weighted 0–100 "preview". That did
// not come across. A number invites being read as a score of the product,
// and a weighted mean of unlike facts is a number nobody can argue with or
// act on. Each check here passes or fails on its own terms.
//
// # What is sent
//
// Streamable HTTP is a POST protocol, so the GET-only rule the endpoint
// half keeps cannot hold here — the catalog probe learned that on
// 7 September (cmd/lyntway-catalog/probe.go). What holds instead is that
// every request body is written in this file and none is read from the
// server: initialize, the initialized notification, tools/list and its
// pages, one tools/call naming a tool that does not exist, one method that
// does not exist, and a DELETE of the session the server gave us. A tool
// the server lists is never called. Annotations are hints a server asserts
// about itself; calling a tool to see whether its label is true would be
// exactly the act this check is not entitled to perform.
//
// # Why the credential question is asked first and alone
//
// The first request carries nothing, whatever the operator supplied,
// because "what does a stranger reach" is the question a security reviewer
// reads first. A token, when one is given, is used afterwards to read what
// an authorised agent would see.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// mcpProtocol is the revision asked for. A server that speaks another
// answers with its own, and that is recorded rather than refused.
const mcpProtocol = "2025-06-18"

// Check outcomes. Inconclusive is its own value, never folded into pass: a
// server that could not be asked has not passed anything.
const (
	checkPass         = "pass"
	checkFail         = "fail"
	checkInconclusive = "inconclusive"
)

// maxToolPages bounds how far a cursor is followed. A server whose list
// never ends is a finding, not a reason to keep asking.
const maxToolPages = 20

// maxReplyBytes bounds one reply. A tool list is kilobytes; anything past
// this is not a tool list.
const maxReplyBytes = 4 << 20

// agentPause is the gap between two requests to the same server. A
// variable only so the tests need not sleep; the command always uses the
// same walking pace as the endpoint half.
var agentPause = probePause

// agentCheck is one question asked of a server, with its answer.
type agentCheck struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`

	// Criterion is the pass condition, written before the answer was
	// known, so a reader can disagree with the rule rather than the result.
	Criterion string `json:"criterion"`
	Evidence  string `json:"evidence"`

	// NotProven travels with every check, pass or fail. A passing check
	// read without its limit is how a pre-assessment becomes an assurance.
	NotProven string `json:"does_not_prove"`
}

// agentTarget is everything asked of one server or docs site.
type agentTarget struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`

	// Server is how the server described itself: its own words, not ours.
	Server   string `json:"server,omitempty"`
	Protocol string `json:"protocol,omitempty"`

	// Tools holds names only. The descriptions are the vendor's text, and
	// a report that copied them would be carrying somebody else's product.
	Tools     []string `json:"tools,omitempty"`
	ToolsRead bool     `json:"tools_read"`

	Checks []agentCheck `json:"checks"`
}

func (t agentTarget) failed() int {
	n := 0
	for _, c := range t.Checks {
		if c.Status == checkFail {
			n++
		}
	}
	return n
}

// The checks, in the order a reader meets them. Each definition carries
// its criterion and its limit so no code path can emit a check without
// them.
type checkDef struct{ id, title, criterion, notProven string }

var (
	defAuth = checkDef{"mcp.auth", "A stranger reaches nothing that changes state",
		"With no credential, the server either refuses with 401 or 403 and a WWW-Authenticate header a client can act on, or lists only tools labelled read-only whose names do not say otherwise.",
		"It does not show that a valid credential is checked properly, that one account cannot reach another's data, or that a tool labelled read-only really is."}
	defDescribed = checkDef{"mcp.tools_described", "Every tool says what it does",
		"Every listed tool has a description of at least 20 characters that is more than its own name.",
		"It does not show that a description is accurate, only that one exists for an agent to read."}
	defSchema = checkDef{"mcp.tools_schema", "Every input is typed and explained",
		`Every tool's inputSchema is an object schema; every property has a type and a description; "required" names only properties that exist.`,
		"It does not show that the server validates what it receives against the schema it publishes."}
	defNames = checkDef{"mcp.tool_names", "Tool names are unique and portable",
		"Every tool name is unique in the list and uses only letters, digits, underscore, hyphen and dot, 1 to 128 characters, as the MCP specification recommends.",
		"Some clients accept less — 64 characters, no dots — so a name that passes here can still be refused by a particular client."}
	defEffects = checkDef{"mcp.effects_labelled", "Every tool says whether it changes things",
		"Every tool sets readOnlyHint explicitly; every tool that is not read-only sets destructiveHint explicitly; no tool labelled read-only is named like a write (delete_, create_, send_ and the like).",
		"Labels are what the server asserts about itself. No tool was called, so none was seen to behave as labelled."}
	defIdempotent = checkDef{"mcp.idempotency_declared", "Every change says whether repeating it is safe",
		"Every tool that is not labelled read-only sets idempotentHint explicitly, so an agent that retries after a timeout knows whether it may.",
		"Nothing was repeated. A tool that declares itself idempotent was not seen to be."}
	defUnknownTool = checkDef{"mcp.error_unknown_tool", "A wrong tool name gets an error that says so",
		"A tools/call naming a tool the server does not list comes back as an error — a JSON-RPC error or a result marked isError — whose message contains the name that was asked for.",
		"It shows how one kind of mistake is answered. Errors from real tools, with real arguments, were not seen."}
	defUnknownMethod = checkDef{"mcp.error_unknown_method", "A wrong method gets the protocol's error",
		"A method the server does not implement is answered with JSON-RPC error -32601 and a message, which is what every client library knows how to read.",
		"It says nothing about how the server reports failures inside the methods it does implement."}
	defLimits = checkDef{"mcp.rate_limits_stated", "Rate limits are stated in replies",
		"At least one reply carried a rate-limit header (RateLimit, RateLimit-Policy, X-RateLimit-*) or Retry-After, so an agent can pace itself before it is refused.",
		"A handful of requests were sent at walking pace and no limit was reached. How the server behaves at its limit was not tested, and a server that states nothing may still enforce a limit."}
	defPaging = checkDef{"mcp.tools_paging", "The tool list can be read to the end",
		"Following nextCursor ends within 20 pages, never repeats a cursor, and never lists a tool twice.",
		"Only the tool list was paged. Paging in the server's own tools, which an agent meets far more often, was not exercised."}
)

func (d checkDef) result(status, evidence string) agentCheck {
	return agentCheck{ID: d.id, Title: d.title, Status: status, Criterion: d.criterion, Evidence: evidence, NotProven: d.notProven}
}

// mcpDefs lists every MCP check, so a run that stops early still reports
// each one — as inconclusive, with the reason — rather than omitting it.
// A check that is missing from a report reads as a check nobody thought
// of; one marked inconclusive reads as what it is.
var mcpDefs = []checkDef{defAuth, defDescribed, defSchema, defNames, defEffects, defIdempotent, defUnknownTool, defUnknownMethod, defLimits, defPaging}

// rpcReply is one JSON-RPC answer.
type rpcReply struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// mcpSession is one conversation with one server.
type mcpSession struct {
	endpoint  string
	token     string
	sessionID string
	protocol  string
	client    *http.Client
	nextID    int
	requests  int

	// headers holds every reply's headers, read once at the end for the
	// rate-limit check.
	headers []http.Header
}

// httpReply is what came back to one POST, before any JSON-RPC meaning.
type httpReply struct {
	status  int
	header  http.Header
	rpc     *rpcReply
	rawHead string
}

func newMCPSession(endpoint, token string) *mcpSession {
	return &mcpSession{
		endpoint: endpoint,
		token:    token,
		// Redirects are not followed: an MCP address that answers 302 has
		// moved or wants a browser, and following it would report what a
		// different address said.
		client: &http.Client{
			Timeout:       probeTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// post sends one JSON-RPC message. withAuth decides whether the token
// rides along; the first request never carries it.
func (s *mcpSession) post(method string, params any, notify, withAuth bool) (httpReply, error) {
	if s.requests > 0 && agentPause > 0 {
		time.Sleep(agentPause)
	}
	s.requests++

	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		msg["params"] = params
	}
	if !notify {
		s.nextID++
		msg["id"] = s.nextID
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return httpReply{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return httpReply{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "lyntway-readiness/"+version+" (agent-readiness check; calls no listed tool)")
	if s.protocol != "" {
		req.Header.Set("MCP-Protocol-Version", s.protocol)
	}
	if s.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", s.sessionID)
	}
	if withAuth && s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return httpReply{}, err
	}
	defer resp.Body.Close()
	s.headers = append(s.headers, resp.Header.Clone())

	out := httpReply{status: resp.StatusCode, header: resp.Header}
	if notify {
		return out, nil
	}

	// The body is read whatever the status. Plenty of servers answer an
	// unknown method with a 400 or 404 that still carries a proper
	// JSON-RPC error, and reading only 2xx bodies would call that silence.
	want := fmt.Sprint(s.nextID)
	limited := io.LimitReader(resp.Body, maxReplyBytes)
	if strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		out.rpc, err = readSSEReply(limited, want)
		if err != nil && (resp.StatusCode < 200 || resp.StatusCode > 299) {
			err = nil
		}
		return out, err
	}
	raw, rerr := io.ReadAll(limited)
	if rerr != nil {
		return out, rerr
	}
	var r rpcReply
	if json.Unmarshal(raw, &r) == nil && (r.Result != nil || r.Error != nil) {
		out.rpc = &r
	} else {
		out.rawHead = flatText(string(raw[:min(len(raw), 200)]))
	}
	return out, nil
}

// readSSEReply reads events until the one answering our request. A server
// may send its own requests and notifications first on the same stream;
// those are skipped rather than mistaken for the answer.
func readSSEReply(r io.Reader, wantID string) (*rpcReply, error) {
	raw, err := io.ReadAll(r)
	if err != nil && len(raw) == 0 {
		return nil, err
	}
	var data []string
	flush := func() *rpcReply {
		defer func() { data = data[:0] }()
		if len(data) == 0 {
			return nil
		}
		var rep rpcReply
		if json.Unmarshal([]byte(strings.Join(data, "\n")), &rep) != nil {
			return nil
		}
		if strings.Trim(string(rep.ID), `"`) != wantID {
			return nil
		}
		return &rep
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		switch {
		case line == "":
			if rep := flush(); rep != nil {
				return rep, nil
			}
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if rep := flush(); rep != nil {
		return rep, nil
	}
	return nil, errors.New("the event stream ended without an answer to the request")
}

// listedTool is the part of a listed tool these checks read.
type listedTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations *struct {
		ReadOnly    *bool `json:"readOnlyHint"`
		Destructive *bool `json:"destructiveHint"`
		Idempotent  *bool `json:"idempotentHint"`
	} `json:"annotations"`
}

// readOnly is what the server declared. An absent label is not read-only:
// the specification's default for readOnlyHint is false, and a client that
// assumed otherwise would run a write without asking.
func (t listedTool) readOnly() bool {
	return t.Annotations != nil && t.Annotations.ReadOnly != nil && *t.Annotations.ReadOnly
}

// checkMCP asks one server every question and returns the answers.
func checkMCP(endpoint, token string) agentTarget {
	target := agentTarget{Kind: "mcp", Target: endpoint}
	answered := map[string]agentCheck{}
	finish := func(reason string) agentTarget {
		for _, d := range mcpDefs {
			if c, ok := answered[d.id]; ok {
				target.Checks = append(target.Checks, c)
			} else {
				target.Checks = append(target.Checks, d.result(checkInconclusive, reason))
			}
		}
		return target
	}

	s := newMCPSession(endpoint, token)
	initParams := map[string]any{
		"protocolVersion": mcpProtocol,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "lyntway-readiness", "version": version},
	}

	// The stranger's view first, with nothing attached.
	first, err := s.post("initialize", initParams, false, false)
	if err != nil {
		return finish("The server could not be reached: " + err.Error())
	}

	open := false
	switch {
	case first.status == http.StatusUnauthorized || first.status == http.StatusForbidden:
		answered[defAuth.id] = authRefusal(first)
		if token == "" {
			return finish(fmt.Sprintf("The server asked for a credential (%d) and none was supplied, so its tools were not read. "+
				"Name an environment variable holding a token with --mcp-token-env to read them.", first.status))
		}
		// Asked again, now as an authorised agent would.
		first, err = s.post("initialize", initParams, false, true)
		if err != nil {
			return finish("The server could not be reached with the credential: " + err.Error())
		}
		if first.status < 200 || first.status > 299 || first.rpc == nil || first.rpc.Result == nil {
			return finish(fmt.Sprintf("The server refused the supplied credential too (%d), so its tools were not read.", first.status))
		}
	case first.status >= 300 && first.status < 400:
		answered[defAuth.id] = defAuth.result(checkFail, fmt.Sprintf(
			"initialize was answered %d, redirecting to %s. An agent's client does not follow a redirect to sign in; it stops.",
			first.status, first.header.Get("Location")))
		return finish("The server redirected instead of answering, so nothing further was asked.")
	case first.status >= 200 && first.status <= 299 && first.rpc != nil && first.rpc.Result != nil:
		open = true
	case first.status >= 200 && first.status <= 299 && first.rpc != nil && first.rpc.Error != nil:
		return finish(fmt.Sprintf("initialize was refused with JSON-RPC error %d: %s", first.rpc.Error.Code, flatText(first.rpc.Error.Message)))
	default:
		detail := fmt.Sprintf("initialize was answered %d", first.status)
		if first.rawHead != "" {
			detail += ": " + first.rawHead
		}
		return finish(detail + ". That is not an MCP answer, so nothing further was asked.")
	}

	// From here the token rides along only if the server wanted one. An
	// open server is asked everything as the stranger it already answered,
	// because what a stranger reaches is what the auth check is about.
	withAuth := !open
	if sid := first.header.Get("Mcp-Session-Id"); sid != "" {
		s.sessionID = sid
	}
	var init struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	_ = json.Unmarshal(first.rpc.Result, &init)
	s.protocol = init.ProtocolVersion
	if s.protocol == "" {
		s.protocol = mcpProtocol
	}
	target.Protocol = s.protocol
	target.Server = strings.TrimSpace(init.ServerInfo.Name + " " + init.ServerInfo.Version)

	_, _ = s.post("notifications/initialized", nil, true, withAuth)

	tools, paging, listErr := listTools(s, withAuth)
	answered[defPaging.id] = paging
	if listErr != "" {
		if _, decided := answered[defAuth.id]; !decided {
			answered[defAuth.id] = defAuth.result(checkInconclusive,
				"initialize was answered with no credential, but the tool list could not be read, so what a stranger reaches is unknown.")
		}
		s.close(withAuth)
		answered[defLimits.id] = rateLimitCheck(s.headers)
		return finish(listErr)
	}
	target.ToolsRead = true
	for _, t := range tools {
		target.Tools = append(target.Tools, t.Name)
	}
	sort.Strings(target.Tools)

	if open {
		answered[defAuth.id] = openAuth(tools)
	}
	answered[defDescribed.id] = describedCheck(tools)
	answered[defSchema.id] = schemaCheck(tools)
	answered[defNames.id] = namesCheck(tools)
	answered[defEffects.id] = effectsCheck(tools)
	answered[defIdempotent.id] = idempotentCheck(tools)
	answered[defUnknownTool.id] = unknownToolCheck(s, tools, withAuth)
	answered[defUnknownMethod.id] = unknownMethodCheck(s, withAuth)
	s.close(withAuth)
	answered[defLimits.id] = rateLimitCheck(s.headers)
	return finish("")
}

// close ends the session the server opened for us, when it opened one. The
// only DELETE this sends, and only ever to the session id the server just
// handed over.
func (s *mcpSession) close(withAuth bool) {
	if s.sessionID == "" {
		return
	}
	if agentPause > 0 {
		time.Sleep(agentPause)
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("Mcp-Session-Id", s.sessionID)
	req.Header.Set("User-Agent", "lyntway-readiness/"+version+" (agent-readiness check; ending its own session)")
	if withAuth && s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	if resp, err := s.client.Do(req); err == nil {
		resp.Body.Close()
	}
}

// authRefusal judges a 401 or 403. A refusal with no WWW-Authenticate
// header leaves an agent's client nothing to act on: it cannot tell a key
// from OAuth from a wrong address.
func authRefusal(r httpReply) agentCheck {
	www := r.header.Get("WWW-Authenticate")
	if www == "" {
		return defAuth.result(checkFail, fmt.Sprintf(
			"With no credential the server answered %d with no WWW-Authenticate header, so a client cannot tell how to authenticate.", r.status))
	}
	ev := fmt.Sprintf("With no credential the server answered %d and WWW-Authenticate: %s.", r.status, flatText(www))
	if strings.Contains(strings.ToLower(www), "resource_metadata") {
		// Said because it decides what Lyntway can do for this server: a
		// token bound to the server's own address is refused when it
		// arrives from the gateway's (CLAUDE.md, "What is deliberately not
		// here").
		ev += " It names OAuth protected-resource metadata, so it expects OAuth; the Lyntway gateway cannot front a server that does."
	}
	return defAuth.result(checkPass, ev)
}

// openAuth judges a server that answered a stranger.
func openAuth(tools []listedTool) agentCheck {
	// A read-only label on a tool named like a write is not taken at its
	// word here: the stranger's view is judged by the weaker reading, the
	// same way an absent label is.
	var writes []string
	for _, t := range tools {
		if !t.readOnly() || namedLikeAWrite(t.Name) {
			writes = append(writes, t.Name)
		}
	}
	if len(writes) == 0 {
		return defAuth.result(checkPass, fmt.Sprintf(
			"The server answered with no credential and listed %d %s, every one labelled read-only.",
			len(tools), plural(len(tools), "tool", "tools")))
	}
	return defAuth.result(checkFail, fmt.Sprintf(
		"The server answered with no credential and listed %d of %d %s not labelled read-only, which a client must treat as able to change things: %s.",
		len(writes), len(tools), plural(len(tools), "tool", "tools"), nameList(writes)))
}

// listTools reads the whole tool list, following cursors, and judges the
// paging as it goes. It returns a non-empty reason when the list could not
// be read at all.
func listTools(s *mcpSession, withAuth bool) ([]listedTool, agentCheck, string) {
	var all []listedTool
	seenCursor := map[string]bool{}
	seenName := map[string]bool{}
	var dupes []string
	cursor := ""
	pages := 0
	for {
		var params any
		if cursor != "" {
			params = map[string]any{"cursor": cursor}
		}
		r, err := s.post("tools/list", params, false, withAuth)
		pages++
		if err != nil {
			reason := "tools/list could not be read: " + err.Error()
			if pages == 1 {
				return nil, defPaging.result(checkInconclusive, reason), reason
			}
			return all, defPaging.result(checkFail, fmt.Sprintf("Page %d of the tool list failed: %v.", pages, err)), ""
		}
		if r.rpc == nil || r.rpc.Result == nil {
			why := fmt.Sprintf("tools/list was answered %d", r.status)
			if r.rpc != nil && r.rpc.Error != nil {
				why = fmt.Sprintf("tools/list was refused with JSON-RPC error %d: %s", r.rpc.Error.Code, flatText(r.rpc.Error.Message))
			}
			if pages == 1 {
				return nil, defPaging.result(checkInconclusive, why+"."), why + "."
			}
			return all, defPaging.result(checkFail, fmt.Sprintf("Following the cursor to page %d: %s.", pages, why)), ""
		}
		var page struct {
			Tools      []listedTool `json:"tools"`
			NextCursor string       `json:"nextCursor"`
		}
		if err := json.Unmarshal(r.rpc.Result, &page); err != nil {
			reason := "the tool list was not in the shape the protocol defines: " + err.Error()
			if pages == 1 {
				return nil, defPaging.result(checkInconclusive, reason), reason
			}
			return all, defPaging.result(checkFail, "Page "+fmt.Sprint(pages)+": "+reason+"."), ""
		}
		for _, t := range page.Tools {
			if seenName[t.Name] {
				dupes = append(dupes, t.Name)
				continue
			}
			seenName[t.Name] = true
			all = append(all, t)
		}
		switch {
		case page.NextCursor == "":
			if len(dupes) > 0 {
				return all, defPaging.result(checkFail, fmt.Sprintf("Across %d %s, %s listed more than once: %s.",
					pages, plural(pages, "page", "pages"), plural(len(dupes), "a tool was", "tools were"), nameList(dupes))), ""
			}
			if pages == 1 {
				return all, defPaging.result(checkInconclusive, fmt.Sprintf(
					"The whole list, %d %s, came in one page with no cursor, so paging was not exercised.",
					len(all), plural(len(all), "tool", "tools"))), ""
			}
			return all, defPaging.result(checkPass, fmt.Sprintf("%d %s over %d pages, each cursor new and no tool repeated.",
				len(all), plural(len(all), "tool", "tools"), pages)), ""
		case seenCursor[page.NextCursor]:
			return all, defPaging.result(checkFail, fmt.Sprintf(
				"Page %d handed back a cursor already followed, so a client paging to the end never arrives.", pages)), ""
		case pages >= maxToolPages:
			return all, defPaging.result(checkFail, fmt.Sprintf(
				"After %d pages the list still had a next cursor; it was not followed further.", pages)), ""
		}
		seenCursor[page.NextCursor] = true
		cursor = page.NextCursor
	}
}

func describedCheck(tools []listedTool) agentCheck {
	if len(tools) == 0 {
		return defDescribed.result(checkInconclusive, "The server lists no tools.")
	}
	var weak []string
	for _, t := range tools {
		d := strings.TrimSpace(t.Description)
		if len(d) < 20 || strings.EqualFold(d, t.Name) {
			weak = append(weak, t.Name)
		}
	}
	if len(weak) == 0 {
		return defDescribed.result(checkPass, fmt.Sprintf("All %d %s carry a description.", len(tools), plural(len(tools), "tool", "tools")))
	}
	return defDescribed.result(checkFail, fmt.Sprintf("%d of %d %s no usable description: %s.",
		len(weak), len(tools), plural(len(tools), "tool has", "tools have"), nameList(weak)))
}

// schemaCheck reads each inputSchema the way an agent filling it in would:
// what is this field, what shape does it take, and is it needed.
func schemaCheck(tools []listedTool) agentCheck {
	if len(tools) == 0 {
		return defSchema.result(checkInconclusive, "The server lists no tools.")
	}
	var problems []string
	bad := 0
	for _, t := range tools {
		p := schemaProblems(t)
		if len(p) > 0 {
			bad++
			problems = append(problems, p...)
		}
	}
	if bad == 0 {
		return defSchema.result(checkPass, fmt.Sprintf("Every input of all %d %s is typed and described.",
			len(tools), plural(len(tools), "tool", "tools")))
	}
	return defSchema.result(checkFail, fmt.Sprintf("%d of %d %s inputs an agent has to guess at: %s.",
		bad, len(tools), plural(len(tools), "tool has", "tools have"), nameList(problems)))
}

func schemaProblems(t listedTool) []string {
	if len(t.InputSchema) == 0 || string(t.InputSchema) == "null" {
		return []string{t.Name + " has no inputSchema"}
	}
	var schema map[string]any
	if json.Unmarshal(t.InputSchema, &schema) != nil {
		return []string{t.Name + "'s inputSchema is not a JSON object"}
	}
	if typ, _ := schema["type"].(string); typ != "object" {
		return []string{t.Name + `'s inputSchema is not "type": "object"`}
	}
	var out []string
	props, _ := schema["properties"].(map[string]any)
	names := make([]string, 0, len(props))
	for n := range props {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p, _ := props[n].(map[string]any)
		if p == nil {
			out = append(out, t.Name+"."+n+" is not a schema")
			continue
		}
		typed := false
		for _, k := range []string{"type", "anyOf", "oneOf", "allOf", "$ref", "enum", "const"} {
			if _, ok := p[k]; ok {
				typed = true
				break
			}
		}
		if !typed {
			out = append(out, t.Name+"."+n+" has no type")
		}
		if d, _ := p["description"].(string); strings.TrimSpace(d) == "" {
			out = append(out, t.Name+"."+n+" has no description")
		}
	}
	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			name, _ := r.(string)
			if _, exists := props[name]; !exists {
				out = append(out, t.Name+` requires "`+name+`", which it does not define`)
			}
		}
	}
	return out
}

var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func namesCheck(tools []listedTool) agentCheck {
	if len(tools) == 0 {
		return defNames.result(checkInconclusive, "The server lists no tools.")
	}
	var bad []string
	for _, t := range tools {
		if !toolNamePattern.MatchString(t.Name) {
			bad = append(bad, fmt.Sprintf("%q", t.Name))
		}
	}
	if len(bad) == 0 {
		return defNames.result(checkPass, fmt.Sprintf("All %d names are unique and use only the recommended characters.", len(tools)))
	}
	return defNames.result(checkFail, fmt.Sprintf("%d %s outside the recommended characters or length: %s.",
		len(bad), plural(len(bad), "name falls", "names fall"), nameList(bad)))
}

// writeVerbs are the words that, first or last in a tool's name, say it
// changes something. A tool labelled read-only and named like this is
// contradicting itself, and a client that trusts the label runs it without
// asking.
var writeVerbs = map[string]bool{
	"add": true, "archive": true, "assign": true, "cancel": true, "charge": true, "create": true,
	"delete": true, "destroy": true, "disable": true, "drop": true, "enable": true, "execute": true,
	"insert": true, "install": true, "kill": true, "merge": true, "move": true, "patch": true,
	"pay": true, "post": true, "publish": true, "purge": true, "put": true, "refund": true,
	"remove": true, "rename": true, "reset": true, "revoke": true, "run": true, "send": true,
	"set": true, "terminate": true, "transfer": true, "trigger": true, "uninstall": true,
	"update": true, "upload": true, "upsert": true, "write": true,
}

// nameWords splits snake_case, kebab-case, dotted and camelCase names.
func nameWords(name string) []string {
	var words []string
	var cur strings.Builder
	runes := []rune(name)
	for i, r := range runes {
		if r == '_' || r == '-' || r == '.' || r == ' ' {
			if cur.Len() > 0 {
				words = append(words, strings.ToLower(cur.String()))
				cur.Reset()
			}
			continue
		}
		if unicode.IsUpper(r) && i > 0 && unicode.IsLower(runes[i-1]) && cur.Len() > 0 {
			words = append(words, strings.ToLower(cur.String()))
			cur.Reset()
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		words = append(words, strings.ToLower(cur.String()))
	}
	return words
}

func namedLikeAWrite(name string) bool {
	w := nameWords(name)
	if len(w) == 0 {
		return false
	}
	return writeVerbs[w[0]] || writeVerbs[w[len(w)-1]]
}

func effectsCheck(tools []listedTool) agentCheck {
	if len(tools) == 0 {
		return defEffects.result(checkInconclusive, "The server lists no tools.")
	}
	var unlabelled, noDestructive, contradicted []string
	for _, t := range tools {
		switch {
		case t.Annotations == nil || t.Annotations.ReadOnly == nil:
			unlabelled = append(unlabelled, t.Name)
		case *t.Annotations.ReadOnly && namedLikeAWrite(t.Name):
			contradicted = append(contradicted, t.Name)
		case !*t.Annotations.ReadOnly && t.Annotations.Destructive == nil:
			noDestructive = append(noDestructive, t.Name)
		}
	}
	if len(unlabelled)+len(noDestructive)+len(contradicted) == 0 {
		return defEffects.result(checkPass, fmt.Sprintf("All %d %s declare whether they change things, and no read-only label contradicts a name.",
			len(tools), plural(len(tools), "tool", "tools")))
	}
	var parts []string
	if len(contradicted) > 0 {
		parts = append(parts, fmt.Sprintf("labelled read-only but named like a write: %s", nameList(contradicted)))
	}
	if len(unlabelled) > 0 {
		parts = append(parts, fmt.Sprintf("%d with no readOnlyHint, which a client must treat as able to change things: %s", len(unlabelled), nameList(unlabelled)))
	}
	if len(noDestructive) > 0 {
		parts = append(parts, fmt.Sprintf("%d that change things without saying whether they destroy: %s", len(noDestructive), nameList(noDestructive)))
	}
	return defEffects.result(checkFail, capitalise(strings.Join(parts, "; "))+".")
}

func idempotentCheck(tools []listedTool) agentCheck {
	if len(tools) == 0 {
		return defIdempotent.result(checkInconclusive, "The server lists no tools.")
	}
	var writes, silent []string
	for _, t := range tools {
		if t.readOnly() {
			continue
		}
		writes = append(writes, t.Name)
		if t.Annotations == nil || t.Annotations.Idempotent == nil {
			silent = append(silent, t.Name)
		}
	}
	if len(writes) == 0 {
		return defIdempotent.result(checkPass, "Every tool is labelled read-only, so there is no change whose repetition needs declaring.")
	}
	if len(silent) == 0 {
		return defIdempotent.result(checkPass, fmt.Sprintf("All %d %s that can change things declare whether repeating them is safe.",
			len(writes), plural(len(writes), "tool", "tools")))
	}
	return defIdempotent.result(checkFail, fmt.Sprintf("%d of %d %s that may change things %s not say whether a retry is safe: %s.",
		len(silent), len(writes), plural(len(writes), "tool", "tools"), plural(len(silent), "does", "do"), nameList(silent)))
}

// unknownToolCheck calls a tool that does not exist. The name is random
// and checked against the list first, so there is no path by which this
// reaches a real tool.
func unknownToolCheck(s *mcpSession, tools []listedTool, withAuth bool) agentCheck {
	name := unknownToolName()
	for _, t := range tools {
		if t.Name == name {
			return defUnknownTool.result(checkInconclusive, "The name chosen for a tool that does not exist turned out to exist, so it was not called.")
		}
	}
	r, err := s.post("tools/call", map[string]any{"name": name, "arguments": map[string]any{}}, false, withAuth)
	if err != nil {
		return defUnknownTool.result(checkInconclusive, "The request could not be sent: "+err.Error())
	}
	if r.rpc == nil {
		return defUnknownTool.result(checkFail, fmt.Sprintf("tools/call for %s was answered %d with no JSON-RPC reply an agent could read.", name, r.status))
	}
	if r.rpc.Error != nil {
		msg := flatText(r.rpc.Error.Message)
		if strings.Contains(r.rpc.Error.Message, name) {
			return defUnknownTool.result(checkPass, fmt.Sprintf("Answered with JSON-RPC error %d: %q.", r.rpc.Error.Code, msg))
		}
		return defUnknownTool.result(checkFail, fmt.Sprintf("Answered with JSON-RPC error %d, %q, which does not name the tool that was asked for.", r.rpc.Error.Code, msg))
	}
	var res struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	_ = json.Unmarshal(r.rpc.Result, &res)
	var text []string
	for _, c := range res.Content {
		text = append(text, c.Text)
	}
	joined := strings.Join(text, " ")
	switch {
	case !res.IsError:
		return defUnknownTool.result(checkFail, "A call to a tool that does not exist came back as a success, so an agent cannot tell it named the wrong tool.")
	case strings.Contains(joined, name):
		return defUnknownTool.result(checkPass, fmt.Sprintf("Answered isError with %q.", flatText(joined)))
	default:
		return defUnknownTool.result(checkFail, fmt.Sprintf("Answered isError with %q, which does not name the tool that was asked for.", flatText(joined)))
	}
}

func unknownToolName() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "lyntway_readiness_no_such_tool_" + hex.EncodeToString(b)
}

func unknownMethodCheck(s *mcpSession, withAuth bool) agentCheck {
	const method = "lyntway/readiness_no_such_method"
	r, err := s.post(method, map[string]any{}, false, withAuth)
	if err != nil {
		return defUnknownMethod.result(checkInconclusive, "The request could not be sent: "+err.Error())
	}
	switch {
	case r.rpc == nil:
		return defUnknownMethod.result(checkFail, fmt.Sprintf("%s was answered %d with no JSON-RPC reply.", method, r.status))
	case r.rpc.Error == nil:
		return defUnknownMethod.result(checkFail, method+" was answered as though it had succeeded.")
	case r.rpc.Error.Code != -32601:
		return defUnknownMethod.result(checkFail, fmt.Sprintf("Answered with error %d, %q, rather than -32601, method not found.",
			r.rpc.Error.Code, flatText(r.rpc.Error.Message)))
	case strings.TrimSpace(r.rpc.Error.Message) == "":
		return defUnknownMethod.result(checkFail, "Answered -32601 with an empty message.")
	}
	return defUnknownMethod.result(checkPass, fmt.Sprintf("Answered -32601: %q.", flatText(r.rpc.Error.Message)))
}

func rateLimitCheck(headers []http.Header) agentCheck {
	found := map[string]bool{}
	for _, h := range headers {
		for k := range h {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "ratelimit") || strings.HasPrefix(lk, "x-ratelimit") ||
				strings.HasPrefix(lk, "x-rate-limit") || lk == "retry-after" {
				found[k] = true
			}
		}
	}
	if len(headers) == 0 {
		return defLimits.result(checkInconclusive, "No reply was received to read.")
	}
	if len(found) == 0 {
		return defLimits.result(checkFail, fmt.Sprintf("None of the %d %s carried a rate-limit or Retry-After header.",
			len(headers), plural(len(headers), "reply", "replies")))
	}
	names := make([]string, 0, len(found))
	for k := range found {
		names = append(names, k)
	}
	sort.Strings(names)
	return defLimits.result(checkPass, "Replies carried "+strings.Join(names, ", ")+".")
}

// nameList prints up to five names and counts the rest, so one server with
// two hundred unlabelled tools does not become a report nobody scrolls.
func nameList(names []string) string {
	const shown = 5
	if len(names) <= shown {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:shown], ", "), len(names)-shown)
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func flatText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// validateAgentTarget refuses what should never be sent: a scheme that is
// not http, and a token over plain http to anything but this machine.
func validateAgentTarget(raw string, hasToken bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not an address; give the full URL, e.g. https://mcp.example.com/mcp", raw)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("%q: only http and https servers can be checked", raw)
	}
	if u.Scheme == "http" && hasToken && !isLoopback(u.Hostname()) {
		return "", fmt.Errorf("%q is plain http, and the token would cross the network readable by anyone on the path; use https", raw)
	}
	return u.String(), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// splitList reads a comma-separated flag value.
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// printAgentTarget writes one server's answers for a person.
func printAgentTarget(t agentTarget) {
	head := t.Target
	var about []string
	if t.Server != "" {
		about = append(about, t.Server)
	}
	if t.ToolsRead {
		about = append(about, fmt.Sprintf("%d %s", len(t.Tools), plural(len(t.Tools), "tool", "tools")))
	}
	if len(about) > 0 {
		head += "  (" + strings.Join(about, ", ") + ")"
	}
	fmt.Fprintf(stdout, "\n  %s\n", head)
	width := 0
	for _, c := range t.Checks {
		width = max(width, len([]rune(c.Title)))
	}
	// A server that refused at the door leaves nine checks undecided for
	// one reason. Printed nine times, the reason is the whole screen and
	// the one decided check is lost in it; the report keeps all nine.
	undecided := map[string][]string{}
	var order []string
	for _, c := range t.Checks {
		if c.Status != checkInconclusive {
			continue
		}
		if _, seen := undecided[c.Evidence]; !seen {
			order = append(order, c.Evidence)
		}
		undecided[c.Evidence] = append(undecided[c.Evidence], c.Title)
	}
	for _, c := range t.Checks {
		switch {
		case c.Status == checkPass:
			fmt.Fprintf(stdout, "  ✓ %-*s  %s\n", width, c.Title, c.Evidence)
		case c.Status == checkFail:
			fmt.Fprintf(stdout, "  ! %-*s  %s\n", width, c.Title, c.Evidence)
		case len(undecided[c.Evidence]) < 3:
			fmt.Fprintf(stdout, "  ~ %-*s  %s\n", width, c.Title, c.Evidence)
		}
	}
	for _, reason := range order {
		if n := len(undecided[reason]); n >= 3 {
			fmt.Fprintf(stdout, "  ~ %d checks not decided: %s\n", n, reason)
		}
	}
}

// runAgentChecks checks every named server and docs site, or with dry set
// only says what it would ask. Every address is validated before anything
// is sent, so one typo does not leave a run half done.
func runAgentChecks(mcps, docs []string, tokenEnv string, dry bool) ([]agentTarget, error) {
	// The token is read from the environment, never from a flag: a flag's
	// value sits in shell history and in every process listing on the box.
	token := ""
	if tokenEnv != "" {
		token = os.Getenv(tokenEnv)
		if token == "" {
			return nil, fmt.Errorf("--mcp-token-env names %s, which is unset or empty", tokenEnv)
		}
	}
	var mcpURLs, docsURLs []string
	for _, m := range mcps {
		u, err := validateAgentTarget(m, token != "")
		if err != nil {
			return nil, err
		}
		mcpURLs = append(mcpURLs, u)
	}
	for _, d := range docs {
		u, err := validateAgentTarget(d, false)
		if err != nil {
			return nil, err
		}
		docsURLs = append(docsURLs, u)
	}

	if dry {
		fmt.Fprintln(stdout, "\nAgent readiness would ask, sending nothing now:")
		for _, u := range mcpURLs {
			fmt.Fprintf(stdout, "  %s  initialize (with no credential first), tools/list, one tools/call for a tool that does not exist, one method that does not exist\n", u)
		}
		for _, u := range docsURLs {
			fmt.Fprintf(stdout, "  %s  GET the page, /llms.txt, /robots.txt and the usual OpenAPI paths\n", u)
		}
		return nil, nil
	}

	fmt.Fprintln(stdout, "\nAgent readiness: what each server and docs site tells an agent about itself.")
	var out []agentTarget
	for _, u := range mcpURLs {
		t := checkMCP(u, token)
		printAgentTarget(t)
		out = append(out, t)
	}
	for _, u := range docsURLs {
		t := checkDocs(u)
		printAgentTarget(t)
		out = append(out, t)
	}

	total, failed := 0, 0
	for _, t := range out {
		total += len(t.Checks)
		failed += t.failed()
	}
	fmt.Fprintf(stdout, "\n%d of %d agent-readiness %s failed. No listed tool was called: labels and schemas are what each server says of itself.\n",
		failed, total, plural(total, "check", "checks"))
	return out, nil
}
