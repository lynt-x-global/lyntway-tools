package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as the MCP server under test. A real subprocess
// on a real pipe is the only arrangement that shows whether the agent's
// side of the conversation stalls, which is the failure being guarded
// against — a unit test of govern() cannot hang.
func TestMain(m *testing.M) {
	if os.Getenv("LYNTWAY_MCP_TEST_FAKE_SERVER") == "1" {
		fakeServer()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeServer answers like a minimal MCP server. A tools/call whose
// arguments ask for a secret answers with an AWS access key, which the
// default policy blocks.
func fakeServer() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for in.Scan() {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if err := json.Unmarshal(in.Bytes(), &req); err != nil || len(req.ID) == 0 {
			continue
		}
		var result string
		switch req.Method {
		case "initialize":
			result = `{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"0"}}`
		case "tools/list":
			result = `{"tools":[{"name":"lookup","inputSchema":{"type":"object"}}]}`
		case "tools/call":
			text := "nothing to see"
			if req.Params.Arguments["want"] == "secret" {
				text = "aws_access_key_id = AK" + "IA5J7QWMNBZX2LKPRD"
			}
			result = `{"content":[{"type":"text","text":"` + text + `"}]}`
		default:
			fmt.Printf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`+"\n", req.ID)
			continue
		}
		fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":%s}`+"\n", req.ID, result)
	}
}

type rpcMessage struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

// runProxy drives the shim as an agent would, and fails if the agent is
// still waiting once the conversation should be over.
func runProxy(t *testing.T, g *governor, agentInput string) []rpcMessage {
	t.Helper()
	t.Setenv("LYNTWAY_MCP_TEST_FAKE_SERVER", "1")

	var agentOut bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- proxy([]string{os.Args[0]}, g, strings.NewReader(agentInput), &agentOut) }()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("proxy exited %d", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("the agent is still waiting; it received:\n%s", agentOut.String())
	}

	var msgs []rpcMessage
	for _, line := range strings.Split(strings.TrimSpace(agentOut.String()), "\n") {
		if line == "" {
			continue
		}
		var m rpcMessage
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("the agent received a line that is not JSON-RPC: %q", line)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

// A refused result must not simply vanish. The agent sent a request and is
// blocked until something with that id comes back; dropping the result
// leaves Claude Desktop or Cursor waiting forever on a tool call that has
// already been decided.
func TestARefusedResultAnswersTheAgentWithAnError(t *testing.T) {
	g := testGovernor(t)

	msgs := runProxy(t, g,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`+"\n"+
			`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"+
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lookup","arguments":{"want":"secret"}}}`+"\n"+
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lookup","arguments":{"want":"secret"}}}`+"\n")

	byID := map[string]rpcMessage{}
	for _, m := range msgs {
		byID[string(m.ID)] = m
	}
	if len(byID) != 3 {
		t.Fatalf("the agent sent three requests and received %d responses: %+v", len(byID), msgs)
	}
	if byID["1"].Result == nil {
		t.Errorf("the initialize response did not arrive: %+v", byID["1"])
	}
	for _, id := range []string{"2", "3"} {
		m := byID[id]
		if m.Error == nil {
			t.Fatalf("request %s was refused but the agent got no error: %+v", id, m)
		}
		if m.Result != nil {
			t.Errorf("request %s carried both a result and an error", id)
		}
		if !strings.Contains(strings.ToLower(m.Error.Message), "refused") {
			t.Errorf("request %s: the error does not say governance refused it: %q", id, m.Error.Message)
		}
		if !strings.Contains(m.Error.Message, "rcpt_") {
			t.Errorf("request %s: the error does not name the receipt: %q", id, m.Error.Message)
		}
		if m.Error.Code >= -32000 || m.Error.Code < -32099 {
			t.Errorf("request %s: code %d is outside the JSON-RPC server-defined range", id, m.Error.Code)
		}
	}
}

// A refused request is refused before it reaches the server, so the server
// will never answer it. The agent still needs an answer.
func TestARefusedRequestAnswersTheAgentWithAnError(t *testing.T) {
	g := testGovernor(t)

	msgs := runProxy(t, g,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"lookup","arguments":{"note":"key AK`+`IA5J7QWMNBZX2LKPRD"}}}`+"\n"+
			`{"jsonrpc":"2.0","id":8,"method":"tools/list"}`+"\n")

	byID := map[string]rpcMessage{}
	for _, m := range msgs {
		byID[string(m.ID)] = m
	}
	if byID["7"].Error == nil {
		t.Fatalf("the refused request got no error: %+v", msgs)
	}
	if !strings.Contains(byID["7"].Error.Message, "rcpt_") {
		t.Errorf("the error does not name the receipt: %q", byID["7"].Error.Message)
	}
	if byID["8"].Result == nil {
		t.Errorf("the request after the refused one was not answered: %+v", msgs)
	}
}
