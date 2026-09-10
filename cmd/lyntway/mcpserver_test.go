package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mcpRoundTrip sends one JSON-RPC request through the MCP server and
// returns the response. It feeds the line to stdin and captures stdout.
func mcpRoundTrip(t *testing.T, req map[string]any) jsonRPCResponse {
	t.Helper()
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	line = append(line, '\n')

	var out bytes.Buffer
	prevStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	// The server reads from stdin, but we need to feed it our line and
	// then close so it hits EOF and returns.
	prevStdin := os.Stdin
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = pr
	_, _ = pw.Write(line)
	pw.Close()

	mcpErr := mcpServer(nil)

	w.Close()
	os.Stdout = prevStdout
	os.Stdin = prevStdin

	if mcpErr != nil {
		t.Fatalf("mcpServer returned error: %v", mcpErr)
	}

	_, _ = out.ReadFrom(r)

	var resp jsonRPCResponse
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("could not parse response: %v\nraw: %s", err, out.String())
	}
	return resp
}

func TestMCPInitialize(t *testing.T) {
	resp := mcpRoundTrip(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]any{},
	})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	result := string(raw)
	if !strings.Contains(result, "lyntway") {
		t.Errorf("init result does not contain server name: %s", result)
	}
	if !strings.Contains(result, "protocolVersion") {
		t.Errorf("init result does not contain protocolVersion: %s", result)
	}
}

func TestMCPToolsList(t *testing.T) {
	resp := mcpRoundTrip(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	result := string(raw)

	for _, tool := range []string{
		"lyntway_status", "lyntway_setup", "lyntway_scan",
		"lyntway_migrate", "lyntway_init", "lyntway_receipts",
	} {
		if !strings.Contains(result, tool) {
			t.Errorf("tools/list does not contain %s", tool)
		}
	}
}

func TestMCPUnknownTool(t *testing.T) {
	resp := mcpRoundTrip(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "nonexistent_tool",
			"arguments": map[string]any{},
		},
	})
	if resp.Error == nil {
		t.Fatal("expected an error for an unknown tool")
	}
	if !strings.Contains(resp.Error.Message, "Unknown tool") {
		t.Errorf("error message should mention unknown tool: %s", resp.Error.Message)
	}
}

func TestMCPUnknownMethod(t *testing.T) {
	resp := mcpRoundTrip(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "bogus/method",
	})
	if resp.Error == nil {
		t.Fatal("expected an error for an unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected code -32601, got %d", resp.Error.Code)
	}
}

func TestMCPScanFindsKeysAndHidesValues(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY="+tOpenAI+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Call the scan tool directly rather than through the full stdio
	// loop, because scan reads the filesystem and the config — and a
	// config that does not exist is fine for scan (it proceeds without
	// the Lyntway key filter).
	args, _ := json.Marshal(map[string]string{"directory": dir})
	text, err := mcpToolScan(args)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	if !strings.Contains(text, "OPENAI_API_KEY") {
		t.Error("scan did not find the key variable")
	}
	if !strings.Contains(text, "openai") {
		t.Error("scan did not identify the upstream")
	}
	if !strings.Contains(text, "ABCD") {
		t.Error("scan did not show last4")
	}
	// The full key value must never appear in the output.
	assertNoValue(t, text)
}

func TestMCPMigratePlanDoesNotChangeFiles(t *testing.T) {
	dir := t.TempDir()
	envContent := "OPENAI_API_KEY=" + tOpenAI + "\n"
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Set up a minimal config so migrate plan can run.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if _, err := saveConfig(config{Origin: "https://lyntway.com", Key: "lyk_test"}); err != nil {
		t.Fatal(err)
	}

	args, _ := json.Marshal(map[string]any{"directory": dir, "confirm": false})
	text, err := mcpToolMigrate(args)
	if err != nil {
		t.Fatalf("migrate plan error: %v", err)
	}

	// The plan should mention the key was found.
	if !strings.Contains(text, "OPENAI_API_KEY") {
		t.Error("plan did not mention the key")
	}
	if !strings.Contains(text, "confirm") {
		t.Error("plan did not mention confirm")
	}

	// The file must not have changed.
	after, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != envContent {
		t.Errorf("the .env file was changed by plan mode:\nbefore: %q\nafter:  %q", envContent, string(after))
	}

	assertNoValue(t, text)
}

func TestMCPReceiptsEmptyDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	text, err := mcpToolReceipts(nil)
	if err != nil {
		t.Fatalf("receipts error: %v", err)
	}
	if !strings.Contains(text, "No receipts") {
		t.Errorf("expected no-receipts message, got: %s", text)
	}
}

func TestMCPReceiptsListsFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	dir := filepath.Join(home, ".lyntway", "receipts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rcpt_test01.json"), []byte(`{"id":"rcpt_test01"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	text, err := mcpToolReceipts(nil)
	if err != nil {
		t.Fatalf("receipts error: %v", err)
	}
	if !strings.Contains(text, "rcpt_test01.json") {
		t.Errorf("receipts did not list the file: %s", text)
	}
}

func TestMCPMalformedInputDoesNotCrash(t *testing.T) {
	// Feed garbage followed by EOF.
	var out bytes.Buffer
	prevStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	prevStdin := os.Stdin
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = pr
	_, _ = pw.Write([]byte("this is not json\n"))
	pw.Close()

	mcpErr := mcpServer(nil)
	w.Close()
	os.Stdout = prevStdout
	os.Stdin = prevStdin

	if mcpErr != nil {
		t.Fatalf("mcpServer should not return error on malformed input: %v", mcpErr)
	}

	_, _ = out.ReadFrom(r)
	raw := out.String()

	// It should have written a parse error response.
	if !strings.Contains(raw, "Parse error") {
		t.Errorf("expected parse error in output: %s", raw)
	}
}

// An agent migrating a second project must not replace the key a first
// project already stored for the same upstream. The CLI asks before doing
// that; the agent path cannot ask, so it must leave the stored key alone
// unless it is told — separately from confirm — that the user agreed.
func TestMCPMigrateLeavesAStoredKeyAloneWithoutReplace(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	fake := &fakeServer{existing: []map[string]string{{"upstream": "openai", "last4": "OLD1"}}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	if _, err := saveConfig(config{Origin: srv.URL, Key: "lyk_mine"}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	body := "OPENAI_API_KEY=sk-proj-openai0000ABCD\nANTHROPIC_API_KEY=sk-ant-api03-anthropicWXYZ\n"
	if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// The plan has to say so before anybody confirms anything.
	plan, err := mcpToolMigrate(mustJSON(t, map[string]any{"directory": dir}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "OLD1") || !strings.Contains(plan, "replace: true") {
		t.Errorf("the plan did not say a stored key would be affected:\n%s", plan)
	}

	// confirm alone: the new key is stored, the held one is not replaced.
	out, err := mcpToolMigrate(mustJSON(t, map[string]any{"directory": dir, "confirm": "true"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range fake.stored {
		if s["upstream"] == "openai" {
			t.Fatalf("the stored openai key was replaced without replace: true\n%s", out)
		}
	}
	after, _ := os.ReadFile(envPath)
	if !strings.Contains(string(after), "OPENAI_API_KEY=sk-proj-openai0000ABCD") {
		t.Error("the OpenAI line was rewritten although its key was not stored")
	}
	if strings.Contains(string(after), "sk-ant-api03-anthropicWXYZ") {
		t.Error("the Anthropic key, which nothing held, was not migrated")
	}
}

// With replace: true the user has agreed, and the stored key is replaced.
func TestMCPMigrateReplacesAStoredKeyWhenToldTo(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	fake := &fakeServer{existing: []map[string]string{{"upstream": "openai", "last4": "OLD1"}}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	if _, err := saveConfig(config{Origin: srv.URL, Key: "lyk_mine"}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-openai0000ABCD\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := mcpToolMigrate(mustJSON(t, map[string]any{"directory": dir, "confirm": true, "replace": true})); err != nil {
		t.Fatal(err)
	}
	replaced := false
	for _, s := range fake.stored {
		if s["upstream"] == "openai" {
			replaced = true
		}
	}
	if !replaced {
		t.Fatal("replace: true did not replace the stored key")
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
