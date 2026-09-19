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

func agentTargetWith(target string, tools []string, st map[string]string) agentTarget {
	t := agentTarget{Kind: "mcp", Target: target, Tools: tools, ToolsRead: tools != nil}
	for _, d := range mcpDefs {
		s, ok := st[d.id]
		if !ok {
			s = checkPass
		}
		t.Checks = append(t.Checks, d.result(s, "evidence"))
	}
	return t
}

// A check that used to pass and now fails is the alarm; the reverse is
// somebody having done the work.
func TestAnAgentCheckThatStartsFailingIsWorse(t *testing.T) {
	old := readinessSnapshot{AgentsChecked: true, Agents: []agentTarget{
		agentTargetWith("https://mcp.acme.test/mcp", []string{"a", "b"}, map[string]string{"mcp.tools_schema": checkFail}),
	}}
	now := readinessSnapshot{AgentsChecked: true, Agents: []agentTarget{
		agentTargetWith("https://mcp.acme.test/mcp", []string{"a", "c"}, map[string]string{"mcp.effects_labelled": checkFail}),
	}}
	got := changeText(diffSnapshots(old, now))
	for _, want := range []string{
		`! https://mcp.acme.test/mcp: "Every tool says whether it changes things" passed last time and fails now`,
		`· https://mcp.acme.test/mcp: "Every input is typed and explained" failed last time and passes now`,
		"· https://mcp.acme.test/mcp lists 1 new tool: c",
		"· https://mcp.acme.test/mcp no longer lists 1 tool: b",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// A vendor having a bad minute is not a regression. Undecided is reported,
// never as worse, or the alarm fires on every outage and is soon ignored.
func TestACheckThatCouldNotBeDecidedIsNeverWorse(t *testing.T) {
	old := readinessSnapshot{AgentsChecked: true, Agents: []agentTarget{agentTargetWith("https://m.test", nil, nil)}}
	now := readinessSnapshot{AgentsChecked: true, Agents: []agentTarget{
		agentTargetWith("https://m.test", nil, map[string]string{"mcp.auth": checkInconclusive}),
	}}
	for _, c := range diffSnapshots(old, now) {
		if c.Worse {
			t.Errorf("an undecided check was reported as worse: %s", c.Text)
		}
	}
	back := diffSnapshots(now, readinessSnapshot{AgentsChecked: true, Agents: []agentTarget{
		agentTargetWith("https://m.test", nil, map[string]string{"mcp.auth": checkFail}),
	}})
	if len(back) != 1 || !back[0].Worse {
		t.Errorf("undecided to failing was not worse: %+v", back)
	}
}

// A run that did not check agents says nothing about them. Reporting every
// server as gone because nobody looked would be the loudest possible lie.
func TestARunWithoutAgentChecksSaysNothingAboutThem(t *testing.T) {
	old := readinessSnapshot{AgentsChecked: true, Agents: []agentTarget{agentTargetWith("https://m.test", nil, nil)}}
	if got := diffSnapshots(old, readinessSnapshot{}); len(got) != 0 {
		t.Errorf("a run that never checked agents reported %d change(s): %+v", len(got), got)
	}
}

// The limits travel inside the signed file, and so does every check's own
// criterion and limit.
func TestTheReportCarriesAgentChecksWithTheirLimits(t *testing.T) {
	snap := readinessSnapshot{TakenAt: "2026-09-19T10:00:00Z", Dir: ".", AgentsChecked: true,
		Agents: []agentTarget{agentTargetWith("https://m.test", []string{"a"}, map[string]string{"mcp.auth": checkFail})}}
	rep := buildReport(snap, nil, surfaceDoc{}, false)

	dir := t.TempDir()
	path := filepath.Join(dir, "r.json")
	if _, _, err := writeReport(rep, path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	agents, _ := doc["agent_readiness"].([]any)
	if len(agents) != 1 {
		t.Fatalf("agent_readiness has %d entries, want 1:\n%s", len(agents), raw)
	}
	first := agents[0].(map[string]any)["checks"].([]any)[0].(map[string]any)
	for _, k := range []string{"criterion", "evidence", "does_not_prove", "status"} {
		if s, _ := first[k].(string); s == "" {
			t.Errorf("a check in the signed report has no %s", k)
		}
	}
	joined := strings.Join(rep.Limits, " | ")
	for _, want := range []string{"No tool a server listed was called", "No agent was run", "covers the servers named for agent readiness only"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the report does not state %q:\n%s", want, joined)
		}
	}
}

// Naming a server to check is being given something to do. A run that
// named one and no --scope checks it and succeeds, and with neither it
// still fails as before.
func TestAnMCPRunNeedsNoScopeButAnEmptyRunStillFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	dir := t.TempDir()
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(prev)

	var buf bytes.Buffer
	prevOut := stdout
	stdout = &buf
	defer func() { stdout = prevOut }()

	srv := httptest.NewServer(&fakeMCP{tools: goodTools()})
	defer srv.Close()

	if err := readiness([]string{"--mcp", srv.URL, "--no-deps", "--out", "r.json"}); err != nil {
		t.Fatalf("a run naming an MCP server failed: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "A stranger reaches nothing that changes state") {
		t.Errorf("the checks were not printed:\n%s", buf.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "r.json"))
	if err != nil || !strings.Contains(string(raw), `"agent_readiness"`) {
		t.Errorf("the written report carries no agent_readiness (%v):\n%s", err, raw)
	}
	if err := readiness([]string{"--no-deps"}); err == nil || !strings.Contains(err.Error(), "--scope is required") {
		t.Errorf("a run with nothing named did not fail: %v", err)
	}
}
