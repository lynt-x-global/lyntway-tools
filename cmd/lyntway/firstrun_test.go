package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The first screen is read by somebody who has given us nothing, so the
// tests here are mostly about what it must not say. Two of them matter
// more than the rest: it must never print a credential, and it must never
// describe a file it could not read as a file with nothing in it.

func captureFirstRun(t *testing.T, r firstRunReport) string {
	t.Helper()
	var buf bytes.Buffer
	prevOut := stdout
	stdout = &buf
	defer func() { stdout = prevOut }()
	printFirstRun(r)
	return buf.String()
}

// secretValue is a key shaped like a real one, so a report that leaked it
// would be leaking something a provider would actually accept.
const secretValue = "sk-proj-NOTAREAL0000FAKE0000NOTAREAL4f9a"

func TestFirstRunNeverPrintsACredentialValue(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("OPENAI_API_KEY="+secretValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureFirstRun(t, takeFirstRunReport(dir))

	if strings.Contains(out, secretValue) {
		t.Fatalf("the first screen printed the key itself:\n%s", out)
	}
	// The last four are the point of the line, so their absence means the
	// finding was dropped rather than redacted.
	if !strings.Contains(out, "…4f9a") {
		t.Fatalf("the key was not reported at all:\n%s", out)
	}
	if !strings.Contains(out, ".env:1") {
		t.Fatalf("the finding did not name the file and line:\n%s", out)
	}
	// An absolute path makes a screen that has to be read in two seconds
	// unreadable, and says nothing the relative path does not.
	if strings.Contains(out, dir) {
		t.Fatalf("the finding was printed with an absolute path:\n%s", out)
	}
}

func TestFirstRunSaysWhenNoClientFileWasFound(t *testing.T) {
	out := captureFirstRun(t, firstRunReport{Hostname: "h"})

	// "None configured in the 0 files read" is a claim about nothing, and
	// reads as though the agents were checked and reach nothing.
	if strings.Contains(out, "0 client file") {
		t.Fatalf("a count of zero files was reported as a finding:\n%s", out)
	}
	if !strings.Contains(out, "No MCP client config file was found") {
		t.Fatalf("the absence of any config file was not stated:\n%s", out)
	}
}

func TestFirstRunReportsFilesItCouldNotRead(t *testing.T) {
	r := firstRunReport{
		Hostname: "h",
		MCP: mcpDiscovery{
			Read:       1,
			Servers:    []mcpServerInfo{{Client: "cursor", Name: "jira", Host: "jira.example.com"}},
			Unreadable: []string{"/home/someone/.cursor/mcp.json"},
			NotLocal:   2,
		},
	}
	out := captureFirstRun(t, r)

	if !strings.Contains(out, "1 config file could not be read") {
		t.Fatalf("an unreadable config file was not admitted:\n%s", out)
	}
	if !strings.Contains(out, "2 is in cloud storage") {
		t.Fatalf("files left in cloud storage were not admitted:\n%s", out)
	}
	// The path of a file we failed to parse is not a fact about the
	// person's agents, and printing it invites a support conversation
	// about our parser instead of about their exposure.
	if strings.Contains(out, ".cursor/mcp.json") {
		t.Fatalf("the unreadable file's path was printed:\n%s", out)
	}
}

func TestFirstRunCountsCredentialsAndAgreesWithItself(t *testing.T) {
	one := firstRunReport{Hostname: "h", MCP: mcpDiscovery{Read: 1, Servers: []mcpServerInfo{
		{Client: "cursor", Name: "jira", Host: "jira.example.com", HasCredentials: true},
	}}}
	if got := captureFirstRun(t, one); !strings.Contains(got, "1 of these has a credential") ||
		!strings.Contains(got, "beside\n  it.") {
		t.Fatalf("the singular form is wrong:\n%s", got)
	}

	two := firstRunReport{Hostname: "h", MCP: mcpDiscovery{Read: 1, Servers: []mcpServerInfo{
		{Client: "cursor", Name: "jira", Host: "jira.example.com", HasCredentials: true},
		{Client: "cursor", Name: "slack", Host: "slack.example.com", HasCredentials: true},
		{Client: "cursor", Name: "docs", Host: "docs.example.com"},
	}}}
	out := captureFirstRun(t, two)
	if !strings.Contains(out, "2 of these have a credential") ||
		!strings.Contains(out, "beside\n  them.") {
		t.Fatalf("the plural form is wrong:\n%s", out)
	}
	// The server with no credential must not be swept into the count by
	// the reordering that puts credentialled ones last.
	if strings.Contains(out, "3 of these") {
		t.Fatalf("a server with no credential was counted:\n%s", out)
	}
}

// The closing paragraph is the part of this screen that is load-bearing:
// the report is a list of configuration, and somebody who reads it as a
// list of traffic has been misled by us.
func TestFirstRunStatesWhatItDidNotDo(t *testing.T) {
	out := captureFirstRun(t, firstRunReport{Hostname: "h"})
	for _, want := range []string{
		"Nothing left this machine",
		"no traffic was\nwatched",
		"no account was needed",
		"Nothing here is being recorded yet",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the screen no longer says %q:\n%s", want, out)
		}
	}
}

// `lyntway status` used to refuse to answer without an account. The
// question it answers does not need one, and the refusal was the first
// thing a new install did.
func TestStatusWithoutAnAccountReportsTheMachine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows reads this one

	var buf bytes.Buffer
	prevOut := stdout
	stdout = &buf
	defer func() { stdout = prevOut }()

	if err := status(); err != nil {
		t.Fatalf("status refused to run without an account: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "not signed in") {
		t.Fatalf("status still answers with the sign-in error:\n%s", out)
	}
	if !strings.Contains(out, "what is on this machine") {
		t.Fatalf("status did not report the machine:\n%s", out)
	}
}

// Damaged settings are a different state from no settings, with a
// different fix, and the opening picture must not stand in for saying so.
// Showing it there would tell somebody they have no account when what
// they have is a config file we cannot read.
func TestStatusStillReportsUnreadableSettings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	if err := os.MkdirAll(filepath.Join(home, ".lyntway"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".lyntway", "config.json"),
		[]byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevOut := stdout
	stdout = &buf
	defer func() { stdout = prevOut }()

	err := status()
	if err == nil {
		t.Fatalf("unreadable settings were reported as a clean machine:\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("the error does not say the settings are unreadable: %v", err)
	}
	if strings.Contains(buf.String(), "what is on this machine") {
		t.Fatalf("the first-run picture stood in for a real error:\n%s", buf.String())
	}
	if firstRunWanted() {
		t.Fatal("a config file that exists was treated as a first run")
	}
}
