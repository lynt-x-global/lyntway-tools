package main

import (
	"strings"
	"testing"
)

// The finding this whole surface exists for: something reaching an AI
// service that no list here has a name for.
func TestAProcessNobodyKnowsIsReportedAsUnrecognised(t *testing.T) {
	p := procInfo{PID: 4100, Name: "sync-helper", Path: "/opt/vendor/bin/sync-helper"}
	name, isAI, known := appForProcess("darwin", p)
	if name != "sync-helper" {
		t.Errorf("name = %q, want the process's own name", name)
	}
	if isAI {
		t.Error("a process nobody has heard of was treated as catalogued AI software")
	}
	if known {
		t.Error("a process nobody has heard of was reported as recognised, so it would never be surfaced")
	}
}

// A browser reaching an AI site is a person using a website. Reporting it
// as something nobody recognises is the false alarm that makes the list
// stop being read.
func TestABrowserIsNotReportedAsUnrecognised(t *testing.T) {
	for _, name := range []string{"Google Chrome", "Safari", "firefox", "Microsoft Edge"} {
		p := procInfo{PID: 51, Name: name}
		got, _, known := appForProcess("darwin", p)
		if !known {
			t.Errorf("%s was reported as a process nobody recognises", name)
		}
		if got == "unknown process" {
			t.Errorf("%s was not named", name)
		}
	}
}

// The privacy property that the existing aggregator test protects, stated
// here as its own invariant so the reason survives.
//
// A browser holds connections to the whole web. Treating it as AI software
// would spend a reverse lookup on every one of them, which is slow and
// tells this machine's resolver which sites the person visits.
func TestABrowserDoesNotEarnReverseLookups(t *testing.T) {
	p := procInfo{PID: 52, Name: "Google Chrome"}
	_, isAI, known := appForProcess("darwin", p)
	if isAI {
		t.Error("a browser was marked as AI software, which enables a reverse lookup for every site visited")
	}
	if !known {
		t.Error("the browser stopped being recognised, which is the other half of this")
	}
}

// An empty look must not read as a clean machine. One snapshot sees only
// what is open at that instant, and the report has to say so.
func TestAnEmptyLookIsNotReportedAsNothingRunning(t *testing.T) {
	d := agentDiscovery{Looked: true}
	if len(d.Sightings) != 0 || len(d.Unrecognised()) != 0 {
		t.Fatal("fixture is wrong")
	}
	var sb strings.Builder
	writeAgentSightings(&sb, d)
	out := sb.String()
	if out == "" {
		t.Fatal("an empty look printed nothing at all, so the reader is told nothing")
	}
	// The whole point: the sentence has to be about the moment, not about
	// the machine.
	if !strings.Contains(out, "moment") {
		t.Errorf("an empty look does not say it was a snapshot:\n%s", out)
	}
}

// A look that could not be made must never be printed as a look that
// found nothing.
func TestALookThatFailedSaysSo(t *testing.T) {
	d := agentDiscovery{Why: "the connection table could not be read"}
	var sb strings.Builder
	writeAgentSightings(&sb, d)
	out := sb.String()
	if !strings.Contains(out, "could not be read") {
		t.Errorf("a failed look did not report its reason:\n%s", out)
	}
	if strings.Contains(out, "moment") {
		t.Errorf("a failed look was described as an empty one:\n%s", out)
	}
}

// The unrecognised ones are the headline, so they have to be separable
// from the rest without re-deriving the rule.
func TestUnrecognisedSightingsAreSeparable(t *testing.T) {
	d := agentDiscovery{Looked: true, Sightings: []agentSighting{
		{App: "Claude Code", Host: "api.anthropic.com", Connections: 2},
		{App: "sync-helper", Host: "api.openai.com", Connections: 1, Unrecognised: true},
		{App: "Google Chrome", Host: "claude.ai", Connections: 3},
	}}
	un := d.Unrecognised()
	if len(un) != 1 || un[0].App != "sync-helper" {
		t.Fatalf("Unrecognised() = %+v", un)
	}
}
