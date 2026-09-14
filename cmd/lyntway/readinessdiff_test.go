package main

import (
	"strings"
	"testing"
)

func changeText(changes []change) string {
	var b strings.Builder
	for _, c := range changes {
		if c.Worse {
			b.WriteString("! ")
		} else {
			b.WriteString("· ")
		}
		b.WriteString(c.Text)
		b.WriteString("\n")
	}
	return b.String()
}

// The line this whole feature exists for: nobody touched the project, and
// the world published an advisory overnight.
func TestANewAdvisoryOnAnUnchangedPackageIsReported(t *testing.T) {
	old := readinessSnapshot{DepsChecked: true, Deps: []depState{
		{Ecosystem: "npm", Name: "axios", Version: "1.6.0", Advisories: []string{"GHSA-old"}},
	}}
	now := readinessSnapshot{DepsChecked: true, Deps: []depState{
		{Ecosystem: "npm", Name: "axios", Version: "1.6.0", Advisories: []string{"GHSA-old", "GHSA-new"}},
	}}

	got := changeText(diffSnapshots(old, now))
	if !strings.Contains(got, "! axios 1.6.0 has a new advisory since the last run: GHSA-new") {
		t.Errorf("the new advisory was not reported as a change for the worse:\n%s", got)
	}
	if strings.Contains(got, "GHSA-old") {
		t.Errorf("an advisory that was already there was reported as news:\n%s", got)
	}
}

// An endpoint that used to ask for a key and now does not is the alarm.
// The reverse is somebody having fixed it, and is worth saying so.
func TestAnEndpointLosingAndRegainingItsCheckAreBothReported(t *testing.T) {
	old := readinessSnapshot{EndpointsChecked: true, Endpoints: []endpointState{
		{Endpoint: "GET /v1/orders", Verdict: verdictProtected, Status: 401},
		{Endpoint: "GET /v1/reports", Verdict: verdictOpen, Status: 200},
	}}
	now := readinessSnapshot{EndpointsChecked: true, Endpoints: []endpointState{
		{Endpoint: "GET /v1/orders", Verdict: verdictOpen, Status: 200},
		{Endpoint: "GET /v1/reports", Verdict: verdictProtected, Status: 401},
	}}

	changes := diffSnapshots(old, now)
	got := changeText(changes)
	if !strings.Contains(got, "! GET /v1/orders used to ask for a credential and now answers without one (200)") {
		t.Errorf("an endpoint that lost its check was not raised:\n%s", got)
	}
	if !strings.Contains(got, "· GET /v1/reports now asks for a credential") {
		t.Errorf("an endpoint that gained a check was not reported:\n%s", got)
	}
	// Worse first, so the eye lands on it.
	if !changes[0].Worse {
		t.Errorf("the change for the worse is not first:\n%s", got)
	}
}

// A half that did not run says nothing about that half. Reporting every
// package as gone because --no-deps was passed would be the loudest
// possible lie, and the one most likely to be believed.
func TestAHalfThatDidNotRunIsNotReportedAsEverythingDisappearing(t *testing.T) {
	old := readinessSnapshot{
		DepsChecked: true, Deps: []depState{{Ecosystem: "npm", Name: "axios", Version: "1.6.0"}},
		EndpointsChecked: true, Endpoints: []endpointState{{Endpoint: "GET /v1/orders", Verdict: verdictProtected}},
	}
	// This run checked endpoints only.
	now := readinessSnapshot{
		EndpointsChecked: true, Endpoints: []endpointState{{Endpoint: "GET /v1/orders", Verdict: verdictProtected}},
	}

	got := changeText(diffSnapshots(old, now))
	if strings.Contains(got, "axios") {
		t.Errorf("a dependency was reported as changed by a run that never looked at dependencies:\n%s", got)
	}
	if got != "" {
		t.Errorf("nothing changed, but something was reported:\n%s", got)
	}
}

// Somebody upgraded the package. That is the work, and the run is the
// record of it.
func TestAnUpgradeThatClearsAnAdvisoryIsReportedAsProgress(t *testing.T) {
	old := readinessSnapshot{DepsChecked: true, Deps: []depState{
		{Ecosystem: "npm", Name: "axios", Version: "0.21.1", Advisories: []string{"GHSA-cph5-m8f7-6c5x"}},
	}}
	now := readinessSnapshot{DepsChecked: true, Deps: []depState{
		{Ecosystem: "npm", Name: "axios", Version: "1.16.0"},
	}}

	changes := diffSnapshots(old, now)
	got := changeText(changes)
	if !strings.Contains(got, "· axios went 0.21.1 → 1.16.0 and no longer has a published advisory") {
		t.Errorf("the upgrade was not reported:\n%s", got)
	}
	for _, c := range changes {
		if c.Worse {
			t.Errorf("an upgrade that cleared an advisory was counted as a finding: %s", c.Text)
		}
	}
}

// A snapshot from an older build is discarded rather than misread: a wrong
// "what changed" is worse than none at all.
func TestASnapshotFromAnotherShapeIsNotRead(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	if err := saveSnapshot(readinessSnapshot{
		Version: snapshotVersion + 1, TakenAt: "2026-09-01T00:00:00Z", Dir: ".",
		DepsChecked: true, Deps: []depState{{Ecosystem: "npm", Name: "axios", Version: "1.0.0"}},
	}, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadSnapshot(".", ""); ok {
		t.Error("a snapshot written in another shape was read as though it were comparable")
	}
}

// Two projects on one machine keep their own history.
func TestEachDirectoryRemembersItsOwnRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	a, err := snapshotPath(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := snapshotPath(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("two projects share one snapshot file (%s); one would overwrite the other's history", a)
	}
}
