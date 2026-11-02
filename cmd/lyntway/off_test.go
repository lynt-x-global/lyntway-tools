package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// The undo record may not be deleted before undo has read it.
//
// The first version of `off` removed it in the same pass as the other
// state it owns, which left undo with nothing to restore: every .env
// `keys migrate` had rewritten stayed pointing at the gateway, on the one
// command whose entire promise is that nothing is left behind.
func TestTheUndoRecordIsNotRemovedBeforeUndoRuns(t *testing.T) {
	for _, f := range ownStateBeforeUndo() {
		if strings.Contains(filepath.Base(f.path), "undo") {
			t.Errorf("%s is removed before undo() runs, so undo would have nothing to read", f.path)
		}
	}
}

// What `off` takes and what it keeps, stated as a list so a file added
// later has to be thought about rather than silently left behind.
func TestOffTakesItsOwnStateAndKeepsTheEvidence(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var names []string
	for _, f := range ownStateBeforeUndo() {
		names = append(names, filepath.Base(f.path))
	}
	joined := strings.Join(names, " ")

	for _, want := range []string{
		upstreamsFile,           // registered databases
		"dbgateway-signing.key", // a private key may never be left behind
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("`off` leaves %s behind; it is this tool's own state", want)
		}
	}

	// Receipts are evidence and are kept unless asked for. Their
	// directory must never appear in the unconditional list.
	if strings.Contains(joined, "receipts") {
		t.Error("`off` deletes receipts unconditionally; that is an audit trail and needs --receipts")
	}
}

// The way out of a lockout has to be discoverable.
//
// `device uninstall` verifies its token over the network, and the agent
// has taken this machine off the network twice. An escape hatch nobody
// can find is not an escape hatch, so both the device usage and `off`
// have to name it.
func TestTheOfflineEscapeIsDocumented(t *testing.T) {
	var usage strings.Builder
	old := stdout
	stdout = &usage
	defer func() { stdout = old }()

	deviceUsage()
	if got := usage.String(); !strings.Contains(got, "--local") {
		t.Errorf("`lyntway device` usage does not mention --local, so nobody locked out can find it:\n%s", got)
	}
}
