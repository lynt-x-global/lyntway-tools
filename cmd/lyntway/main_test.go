package main

import (
	"runtime"
	"strings"
	"testing"
)

// An unknown command must say which build is running and how to get a
// newer one.
//
// A tester ran `npx lyntway secure` against a build predating the command
// and read "no command called" as the feature not existing — on the same
// day the npm page told them to run it. npx reuses a global install or its
// own cache, so an old binary answering a new instruction is the ordinary
// case, not the odd one, and the message they met named no way through.
func TestAnUnknownCommandNamesTheBuildAndTheWayThrough(t *testing.T) {
	var out strings.Builder
	writeUnknownCommand(&out, "secure")
	got := out.String()

	for _, want := range []string{
		`no command called "secure"`,
		"This is lyntway ",   // which build is speaking
		"npx lyntway@latest", // how to get a newer one
		"brew upgrade",       // and the other way people install it
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the refusal does not contain %q:\n%s", want, got)
		}
	}

	// The command the person asked for is named in the suggestion, not
	// just in the complaint — otherwise they have to compose it.
	if !strings.Contains(got, "npx lyntway@latest secure") {
		t.Errorf("the suggested command does not carry what they typed:\n%s", got)
	}
}

// Instructions must be in the shell the reader is typing into.
//
// Every "when you set one, pair it:" line printed `export NAME="value"`,
// including on Windows, where it is not a command. The first Windows
// tester saw it directly under a line confirming their PowerShell profile
// had been written — advice in one language about a file in another.
func TestEnvInstructionsFollowThePlatform(t *testing.T) {
	got := setEnvLine("OPENAI_API_KEY", "lynt_sk_x~YOUR_OPENAI_KEY")

	if runtime.GOOS == "windows" {
		if !strings.HasPrefix(got, "$env:OPENAI_API_KEY = ") {
			t.Errorf("on Windows the instruction is %q; PowerShell has no export", got)
		}
		if strings.Contains(got, "export ") {
			t.Errorf("Bourne syntax on Windows: %q", got)
		}
		return
	}
	if !strings.HasPrefix(got, `export OPENAI_API_KEY="`) {
		t.Errorf("on %s the instruction is %q", runtime.GOOS, got)
	}
	if strings.Contains(got, "$env:") {
		t.Errorf("PowerShell syntax on %s: %q", runtime.GOOS, got)
	}
}
