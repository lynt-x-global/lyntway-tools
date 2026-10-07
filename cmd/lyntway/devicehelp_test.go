package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Asking for help must not install an agent, and neither must a typo.
//
// deviceCommand recognised its subcommands and fell through to deviceInstall
// for everything else — so `lyntway device --help` read "--help" as an
// argument, found no enrollment key, and went on to download the agent binary
// and write a config. It printed "Configured." and exited zero. Any misspelled
// flag did the same.
func TestDeviceRefusesFlagsItDoesNotKnow(t *testing.T) {
	// These must not reach deviceInstall. Each returns before anything is
	// downloaded, so the test can call deviceCommand directly: if one of them
	// ever falls through again, this test starts touching the network and the
	// filesystem, which is a failure loud enough to notice.
	for _, arg := range []string{"--hepl", "--keys", "-k", "--token", "--install"} {
		err := deviceCommand([]string{arg})
		if err == nil {
			t.Errorf("device %s returned no error; an unknown flag must not start an install", arg)
			continue
		}
		if !strings.Contains(err.Error(), arg) {
			t.Errorf("device %s: error %q does not name the argument, so the person cannot see the typo", arg, err)
		}
	}
}

func TestDeviceHelpIsHelp(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		if err := deviceCommand([]string{arg}); err != nil {
			t.Errorf("device %s returned %v; asking for help is not a failure", arg, err)
		}
	}
}

// knownInstallFlag has to agree with the flag loop in deviceInstall. If a flag
// is added to one and not the other, either the flag is refused as a typo or an
// unknown flag silently starts an install — which is the defect this guards.
func TestKnownInstallFlagsAreTheOnesInstallReads(t *testing.T) {
	accepted := []string{"--key", "--key=abc", "--url", "--url=https://x", "--no-proxy"}
	for _, a := range accepted {
		if !knownInstallFlag(a) {
			t.Errorf("deviceInstall reads %s and knownInstallFlag rejects it, so it is refused as a typo", a)
		}
	}
	for _, a := range []string{"--keyy", "--urls", "--proxy", "--no-sidecar", "-key", ""} {
		if knownInstallFlag(a) {
			t.Errorf("knownInstallFlag accepts %q, which deviceInstall's loop ignores — so it would fall through to an install", a)
		}
	}
}

// An install with no enrollment key must stop before it downloads anything.
//
// The prompt reads from stdin and discards the read error, so a closed stdin
// gave an empty line. That skipped activation, and the install carried on to
// download the agent and write a config whose auth_token was the empty string.
// It printed "Configured." and exited zero, leaving an agent that authenticates
// with nothing and therefore reports nothing — which looks exactly like a quiet
// machine.
//
// HOME is redirected so the developer's own sign-in cannot satisfy the guard and
// let the test reach the download.
func TestInstallWithoutAKeyDownloadsNothing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// The machine running the tests may have a live agent; this test is
	// about the no-key path, which only exists when there is none.
	oldReach := agentReachable
	agentReachable = func() bool { return false }
	t.Cleanup(func() { agentReachable = oldReach })

	oldIn, oldOut := stdin, stdout
	var out strings.Builder
	stdin, stdout = strings.NewReader(""), &out
	t.Cleanup(func() { stdin, stdout = oldIn, oldOut })

	err := deviceInstall(nil)
	if err == nil {
		t.Fatal("deviceInstall returned no error with no key; it would have installed an agent that cannot authenticate")
	}
	if !strings.Contains(err.Error(), "enrollment key") {
		t.Errorf("error %q does not say what is missing", err)
	}
	if strings.Contains(out.String(), "Configured") {
		t.Error(`it printed "Configured" without a key`)
	}
	// Nothing on disk: no binary, no agent config.
	for _, p := range []string{
		filepath.Join(home, ".lyntway", "bin", "lyntway-agent"),
		filepath.Join(home, ".lyntway", "agent", "agent.json"),
	} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was written despite there being no key", p)
		}
	}
}
