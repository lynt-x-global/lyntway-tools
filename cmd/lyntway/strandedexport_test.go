package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The agent points this machine's traffic at itself two ways, because they
// reach different software: the operating system's proxy setting, which
// browsers read, and HTTP_PROXY/HTTPS_PROXY exported into the login
// profiles, which curl, git, pip, npm and the cloud CLIs read. Until
// 26 Oct 2026 the doctor only knew about the first, so a machine whose
// agent had been killed looked healthy while every command in a new shell
// failed with "Unable to connect to proxy". That is the failure this
// product must never cause, so it is pinned from both directions.
func TestTheDoctorFindsAProxyStrandedInALoginProfile(t *testing.T) {
	h := t.TempDir()
	withHome(t, h)

	// 19090 rather than the agent's default 9090 on purpose: the machine
	// this was found on had no agent config, so the configured address was
	// the default and the profiles exported a different port entirely. A
	// check that trusted the configured port would pass here.
	profile := filepath.Join(h, ".zprofile")
	write(t, profile, "# something the user wrote\nexport EDITOR=vim\n\n"+
		proxyRCMarker+"\nexport HTTP_PROXY=http://127.0.0.1:19090\n"+
		"export HTTPS_PROXY=http://127.0.0.1:19090\n"+
		"export NO_PROXY=127.0.0.1,localhost,lyntway.com\n")

	restore := stubListening(t, func(string) bool { return false })
	defer restore()
	// The system proxy is clean. This is exactly the state that was missed.
	proxyPointsAt = func(string) bool { return false }

	var out bytes.Buffer
	stdout = &out
	defer func() { stdout = os.Stdout }()

	clearStrandedProxy()

	if !strings.Contains(out.String(), "19090") {
		t.Errorf("the doctor did not name the stranded address:\n%s", out.String())
	}
	got := read(t, profile)
	if strings.Contains(got, "HTTPS_PROXY") {
		t.Errorf("the export was left in place, so a new shell is still broken:\n%s", got)
	}
	if !strings.Contains(got, "export EDITOR=vim") {
		t.Errorf("the user's own profile lines were removed:\n%s", got)
	}
	// The marker has to go with the block. The agent decides whether to
	// append by searching for it, so a marker left behind — commented out
	// or not — means the proxy is never set up again and the symptom is
	// silence.
	if strings.Contains(got, proxyRCMarker) {
		t.Errorf("the marker survived, so the agent will never re-add the proxy:\n%s", got)
	}
}

// The opposite error is just as bad: clearing a proxy that is in use takes
// the machine off Lyntway's governance without saying so, and the receipts
// simply stop.
func TestTheDoctorLeavesAProxyThatIsListening(t *testing.T) {
	h := t.TempDir()
	withHome(t, h)
	profile := filepath.Join(h, ".zprofile")
	body := proxyRCMarker + "\nexport HTTPS_PROXY=http://127.0.0.1:19090\n"
	write(t, profile, body)

	restore := stubListening(t, func(string) bool { return true })
	defer restore()
	proxyPointsAt = func(string) bool { return false }

	var out bytes.Buffer
	stdout = &out
	defer func() { stdout = os.Stdout }()

	clearStrandedProxy()

	if !strings.Contains(read(t, profile), "HTTPS_PROXY") {
		t.Error("an export was removed while something was listening on it")
	}
	if out.Len() != 0 {
		t.Errorf("nothing was stranded and the doctor still said something:\n%s", out.String())
	}
}

func TestProxyAddrsInBlockReadsOnlyTheAgentsOwnBlock(t *testing.T) {
	for _, tc := range []struct {
		name     string
		contents string
		want     []string
	}{
		{
			"a proxy the user set themselves is not ours to remove",
			"export HTTPS_PROXY=http://corporate.example:3128\n",
			nil,
		},
		{
			"NO_PROXY is a list of exemptions, not somewhere to connect",
			proxyRCMarker + "\nexport NO_PROXY=127.0.0.1,localhost\n",
			nil,
		},
		{
			"the block ends at the first line that is not an export",
			proxyRCMarker + "\nexport HTTP_PROXY=http://127.0.0.1:19090\n" +
				"\nexport HTTPS_PROXY=http://127.0.0.1:9999\n",
			[]string{"127.0.0.1:19090"},
		},
		{
			"both halves of our own block",
			proxyRCMarker + "\nexport HTTP_PROXY=http://127.0.0.1:19090\n" +
				"export HTTPS_PROXY=http://127.0.0.1:19090\n",
			[]string{"127.0.0.1:19090", "127.0.0.1:19090"},
		},
		{
			"a value with no port is not an address",
			proxyRCMarker + "\nexport HTTPS_PROXY=http://127.0.0.1\n",
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := proxyAddrsInBlock(tc.contents)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func stubListening(t *testing.T, f func(string) bool) func() {
	t.Helper()
	prevListen, prevPoints := listeningAt, proxyPointsAt
	listeningAt = f
	return func() { listeningAt, proxyPointsAt = prevListen, prevPoints }
}

func withHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
