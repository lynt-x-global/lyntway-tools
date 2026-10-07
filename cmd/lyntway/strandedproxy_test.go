package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The address the doctor reports must be the one the agent uses.
//
// It printed "127.0.0.1:9090" unconditionally — a reassuring line about a port
// the agent may not be listening on, which is the same stale assumption that had
// enableSystemProxy pointing a whole machine at the wrong place.
func TestTheDoctorReadsThePortFromTheConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// No config: the documented default, not a guess.
	if got := agentProxyAddr(); got != "127.0.0.1:9090" {
		t.Errorf("with no config, addr = %q, want the default", got)
	}

	dir := filepath.Join(home, ".lyntway", "agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ cfg, want string }{
		{`{"listen_addr":"127.0.0.1:19090"}`, "127.0.0.1:19090"},
		{`{"listen_addr":"0.0.0.0:8080"}`, "0.0.0.0:8080"},
		// Unreadable or empty falls back rather than producing ":" or "".
		{`{"listen_addr":""}`, "127.0.0.1:9090"},
		{`{"listen_addr":"   "}`, "127.0.0.1:9090"},
		{`not json`, "127.0.0.1:9090"},
	} {
		if err := os.WriteFile(filepath.Join(dir, "agent.json"), []byte(tc.cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := agentProxyAddr(); got != tc.want {
			t.Errorf("config %s -> %q, want %q", tc.cfg, got, tc.want)
		}
	}
}

// systemProxyPointsAt must answer about this machine, and must not claim a match
// it cannot establish.
//
// The consequence of a false positive is turning off a proxy somebody is using;
// the consequence of a false negative is leaving them offline. Both matter, so
// the parsing is checked against addresses it must reject outright.
func TestSystemProxyPointsAtRejectsWhatIsNotAnAddress(t *testing.T) {
	for _, bad := range []string{"", "127.0.0.1", "garbage", ":", "127.0.0.1:", "::"} {
		if systemProxyPointsAt(bad) {
			t.Errorf("claimed the system proxy points at %q, which is not an address", bad)
		}
	}
	// A port nothing could be set to. Whatever this machine's real settings are,
	// they are not this.
	if systemProxyPointsAt("127.0.0.1:65534") {
		t.Error("claimed the system proxy points at a port nothing uses")
	}
}

// The doctor must only clear a proxy when nothing is listening — that is the
// whole safety argument for doing it without asking.
func TestClearStrandedProxyOnlyActsWhenNothingIsListening(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Something listening on the address the config names. clearStrandedProxy is
	// only ever called from the branch where the agent is unreachable, but if
	// that ever changes, taking the network down from under a working agent is
	// the failure to avoid — so the address it reads must be the live one.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	dir := filepath.Join(home, ".lyntway", "agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := `{"listen_addr":"` + ln.Addr().String() + `"}`
	if err := os.WriteFile(filepath.Join(dir, "agent.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := agentProxyAddr(); got != ln.Addr().String() {
		t.Errorf("addr = %q, want the listening address %q", got, ln.Addr().String())
	}

	// And the detector says no for that ephemeral port, so nothing is cleared on
	// a developer's machine by running the suite.
	if systemProxyPointsAt(ln.Addr().String()) {
		t.Error("claimed this machine's proxy points at an ephemeral test port")
	}
}

// networkServices must never return nothing: an empty list means no service is
// asked about, so a stranded proxy is reported as fine.
func TestNetworkServicesAlwaysNamesSomething(t *testing.T) {
	if got := networkServices(); len(got) == 0 {
		t.Error("no network services returned, so a stranded proxy could never be found")
	}
}

// clearStrandedProxy must act only when the machine really is pointed at a dead
// agent, and must act when it is.
//
// Both halves matter in opposite directions: clearing a proxy somebody is using
// breaks their traffic, and failing to clear a stranded one leaves them with no
// network at all. The detector and the clearer are swapped so this runs without
// changing the settings of the machine running the suite.
func TestClearStrandedProxyActsOnlyOnARealStranding(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".lyntway", "agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.json"),
		[]byte(`{"listen_addr":"127.0.0.1:19090"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	oldPoints, oldClear, oldOut := proxyPointsAt, clearProxy, stdout
	t.Cleanup(func() { proxyPointsAt, clearProxy, stdout = oldPoints, oldClear, oldOut })

	t.Run("not pointed at us: nothing is touched and nothing is said", func(t *testing.T) {
		var out strings.Builder
		cleared := false
		stdout = &out
		proxyPointsAt = func(string) bool { return false }
		clearProxy = func() bool { cleared = true; return true }

		clearStrandedProxy()

		if cleared {
			t.Error("cleared a proxy this machine was not pointed at")
		}
		if out.Len() != 0 {
			t.Errorf("said something when there was nothing wrong: %q", out.String())
		}
	})

	t.Run("pointed at a dead agent: it is cleared, and the address is named", func(t *testing.T) {
		var out strings.Builder
		var askedAbout string
		cleared := false
		stdout = &out
		proxyPointsAt = func(addr string) bool { askedAbout = addr; return true }
		clearProxy = func() bool { cleared = true; return true }

		clearStrandedProxy()

		if askedAbout != "127.0.0.1:19090" {
			t.Errorf("checked %q, want the address from the config", askedAbout)
		}
		if !cleared {
			t.Error("left the machine pointed at a dead agent")
		}
		// Named, not counted: somebody reading this needs to know which address
		// was wrong, and that their browser was the thing affected.
		if !strings.Contains(out.String(), "127.0.0.1:19090") {
			t.Errorf("did not name the address: %q", out.String())
		}
		if !strings.Contains(out.String(), "no network") {
			t.Errorf("did not say what the consequence was: %q", out.String())
		}
	})

	t.Run("clearing fails: the manual command is printed", func(t *testing.T) {
		var out strings.Builder
		stdout = &out
		proxyPointsAt = func(string) bool { return true }
		clearProxy = func() bool { return false }

		clearStrandedProxy()

		if !strings.Contains(out.String(), "networksetup") {
			t.Errorf("gave no way out when it could not fix it itself: %q", out.String())
		}
	})
}

// The doctor must print the address the agent uses, not a constant.
func TestTheDoctorNamesTheConfiguredPort(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".lyntway", "agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.json"),
		[]byte(`{"listen_addr":"127.0.0.1:17777"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	oldPoints, oldClear, oldOut, oldReach := proxyPointsAt, clearProxy, stdout, agentReachable
	t.Cleanup(func() {
		proxyPointsAt, clearProxy, stdout, agentReachable = oldPoints, oldClear, oldOut, oldReach
	})
	proxyPointsAt = func(string) bool { return false }
	clearProxy = func() bool { return false }

	// Both branches, because the address is printed in one and the stranding
	// check runs in the other, and a constant in either is a lie about which
	// port this machine is pointed at.
	for _, reachable := range []bool{true, false} {
		agentReachable = func() bool { return reachable }
		var out strings.Builder
		stdout = &out
		_ = deviceDoctor()
		if strings.Contains(out.String(), "9090") {
			t.Errorf("agent reachable=%v: the doctor printed the default port while the config says 17777:\n%s",
				reachable, out.String())
		}
		if reachable && !strings.Contains(out.String(), "17777") {
			t.Errorf("the doctor never named the configured port:\n%s", out.String())
		}
	}

	// And when the agent is unreachable, the doctor must actually look for a
	// stranding rather than only reporting that the agent is down. Somebody
	// whose browser has no network runs this command; telling them the agent is
	// not running, while leaving the setting that broke their network in place,
	// is a diagnosis without a remedy.
	agentReachable = func() bool { return false }
	stranded := false
	proxyPointsAt = func(string) bool { stranded = true; return true }
	cleared := false
	clearProxy = func() bool { cleared = true; return true }

	var out strings.Builder
	stdout = &out
	_ = deviceDoctor()

	if !stranded {
		t.Error("the doctor never checked whether the machine was left pointed at a dead agent")
	}
	if !cleared {
		t.Error("the doctor found a stranded proxy and did not put it back")
	}
	if !strings.Contains(out.String(), "17777") {
		t.Errorf("the doctor did not name the stranded address:\n%s", out.String())
	}
}

func TestParseNetworkServicesNeverReturnsNothing(t *testing.T) {
	// An empty list means no service is asked about, so a stranded proxy reads
	// as fine and somebody stays offline.
	for _, in := range []string{"", "\n\n", "An asterisk (*) denotes that a network service is disabled.\n", "*Disabled Thing\n"} {
		if got := parseNetworkServices(in); len(got) == 0 {
			t.Errorf("parseNetworkServices(%q) returned nothing", in)
		}
	}
	// And it reads a real listing, skipping the preamble and disabled services.
	got := parseNetworkServices("An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bridge\nThunderbolt Bridge\n")
	want := []string{"Wi-Fi", "Thunderbolt Bridge"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("parsed %v, want %v", got, want)
	}
}
