package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func readNetFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "agent", "net", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestParseLsof(t *testing.T) {
	got := parseLsof(readNetFixture(t, "lsof.txt"))
	want := []tcpConn{
		{PID: 501, Proc: "Cursor Helper (Plugin)", Local: ap("192.168.1.20:53001"), Remote: ap("104.18.1.1:443")},
		{PID: 501, Proc: "Cursor Helper (Plugin)", Local: ap("192.168.1.20:53002"), Remote: ap("104.18.1.1:443")},
		{PID: 777, Proc: "claude", Local: ap("[2001:db8::20]:53100"), Remote: ap("[2607:6bc0::10]:443")},
		{PID: 777, Proc: "claude", Local: ap("127.0.0.1:53200"), Remote: ap("127.0.0.1:11434")},
		{PID: 888, Proc: "Google Chrome Helper", Local: ap("192.168.1.20:53300"), Remote: ap("104.18.2.2:443")},
		{PID: 888, Proc: "Google Chrome Helper", Local: ap("192.168.1.20:53301"), Remote: ap("93.184.216.34:443")},
		{PID: 900, Proc: "ollama", Local: ap("127.0.0.1:11434"), Remote: ap("127.0.0.1:53200")},
	}
	assertConns(t, got, want)
}

func TestParseProcNetTCP(t *testing.T) {
	got := parseProcNetTCP(readNetFixture(t, "proc_net_tcp.txt"))
	want := []procSocket{
		{Local: ap("127.0.0.1:53448"), Remote: ap("127.0.0.1:11434"), Inode: "1001"},
		{Local: ap("192.168.1.20:53449"), Remote: ap("104.18.1.1:443"), Inode: "1002"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sockets, want %d (the LISTEN line must be skipped): %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("socket %d: got %+v, want %+v", i, got[i], want[i])
		}
	}

	six := parseProcNetTCP(readNetFixture(t, "proc_net_tcp6.txt"))
	if len(six) != 1 || six[0].Remote != ap("[2607:6bc0::10]:443") || six[0].Local != ap("192.168.1.20:53450") {
		t.Fatalf("tcp6: %+v", six)
	}
}

// procConnections is exercised on a fake /proc: the tables, and a process
// whose fd links name the sockets, as the kernel lays them out.
func TestProcConnectionsNamesTheOwningProcess(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "net"), 0o755))
	must(os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(readNetFixture(t, "proc_net_tcp.txt")), 0o644))
	must(os.WriteFile(filepath.Join(root, "net", "tcp6"), []byte(readNetFixture(t, "proc_net_tcp6.txt")), 0o644))
	for pid, spec := range map[string][2]string{"123": {"python3", "1002"}, "124": {"node", "2001"}} {
		must(os.MkdirAll(filepath.Join(root, pid, "fd"), 0o755))
		must(os.WriteFile(filepath.Join(root, pid, "comm"), []byte(spec[0]+"\n"), 0o644))
		must(os.Symlink("socket:["+spec[1]+"]", filepath.Join(root, pid, "fd", "3")))
		must(os.Symlink("/dev/null", filepath.Join(root, pid, "fd", "0")))
	}
	conns, err := procConnections(root)
	must(err)
	byRemote := map[netip.AddrPort]tcpConn{}
	for _, c := range conns {
		byRemote[c.Remote] = c
	}
	if c := byRemote[ap("104.18.1.1:443")]; c.PID != 123 || c.Proc != "python3" {
		t.Errorf("tcp socket owner: %+v", c)
	}
	if c := byRemote[ap("[2607:6bc0::10]:443")]; c.PID != 124 || c.Proc != "node" {
		t.Errorf("tcp6 socket owner: %+v", c)
	}
	// A socket nobody could be matched to is still a connection.
	if c, ok := byRemote[ap("127.0.0.1:11434")]; !ok || c.PID != 0 {
		t.Errorf("unowned socket: %+v, %v", c, ok)
	}
}

func TestParseWindowsConnections(t *testing.T) {
	got := parseNetstat(readNetFixture(t, "netstat.txt"))
	assertConns(t, got, []tcpConn{
		{PID: 4242, Local: ap("192.168.1.20:53001"), Remote: ap("104.18.1.1:443")},
		{PID: 4243, Local: ap("[::1]:53002"), Remote: ap("[::1]:11434")},
		{PID: 4244, Local: ap("[2001:db8::20]:53003"), Remote: ap("[2607:6bc0::10]:443")},
	})

	ps := parseNetTCPConnection("4242\t192.168.1.20\t53001\t104.18.1.1\t443\r\n4244\t2001:db8::20\t53003\t2607:6bc0::10\t443\r\nnot a line\n")
	assertConns(t, ps, []tcpConn{
		{PID: 4242, Local: ap("192.168.1.20:53001"), Remote: ap("104.18.1.1:443")},
		{PID: 4244, Local: ap("[2001:db8::20]:53003"), Remote: ap("[2607:6bc0::10]:443")},
	})

	procs := parseTasklist(readNetFixture(t, "tasklist.txt"))
	if len(procs) != 2 || procs[0] != (procInfo{PID: 4242, Name: "ChatGPT"}) || procs[1].Name != "claude" {
		t.Errorf("tasklist: %+v", procs)
	}
	tab := parseTabProcs("4242\tChatGPT\tC:\\Program Files\\WindowsApps\\OpenAI.ChatGPT-Desktop_1.0\\ChatGPT.exe\r\n4244\tclaude\t\r\n")
	if len(tab) != 2 || tab[0].Path == "" || tab[1].Name != "claude" {
		t.Errorf("Get-Process: %+v", tab)
	}
}

func TestParsePS(t *testing.T) {
	procs := parsePS(readNetFixture(t, "ps.txt"))
	if len(procs) != 6 {
		t.Fatalf("got %d processes: %+v", len(procs), procs)
	}
	if p := procs[1]; p.PID != 501 || p.Name != "Cursor Helper (Plugin)" || p.Path == "" {
		t.Errorf("a name with spaces: %+v", p)
	}
	if p := procs[2]; p.Name != "claude" || p.Path != "" {
		t.Errorf("a bare name: %+v", p)
	}
}

// fakeResolver answers forward lookups from a table and records reverse
// lookups, which must only be made for AI applications' connections.
func fakeResolver(forward map[string][]string, reverse map[string][]string) (*hostResolver, *[]string) {
	var asked []string
	r := newHostResolver()
	r.lookupHost = func(_ context.Context, host string) ([]string, error) {
		if a, ok := forward[host]; ok {
			return a, nil
		}
		return nil, errors.New("no such host")
	}
	r.lookupAddr = func(_ context.Context, addr string) ([]string, error) {
		asked = append(asked, addr)
		if n, ok := reverse[addr]; ok {
			return n, nil
		}
		return nil, errors.New("no PTR")
	}
	return r, &asked
}

func TestDestinationsAreAttributedAndCounted(t *testing.T) {
	r, asked := fakeResolver(map[string][]string{
		"api2.cursor.sh":    {"104.18.1.1"},
		"api.anthropic.com": {"2607:6bc0::10"},
		"api.openai.com":    {"104.18.2.2"},
		"chatgpt.com":       {"104.18.2.2"},
	}, map[string][]string{
		"203.0.113.9": {"my-resource.openai.azure.com."},
	})
	r.refresh()

	procs := map[int]procInfo{}
	for _, p := range parsePS(readNetFixture(t, "ps.txt")) {
		procs[p.PID] = p
	}
	conns := parseLsof(readNetFixture(t, "lsof.txt"))
	agg := newDestAggregator()
	agg.add(conns, procs, "darwin", r)
	// The same connections seen again in the next sample are the same
	// connections, not twice as many.
	agg.add(conns, procs, "darwin", r)
	// A connection from Claude (an AI app) to an address only a reverse
	// lookup can name.
	agg.add([]tcpConn{{PID: 1404, Local: ap("192.168.1.20:54000"), Remote: ap("203.0.113.9:443")}}, procs, "darwin", r)

	want := map[destKey]int{
		{Host: "api2.cursor.sh", App: "Cursor"}:               2,
		{Host: "api.anthropic.com", App: "Claude Code"}:       1,
		{Host: "localhost:11434", App: "Claude Code"}:         1,
		{Host: "104.18.2.2", App: "Google Chrome"}:            1,
		{Host: "my-resource.openai.azure.com", App: "Claude"}: 1,
	}
	rows := agg.rows()
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(rows), len(want), rows)
	}
	for _, row := range rows {
		if n, ok := want[destKey{row.Host, row.App}]; !ok || n != row.Connections {
			t.Errorf("unexpected row %+v", row)
		}
	}
	if agg.samples != 3 {
		t.Errorf("samples = %d", agg.samples)
	}
	// example.com from Chrome is not an AI host and Chrome is not an AI
	// app: no reverse lookup is spent on it, and it is not reported.
	for _, a := range *asked {
		if a == "93.184.216.34" {
			t.Errorf("a reverse lookup was made for a browser's non-AI connection")
		}
	}
}

func TestAnExtensionsBundledBinaryIsTheExtension(t *testing.T) {
	p := procInfo{PID: 5023, Name: "codex", Path: "/Users/someone/.vscode/extensions/openai.chatgpt-26.908.40401-darwin-arm64/bin/macos-aarch64/codex"}
	if name, ok := appForProcess("darwin", p); name != "Codex in VS Code" || !ok {
		t.Errorf("appForProcess = %q, %v", name, ok)
	}
	for _, d := range aiApps {
		if d.Name == "Codex CLI" && d.procMatches("darwin", p) {
			t.Error("an extension's bundled codex was taken for the Codex CLI")
		}
	}
}

func assertConns(t *testing.T, got, want []tcpConn) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d connections, want %d:\n%+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("connection %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}
