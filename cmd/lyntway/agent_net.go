package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Where this machine's AI traffic goes, from connection metadata alone.
//
// # What is looked at
//
// The operating system's table of established TCP connections: which
// process holds a socket, and the address at the other end. Sampled on an
// interval, the same way `lsof` or `netstat` would show it to somebody at
// the terminal. No packet is captured, no TLS is intercepted, no proxy is
// inserted, and nothing about a connection's content is knowable from
// here — which is why every line this produces is metadata and says so.
//
// # How an address becomes a name
//
// The known AI hosts below are resolved forward, through this machine's
// own resolver, and a connection whose remote address is one of the
// answers is attributed to that host. That is more accurate than reverse
// DNS (a pointer record for a CDN address names the CDN, not the site) and
// it tells the resolver nothing it did not already know. It can still be
// ambiguous: api.anthropic.com and claude.ai answer from the same
// addresses, and nothing in a connection's metadata says which was meant.
// Such a connection is reported under its address, which is true, rather
// than under either name, which would be a guess — the first build joined
// both names with "or", which the report endpoint rightly refuses as not
// a host. Reverse lookups are made only for connections
// held by a known AI application, and only accepted when the answer is a
// known AI host.
//
// # What is missed, said plainly
//
// A connection that opens and closes between two samples. Traffic through
// a VPN or a corporate proxy, where the remote address is the proxy's.
// And, without root, other users' processes.

// aiHostDef is a known AI endpoint.
type aiHostDef struct {
	Host string
	// Upstream is the gateway route that fronts it, when there is one; it
	// decides what server mode can tell somebody to change.
	Upstream string
}

var aiHosts = []aiHostDef{
	{"api.openai.com", "openai"}, {"chatgpt.com", ""}, {"chat.openai.com", ""},
	{"api.anthropic.com", "anthropic"}, {"claude.ai", ""},
	{"generativelanguage.googleapis.com", "gemini"}, {"gemini.google.com", ""}, {"aistudio.google.com", ""},
	{"api.x.ai", "xai"}, {"grok.com", ""},
	{"api.mistral.ai", "mistral"}, {"chat.mistral.ai", ""},
	{"api.cohere.com", ""}, {"api.cohere.ai", ""},
	{"api.groq.com", ""}, {"api.together.xyz", ""}, {"api.fireworks.ai", ""},
	{"api.perplexity.ai", ""}, {"www.perplexity.ai", ""}, {"perplexity.ai", ""},
	{"api.deepseek.com", ""}, {"chat.deepseek.com", ""},
	{"openrouter.ai", ""}, {"api.replicate.com", ""},
	{"router.huggingface.co", ""}, {"api-inference.huggingface.co", ""},
	{"api.cerebras.ai", ""}, {"api.sambanova.ai", ""}, {"api.ai21.com", ""}, {"api.voyageai.com", ""},
	{"api.githubcopilot.com", ""}, {"api.individual.githubcopilot.com", ""},
	{"api.business.githubcopilot.com", ""}, {"api.enterprise.githubcopilot.com", ""},
	{"copilot-proxy.githubusercontent.com", ""},
	{"api2.cursor.sh", ""}, {"api3.cursor.sh", ""}, {"api4.cursor.sh", ""}, {"repo42.cursor.sh", ""},
	{"server.codeium.com", ""}, {"inference.codeium.com", ""}, {"server.self-serve.windsurf.com", ""},
	{"copilot.microsoft.com", ""}, {"ampcode.com", ""},
	{"lyntway.com", "lyntway"},
}

// aiHostSuffixes are families with per-customer names, which cannot be
// resolved in advance and are matched when a reverse lookup names them.
var aiHostSuffixes = []string{".openai.azure.com", ".services.ai.azure.com", ".cognitiveservices.azure.com", "-aiplatform.googleapis.com"}

// localModelPorts are loopback ports where local model servers answer by
// default, and our proxy in front of them.
var localModelPorts = map[uint16]string{11434: "Ollama", 1234: "LM Studio", 11435: "lyntway proxy"}

// matchAIHostName reports whether a DNS name is a known AI host.
func matchAIHostName(name string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, d := range aiHosts {
		if name == d.Host {
			return name, true
		}
	}
	for _, s := range aiHostSuffixes {
		if strings.HasSuffix(name, s) {
			return name, true
		}
	}
	if strings.HasPrefix(name, "bedrock-runtime.") && strings.HasSuffix(name, ".amazonaws.com") {
		return name, true
	}
	return "", false
}

func upstreamForHost(host string) string {
	for _, d := range aiHosts {
		if d.Host == host {
			return d.Upstream
		}
	}
	return ""
}

// hostRouting says what can be done about traffic to a host from code.
type hostRouting int

const (
	routeBuiltIn     hostRouting = iota // a gateway route exists
	routeAsUpstream                     // a provider API; add it as an upstream
	routeSigned                         // Bedrock or Vertex: signed requests, cannot be proxied
	routeNotFromCode                    // a subscription or consumer service, or a bare address
)

func routingFor(h string) hostRouting {
	switch {
	case upstreamForHost(h) != "":
		return routeBuiltIn
	case strings.HasPrefix(h, "bedrock-runtime.") || strings.HasSuffix(h, "-aiplatform.googleapis.com"):
		return routeSigned
	case strings.Contains(h, "githubcopilot") || strings.HasSuffix(h, "cursor.sh") ||
		strings.Contains(h, "codeium") || strings.Contains(h, "windsurf"):
		// Editors' own backends, reached with the editor's subscription.
		// Nothing on a server points at them.
		return routeNotFromCode
	case strings.HasPrefix(h, "api.") || strings.HasPrefix(h, "api-") || h == "openrouter.ai" ||
		h == "router.huggingface.co" || strings.HasSuffix(h, ".openai.azure.com") ||
		strings.HasSuffix(h, ".services.ai.azure.com") || strings.HasSuffix(h, ".cognitiveservices.azure.com"):
		return routeAsUpstream
	}
	return routeNotFromCode
}

// deviceHostPattern is the report endpoint's own test of a host: a bare
// name or address with an optional port, and nothing a token could hide
// in. Checked here too, so a row the service would refuse is dropped
// rather than costing the whole report.
var deviceHostPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?$`)

// tcpConn is one established connection.
type tcpConn struct {
	PID    int
	Proc   string
	Local  netip.AddrPort
	Remote netip.AddrPort
}

// sampleConnections reads this machine's established TCP connections.
func sampleConnections(goos string) ([]tcpConn, error) {
	switch goos {
	case "linux":
		return procConnections("/proc")
	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-NetTCPConnection -State Established | ForEach-Object { \"$($_.OwningProcess)`t$($_.LocalAddress)`t$($_.LocalPort)`t$($_.RemoteAddress)`t$($_.RemotePort)\" }").Output()
		if err == nil {
			return parseNetTCPConnection(string(out)), nil
		}
		// netstat's state column is translated on a non-English Windows,
		// which is why it is the fallback and not the first choice.
		out, err = exec.Command("netstat", "-ano", "-p", "TCP").Output()
		if err != nil {
			return nil, err
		}
		return parseNetstat(string(out)), nil
	default:
		// +c 0: full command names. Without it lsof cuts them at nine
		// characters and "Code Helper" and "Code Helper (Plugin)" merge.
		out, err := exec.Command("lsof", "+c", "0", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn").Output()
		if err != nil && len(out) == 0 {
			// lsof exits 1 when it found nothing, which is an answer.
			if _, ok := err.(*exec.ExitError); ok {
				return nil, nil
			}
			return nil, err
		}
		return parseLsof(string(out)), nil
	}
}

// parseLsof reads `lsof -F pcn`: a p line starts a process, c names it,
// and each n line is one socket as "local->remote".
func parseLsof(out string) []tcpConn {
	var conns []tcpConn
	pid, proc := 0, ""
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
			proc = ""
		case 'c':
			proc = line[1:]
		case 'n':
			local, remote, ok := strings.Cut(line[1:], "->")
			if !ok {
				continue
			}
			l, err1 := netip.ParseAddrPort(local)
			r, err2 := netip.ParseAddrPort(remote)
			if err1 != nil || err2 != nil {
				continue
			}
			conns = append(conns, tcpConn{PID: pid, Proc: proc, Local: l, Remote: r})
		}
	}
	return conns
}

// parseNetTCPConnection reads the tab-separated lines the PowerShell
// command above prints.
func parseNetTCPConnection(out string) []tcpConn {
	var conns []tcpConn
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) != 5 {
			continue
		}
		pid, _ := strconv.Atoi(f[0])
		l, err1 := addrPort(f[1], f[2])
		r, err2 := addrPort(f[3], f[4])
		if err1 != nil || err2 != nil {
			continue
		}
		conns = append(conns, tcpConn{PID: pid, Local: l, Remote: r})
	}
	return conns
}

func addrPort(addr, port string) (netip.AddrPort, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := strconv.ParseUint(strings.TrimSpace(port), 10, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(p)), nil
}

// parseNetstat reads `netstat -ano -p TCP` on Windows.
func parseNetstat(out string) []tcpConn {
	var conns []tcpConn
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 5 || !strings.EqualFold(f[0], "TCP") || f[3] != "ESTABLISHED" {
			continue
		}
		l, err1 := netip.ParseAddrPort(f[1])
		r, err2 := netip.ParseAddrPort(f[2])
		pid, err3 := strconv.Atoi(f[4])
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		conns = append(conns, tcpConn{PID: pid, Local: l, Remote: r})
	}
	return conns
}

// procConnections reads /proc/net/tcp and tcp6, and finds the process
// holding each socket through /proc/<pid>/fd. Without root only the
// caller's own processes can be looked into; their connections are still
// counted, under an unnamed process.
func procConnections(root string) ([]tcpConn, error) {
	var socks []procSocket
	var firstErr error
	for _, name := range []string{"tcp", "tcp6"} {
		body, err := os.ReadFile(filepath.Join(root, "net", name))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		socks = append(socks, parseProcNetTCP(string(body))...)
	}
	if len(socks) == 0 && firstErr != nil {
		return nil, firstErr
	}
	owners := socketOwners(root)
	conns := make([]tcpConn, 0, len(socks))
	for _, s := range socks {
		c := tcpConn{Local: s.Local, Remote: s.Remote}
		if o, ok := owners[s.Inode]; ok {
			c.PID, c.Proc = o.PID, o.Name
		}
		conns = append(conns, c)
	}
	return conns, nil
}

type procSocket struct {
	Local, Remote netip.AddrPort
	Inode         string
}

// parseProcNetTCP reads the kernel's socket table. Addresses are hex, in
// the host's byte order per 32-bit word; state 01 is ESTABLISHED.
func parseProcNetTCP(body string) []procSocket {
	var out []procSocket
	for i, line := range strings.Split(body, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 || f[3] != "01" {
			continue
		}
		l, ok1 := procAddr(f[1])
		r, ok2 := procAddr(f[2])
		if !ok1 || !ok2 {
			continue
		}
		out = append(out, procSocket{Local: l, Remote: r, Inode: f[9]})
	}
	return out
}

// procAddr decodes "0100007F:2CAA" or its 32-hex-digit IPv6 form.
func procAddr(s string) (netip.AddrPort, bool) {
	hexAddr, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(hexAddr)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, false
	}
	// Each 32-bit word is little-endian on every architecture Linux ships
	// this format for in practice (x86, arm64); reverse within words.
	for w := 0; w < len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), true
}

// socketOwners maps socket inodes to the processes that hold them.
func socketOwners(root string) map[string]procInfo {
	owners := map[string]procInfo{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return owners
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(root, e.Name(), "fd"))
		if err != nil {
			continue
		}
		var name string
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(root, e.Name(), "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			if name == "" {
				comm, _ := os.ReadFile(filepath.Join(root, e.Name(), "comm"))
				name = strings.TrimSpace(string(comm))
			}
			owners[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = procInfo{PID: pid, Name: name}
		}
	}
	return owners
}

// hostResolver turns remote addresses into known AI host names.
type hostResolver struct {
	lookupHost func(ctx context.Context, host string) ([]string, error)
	lookupAddr func(ctx context.Context, addr string) ([]string, error)
	extra      []string // e.g. a self-hosted Lyntway's own host

	mu        sync.Mutex
	byAddr    map[netip.Addr][]string
	ptr       map[netip.Addr]string
	refreshed time.Time
}

func newHostResolver(extra ...string) *hostResolver {
	return &hostResolver{
		lookupHost: net.DefaultResolver.LookupHost,
		lookupAddr: net.DefaultResolver.LookupAddr,
		extra:      extra,
		ptr:        map[netip.Addr]string{},
	}
}

// refresh resolves every known host, at most every ten minutes: often
// enough to follow a CDN's rotation, rarely enough to be invisible.
func (r *hostResolver) refresh() {
	r.mu.Lock()
	fresh := time.Since(r.refreshed) < 10*time.Minute && r.byAddr != nil
	r.mu.Unlock()
	if fresh {
		return
	}
	hosts := make([]string, 0, len(aiHosts)+len(r.extra))
	for _, d := range aiHosts {
		hosts = append(hosts, d.Host)
	}
	hosts = append(hosts, r.extra...)

	byAddr := map[netip.Addr][]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			addrs, err := r.lookupHost(ctx, h)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, a := range addrs {
				if ip, err := netip.ParseAddr(a); err == nil {
					ip = ip.Unmap()
					if !contains(byAddr[ip], h) {
						byAddr[ip] = append(byAddr[ip], h)
					}
				}
			}
		}(h)
	}
	wg.Wait()
	for ip := range byAddr {
		sort.Strings(byAddr[ip])
	}
	r.mu.Lock()
	r.byAddr, r.refreshed = byAddr, time.Now()
	r.mu.Unlock()
}

// name returns the known AI host at addr, or "". byAIApp permits a reverse
// lookup, which is only spent on connections an AI application holds.
func (r *hostResolver) name(addr netip.Addr, byAIApp bool) string {
	addr = addr.Unmap()
	r.mu.Lock()
	hosts := r.byAddr[addr]
	cached, looked := r.ptr[addr]
	r.mu.Unlock()
	switch {
	case len(hosts) == 1:
		return hosts[0]
	case len(hosts) > 1:
		if addr.Is6() {
			return "[" + addr.String() + "]"
		}
		return addr.String()
	}
	if !byAIApp || addr.IsLoopback() || addr.IsPrivate() {
		return ""
	}
	if looked {
		return cached
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	found := ""
	if names, err := r.lookupAddr(ctx, addr.String()); err == nil {
		for _, n := range names {
			if h, ok := matchAIHostName(n); ok {
				found = h
				break
			}
		}
	}
	r.mu.Lock()
	r.ptr[addr] = found
	r.mu.Unlock()
	return found
}

// destKey is one row of the destinations list.
type destKey struct{ Host, App string }

// destAggregator counts distinct connections per host and application
// over a reporting window.
type destAggregator struct {
	mu   sync.Mutex
	seen map[destKey]map[string]bool
	// samples and failures say how much of the window was actually looked
	// at, which the coverage line reports.
	samples, failures int
	lastErr           error
}

func newDestAggregator() *destAggregator {
	return &destAggregator{seen: map[destKey]map[string]bool{}}
}

// add attributes one sample's connections.
func (a *destAggregator) add(conns []tcpConn, procs map[int]procInfo, goos string, r *hostResolver) {
	type hit struct {
		k  destKey
		id string
	}
	var hits []hit
	for _, c := range conns {
		p, known := procs[c.PID]
		if !known {
			p = procInfo{PID: c.PID, Name: c.Proc}
		} else if p.Name == "" {
			p.Name = c.Proc
		}
		app, isAI := appForProcess(goos, p)

		var host string
		if c.Remote.Addr().IsLoopback() {
			if _, ok := localModelPorts[c.Remote.Port()]; ok {
				host = "localhost:" + strconv.Itoa(int(c.Remote.Port()))
			}
		} else if r != nil {
			host = r.name(c.Remote.Addr(), isAI)
		}
		if host == "" {
			continue
		}
		hits = append(hits, hit{destKey{Host: host, App: app}, fmt.Sprintf("%d|%s|%s", c.PID, c.Local, c.Remote)})
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.samples++
	for _, h := range hits {
		if a.seen[h.k] == nil {
			a.seen[h.k] = map[string]bool{}
		}
		a.seen[h.k][h.id] = true
	}
}

func (a *destAggregator) fail(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures++
	a.lastErr = err
}

// destination is one row of the report.
type destination struct {
	Host        string `json:"host"`
	App         string `json:"app"`
	Connections int    `json:"connections"`
}

func (a *destAggregator) rows() []destination {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]destination, 0, len(a.seen))
	for k, ids := range a.seen {
		out = append(out, destination{Host: k.Host, App: k.App, Connections: len(ids)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Connections != out[j].Connections {
			return out[i].Connections > out[j].Connections
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].App < out[j].App
	})
	return out
}

// appForProcess names the application a process belongs to, and whether
// it is one of the AI applications in the catalogue.
func appForProcess(goos string, p procInfo) (string, bool) {
	if name, ok := extensionForPath(p.Path); ok {
		return name, true
	}
	for _, d := range aiApps {
		if d.procMatches(goos, p) {
			return d.Name, true
		}
	}
	name := p.Name
	if name == "" && p.Path != "" {
		name = filepath.Base(p.Path)
	}
	name = strings.TrimSuffix(name, ".exe")
	// Electron and Chromium split an application into helpers named after
	// it; the application is the useful name.
	if i := strings.Index(name, " Helper"); i > 0 {
		name = name[:i]
	}
	for _, ed := range editors {
		if nameMatches(goos, name, ed.Procs) || (goos == "darwin" && strings.Contains(p.Path, "/"+ed.MacBundle+"/")) {
			return ed.Name, true
		}
	}
	if name == "" {
		return "unknown process", false
	}
	return name, false
}
