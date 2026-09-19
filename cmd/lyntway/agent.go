package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// `lyntway agent`: what AI is on this machine, reported on a schedule.
//
// # What it is for
//
// An organisation cannot govern AI it cannot see, and most of it is not
// in any proxy's path: a desktop app with a subscription, an editor
// extension, a local model, an MCP server somebody added last Tuesday.
// The agent lists those, says which ones anything here actually covers,
// and reports that to the account every few minutes so the console can
// show a device as covered, partly covered, or silent.
//
// # What it is careful never to be
//
// A monitor of people. Endpoint agents in this category read browser
// history to find which AI websites somebody visited; this one does not,
// and a ChatGPT tab is therefore visible only as connections from a
// browser to chatgpt.com, never as a page anybody opened. It collects no
// prompts, no file contents, no window titles, no keystrokes and no
// credential values, and the struct it sends has no field that could hold
// any of them. `--explain` says all of this in plain words, `--dry-run`
// prints the exact bytes a report would carry and sends nothing, and the
// last report actually sent is kept on disk for anybody to read.
//
// # Coverage is stated, never implied
//
// Every report carries a coverage line per surface, and the level is the
// weakest that is true. Local models read "content" only while `lyntway
// proxy` is running in front of them and no connection was seen going
// around it; an inventory is always "metadata", because knowing Cursor is
// installed says nothing about what it sent. A device whose report says
// "metadata" everywhere is a device we can describe, not one we govern.

// deviceReport is the POST /v1/devices/report body. Field for field the
// contract; nothing optional is omitted, so a reader of --dry-run sees
// every key the service will.
type deviceReport struct {
	DeviceID      string          `json:"device_id"`
	Kind          string          `json:"kind"`
	Hostname      string          `json:"hostname"`
	OS            string          `json:"os"`
	OSVersion     string          `json:"os_version"`
	Agent         string          `json:"agent"`
	User          string          `json:"user"`
	Coverage      []coverageEntry `json:"coverage"`
	AIApps        []aiApp         `json:"ai_apps"`
	MCPServers    []mcpServerInfo `json:"mcp_servers"`
	Destinations  []destination   `json:"destinations"`
	WindowSeconds int             `json:"window_seconds"`
	ReportedAt    string          `json:"reported_at"`
}

type coverageEntry struct {
	Surface string `json:"surface"`
	Level   string `json:"level"`
	Detail  string `json:"detail"`
}

// agentOptions is what the flags decide.
type agentOptions struct {
	Server   bool
	Once     bool
	DryRun   bool
	Proxy    bool
	StateDir string
	Scan     []string
	Interval time.Duration
	Window   time.Duration
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func agentUsage() {
	fmt.Fprint(os.Stderr, `lyntway agent — report what AI is on this machine

Usage:
  lyntway agent                 run: sample, report every few minutes, repeat
  lyntway agent --once          take one report, print it, send it
  lyntway agent --dry-run       take one report and print it; send nothing, write nothing
  lyntway agent --explain       what is collected, and what never is
  lyntway agent --server        server mode: keys in files, SDKs, outbound AI calls
  lyntway agent install         run the agent as a service (launchd, systemd, Task Scheduler)
  lyntway agent uninstall       remove that service

Flags:
  --scan DIR        also scan DIR for provider keys (repeatable; server mode has defaults)
  --proxy           keep `+"`lyntway proxy`"+` running in front of Ollama or LM Studio
  --state-dir DIR   where the device id and last report are kept
  --window 15s      how long --once and --dry-run sample connections for
  --interval 30s    how often connections are sampled

The API key comes from LYNTWAY_API_KEY, then the agent's own settings file,
then `+"`lyntway login`"+`. It is never accepted on the command line, where
every other user's process list would show it.
`)
}

func agentCommand(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "install":
			return agentInstall(args[1:])
		case "uninstall":
			return agentUninstall(args[1:])
		case "explain":
			fmt.Fprint(stdout, agentExplanation)
			return nil
		}
	}

	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	fs.Usage = agentUsage
	var opts agentOptions
	var scan stringList
	explain := fs.Bool("explain", false, "print what is collected and what never is")
	fs.BoolVar(&opts.Server, "server", false, "server mode")
	fs.BoolVar(&opts.Once, "once", false, "take one report, print it and send it")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "take one report and print it; send nothing")
	fs.BoolVar(&opts.Proxy, "proxy", false, "keep lyntway proxy running in front of a local model server")
	fs.StringVar(&opts.StateDir, "state-dir", "", "where the device id and last report are kept")
	fs.Var(&scan, "scan", "a directory to scan for provider keys (repeatable)")
	fs.DurationVar(&opts.Interval, "interval", 30*time.Second, "how often connections are sampled")
	fs.DurationVar(&opts.Window, "window", 15*time.Second, "how long --once and --dry-run sample for")
	// A key on the command line is readable by every user through ps.
	// Refused by name, so the person who tried learns why.
	fs.String("key", "", "not accepted: set LYNTWAY_API_KEY instead")
	_ = fs.Parse(flagsFirst(fs, args))
	if f := fs.Lookup("key"); f != nil && f.Value.String() != "" {
		return fmt.Errorf("--key is refused: a key on the command line is visible to every user in the process list. Set LYNTWAY_API_KEY instead")
	}
	opts.Scan = scan

	if *explain {
		fmt.Fprint(stdout, agentExplanation)
		return nil
	}
	if opts.Interval < time.Second {
		return fmt.Errorf("--interval must be at least a second")
	}
	if opts.StateDir == "" {
		opts.StateDir = defaultStateDir(runtime.GOOS, opts.Server, elevated(), home())
	}

	a, err := newAgent(opts)
	if err != nil {
		return err
	}
	if opts.Once || opts.DryRun {
		return a.runOnce(context.Background())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.run(ctx)
}

// defaultStateDir is where the device id lives: per user for an agent a
// person runs, machine-wide for one installed as root or SYSTEM.
func defaultStateDir(goos string, server, elevated bool, userHome string) string {
	if server || elevated {
		switch goos {
		case "linux":
			return "/var/lib/lyntway"
		case "darwin":
			if elevated {
				return "/Library/Application Support/Lyntway"
			}
		case "windows":
			if pd := os.Getenv("ProgramData"); pd != "" && elevated {
				return filepath.Join(pd, "Lyntway")
			}
		}
	}
	if userHome == "" {
		return ""
	}
	return filepath.Join(userHome, ".lyntway", "agent")
}

// agent holds what persists between reports.
type agent struct {
	opts      agentOptions
	host      agentHost
	c         config
	haveKey   bool
	signer    *requestSigner
	deviceID  string
	idStored  bool
	published bool
	resolver  *hostResolver
	client    *http.Client
	log       io.Writer
	sent      map[string]string // file → fingerprint of the last attested findings

	// proxyCancel stops a proxy this agent started in-process.
	proxyCancel context.CancelFunc
	proxyDone   chan struct{}

	// serverUnsupported is set when the service answers the report with
	// 404, so the explanation is printed once rather than every cycle.
	serverUnsupported bool
}

func newAgent(opts agentOptions) (*agent, error) {
	a := &agent{
		opts:   opts,
		host:   currentHost(opts.Server),
		client: &http.Client{Timeout: 20 * time.Second},
		log:    os.Stderr,
		sent:   map[string]string{},
	}

	a.c, a.haveKey = agentConfig(opts.StateDir)
	if !a.haveKey && !opts.DryRun {
		return nil, fmt.Errorf("no API key: set LYNTWAY_API_KEY (and LYNTWAY_URL for a self-hosted service), or run `lyntway login`. --dry-run needs neither")
	}
	if a.haveKey {
		signer, err := loadRequestSigner(a.c)
		if err != nil {
			return nil, err
		}
		a.signer = signer
	}

	id, stored, err := loadDeviceID(opts.StateDir, !opts.DryRun)
	if err != nil {
		return nil, err
	}
	a.deviceID, a.idStored = id, stored

	var extra []string
	if u, err := url.Parse(a.c.Origin); err == nil && u.Hostname() != "" {
		if _, known := matchAIHostName(u.Hostname()); !known {
			extra = append(extra, u.Hostname())
		}
	}
	a.resolver = newHostResolver(extra...)

	if body, err := os.ReadFile(filepath.Join(opts.StateDir, "attested.json")); err == nil {
		_ = json.Unmarshal(body, &a.sent)
	}
	return a, nil
}

// agentConfig finds the key and address to report to. The environment
// first, because that is how an RMM tool hands one over; then the agent's
// own settings file, which `agent install` writes; then the CLI's login.
func agentConfig(stateDir string) (config, bool) {
	origin := strings.TrimRight(strings.TrimSpace(os.Getenv("LYNTWAY_URL")), "/")
	if key := strings.TrimSpace(os.Getenv("LYNTWAY_API_KEY")); key != "" {
		if origin == "" {
			origin = defaultOrigin
		}
		return config{Origin: origin, Key: key}, true
	}
	if stateDir != "" {
		if body, err := os.ReadFile(filepath.Join(stateDir, "agent.json")); err == nil {
			var c config
			if json.Unmarshal(body, &c) == nil && c.Key != "" {
				if c.Origin == "" {
					c.Origin = defaultOrigin
				}
				return c, true
			}
		}
	}
	if c, err := loadConfig(); err == nil && c.Key != "" {
		return c, true
	}
	if origin == "" {
		origin = defaultOrigin
	}
	return config{Origin: origin}, false
}

var deviceIDPattern = regexp.MustCompile(`^dev_[a-z0-9]{22,40}$`)

// loadDeviceID reads the device id, or makes one. With create false (a dry
// run) a new id is made and not stored, and the caller says so.
func loadDeviceID(stateDir string, create bool) (id string, stored bool, err error) {
	path := ""
	if stateDir != "" {
		path = filepath.Join(stateDir, "device_id")
		if body, err := os.ReadFile(path); err == nil {
			id := strings.TrimSpace(string(body))
			if deviceIDPattern.MatchString(id) {
				return id, true, nil
			}
			// A corrupted file is replaced rather than trusted: an id the
			// service refuses would silently stop every report.
		}
	}
	id, err = newDeviceID()
	if err != nil {
		return "", false, err
	}
	if !create {
		return id, false, nil
	}
	if path == "" {
		return "", false, fmt.Errorf("no directory to keep this device's id in; pass --state-dir")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", false, fmt.Errorf("cannot create %s: %w (server mode keeps its state in /var/lib/lyntway; run as root or pass --state-dir)", stateDir, err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", false, err
	}
	return id, true, nil
}

// publishDeviceID makes the device id readable by the person at the
// machine, so another Lyntway component there — the browser extension,
// through a native-messaging host that runs as that person — can one day
// say it is the same device rather than a second one.
//
// The id is not a secret: it identifies the machine to the account and
// authorises nothing; the key beside it does that, and stays 0600. For a
// per-user agent the copy is ~/.lyntway/device_id. For a machine-wide one
// the state directory becomes traversable (0711, not listable) and the id
// file readable, so the path works for everyone while agent.json does not.
func publishDeviceID(stateDir, id string, elevated bool, h string) error {
	if elevated {
		if runtime.GOOS == "windows" {
			return nil // `agent install` grants Users read on the file
		}
		if err := os.Chmod(stateDir, 0o711); err != nil {
			return err
		}
		return os.Chmod(filepath.Join(stateDir, "device_id"), 0o644)
	}
	if h == "" {
		return nil
	}
	shared := filepath.Join(h, ".lyntway", "device_id")
	if cur, err := os.ReadFile(shared); err == nil && strings.TrimSpace(string(cur)) == id {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(shared), 0o700); err != nil {
		return err
	}
	return os.WriteFile(shared, []byte(id+"\n"), 0o644)
}

// newDeviceID is dev_ and 26 characters of base32 over 16 random bytes:
// 128 bits, lower case, within the contract's [a-z0-9].
func newDeviceID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	return "dev_" + strings.ToLower(enc), nil
}

// localModelState is what is known about local model servers right now.
type localModelState struct {
	Servers       []string // "Ollama on 127.0.0.1:11434"
	Upstream      string   // the first server's address, for the proxy
	ProxyRunning  bool
	ProxyUpstream string
}

var (
	probeLocalModel = func(url string) bool {
		client := &http.Client{Timeout: 700 * time.Millisecond}
		resp, err := client.Get(url)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	probeAgentProxy = probeProxy
)

func localModels() localModelState {
	var s localModelState
	if probeLocalModel("http://127.0.0.1:11434/api/version") {
		s.Servers = append(s.Servers, "Ollama on 127.0.0.1:11434")
		s.Upstream = "http://127.0.0.1:11434"
	}
	if probeLocalModel("http://127.0.0.1:1234/v1/models") {
		s.Servers = append(s.Servers, "LM Studio on 127.0.0.1:1234")
		if s.Upstream == "" {
			s.Upstream = "http://127.0.0.1:1234"
		}
	}
	if got, ok := probeAgentProxy(defaultProxyListen); ok {
		s.ProxyRunning = true
		s.ProxyUpstream, _ = got["upstream"].(string)
	}
	return s
}

// The two readings of live machine state, as variables so a test can
// replace them with a fixture and exercise everything downstream for real.
var (
	listProcessesFn     = listProcesses
	sampleConnectionsFn = sampleConnections
)

// collected is one window's worth of observation, before it is a report.
type collected struct {
	apps      []aiApp
	procErr   error
	mcp       mcpDiscovery
	local     localModelState
	agg       *destAggregator
	scan      *serverScan
	window    time.Duration
	finished  time.Time
	scanRoots []string
}

// collect samples connections for window, then takes the inventory.
func (a *agent) collect(ctx context.Context, window time.Duration) collected {
	agg := newDestAggregator()
	start := time.Now()
	var procs []procInfo
	var procErr error
	sample := func() {
		a.resolver.refresh()
		ps, err := listProcessesFn(a.host.GOOS)
		if err == nil {
			procs, procErr = ps, nil
		} else if procs == nil {
			procErr = err
		}
		byPID := make(map[int]procInfo, len(procs))
		for _, p := range procs {
			byPID[p.PID] = p
		}
		conns, err := sampleConnectionsFn(a.host.GOOS)
		if err != nil {
			agg.fail(err)
			return
		}
		agg.add(conns, byPID, a.host.GOOS, a.resolver)
	}

	sample()
	for time.Since(start)+a.opts.Interval <= window {
		select {
		case <-ctx.Done():
			return a.finish(agg, procs, procErr, time.Since(start))
		case <-time.After(a.opts.Interval):
		}
		sample()
	}
	// The window is what was actually observed, not what was asked for.
	return a.finish(agg, procs, procErr, time.Since(start))
}

func (a *agent) finish(agg *destAggregator, procs []procInfo, procErr error, window time.Duration) collected {
	c := collected{
		apps:     inventory(a.host, procs),
		procErr:  procErr,
		mcp:      discoverMCP(mcpSources(a.host, projectRoots(a.host))),
		local:    localModels(),
		agg:      agg,
		window:   window,
		finished: time.Now().UTC(),
	}
	// Absolute, because a finding's path is only useful to whoever reads
	// it somewhere else if it does not depend on where the agent started.
	var roots []string
	for _, r := range a.opts.Scan {
		if abs, err := filepath.Abs(r); err == nil {
			r = abs
		}
		roots = append(roots, r)
	}
	if len(roots) == 0 && a.opts.Server {
		if a.host.GOOS == "linux" {
			roots = defaultServerRoots
		} else if wd, err := os.Getwd(); err == nil {
			roots = []string{wd}
		}
	}
	if len(roots) > 0 {
		s := scanServerFiles(roots, defaultServerLimits)
		c.scan = &s
		c.scanRoots = roots
	}
	return c
}

// report turns an observation into the contract's body.
func (a *agent) report(c collected) deviceReport {
	hostname, _ := os.Hostname()
	kind := "laptop"
	if a.opts.Server {
		kind = "server"
	}
	r := deviceReport{
		DeviceID:      a.deviceID,
		Kind:          kind,
		Hostname:      hostname,
		OS:            reportOS(a.host.GOOS),
		OSVersion:     osVersion(a.host.GOOS),
		Agent:         "lyntway-agent/" + version,
		User:          a.host.User,
		AIApps:        c.apps,
		MCPServers:    c.mcp.Servers,
		Destinations:  c.agg.rows(),
		WindowSeconds: int(c.window.Round(time.Second) / time.Second),
		ReportedAt:    c.finished.Format(time.RFC3339),
	}
	// Empty lists are sent as [], never null: "none found" and "field
	// missing" must not read alike to whoever consumes this.
	if r.AIApps == nil {
		r.AIApps = []aiApp{}
	}
	if r.MCPServers == nil {
		r.MCPServers = []mcpServerInfo{}
	}
	r.Coverage = buildCoverage(coverageInputs{
		GOOS: a.host.GOOS, Elevated: a.host.Elevated,
		Apps: c.apps, ProcErr: c.procErr,
		MCP: c.mcp, Local: c.local, Destinations: r.Destinations,
		Scan: c.scan, ScanRoots: c.scanRoots,
		Samples: c.agg.samples, Failures: c.agg.failures, SampleErr: c.agg.lastErr,
		Interval: a.opts.Interval, Window: c.window,
	})
	sanitiseReport(&r)
	return r
}

// coverageInputs is everything coverage is decided from, so the decision
// can be tested without a machine in any particular state.
type coverageInputs struct {
	GOOS         string
	Elevated     bool
	Apps         []aiApp
	ProcErr      error
	MCP          mcpDiscovery
	Local        localModelState
	Destinations []destination
	Scan         *serverScan
	ScanRoots    []string
	Samples      int
	Failures     int
	SampleErr    error
	Interval     time.Duration
	Window       time.Duration
}

// runOnce is --once and --dry-run.
// publish shares the device id once per process, from whatever host the
// agent has settled on. It ran in newAgent until the image build ran the
// tests as root: the host was still the real, elevated one there, so a
// test's per-user fixture got the machine-wide treatment and no
// ~/.lyntway/device_id.
func (a *agent) publish() {
	if !a.idStored || a.published {
		return
	}
	a.published = true
	if err := publishDeviceID(a.opts.StateDir, a.deviceID, a.host.Elevated, a.host.Home); err != nil {
		fmt.Fprintf(a.log, "lyntway agent: the device id could not be published for other Lyntway components: %v\n", err)
	}
}

func (a *agent) runOnce(ctx context.Context) error {
	a.publish()
	a.offerProxy(ctx)
	fmt.Fprintf(a.log, "lyntway agent: sampling connections for %s…\n", a.opts.Window)
	c := a.collect(ctx, a.opts.Window)
	r := a.report(c)
	body := agentJSON(r)

	a.printSummary(r, c)
	if a.opts.DryRun {
		fmt.Fprintf(stdout, "\nThis is the report, byte for byte. --dry-run sent nothing and wrote nothing.\n")
		if !a.idStored {
			fmt.Fprintf(stdout, "The device id above is a sample; a real run keeps one in %s.\n", filepath.Join(a.opts.StateDir, "device_id"))
		}
		fmt.Fprintf(stdout, "\n%s", body)
		if c.scan != nil {
			if atts := keyAttestations(*c.scan, a.deviceID, r.Hostname); len(atts) > 0 {
				fmt.Fprintf(stdout, "\nAnd %d finding%s that would go to /v1/attest:\n\n%s", len(atts), pluralS(len(atts)), agentJSON(atts))
			}
		}
		return nil
	}

	fmt.Fprintf(stdout, "\nSending this report to %s:\n\n%s", a.c.Origin, body)
	next, err := a.send(body)
	// Findings go to /v1/attest whether or not the report was accepted:
	// they are separate endpoints, and a service that predates device
	// reports still records a key found on disk.
	if c.scan != nil {
		if n := sendKeyAttestations(a.client, a.c, a.signer, keyAttestations(*c.scan, a.deviceID, r.Hostname), a.sent, a.log); n > 0 {
			fmt.Fprintf(stdout, "\n%d key finding%s reported to /v1/attest (class and path only).\n", n, pluralS(n))
		}
		a.saveSent()
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\nSent. The service asked for the next report in %s.\n", next)
	return nil
}

// run is the service loop.
func (a *agent) run(ctx context.Context) error {
	a.publish()
	fmt.Fprintf(a.log, "lyntway agent %s: device %s reporting to %s; state in %s\n", version, a.deviceID, a.c.Origin, a.opts.StateDir)
	defer a.stopProxy()

	// The first window is short, so a device appears in the console within
	// a minute of being installed; after that the service sets the pace.
	window := time.Minute
	for ctx.Err() == nil {
		if a.opts.Proxy {
			a.ensureProxy(ctx)
		}
		c := a.collect(ctx, window)
		if ctx.Err() != nil {
			return nil
		}
		r := a.report(c)
		next, err := a.send(agentJSON(r))
		if err != nil {
			fmt.Fprintf(a.log, "lyntway agent: %v\n", err)
		}
		if c.scan != nil {
			sendKeyAttestations(a.client, a.c, a.signer, keyAttestations(*c.scan, a.deviceID, r.Hostname), a.sent, a.log)
			a.saveSent()
		}
		window = next
	}
	return nil
}

const defaultReportEvery = 15 * time.Minute

// send posts one report and returns when the next is due. The bytes sent
// are written to last-report.json first, so what left the machine can
// always be read back on it.
func (a *agent) send(body []byte) (time.Duration, error) {
	// Every field was checked on its way into the report; this is the
	// check of the whole, with the same rules the service applies. A
	// report that fails it is not sent, and says so, rather than being
	// refused at the other end with the secret already in transit.
	if looksSecret(string(body)) {
		return defaultReportEvery, errors.New("the report was not sent: something in it is shaped like a credential or a card number. Run `lyntway agent --dry-run` to see it")
	}
	if a.opts.StateDir != "" {
		_ = os.MkdirAll(a.opts.StateDir, 0o700)
		_ = os.WriteFile(filepath.Join(a.opts.StateDir, "last-report.json"), body, 0o600)
	}
	status, raw, err := doAPIRaw(a.client, a.c, a.signer, http.MethodPost, "/v1/devices/report", body)
	switch {
	case err != nil:
		return defaultReportEvery, err
	case status == http.StatusNotFound || status == http.StatusMethodNotAllowed:
		if !a.serverUnsupported {
			a.serverUnsupported = true
			return defaultReportEvery, fmt.Errorf("%s does not accept device reports yet (HTTP %d); the agent keeps sampling and will retry", a.c.Origin, status)
		}
		return defaultReportEvery, nil
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return defaultReportEvery, fmt.Errorf("%s refused the report: %s", a.c.Origin, apiMessage(status, raw))
	case status < 200 || status > 299:
		return defaultReportEvery, fmt.Errorf("%s answered the report with %s", a.c.Origin, apiMessage(status, raw))
	}
	a.serverUnsupported = false
	var resp struct {
		Next int `json:"next_report_seconds"`
	}
	_ = json.Unmarshal(raw, &resp)
	return nextWindow(resp.Next), nil
}

// nextWindow bounds what the service asks for: never faster than a
// minute, which would make the agent a load on the machine, and never
// slower than a day, after which a device reads as silent.
func nextWindow(seconds int) time.Duration {
	switch {
	case seconds <= 0:
		return defaultReportEvery
	case seconds < 60:
		return time.Minute
	case seconds > 86400:
		return 24 * time.Hour
	}
	return time.Duration(seconds) * time.Second
}

func (a *agent) saveSent() {
	if a.opts.StateDir == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(a.opts.StateDir, "attested.json"), agentJSON(a.sent), 0o600)
}

// printSummary is the part of --once and --dry-run written for a person.
func (a *agent) printSummary(r deviceReport, c collected) {
	fmt.Fprintf(stdout, "\nThis %s: %s, %s %s, user %s\n", r.Kind, r.Hostname, r.OS, r.OSVersion, r.User)

	fmt.Fprintf(stdout, "\nAI apps (%d)\n", len(r.AIApps))
	for _, app := range r.AIApps {
		state := "installed"
		if app.Running {
			state = "running"
		}
		v := app.Version
		if v == "" {
			v = "version unknown"
		}
		fmt.Fprintf(stdout, "  %-40s %-12s %-10s %s\n", app.Name, app.Kind, state, v)
	}

	fmt.Fprintf(stdout, "\nMCP servers (%d)\n", len(r.MCPServers))
	for _, s := range r.MCPServers {
		host := s.Host
		if host == "" {
			host = "local process"
		}
		cred := ""
		if s.HasCredentials {
			cred = "  a credential is written in its config"
		}
		fmt.Fprintf(stdout, "  %-22s %-28s %-6s %s%s\n", c.mcp.Labels[s], s.Name, s.Transport, host, cred)
	}

	fmt.Fprintf(stdout, "\nAI destinations over %ds (%d)\n", r.WindowSeconds, len(r.Destinations))
	for _, d := range r.Destinations {
		fmt.Fprintf(stdout, "  %-40s %-24s %d connection%s\n", d.Host, d.App, d.Connections, pluralS(d.Connections))
	}

	fmt.Fprintln(stdout, "\nCoverage")
	for _, cv := range r.Coverage {
		fmt.Fprintf(stdout, "  %-13s %-9s %s\n", cv.Surface, cv.Level, cv.Detail)
	}

	if c.scan != nil {
		fmt.Fprintf(stdout, "\nKeys in files (%d)\n", len(c.scan.Keys))
		for _, k := range c.scan.Keys {
			fmt.Fprintf(stdout, "  %s:%d\t%s (%s)\n", k.File, k.Line, k.Label, k.Class)
		}
		// A laptop's connections are its desktop apps', which `lyntway
		// init` routes or names as unroutable; advice about them here
		// would be advice about the wrong thing.
		var dests []destination
		if a.opts.Server {
			dests = r.Destinations
		}
		if advice := routingAdvice(a.c.Origin, *c.scan, dests); advice != "" {
			fmt.Fprintf(stdout, "\n%s", advice)
		}
	}
}

// Local models: keeping the proxy in front of them.

// offerProxy asks, on a terminal, whether to start the proxy in front of a
// local model server that has nothing in front of it. Never asked in a
// dry run, which changes nothing, or when nobody is there to answer.
func (a *agent) offerProxy(ctx context.Context) {
	if a.opts.DryRun || !stdinIsTerminal() {
		if a.opts.Proxy && !a.opts.DryRun {
			a.ensureProxy(ctx)
		}
		return
	}
	s := localModels()
	if len(s.Servers) == 0 || s.ProxyRunning {
		return
	}
	if a.opts.Proxy {
		a.ensureProxy(ctx)
		return
	}
	fmt.Fprintf(stdout, "%s is running with nothing in front of it, so its prompts are not inspected.\n", strings.Join(s.Servers, " and "))
	fmt.Fprintf(stdout, "Start `lyntway proxy` in the background now? It governs apps pointed at http://%s/v1; apps that call the model server directly are still not covered. [y/N] ", defaultProxyListen)
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
		fmt.Fprintln(stdout, "Left as it is.")
		return
	}
	if err := startDetachedProxy(s.Upstream); err != nil {
		fmt.Fprintf(stdout, "The proxy did not start: %v\n", err)
		return
	}
	fmt.Fprintf(stdout, "Started. Point apps at it with: export OPENAI_BASE_URL=http://%s/v1\n", defaultProxyListen)
}

// startDetachedProxy runs `lyntway proxy` as its own process, logging to
// ~/.lyntway/proxy.log, and waits briefly for it to answer.
func startDetachedProxy(upstream string) error {
	h := home()
	if h == "" {
		return errors.New("no home directory for the proxy's log")
	}
	logPath := filepath.Join(h, ".lyntway", "proxy.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	cmd := exec.Command(selfPath(), "proxy", "--upstream", upstream)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	for i := 0; i < 20; i++ {
		if _, ok := probeAgentProxy(defaultProxyListen); ok {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("it did not answer on %s; see %s", defaultProxyListen, logPath)
}

// ensureProxy keeps an in-process proxy running while a local model server
// is present. Not done as root: the proxy signs receipts with the person's
// key and writes them to their home, neither of which root should hold.
func (a *agent) ensureProxy(ctx context.Context) {
	if a.host.Elevated {
		return
	}
	if a.proxyDone != nil {
		select {
		case <-a.proxyDone:
			a.proxyDone, a.proxyCancel = nil, nil
		default:
			return // ours, still running
		}
	}
	s := localModels()
	if len(s.Servers) == 0 || s.ProxyRunning {
		return
	}
	pctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	a.proxyCancel, a.proxyDone = cancel, done
	go func() {
		defer close(done)
		err := runProxy(pctx, proxyOptions{Listen: defaultProxyListen, Upstream: s.Upstream, Report: true}, a.log)
		if err != nil {
			fmt.Fprintf(a.log, "lyntway agent: the proxy stopped: %v\n", err)
		}
	}()
}

func (a *agent) stopProxy() {
	if a.proxyCancel != nil {
		a.proxyCancel()
		select {
		case <-a.proxyDone:
		case <-time.After(5 * time.Second):
		}
	}
}

func isAre(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

// stdinIsTerminal is a variable so a test is never asked a question.
var stdinIsTerminal = func() bool { return isTerminal(os.Stdin) }

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
