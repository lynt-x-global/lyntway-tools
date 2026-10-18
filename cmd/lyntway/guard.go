package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/govern"
	"github.com/lynt-x-global/lyntway-tools/receipt"
	"github.com/lynt-x-global/lyntway-tools/usage"
)

// Run one command with its model traffic governed, and nothing else
// changed.
//
// # Why this exists when `lyntway proxy` already did
//
// `lyntway proxy` is a daemon. Somebody has to start it, point a tool at
// it by editing a setting, remember it is running, and stop it afterwards.
// Four steps, and three of them are invisible if they are forgotten — a
// tool pointed at a proxy that is no longer listening fails, and a proxy
// listening with nothing pointed at it governs nothing while looking
// perfectly healthy.
//
//	lyntway guard -- claude
//
// is the same engine with none of that. A listener per provider is bound
// on a loopback port nobody has to know, the child is started with the
// base-URL variables pointing at them, and both die with the command. The
// machine is in exactly the state it was in before: no setting edited, no
// file rewritten, nothing left listening.
//
// # What it will not do
//
// It will not run the command unguarded. If a listener cannot be bound or
// the engine will not start, this stops and says so, because a wrapper
// that silently degrades into `exec` is worse than no wrapper: the person
// believes they were covered on exactly the run where they were not. The
// command itself is still one word away without us, and the error says so.
//
// # The variable that was already set
//
// A tool pointed at Groq or at a local server through OPENAI_BASE_URL is
// a configuration somebody made on purpose. Overwriting it with our
// default would send their request to a provider they did not choose, with
// a key that is not for it. So an inherited value is **fronted, not
// replaced**: the listener forwards to wherever they were already going.
// Our defaults are used only for variables that were not set at all.
//
// # Why "nothing passed through" is reported as a failure
//
// Pointing a tool at an address is a request, not a guarantee. Some tools
// read a different setting; some authenticate in a way that ignores this
// one. Either way the run was not governed, and a summary that said
// "0 findings" would be a receipt-shaped lie — the honest statement is
// that we saw nothing because nothing came, and the run should be treated
// as ungoverned.

// guardTool is how this names itself in receipts, in reports to the
// account, and as the source of a refusal. A person debugging a 403 needs
// the name of the thing they actually ran.
const guardTool = "lyntway-guard"

// guardLabel prefixes the chain id, the vantage and the receipt file, so a
// wrapped session is never mistaken for a standalone proxy's chain.
const guardLabel = "guard"

// guardMarker is set in the child's environment. It stops a guard started
// by an agent that is itself inside a guard from nesting listeners that
// forward to each other.
const guardMarker = "LYNTWAY_GUARD"

// guardGroup is one provider and the variables that point a tool at it.
//
// They are grouped because the members are aliases for one setting: a tool
// reads whichever it knows. Introducing an alias the user had not set
// would change which provider their tool talks to, so a group where
// anything is already set is honoured as it stands and never added to.
type guardGroup struct {
	Vars    []string
	Default string
}

// The two that cover the tools people actually run. OPENAI_API_BASE is the
// older spelling and several tools still read it first.
var guardGroups = []guardGroup{
	{Vars: []string{"ANTHROPIC_BASE_URL"}, Default: "https://api.anthropic.com"},
	{Vars: []string{"OPENAI_BASE_URL", "OPENAI_API_BASE"}, Default: "https://api.openai.com/v1"},
}

// guardProviderNames gives a receipt a word rather than a hostname. A
// chain called "guard/anthropic" is readable a year later; one called
// "guard/api.anthropic.com" is a DNS record.
var guardProviderNames = map[string]string{
	"api.anthropic.com":                 "anthropic",
	"api.openai.com":                    "openai",
	"api.groq.com":                      "groq",
	"api.mistral.ai":                    "mistral",
	"api.deepseek.com":                  "deepseek",
	"openrouter.ai":                     "openrouter",
	"api.together.xyz":                  "together",
	"api.x.ai":                          "xai",
	"generativelanguage.googleapis.com": "gemini",
}

func guardProviderName(u *url.URL) string {
	if name, ok := guardProviderNames[strings.ToLower(u.Hostname())]; ok {
		return name
	}
	return guessUpstreamName(u)
}

// guardRoute is one listener: an upstream, and the variables that will be
// set to its local address.
type guardRoute struct {
	Upstream string
	Vars     []string

	// Inherited records that Upstream came from the environment rather
	// than from our defaults, which is what the banner has to say: we are
	// fronting where they were already going, not redirecting them.
	Inherited bool

	name string
	addr string

	// receipts is kept on the route rather than read back off the proxy,
	// because the proxy is closed before the summary is printed and a
	// verify line nobody can paste is worse than no verify line.
	receipts string

	proxy *localProxy
	srv   *http.Server
}

type guardOptions struct {
	// Set is --set ENV=URL, which adds or replaces a route outright.
	Set []string

	Receipts string
	Report   bool
	Quiet    bool

	// Price is --price MODEL=IN/OUT, for this run only. Currency is the
	// label echoed beside an estimate.
	Price    []string
	Currency string

	// Command is everything after the flags: the program and its
	// arguments, run as given.
	Command []string
}

func guardUsage() {
	fmt.Fprint(os.Stderr, "lyntway guard — run one command with its model traffic governed\n"+
		"\n"+
		"Usage:\n"+
		"  lyntway guard [flags] -- COMMAND [ARGS...]\n"+
		"\n"+
		"Examples:\n"+
		"  lyntway guard -- claude\n"+
		"  lyntway guard -- codex\n"+
		"  lyntway guard -- python app.py\n"+
		"  lyntway guard --set GROQ_BASE_URL=https://api.groq.com/openai/v1 -- aider\n"+
		"\n"+
		"A listener is started on this machine for each provider, the command is\n"+
		"run with its base-URL variables pointing at them, and both stop when the\n"+
		"command stops. Nothing on this machine is edited and nothing is left\n"+
		"running. Every request and reply is governed here and written to a signed\n"+
		"receipt under ~/.lyntway/receipts/guard/.\n"+
		"\n"+
		"A variable you had already set is fronted, not replaced: the listener\n"+
		"forwards to wherever you were already pointing.\n"+
		"\n"+
		"When the command stops, the summary says what it cost: the tokens the\n"+
		"providers reported, by the model that answered. There is no built-in\n"+
		"price table — we do not know what you pay — so a money figure appears\n"+
		"only against prices you set, in ~/.lyntway/prices.json or for one run:\n"+
		"\n"+
		"  lyntway guard --price claude-opus-4=15/75 --currency USD -- claude\n"+
		"\n"+
		"Flags:\n"+
		"  --set ENV=URL   front URL and set ENV to the local address (repeatable)\n"+
		"  --price M=IN/OUT  what a million tokens of model M costs you (repeatable)\n"+
		"  --currency LABEL  echoed beside an estimate, like USD\n"+
		"  --receipts DIR  where to keep this session's receipts\n"+
		"  --report=false  keep even the classes and counts on this machine\n"+
		"  --quiet         do not print a line when something is withheld\n")
}

func guardCmd(args []string) error {
	fs := flag.NewFlagSet("guard", flag.ExitOnError)
	fs.Usage = guardUsage
	var opts guardOptions
	var sets stringList
	fs.Var(&sets, "set", "ENV=URL to front and point ENV at (repeatable)")
	fs.StringVar(&opts.Receipts, "receipts", "", "directory for this session's receipts (default ~/.lyntway/receipts/guard)")
	fs.BoolVar(&opts.Report, "report", true, "report classes and counts to the account this machine is signed in to")
	fs.BoolVar(&opts.Quiet, "quiet", false, "do not print a line when something is withheld")
	var prices stringList
	fs.Var(&prices, "price", "MODEL=IN/OUT per million tokens, for this run (repeatable)")
	fs.StringVar(&opts.Currency, "currency", "", "a label for an estimate, like USD")
	// Deliberately not flagsFirst: everything after the command belongs to
	// the command. `lyntway guard -- claude --model x` must not have
	// --model read as ours.
	_ = fs.Parse(args)
	opts.Set = sets
	opts.Price = prices
	opts.Command = fs.Args()

	if len(opts.Command) == 0 {
		guardUsage()
		return errors.New("guard needs a command to run: lyntway guard -- claude")
	}
	code, err := runGuard(opts, stdout)
	if err != nil {
		return err
	}
	if code != 0 {
		// The command's own exit code is the caller's answer. Returning it
		// as an error would print "lyntway:" in front of somebody else's
		// failure, so exit directly.
		os.Exit(code)
	}
	return nil
}

// guardRoutes decides what will be fronted and which variables will point
// where. env is the lookup, so this is testable without touching the
// process environment.
func guardRoutes(env func(string) string, sets []string) ([]*guardRoute, error) {
	var routes []*guardRoute
	// explicit records variables named by --set, so a group does not also
	// claim them.
	explicit := map[string]bool{}
	for _, s := range sets {
		name, raw, ok := strings.Cut(s, "=")
		name, raw = strings.TrimSpace(name), strings.TrimSpace(raw)
		if !ok || name == "" || raw == "" {
			return nil, fmt.Errorf("--set %q is not ENV=URL", s)
		}
		if _, err := guardUpstreamURL(raw); err != nil {
			return nil, fmt.Errorf("--set %s: %w", name, err)
		}
		explicit[name] = true
		routes = append(routes, &guardRoute{Upstream: raw, Vars: []string{name}})
	}

	for _, g := range guardGroups {
		var inherited []*guardRoute
		for _, v := range g.Vars {
			if explicit[v] {
				continue
			}
			raw := strings.TrimSpace(env(v))
			if raw == "" {
				continue
			}
			if _, err := guardUpstreamURL(raw); err != nil {
				// Their setting, not ours to correct. Fronting something
				// we cannot parse would be worse than leaving it alone.
				return nil, fmt.Errorf("%s is set to %q, which is not an http(s) URL; unset it or pass --set %s=URL", v, raw, v)
			}
			inherited = append(inherited, &guardRoute{Upstream: raw, Vars: []string{v}, Inherited: true})
		}
		if len(inherited) > 0 {
			routes = append(routes, inherited...)
			continue
		}
		// Nothing in this group was set, so there is no configuration to
		// respect and every alias can point at our default.
		var vars []string
		for _, v := range g.Vars {
			if !explicit[v] {
				vars = append(vars, v)
			}
		}
		if len(vars) > 0 {
			routes = append(routes, &guardRoute{Upstream: g.Default, Vars: vars})
		}
	}

	return mergeGuardRoutes(routes)
}

// mergeGuardRoutes collapses routes that forward to the same place, so two
// variables naming one provider cost one listener and one chain rather
// than two of each.
func mergeGuardRoutes(in []*guardRoute) ([]*guardRoute, error) {
	var out []*guardRoute
	byUpstream := map[string]*guardRoute{}
	used := map[string]int{}
	for _, r := range in {
		if existing, ok := byUpstream[r.Upstream]; ok {
			existing.Vars = append(existing.Vars, r.Vars...)
			continue
		}
		u, err := guardUpstreamURL(r.Upstream)
		if err != nil {
			return nil, err
		}
		r.name = sanitiseName(guardProviderName(u))
		// Two different upstreams can share a provider name — a default
		// and a regional endpoint, say — and two chains with one name
		// would interleave in one file. Number the second.
		used[r.name]++
		if n := used[r.name]; n > 1 {
			r.name = fmt.Sprintf("%s-%d", r.name, n)
		}
		byUpstream[r.Upstream] = r
		out = append(out, r)
	}
	return out, nil
}

func guardUpstreamURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%q is not an http(s) URL", raw)
	}
	return u, nil
}

// guardSession is the counting and the notices for one run.
type guardSession struct {
	out   io.Writer
	quiet bool

	mu       sync.Mutex
	messages int
	byRoute  map[string]int
	saves    []guardNotice
	findings map[detect.Class]int

	// tokens is what the providers reported, by the model that answered.
	// unmetered counts replies that reported no figure at all — kept
	// apart, because folding them in as zero would read as calls that
	// were free.
	tokens    map[string]usage.TokenUsage
	unmetered int
}

func (g *guardSession) noteUsage(model string, u usage.TokenUsage, metered bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !metered {
		g.unmetered++
		return
	}
	have := g.tokens[model]
	have.Input += u.Input
	have.Output += u.Output
	have.ReportedBy = usage.ReportedByProvider
	g.tokens[model] = have
}

// guardNotice is one message that was not simply passed on.
type guardNotice struct {
	Route     string
	Direction receipt.Direction
	Decision  receipt.Decision
	Receipt   string
	Findings  []receipt.Finding
}

func (g *guardSession) note(route string, res *govern.Result, dir receipt.Direction) {
	acted := withheldFindings(res.Findings)
	if len(acted) == 0 {
		acted = substitutedFindings(res.Findings)
	}

	g.mu.Lock()
	g.messages++
	g.byRoute[route]++
	for _, f := range res.Findings {
		g.findings[detect.Class(f.Class)] += f.Count
	}
	if len(acted) > 0 {
		g.saves = append(g.saves, guardNotice{
			Route: route, Direction: dir, Decision: res.Decision,
			Receipt: res.Receipt.ID, Findings: acted,
		})
	}
	g.mu.Unlock()

	if len(acted) == 0 || g.quiet {
		return
	}
	// One line, and only when something was actually done. A tool with a
	// full-screen interface is drawing over this; a paragraph would wreck
	// it, and silence would waste the only moment that proves the point.
	//
	// ✗ rather than a red mark, because every other refusal this CLI
	// prints uses it, and because the website reproduces this transcript —
	// where green, amber and red are reserved for provenance and spending
	// red on an error would make the three words mean less.
	fmt.Fprintf(g.out, "\n✗ lyntway %s this %s — %s · receipt %s\n",
		guardVerb(res.Decision), guardNoun(dir),
		strings.Join(findingPhrases(acted), ", "), res.Receipt.ID)
}

// substitutedFindings are the ones replaced on the way out rather than
// stopped. The request went on; the value did not.
func substitutedFindings(all []receipt.Finding) []receipt.Finding {
	var out []receipt.Finding
	for _, f := range all {
		switch f.Decision {
		case receipt.DecisionTokenize, receipt.DecisionRedact:
			out = append(out, f)
		}
	}
	return out
}

func guardVerb(d receipt.Decision) string {
	switch d {
	case receipt.DecisionBlock:
		return "stopped"
	case receipt.DecisionRequireApproval:
		return "held"
	case receipt.DecisionTokenize, receipt.DecisionRedact:
		return "substituted into"
	}
	return "acted on"
}

func guardNoun(d receipt.Direction) string {
	if d == receipt.DirectionResponse {
		return "reply"
	}
	return "request"
}

// findingPhrases names each class the way a person says it and keeps the
// identifier beside it, so a line on a terminal can be matched against the
// receipt it came from without a lookup table.
func findingPhrases(fs []receipt.Finding) []string {
	counts := map[string]int{}
	var order []string
	for _, f := range fs {
		if _, seen := counts[f.Class]; !seen {
			order = append(order, f.Class)
		}
		counts[f.Class] += f.Count
	}
	out := make([]string, 0, len(order))
	for _, class := range order {
		out = append(out, fmt.Sprintf("%s (%s) ×%d", detect.Label(detect.Class(class)), class, counts[class]))
	}
	return out
}

// runGuard binds the listeners, runs the command, and reports. The int is
// the command's own exit code.
func runGuard(opts guardOptions, out io.Writer) (int, error) {
	if v := os.Getenv(guardMarker); v != "" {
		return 0, fmt.Errorf("this is already running inside lyntway guard (session %s); run the command directly", v)
	}

	// Resolved first, before a banner is printed or a port is bound. A
	// command that does not exist is the commonest mistake there is, and
	// answering it with a page of start-up output and then an error reads
	// as a failure of ours.
	path, err := exec.LookPath(opts.Command[0])
	if err != nil {
		return 0, fmt.Errorf("%s: %w", opts.Command[0], err)
	}

	book, err := loadPriceBook()
	if err != nil {
		return 0, err
	}
	if book, err = applyPriceFlags(book, opts.Price, opts.Currency); err != nil {
		return 0, err
	}

	routes, err := guardRoutes(os.Getenv, opts.Set)
	if err != nil {
		return 0, err
	}
	if len(routes) == 0 {
		return 0, errors.New("nothing to govern: every base-URL variable was claimed by --set and none was given a URL")
	}

	session := guardSessionID()
	dir, store, err := guardReceiptsDir(opts.Receipts, session)
	if err != nil {
		return 0, err
	}

	g := &guardSession{
		out: out, quiet: opts.Quiet,
		byRoute:  map[string]int{},
		findings: map[detect.Class]int{},
		tokens:   map[string]usage.TokenUsage{},
	}

	// Everything is bound before the command starts. A listener that fails
	// after the child is running would leave it half covered with no way
	// to say which half.
	started, err := startGuardRoutes(routes, dir, store, opts, g)
	stop := func() {
		stopGuardRoutes(started)
		started = nil
	}
	defer func() {
		stop()
		// Tidy on the way out however this ended. A run that failed to
		// start still opened its receipt files, and a directory of empty
		// ones implies a session that governed something.
		guardTidy(dir, routes)
	}()
	if err != nil {
		return 0, err
	}

	guardBanner(out, opts, routes, dir)

	code, runErr := runGuardedCommand(path, opts.Command, routes, session)
	stop()
	if runErr != nil {
		return 0, runErr
	}

	guardSummary(out, g, opts.Command[0], code, routes, dir, book)
	return code, nil
}

// guardCommandLine is the command as a banner line. A wrapper around
// `sh -c` carries an entire script in one argument, and printing it whole
// pushes everything that matters off the screen.
func guardCommandLine(command []string) string {
	line := strings.Join(command, " ")
	if len(line) <= 60 {
		return line
	}
	return line[:57] + "..."
}

func guardSessionID() string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// guardReceiptsDir gives this session a directory of its own.
//
// One directory per session, rather than appending to the proxy's, because
// two processes writing one chain file overwrite each other's positions —
// and the result reads afterwards as a chain with a gap in it, which is
// indistinguishable from a deleted receipt. Several guards run at once is
// the ordinary case, not the exotic one, so the layout has to make that
// safe rather than warn against it.
func guardReceiptsDir(override, session string) (string, govern.ChainStore, error) {
	base := override
	if base == "" {
		if d := defaultReceiptsDir(); d != "" {
			base = filepath.Join(d, guardLabel)
		}
	}
	if base == "" {
		// No home directory. The engine still governs; there is nowhere to
		// keep the evidence, and the banner says so.
		return "", nil, nil
	}
	dir := filepath.Join(base, session)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	return dir, &proxyChainStore{path: filepath.Join(dir, "chain.json")}, nil
}

func startGuardRoutes(routes []*guardRoute, dir string, store govern.ChainStore, opts guardOptions, g *guardSession) ([]*guardRoute, error) {
	var started []*guardRoute
	for _, r := range routes {
		name := r.name
		p, err := newLocalProxy(proxyOptions{
			Listen:   "127.0.0.1:0",
			Upstream: r.Upstream,
			Name:     name,
			Receipts: dir,
			Report:   opts.Report,
			label:    guardLabel,
			tool:     guardTool,
			store:    store,
			onDecision: func(res *govern.Result, d receipt.Direction) {
				g.note(name, res, d)
			},
			onUsage: func(model string, u usage.TokenUsage, metered bool) {
				g.noteUsage(model, u, metered)
			},
		})
		if err != nil {
			return started, fmt.Errorf("preparing %s: %w", r.Upstream, err)
		}
		r.proxy = p
		r.receipts = p.receiptsPath

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			p.close()
			r.proxy = nil
			return started, fmt.Errorf("listening for %s: %w", r.Upstream, err)
		}
		r.addr = ln.Addr().String()
		r.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
		go func(r *guardRoute) { _ = r.srv.Serve(ln) }(r)
		started = append(started, r)
	}
	return started, nil
}

func stopGuardRoutes(routes []*guardRoute) {
	for _, r := range routes {
		if r.srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = r.srv.Shutdown(ctx)
			cancel()
			r.srv = nil
		}
		if r.proxy != nil {
			r.proxy.close()
			r.proxy = nil
		}
	}
}

// guardEnv is the child's environment: everything this process has, with
// the routed variables replaced rather than added to.
func guardEnv(parent []string, routes []*guardRoute, session string) []string {
	replaced := map[string]string{guardMarker: session}
	for _, r := range routes {
		for _, v := range r.Vars {
			replaced[v] = "http://" + r.addr
		}
	}
	out := make([]string, 0, len(parent)+len(replaced))
	for _, kv := range parent {
		name, _, _ := strings.Cut(kv, "=")
		if _, ok := replaced[name]; ok {
			continue
		}
		out = append(out, kv)
	}
	for _, r := range routes {
		for _, v := range r.Vars {
			out = append(out, v+"=http://"+r.addr)
		}
	}
	out = append(out, guardMarker+"="+session)
	return out
}

func runGuardedCommand(path string, command []string, routes []*guardRoute, session string) (int, error) {
	cmd := exec.Command(path, command[1:]...)
	cmd.Env = guardEnv(os.Environ(), routes, session)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting %s: %w", command[0], err)
	}

	// Ctrl-C reaches the child from the terminal already, so forwarding it
	// would deliver it twice — and a tool where the first interrupt clears
	// the prompt and the second quits would quit on one keypress. A signal
	// sent to this process alone is a different thing and is passed on.
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == os.Interrupt {
					continue
				}
				if cmd.Process != nil {
					_ = cmd.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()

	err := cmd.Wait()
	close(done)
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return 0, fmt.Errorf("running %s: %w", command[0], err)
	}
	return 0, nil
}

func guardBanner(out io.Writer, opts guardOptions, routes []*guardRoute, dir string) {
	fmt.Fprintf(out, "\nlyntway guard: %s is running behind Lyntway\n\n", guardCommandLine(opts.Command))
	for _, r := range routes {
		how := "default"
		if r.Inherited {
			how = "yours, fronted"
		}
		fmt.Fprintf(out, "  %-10s %s → %s  (%s)\n", r.name, strings.Join(r.Vars, ", "), r.Upstream, how)
	}
	if dir == "" {
		fmt.Fprintf(out, "\n  receipts  none: this machine has no home directory to keep them in\n")
	} else {
		fmt.Fprintf(out, "\n  receipts  %s\n", dir)
	}
	if p := routes[0].proxy; p != nil {
		fmt.Fprintf(out, "  signed by %s\n", p.keyNote)
		switch {
		case p.reporter != nil:
			fmt.Fprintf(out, "  reporting classes and counts to %s, recorded there as attested; content stays here\n", p.reporter.c.Origin)
		case opts.Report:
			fmt.Fprintf(out, "  reporting nothing: this machine is not signed in (`lyntway login`)\n")
		default:
			fmt.Fprintf(out, "  reporting nothing (--report=false)\n")
		}
	}
	fmt.Fprintf(out, "\n")
}

func guardSummary(out io.Writer, g *guardSession, command string, code int, routes []*guardRoute, dir string, book priceBook) {
	g.mu.Lock()
	messages, saves := g.messages, append([]guardNotice(nil), g.saves...)
	byRoute := map[string]int{}
	for k, v := range g.byRoute {
		byRoute[k] = v
	}
	tokens := map[string]usage.TokenUsage{}
	for k, v := range g.tokens {
		tokens[k] = v
	}
	unmetered := g.unmetered
	g.mu.Unlock()

	fmt.Fprintf(out, "\nlyntway guard: %s exited (%d)\n\n", command, code)

	if messages == 0 {
		// Reported as a failure on purpose. Nothing arrived, so nothing was
		// governed, and a line reading "0 findings" would describe an
		// inspection that never happened.
		fmt.Fprintf(out, "  Nothing passed through Lyntway, so this run was NOT governed.\n\n")
		fmt.Fprintf(out, "  %s did not use the address it was given. It may read a different\n", command)
		fmt.Fprintf(out, "  setting, or authenticate in a way that ignores this one.\n\n")
		for _, r := range routes {
			fmt.Fprintf(out, "    %s %s set to http://%s\n",
				strings.Join(r.Vars, ", "), plural(len(r.Vars), "was", "were"), r.addr)
		}
		fmt.Fprintf(out, "\n  No receipts were written, because nothing was observed.\n\n")
		return
	}

	var parts []string
	for _, r := range routes {
		if n := byRoute[r.name]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", r.name, n))
		}
	}
	fmt.Fprintf(out, "  governed  %d %s (%s)\n", messages, plural(messages, "message", "messages"), strings.Join(parts, ", "))

	if len(saves) == 0 {
		fmt.Fprintf(out, "  withheld  nothing: no rule matched anything that passed\n")
	} else {
		fmt.Fprintf(out, "  withheld  %d %s\n", len(saves), plural(len(saves), "message", "messages"))
		for _, s := range saves {
			fmt.Fprintf(out, "            %s %s — %s · receipt %s\n",
				guardVerb(s.Decision), guardNoun(s.Direction),
				strings.Join(findingPhrases(s.Findings), ", "), s.Receipt)
		}
		if dir != "" {
			// Offered only when something was actually stopped. A share
			// prompt after a quiet session would be asking somebody to
			// publish a receipt that says nothing happened.
			fmt.Fprintf(out, "  share     lyntway share — a link anyone can check; nothing is uploaded\n")
		}
	}

	guardTokenLines(out, tokens, unmetered, book)

	if dir == "" {
		fmt.Fprintf(out, "\n")
		return
	}
	fmt.Fprintf(out, "  receipts  %s\n\n", dir)
	for _, r := range routes {
		if byRoute[r.name] == 0 || r.receipts == "" {
			continue
		}
		fmt.Fprintf(out, "  verify    lyntway-verify -chain -keys %s %s\n",
			filepath.Join(dir, "keys.json"), r.receipts)
	}
	fmt.Fprintf(out, "\n")
}

// guardTidy removes what a session did not fill in.
//
// A receipt file is opened when a listener starts, before anything is
// known to be coming, so a route the tool never used leaves a file named
// after a provider with nothing in it. Left there it reads as a session
// where that provider was reached and found clean, which is a different
// claim from the true one. And a session where nothing arrived at all
// leaves no evidence, so it leaves no directory either.
func guardTidy(dir string, routes []*guardRoute) {
	if dir == "" {
		return
	}
	for _, r := range routes {
		if r.receipts == "" {
			continue
		}
		if fi, err := os.Stat(r.receipts); err == nil && fi.Size() == 0 {
			_ = os.Remove(r.receipts)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			return
		}
	}
	_ = os.RemoveAll(dir)
}

// guardableApps names the software this command can wrap, read off the
// one table that already records which tool is documented to read which
// variable. A second list would drift from it, and an entry claiming a
// tool reads a setting it ignores is the overclaim this product exists not
// to make. OLLAMA_HOST is not among them: a model server on this machine
// is `lyntway proxy`'s job, and guard would front the wrong thing.
func guardableApps() map[string]bool {
	routed := map[string]bool{}
	for _, g := range guardGroups {
		for _, v := range g.Vars {
			routed[v] = true
		}
	}
	out := map[string]bool{}
	for _, v := range baseURLVars {
		if !routed[v.Name] {
			continue
		}
		for _, app := range v.Apps {
			out[app] = true
		}
	}
	return out
}

// guardSuggestion is the command to put in front of somebody, named after
// something actually on their machine. Empty when nothing we can wrap was
// found, because a suggestion to run a program they do not have reads as a
// tool that did not look.
func guardSuggestion(apps []aiApp) string {
	wrappable := guardableApps()
	running, installed := "", ""
	for _, a := range apps {
		if !wrappable[a.Name] {
			continue
		}
		var bin string
		for _, d := range aiApps {
			if d.Name == a.Name && len(d.Bins) > 0 {
				bin = d.Bins[0]
				break
			}
		}
		if bin == "" {
			continue
		}
		if a.Running && running == "" {
			running = bin
		}
		if installed == "" {
			installed = bin
		}
	}
	if running != "" {
		return running
	}
	return installed
}

// guardTokenLines prints what the session cost, which is the part somebody
// reads on a day when nothing was withheld.
//
// Tokens first and always: they are the provider's own figure and need no
// configuration. The money line appears only where a price exists, is
// named as an estimate at a price the reader entered, and says which
// models it left out — a total standing alone beside unpriced models would
// be read as the whole bill.
func guardTokenLines(out io.Writer, tokens map[string]usage.TokenUsage, unmetered int, book priceBook) {
	if len(tokens) == 0 && unmetered == 0 {
		return
	}

	var total usage.TokenUsage
	models := make([]string, 0, len(tokens))
	for m, u := range tokens {
		total.Input += u.Input
		total.Output += u.Output
		models = append(models, m)
	}
	sort.Slice(models, func(i, j int) bool {
		a, b := tokens[models[i]], tokens[models[j]]
		if a.Input+a.Output != b.Input+b.Output {
			return a.Input+a.Output > b.Input+b.Output
		}
		return models[i] < models[j]
	})

	if len(tokens) > 0 {
		fmt.Fprintf(out, "  tokens    %s in, %s out, as the provider reported them\n",
			thousands(total.Input), thousands(total.Output))
		for _, m := range models {
			u := tokens[m]
			fmt.Fprintf(out, "            %-34s %9s in %9s out\n", displayModel(m), thousands(u.Input), thousands(u.Output))
		}
	}
	if unmetered > 0 {
		// Named rather than folded in. A reply that reported nothing is
		// not a reply that cost nothing.
		fmt.Fprintf(out, "            %d %s reported no figure, so %s not in the totals\n",
			unmetered, plural(unmetered, "reply", "replies"), plural(unmetered, "it is", "they are"))
	}

	cost, priced := costOf(book, tokens)
	if !priced {
		if len(tokens) > 0 {
			fmt.Fprintf(out, "  cost      no price set for %s — add one with --price %s=IN/OUT\n",
				plural(len(models), "this model", "these models"), models[0])
		}
		return
	}
	currency := cost.Currency
	if currency != "" {
		currency += " "
	}
	fmt.Fprintf(out, "  cost      %s%s — %s\n", currency, strconv.FormatFloat(cost.Amount, 'f', -1, 64), usage.EstimateBasis)
	if len(cost.Unpriced) > 0 {
		fmt.Fprintf(out, "            not included: %s — no price set\n", strings.Join(cost.Unpriced, ", "))
	}
}

// thousands groups a count so a six-figure token total can be read at a
// glance. A number somebody has to count the digits of is a number they
// skip.
func thousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}
