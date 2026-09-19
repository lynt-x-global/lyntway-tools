package main

// Checks the endpoints this account's AI traffic actually reached, by asking
// each one what it answers with no credential at all.
//
// # Why this is not a scanner
//
// A scanner discovers an API by crawling it or by being handed a
// specification, and both describe the endpoints somebody wrote down. The
// list this reads comes from receipts: it is where calls actually went.
// That is the only input here that cannot be bought elsewhere, and it is
// why a check this small finds things a crawl does not.
//
// # Why it runs here and not on the service
//
// Sending an unauthenticated request to somebody's API is an act, not an
// observation. Done from our infrastructure it would be us touching a
// system we were not standing in front of, against a host a caller named —
// the shape of every server-side request forgery. Run from the operator's
// own machine, against hosts they listed themselves, it is the operator
// checking their own estate, which is what it should have been all along.
//
// # What it refuses to do
//
//   - Any method that is not GET, HEAD or OPTIONS. A replayed POST can
//     create an order, send an email or charge a card; "we were only
//     testing" is not a defence anybody accepts afterwards.
//   - Any host the operator did not name. There is no discovery mode and
//     no "scan everything I saw": the scope is typed, every time.
//   - Any path still carrying a template segment, because {id} is not an
//     address and asking for it literally tests nothing.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// errScopeRequired is returned by every exit that finds no scope, so the
// signed-in and not-signed-in paths cannot drift apart again. They did:
// signed in, a missing --scope failed; not signed in, the same command
// exited 0.
var errScopeRequired = errors.New("--scope is required: name the hosts you are authorised to check")

// safeMethods are the ones a request can repeat without changing anything,
// by convention every HTTP implementation follows. Nothing else is sent.
var safeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

// probePause keeps the check to a walking pace. An endpoint that answers
// slowly is somebody's production system, and a readiness check that reads
// like a burst of traffic is a readiness check somebody blocks.
const probePause = 300 * time.Millisecond

// probeTimeout bounds one request. A hung endpoint is reported as such
// rather than holding the whole run.
const probeTimeout = 10 * time.Second

type surfaceEndpoint struct {
	Surface     string           `json:"surface"`
	Destination string           `json:"destination"`
	Method      string           `json:"method,omitempty"`
	Target      string           `json:"target,omitempty"`
	Calls       int64            `json:"calls"`
	Actors      []string         `json:"actors,omitempty"`
	Findings    map[string]int64 `json:"findings,omitempty"`
	FirstSeen   string           `json:"first_seen"`
	LastSeen    string           `json:"last_seen"`
}

type surfaceDoc struct {
	Endpoints  []surfaceEndpoint `json:"endpoints"`
	EventsRead int               `json:"events_read"`
	Oldest     string            `json:"oldest,omitempty"`
	Newest     string            `json:"newest,omitempty"`
	Note       string            `json:"note"`
}

// probeResult is what one endpoint answered, and what that means.
type probeResult struct {
	Endpoint string `json:"endpoint"`
	Host     string `json:"host"`
	Status   int    `json:"status,omitempty"`
	Verdict  string `json:"verdict"`
	Detail   string `json:"detail,omitempty"`
}

const (
	verdictOpen      = "answered without a credential"
	verdictProtected = "asked for a credential"
	verdictOther     = "answered something else"
	verdictSkipped   = "not checked"
	verdictError     = "could not be reached"
)

func readiness(args []string) error {
	fs := flag.NewFlagSet("readiness", flag.ExitOnError)
	var scope string
	var jsonOut bool
	var dry bool
	fs.StringVar(&scope, "scope", "", "comma-separated hosts you are authorised to check (required)")
	fs.BoolVar(&jsonOut, "json", false, "write the result as JSON instead of a table")
	fs.BoolVar(&dry, "dry-run", false, "list what would be checked and send nothing")
	var plain bool
	fs.BoolVar(&plain, "http", false, "reach the hosts in scope over http, for an internal API that is not on TLS")
	var offline bool
	fs.BoolVar(&offline, "offline", false, "skip the vulnerability database, so nothing leaves this machine")
	var skipDeps bool
	fs.BoolVar(&skipDeps, "no-deps", false, "do not read this project's dependencies")
	var failOnNew bool
	fs.BoolVar(&failOnNew, "fail-on-new", false, "exit non-zero when something got worse since the last run, for a pipeline")
	var sign bool
	fs.BoolVar(&sign, "sign", false, "write the run to a file and have it signed, so it can be handed to somebody who trusts neither party")
	var out string
	fs.StringVar(&out, "out", "", "write the run to this file as JSON; --sign also registers it")
	var statePath string
	fs.StringVar(&statePath, "state", "", "where to remember this run, for a machine that starts fresh each time")
	var upload bool
	fs.BoolVar(&upload, "upload", false, "send the report to your account, so every project's last run is in one place")
	var mcpTargets string
	fs.StringVar(&mcpTargets, "mcp", "", "comma-separated MCP server URLs to check for agent readiness; naming one is the authorisation to check it")
	var mcpTokenEnv string
	fs.StringVar(&mcpTokenEnv, "mcp-token-env", "", "name of an environment variable holding a bearer token, to read tools a server keeps behind a credential")
	var docsTargets string
	fs.StringVar(&docsTargets, "docs", "", "comma-separated public documentation URLs to check for agent readiness")
	_ = fs.Parse(flagsFirst(fs, args))

	// Dependencies first, because reading a lockfile needs no account and
	// no permission. Somebody who has not signed in still gets half a
	// readiness report rather than an error.
	snap := readinessSnapshot{Version: snapshotVersion, TakenAt: time.Now().UTC().Format(time.RFC3339), Dir: "."}
	previous, hadPrevious := loadSnapshot(".", statePath)

	// Every way out of this function ends here. The first version had three
	// exits and only one of them saved, so a machine that was not signed in
	// ran the dependency half and then forgot it — which is precisely the
	// case that half exists for.
	var basis surfaceDoc
	var signedIn *config

	finish := func() error {
		changes := diffSnapshots(previous, snap)
		worse := reportChange(previous, snap, hadPrevious)
		if err := saveSnapshot(snap, statePath); err != nil {
			fmt.Fprintf(stdout, "  ~ could not remember this run: %v\n", err)
		}
		// A report is written whenever somebody asked for one. Signing is
		// the extra step, and it is the only part that needs an account.
		target := out
		if target == "" && (sign || upload) {
			target = "lyntway-readiness.json"
		}
		if target != "" {
			rep := buildReport(snap, changes, basis, snap.EndpointsChecked)
			digest, size, err := writeReport(rep, target)
			switch {
			case err != nil:
				fmt.Fprintf(stdout, "\n  ~ the report was not written: %v\n", err)
			case !sign:
				fmt.Fprintf(stdout, "\n  ✓ %s  (%d bytes)\n", target, size)
			case signedIn == nil:
				// Said plainly rather than leaving somebody to wonder why a
				// flag they passed did nothing.
				fmt.Fprintf(stdout, "\n  ✓ %s  (%d bytes)\n", target, size)
				fmt.Fprintln(stdout, "  ~ not signed in, so it was not registered. Run lyntway login first.")
			default:
				fmt.Fprintln(stdout)
				if err := signReport(*signedIn, target, digest, size); err != nil {
					fmt.Fprintf(stdout, "  ~ the report was written but not registered: %v\n", err)
				}
			}
			// Uploading is its own decision: the report names your
			// endpoints and packages, and sending it somewhere is a
			// disclosure even when the somewhere is your own account.
			if upload && err == nil {
				if signedIn == nil {
					fmt.Fprintln(stdout, "  ~ not signed in, so nothing was reported. Run lyntway login first.")
				} else if uerr := uploadReport(*signedIn, target); uerr != nil {
					fmt.Fprintf(stdout, "  ~ the report was not sent: %v\n", uerr)
				}
			}
		}
		if failOnNew && worse > 0 {
			return fmt.Errorf("%d finding(s) got worse since the last run", worse)
		}
		return nil
	}

	// Agent readiness next, because it too needs no account: the operator
	// typed each address, and that is the whole of the authorisation.
	agentsNamed := mcpTargets != "" || docsTargets != ""
	if agentsNamed {
		targets, err := runAgentChecks(splitList(mcpTargets), splitList(docsTargets), mcpTokenEnv, dry)
		if err != nil {
			return err
		}
		if !dry {
			snap.Agents = targets
			snap.AgentsChecked = true
		}
	}

	if !skipDeps {
		states, err := reportDependencies(".", offline)
		if err != nil {
			fmt.Fprintf(stdout, "\n  ~ dependencies were not checked: %v\n", err)
		} else if states != nil {
			snap.Deps = states
			snap.DepsChecked = true
		}
	}

	c, err := loadConfig()
	if err != nil {
		fmt.Fprintln(stdout, "\nNot signed in, so the endpoints your AI reached were not read. "+
			"Run lyntway login to include them.")
		// A required flag is still missing when there was nothing to point
		// it at. The half that needs no scope has run and finish() saves
		// it, but the exit code has to say the command was not given what
		// it asks for — otherwise a nightly job whose token has expired
		// checks nothing, exits 0, and the pipeline stays green while a
		// security team believes readiness is running every night.
		if ferr := finish(); ferr != nil {
			return ferr
		}
		// Naming a server to check is being given something to do, so a
		// run that did only that has not been handed an empty scope.
		if len(hostSet(scope)) == 0 && !agentsNamed {
			return errScopeRequired
		}
		return nil
	}

	status, raw, err := api(c, http.MethodGet, "/v1/surface", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("reading the observed surface: %s", apiMessage(status, raw))
	}
	var doc surfaceDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("reading the observed surface: %w", err)
	}
	basis = doc
	signedIn = &c

	fmt.Fprintf(stdout, "\nObserved surface: %d endpoint(s) from %d recorded event(s)",
		len(doc.Endpoints), doc.EventsRead)
	if doc.Oldest != "" {
		fmt.Fprintf(stdout, ", %s to %s", doc.Oldest, doc.Newest)
	}
	fmt.Fprintln(stdout, ".")
	fmt.Fprintln(stdout, "Anything that never reached Lyntway is not in this list, which is not the same as not in your estate.")

	// The scope is typed, every time. Without it there is nothing to check
	// and the right answer is to say so rather than to pick a default.
	allowed := hostSet(scope)
	if len(allowed) == 0 && agentsNamed {
		fmt.Fprintln(stdout, "No --scope was given, so none of these endpoints was checked; the servers named with --mcp or --docs were.")
		return finish()
	}
	if len(allowed) == 0 {
		fmt.Fprintln(stdout, "\nHosts seen, none checked — name the ones you are authorised to check with --scope:")
		for _, h := range hostsOf(doc.Endpoints) {
			fmt.Fprintf(stdout, "  %s\n", h)
		}
		fmt.Fprintln(stdout, "\nName the hosts you are authorised to check with --scope to include the endpoints above.")
		finish()
		return errScopeRequired
	}

	// https unless the operator says otherwise. Guessing per host would
	// mean a downgrade nobody asked for; the flag makes it a decision.
	scheme := "https"
	if plain {
		scheme = "http"
	}
	plan, skipped := planProbes(doc.Endpoints, allowed, scheme)
	for _, s := range skipped {
		fmt.Fprintf(stdout, "  · %-46s %s\n", s.Endpoint, s.Detail)
	}
	if len(plan) == 0 {
		fmt.Fprintln(stdout, "\nNothing to check: no endpoint in the observed surface is both in scope and safe to repeat.")
		return finish()
	}
	if dry {
		fmt.Fprintf(stdout, "\nWould check %d endpoint(s), sending nothing:\n", len(plan))
		for _, p := range plan {
			fmt.Fprintf(stdout, "  %s\n", p.Endpoint)
		}
		return nil
	}

	fmt.Fprintf(stdout, "\nChecking %d endpoint(s) with no credential attached…\n\n", len(plan))
	results := make([]probeResult, 0, len(plan))
	for i, p := range plan {
		if i > 0 {
			time.Sleep(probePause)
		}
		res := probeEndpoint(p)
		results = append(results, res)
		mark := " "
		if res.Verdict == verdictOpen {
			mark = "!"
		}
		fmt.Fprintf(stdout, "  %s %-46s %s\n", mark, res.Endpoint, describeResult(res))
	}

	if jsonOut {
		out, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(out))
		return nil
	}

	open := 0
	for _, r := range results {
		if r.Verdict == verdictOpen {
			open++
		}
	}
	fmt.Fprintln(stdout)
	switch open {
	case 0:
		fmt.Fprintln(stdout, "Every endpoint checked asked for a credential.")
	case 1:
		fmt.Fprintln(stdout, "1 endpoint answered without a credential. Anyone who knows the address can call it.")
	default:
		fmt.Fprintf(stdout, "%d endpoints answered without a credential. Anyone who knows the address can call them.\n", open)
	}
	fmt.Fprintln(stdout, "This is a check of authentication only. It is not a penetration test, and it does not"+
		"\nreplace one — it is what an assessor would otherwise spend their first day finding.")

	for _, r := range results {
		snap.Endpoints = append(snap.Endpoints, endpointState{
			Endpoint: r.Endpoint, Verdict: r.Verdict, Status: r.Status,
		})
	}
	snap.EndpointsChecked = true

	return finish()
}

// planProbes splits the observed surface into what will be checked and what
// will not, with the reason attached to each thing left out.
func planProbes(endpoints []surfaceEndpoint, allowed map[string]bool, scheme string) (plan, skipped []probeResult) {
	for _, ep := range endpoints {
		method, path, ok := splitMethodPath(ep.Method)
		label := ep.Destination
		if ep.Method != "" {
			label = ep.Method + " on " + ep.Destination
		}
		item := probeResult{Endpoint: label, Host: ep.Destination, Verdict: verdictSkipped}

		switch {
		case !allowed[ep.Destination]:
			item.Detail = "not in scope"
		case !ok:
			item.Detail = "no method and path recorded, so there is nothing to ask for"
		case !safeMethods[method]:
			item.Detail = method + " changes things; only GET, HEAD and OPTIONS are repeated"
		case strings.ContainsAny(path, "{}"):
			item.Detail = "path is a template, and {id} is not an address"
		default:
			plan = append(plan, probeResult{Endpoint: label, Host: ep.Destination,
				Detail: method + " " + scheme + "://" + ep.Destination + path})
			continue
		}
		skipped = append(skipped, item)
	}
	return plan, skipped
}

// probeEndpoint sends one request with nothing attached and reports what
// came back. No credential, no cookie, and a user agent that says who this
// is, so whoever reads their own logs tomorrow can tell what it was.
func probeEndpoint(p probeResult) probeResult {
	fields := strings.SplitN(p.Detail, " ", 2)
	if len(fields) != 2 {
		p.Verdict = verdictError
		p.Detail = "could not build the request"
		return p
	}
	method, target := fields[0], fields[1]

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return probeResult{Endpoint: p.Endpoint, Host: p.Host, Verdict: verdictError, Detail: err.Error()}
	}
	req.Header.Set("User-Agent", "lyntway-readiness/"+version+" (authentication check; no credential attached)")

	// Redirects are not followed. An API that sends a caller with no key to
	// a sign-in page answers 302; followed, the sign-in page's 200 read as
	// "answered without a credential" — an open endpoint that was nothing
	// of the kind, and the one verdict this check must never overstate.
	client := &http.Client{
		Timeout:       probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return probeResult{Endpoint: p.Endpoint, Host: p.Host, Verdict: verdictError, Detail: err.Error()}
	}
	defer resp.Body.Close()

	out := probeResult{Endpoint: p.Endpoint, Host: p.Host, Status: resp.StatusCode}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		out.Verdict = verdictProtected
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		out.Verdict = verdictOpen
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		out.Verdict = verdictOther
		if loc := resp.Header.Get("Location"); loc != "" {
			out.Detail = "redirected to " + loc
		}
	default:
		// A 404 or a 405 is not a pass. It means this address did not
		// answer, which says nothing about whether the endpoint behind it
		// checks credentials.
		out.Verdict = verdictOther
	}
	return out
}

func describeResult(r probeResult) string {
	switch r.Verdict {
	case verdictOpen:
		return fmt.Sprintf("%d — answered with no credential", r.Status)
	case verdictProtected:
		return fmt.Sprintf("%d — asked for a credential", r.Status)
	case verdictOther:
		if r.Detail != "" {
			return fmt.Sprintf("%d — %s, not conclusive either way", r.Status, r.Detail)
		}
		return fmt.Sprintf("%d — not conclusive either way", r.Status)
	case verdictError:
		return "could not be reached: " + r.Detail
	}
	return r.Detail
}

// splitMethodPath reads the recorded "GET /v1/orders" form. Anything else,
// including an MCP method name with no path, is reported as unusable rather
// than guessed at.
func splitMethodPath(recorded string) (method, path string, ok bool) {
	parts := strings.Fields(recorded)
	if len(parts) != 2 {
		return "", "", false
	}
	method = strings.ToUpper(parts[0])
	path = parts[1]
	if !strings.HasPrefix(path, "/") {
		return "", "", false
	}
	return method, path, true
}

func hostSet(scope string) map[string]bool {
	out := map[string]bool{}
	for _, h := range strings.Split(scope, ",") {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			continue
		}
		// A host typed with a scheme is what everybody types. Take the host
		// out of it rather than refusing a reasonable thing.
		if u, err := url.Parse(h); err == nil && u.Host != "" {
			h = u.Host
		}
		out[h] = true
	}
	return out
}

func hostsOf(endpoints []surfaceEndpoint) []string {
	seen := map[string]bool{}
	var out []string
	for _, ep := range endpoints {
		if ep.Destination == "" || seen[ep.Destination] {
			continue
		}
		seen[ep.Destination] = true
		out = append(out, ep.Destination)
	}
	sort.Strings(out)
	return out
}
