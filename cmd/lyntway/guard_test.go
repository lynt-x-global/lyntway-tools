package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// guard is a wrapper, so every test here runs the real thing: a real
// child process, a real listener, a real upstream. The defects a wrapper
// has are all at the seams — which variable was set, what the child
// inherited, what the exit code was, whether anything arrived at all —
// and none of them is visible from inside a unit.

// A key of ours, assembled so the literal is not itself a finding in this
// file. The rule that matches it was added on 18 October 2026.
const testLyntwayKey = "lynt_sk_" + "k3mq7x2vbn4rtyuiopasdfghjkzxcvb2"

// guardChildEnv names the mode the re-executed test binary runs in.
const guardChildEnv = "LYNTWAY_GUARD_TEST_CHILD"

// TestGuardChild is not a test. It is the program `guard` runs, re-entered
// through the test binary so there is a real child process without needing
// a toolchain to build one.
func TestGuardChild(t *testing.T) {
	mode := os.Getenv(guardChildEnv)
	if mode == "" {
		t.Skip("not the child process")
	}
	switch mode {
	case "post":
		base := os.Getenv("ANTHROPIC_BASE_URL")
		resp, err := http.Post(base+"/v1/messages", "application/json",
			strings.NewReader(`{"messages":[{"content":"deploy with `+testLyntwayKey+`"}]}`))
		if err != nil {
			fmt.Println("CHILD-ERROR", err)
			os.Exit(9)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("CHILD-STATUS %d %s\n", resp.StatusCode, body)
	case "clean":
		base := os.Getenv("ANTHROPIC_BASE_URL")
		resp, err := http.Post(base+"/v1/messages", "application/json",
			strings.NewReader(`{"messages":[{"content":"hello"}]}`))
		if err != nil {
			fmt.Println("CHILD-ERROR", err)
			os.Exit(9)
		}
		resp.Body.Close()
	case "ignore":
		// A tool that reads some other setting, which is the case this
		// command has to be honest about.
	case "env":
		for _, v := range []string{"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE", guardMarker} {
			fmt.Printf("ENV %s=%s\n", v, os.Getenv(v))
		}
	}
	os.Exit(7)
}

// guardChild is the command line that re-enters this binary.
func guardChild(mode string) []string {
	return []string{os.Args[0], "-test.run=TestGuardChild", "-test.v=false"}
}

func withGuardChild(t *testing.T, mode string) {
	t.Helper()
	t.Setenv(guardChildEnv, mode)
}

func runGuardTest(t *testing.T, opts guardOptions) (string, int, error) {
	t.Helper()
	var out bytes.Buffer
	code, err := runGuard(opts, &out)
	return out.String(), code, err
}

// A variable somebody has already set points their tool at a provider they
// chose. Overwriting it would send their next request to a service they
// did not pick, with a key that is not for it — so the value is fronted,
// and no alias they had not set is introduced alongside it.
func TestAVariableYouAlreadySetIsFrontedAndItsAliasesAreLeftAlone(t *testing.T) {
	env := map[string]string{"OPENAI_BASE_URL": "https://api.groq.com/openai/v1"}
	routes, err := guardRoutes(func(k string) string { return env[k] }, nil)
	if err != nil {
		t.Fatal(err)
	}

	var openai *guardRoute
	for _, r := range routes {
		for _, v := range r.Vars {
			if v == "OPENAI_API_BASE" {
				t.Fatalf("OPENAI_API_BASE was introduced pointing at %s; the tool may read it before OPENAI_BASE_URL and reach a provider the user did not choose", r.Upstream)
			}
			if v == "OPENAI_BASE_URL" {
				openai = r
			}
		}
	}
	if openai == nil {
		t.Fatal("OPENAI_BASE_URL was not routed at all")
	}
	if openai.Upstream != "https://api.groq.com/openai/v1" {
		t.Errorf("fronting %s, want the value the user had set", openai.Upstream)
	}
	if !openai.Inherited {
		t.Error("the route does not know it came from the environment, so the banner will claim we redirected them")
	}
}

func TestWithNothingSetTheDefaultsAreUsedForEveryAlias(t *testing.T) {
	routes, err := guardRoutes(func(string) string { return "" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range routes {
		for _, v := range r.Vars {
			got[v] = r.Upstream
		}
	}
	want := map[string]string{
		"ANTHROPIC_BASE_URL": "https://api.anthropic.com",
		"OPENAI_BASE_URL":    "https://api.openai.com/v1",
		"OPENAI_API_BASE":    "https://api.openai.com/v1",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s → %q, want %q", k, got[k], v)
		}
	}
	if len(routes) != 2 {
		t.Errorf("%d listeners for two providers; the aliases should share one", len(routes))
	}
	for _, r := range routes {
		if r.Inherited {
			t.Errorf("route %s claims the user set it", r.name)
		}
	}
}

func TestSetReplacesAGroupsVariableAndNamesTheProvider(t *testing.T) {
	routes, err := guardRoutes(func(string) string { return "" },
		[]string{"ANTHROPIC_BASE_URL=https://api.anthropic.com"})
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	for _, r := range routes {
		for _, v := range r.Vars {
			if v == "ANTHROPIC_BASE_URL" {
				seen++
				if r.name != "anthropic" {
					t.Errorf("route named %q, want anthropic: a chain id should read as a provider, not a hostname", r.name)
				}
			}
		}
	}
	if seen != 1 {
		t.Errorf("ANTHROPIC_BASE_URL appears on %d routes; --set must replace the group's entry, not add to it", seen)
	}
}

func TestAnUnparseableSettingIsRefusedRatherThanCorrected(t *testing.T) {
	env := map[string]string{"ANTHROPIC_BASE_URL": "not-a-url"}
	_, err := guardRoutes(func(k string) string { return env[k] }, nil)
	if err == nil {
		t.Fatal("a setting we cannot parse was accepted")
	}
	if !strings.Contains(err.Error(), "ANTHROPIC_BASE_URL") {
		t.Errorf("the error does not name the variable: %v", err)
	}
}

// The child's environment must be replaced, not appended to: an exported
// variable that survived alongside ours is read by whichever the tool
// looks up first, and the answer would be arbitrary.
func TestTheChildsEnvironmentReplacesTheVariablesItRoutes(t *testing.T) {
	routes := []*guardRoute{{Vars: []string{"ANTHROPIC_BASE_URL"}, addr: "127.0.0.1:1234"}}
	env := guardEnv([]string{"PATH=/bin", "ANTHROPIC_BASE_URL=https://api.anthropic.com", "HOME=/home/x"}, routes, "s1")

	var anthropic []string
	for _, kv := range env {
		if strings.HasPrefix(kv, "ANTHROPIC_BASE_URL=") {
			anthropic = append(anthropic, kv)
		}
	}
	if len(anthropic) != 1 {
		t.Fatalf("ANTHROPIC_BASE_URL appears %d times: %v", len(anthropic), anthropic)
	}
	if anthropic[0] != "ANTHROPIC_BASE_URL=http://127.0.0.1:1234" {
		t.Errorf("child got %q", anthropic[0])
	}
	if !hasEnv(env, "PATH=/bin") || !hasEnv(env, "HOME=/home/x") {
		t.Error("the rest of the environment did not survive")
	}
	if !hasEnv(env, guardMarker+"=s1") {
		t.Error("the child was not marked, so a guard inside it would nest")
	}
}

func hasEnv(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestGuardRefusesToNestInsideItself(t *testing.T) {
	proxyHome(t)
	t.Setenv(guardMarker, "20261018-000000-aaaaaa")
	_, _, err := runGuardTest(t, guardOptions{Command: []string{"true"}})
	if err == nil {
		t.Fatal("a nested guard was allowed: its listener would forward to the outer one and govern everything twice")
	}
}

// End to end: a real child, a real listener, a real block. The key the
// child pastes is one of ours, which until 18 October 2026 this ruleset
// could not see.
func TestGuardGovernsTheChildsTrafficAndKeepsItsExitCode(t *testing.T) {
	proxyHome(t)
	withGuardChild(t, "post")
	var reached bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		fmt.Fprint(w, `{"content":[{"text":"ok"}]}`)
	}))
	defer upstream.Close()

	out, code, err := runGuardTest(t, guardOptions{
		Set:     []string{"ANTHROPIC_BASE_URL=" + upstream.URL, "OPENAI_BASE_URL=" + upstream.URL, "OPENAI_API_BASE=" + upstream.URL},
		Report:  false,
		Quiet:   true,
		Command: guardChild("post"),
	})
	if err != nil {
		t.Fatalf("runGuard: %v\n%s", err, out)
	}
	if code != 7 {
		t.Errorf("exit code %d, want the child's 7: a wrapper that eats the exit code breaks every script it is put in front of", code)
	}
	if reached {
		t.Error("the request reached the upstream; it carried one of our own keys and should have been stopped here")
	}
	if !strings.Contains(out, "secret.lyntway_key") {
		t.Errorf("the summary does not name what was withheld:\n%s", out)
	}
	if !strings.Contains(out, "stopped request") {
		t.Errorf("the summary does not say the request was stopped:\n%s", out)
	}
}

// A run where nothing arrived was not governed, and saying "0 findings"
// would describe an inspection that never happened. This is the check that
// tells somebody their tool ignored the address — the single most likely
// way for this command to be useless without anybody noticing.
func TestNothingPassingThroughIsReportedAsAFailureNotACleanRun(t *testing.T) {
	proxyHome(t)
	withGuardChild(t, "ignore")
	out, code, err := runGuardTest(t, guardOptions{
		Report: false, Quiet: true, Command: guardChild("ignore"),
	})
	if err != nil {
		t.Fatalf("runGuard: %v\n%s", err, out)
	}
	if code != 7 {
		t.Errorf("exit code %d, want 7", code)
	}
	if !strings.Contains(out, "NOT governed") {
		t.Errorf("a run that saw nothing did not say so:\n%s", out)
	}
	if strings.Contains(out, "nothing sensitive") || strings.Contains(out, "withheld  nothing") {
		t.Errorf("a run that saw nothing reported a clean inspection:\n%s", out)
	}
	// And it left no directory behind implying it had kept evidence.
	base := filepath.Join(defaultReceiptsDir(), guardLabel)
	if entries, err := os.ReadDir(base); err == nil && len(entries) != 0 {
		t.Errorf("%d session directories left behind for a run with no traffic", len(entries))
	}
}

// If a listener cannot be prepared, the command does not run. A wrapper
// that quietly degrades into exec is worse than none: the person believes
// they were covered on exactly the run where they were not.
func TestTheCommandDoesNotRunWhenAListenerCannotBePrepared(t *testing.T) {
	proxyHome(t)
	marker := filepath.Join(t.TempDir(), "ran")
	_, _, err := runGuardTest(t, guardOptions{
		Set:     []string{"ANTHROPIC_BASE_URL=ftp://example.invalid"},
		Report:  false,
		Command: []string{"touch", marker},
	})
	if err == nil {
		t.Fatal("an unroutable upstream was accepted")
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("the command ran anyway, unguarded, while reporting an error")
	}
}

// Two sessions at once must not share a chain. They did not before this
// command existed, because the proxy holds a fixed port and only one can
// bind it; guard binds an ephemeral port, so running several is ordinary.
// A shared chain file loses one writer's position, and the result reads
// later as a gap — indistinguishable from a deleted receipt.
func TestConcurrentSessionsDoNotShareAChain(t *testing.T) {
	proxyHome(t)
	withGuardChild(t, "clean")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"content":[{"text":"ok"}]}`)
	}))
	defer upstream.Close()

	var dirs []string
	for i := 0; i < 2; i++ {
		out, _, err := runGuardTest(t, guardOptions{
			Set:     []string{"ANTHROPIC_BASE_URL=" + upstream.URL},
			Report:  false,
			Quiet:   true,
			Command: guardChild("clean"),
		})
		if err != nil {
			t.Fatalf("run %d: %v\n%s", i, err, out)
		}
		dirs = append(dirs, out)
	}

	base := filepath.Join(defaultReceiptsDir(), guardLabel)
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("reading %s: %v", base, err)
	}
	if len(entries) != 2 {
		t.Fatalf("%d session directories for two runs; sessions are sharing state", len(entries))
	}
	for _, e := range entries {
		chain := filepath.Join(base, e.Name(), "chain.json")
		raw, err := os.ReadFile(chain)
		if err != nil {
			t.Fatalf("no chain file in %s: %v", e.Name(), err)
		}
		var cf struct {
			Chains map[string]struct {
				NextSeq uint64 `json:"next_seq"`
			} `json:"chains"`
		}
		if err := json.Unmarshal(raw, &cf); err != nil {
			t.Fatal(err)
		}
		if len(cf.Chains) != 1 {
			t.Errorf("session %s holds %d chains", e.Name(), len(cf.Chains))
		}
		for id, pos := range cf.Chains {
			if !strings.HasPrefix(id, guardLabel+"/") {
				t.Errorf("chain %q is not labelled as a guard session, so it could be read as a standalone proxy's", id)
			}
			if pos.NextSeq != 2 {
				t.Errorf("chain %s holds %d receipts, want 2 (one request, one reply)", id, pos.NextSeq)
			}
		}
	}
}

// A session's receipts verify with the binary anyone can download, using
// the key file published beside them.
func TestAGuardSessionVerifiesWithLyntwayVerify(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH to build lyntway-verify")
	}
	proxyHome(t)
	withGuardChild(t, "clean")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"content":[{"text":"ok"}]}`)
	}))
	defer upstream.Close()

	out, _, err := runGuardTest(t, guardOptions{
		Set:     []string{"ANTHROPIC_BASE_URL=" + upstream.URL},
		Report:  false,
		Quiet:   true,
		Command: guardChild("clean"),
	})
	if err != nil {
		t.Fatalf("runGuard: %v\n%s", err, out)
	}

	base := filepath.Join(defaultReceiptsDir(), guardLabel)
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 1 {
		t.Fatalf("one session expected in %s: %v %v", base, entries, err)
	}
	dir := filepath.Join(base, entries[0].Name())
	receipts, err := filepath.Glob(filepath.Join(dir, "guard-*.jsonl"))
	if err != nil || len(receipts) != 1 {
		t.Fatalf("one receipt file expected in %s: %v", dir, receipts)
	}

	bin := filepath.Join(t.TempDir(), "lyntway-verify")
	if b, err := exec.Command("go", "build", "-o", bin, "../lyntway-verify").CombinedOutput(); err != nil {
		t.Fatalf("building lyntway-verify: %v\n%s", err, b)
	}
	verified, err := exec.Command(bin, "-chain", "-json", "-keys", filepath.Join(dir, "keys.json"), receipts[0]).CombinedOutput()
	if err != nil {
		t.Fatalf("the session did not verify: %v\n%s", err, verified)
	}
	var result struct {
		Valid       bool   `json:"valid"`
		ChainID     string `json:"chain_id"`
		ChainLength int    `json:"chain_length"`
	}
	if err := json.Unmarshal(verified, &result); err != nil {
		t.Fatalf("verifier output is not JSON: %s", verified)
	}
	if !result.Valid || result.ChainLength != 2 || !strings.HasPrefix(result.ChainID, guardLabel+"/") {
		t.Errorf("verifier: %+v\n%s", result, verified)
	}
	// The command printed is the one that works. A verify line nobody can
	// paste is worse than no verify line.
	if !strings.Contains(out, "lyntway-verify -chain -keys "+filepath.Join(dir, "keys.json")) {
		t.Errorf("the summary's verify command does not match the files on disk:\n%s", out)
	}
}

// The message the tool prints is the only part of this product most people
// will ever read. "withheld by policy" names no cause; the reader cannot
// tell a detection from a bug.
func TestARefusalNamesWhatItWithheldAndWhereItWasNotSent(t *testing.T) {
	proxyHome(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the upstream was reached")
	}))
	defer upstream.Close()
	base, _ := startProxy(t, upstream.URL, proxyOptions{Name: "anthropic", Report: false})

	resp, err := http.Post(base+"/v1/messages", "application/json",
		strings.NewReader(`{"messages":[{"content":"key `+testLyntwayKey+`"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	var e struct {
		Error struct {
			Message string `json:"message"`
			Source  string `json:"source"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Lyntway key", "secret.lyntway_key", "Nothing was sent"} {
		if !strings.Contains(e.Error.Message, want) {
			t.Errorf("the refusal does not say %q: %q", want, e.Error.Message)
		}
	}
	if strings.Contains(e.Error.Message, testLyntwayKey) {
		t.Errorf("the refusal repeated the secret back: %q", e.Error.Message)
	}
}

// A command that does not exist is the commonest mistake there is. It must
// be answered before a banner claims a session started and before a
// directory is created that implies one did.
func TestAMissingCommandIsAnsweredBeforeAnySessionIsStarted(t *testing.T) {
	proxyHome(t)
	out, _, err := runGuardTest(t, guardOptions{
		Report: false, Command: []string{"lyntway-no-such-command-here"},
	})
	if err == nil {
		t.Fatal("a command that does not exist was accepted")
	}
	if out != "" {
		t.Errorf("a session banner was printed for a command that never ran:\n%s", out)
	}
	base := filepath.Join(defaultReceiptsDir(), guardLabel)
	if entries, err := os.ReadDir(base); err == nil && len(entries) != 0 {
		t.Errorf("%d session directories left by a run that never started", len(entries))
	}
}

// A run that fails after the listeners are up still opened its receipt
// files. A directory of empty ones reads as a session that governed
// something and found it clean.
func TestAFailedRunLeavesNoEmptyEvidenceBehind(t *testing.T) {
	proxyHome(t)
	dir := t.TempDir()
	_, _, err := runGuardTest(t, guardOptions{
		Receipts: dir, Report: false,
		Command: []string{filepath.Join(dir, "not-executable")},
	})
	if err == nil {
		t.Fatal("an unrunnable command was accepted")
	}
	sessions, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Errorf("%d session directories left behind by a run that governed nothing", len(sessions))
	}
}

// What guard offers to wrap comes off the table that records which tool is
// documented to read which variable. A suggestion to run something that
// ignores the setting would be the overclaim this product exists not to
// make, and a suggestion to run software they do not have reads as a tool
// that did not look.
func TestGuardOnlySuggestsToolsThatReadTheSettingAndAreActuallyHere(t *testing.T) {
	for _, c := range []struct {
		name string
		apps []aiApp
		want string
	}{
		{"nothing installed", nil, ""},
		{"a local model server, which is the proxy's job", []aiApp{{Name: "Ollama", Kind: "local_model"}}, ""},
		{"a tool with no documented setting", []aiApp{{Name: "Gemini CLI", Kind: "cli"}}, ""},
		{"Claude Code", []aiApp{{Name: "Claude Code", Kind: "cli"}}, "claude"},
		{"Codex", []aiApp{{Name: "Codex CLI", Kind: "cli"}}, "codex"},
		{
			"the one that is running is preferred over the one that is merely installed",
			[]aiApp{{Name: "Codex CLI", Kind: "cli"}, {Name: "Claude Code", Kind: "cli", Running: true}},
			"claude",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := guardSuggestion(c.apps); got != c.want {
				t.Errorf("suggested %q, want %q", got, c.want)
			}
		})
	}
}

// Every variable guard routes must be one the endpoint table knows, or the
// two halves of this product disagree about what redirects a tool: the
// report would name a setting guard never sets, or guard would set one the
// report never looks for.
func TestEveryRoutedVariableIsOneTheEndpointReportKnows(t *testing.T) {
	known := map[string]bool{}
	for _, v := range baseURLVars {
		known[v.Name] = true
	}
	for _, g := range guardGroups {
		for _, v := range g.Vars {
			if !known[v] {
				t.Errorf("guard sets %s, which agent_endpoints.go does not list; the coverage report cannot see it", v)
			}
		}
	}
}

// The seam: a reply passing through the proxy ends with the provider's
// figure in the session's totals. The unit tests above prove the parser;
// this proves the proxy is wired to it, which is where this kind of thing
// is usually not.
func TestAProvidersFigureReachesTheSessionTotals(t *testing.T) {
	proxyHome(t)

	buffered := `{"id":"m","model":"claude-sonnet-4-5-20250929","content":[{"type":"text","text":"ok"}],` +
		`"usage":{"input_tokens":2095,"output_tokens":503}}`
	// Anthropic opens with the input count and a placeholder output of 1,
	// then closes with the real output. The larger per field wins; summing
	// would double the input.
	streamed := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"m","model":"claude-opus-4-20250514","usage":{"input_tokens":1200,"output_tokens":1}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","usage":{"output_tokens":340}}` + "\n\n"

	for _, c := range []struct {
		name          string
		contentType   string
		body          string
		model         string
		input, output int64
	}{
		{"buffered", "application/json", buffered, "claude-sonnet-4-5-20250929", 2095, 503},
		{"streamed", "text/event-stream", streamed, "claude-opus-4-20250514", 1200, 340},
	} {
		t.Run(c.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", c.contentType)
				fmt.Fprint(w, c.body)
			}))
			defer upstream.Close()

			base, p := startProxy(t, upstream.URL, proxyOptions{Name: "anthropic", Report: false})
			resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"messages":[{"content":"hi"}]}`))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			p.mu.Lock()
			got, ok := p.tokens[c.model]
			unmetered := p.unmetered
			p.mu.Unlock()
			if !ok {
				t.Fatalf("nothing recorded for %s; the proxy is not wired to the parser", c.model)
			}
			if got.Input != c.input || got.Output != c.output {
				t.Errorf("in=%d out=%d, want in=%d out=%d", got.Input, got.Output, c.input, c.output)
			}
			if got.ReportedBy != "provider" {
				t.Errorf("reported_by %q: the figure must stay labelled as the provider's", got.ReportedBy)
			}
			if unmetered != 0 {
				t.Errorf("%d replies counted as unmetered when the provider did report one", unmetered)
			}
		})
	}
}

// A provider that reported nothing is a call, not zero tokens. Zero would
// read as free.
func TestAReplyWithNoFigureIsUnmeteredRatherThanZero(t *testing.T) {
	proxyHome(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
	}))
	defer upstream.Close()

	base, p := startProxy(t, upstream.URL, proxyOptions{Name: "anthropic", Report: false})
	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"messages":[{"content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	p.mu.Lock()
	tokens, unmetered := len(p.tokens), p.unmetered
	p.mu.Unlock()
	if tokens != 0 {
		t.Errorf("%d models recorded for a reply that reported no figure", tokens)
	}
	if unmetered != 1 {
		t.Errorf("unmetered=%d, want 1", unmetered)
	}
}
