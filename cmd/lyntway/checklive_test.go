package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// check runs one entry's logic against a stand-in server, so the table's
// interpretation is tested without presenting anything to a real provider.
func checkAgainst(t *testing.T, c providerCheck, handler http.HandlerFunc) liveness {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	local := c
	local.Endpoint = srv.URL
	// checkOne refuses anything that is not https, which is the guard
	// being relied on everywhere else, so the request is made here with
	// the same client and the entry's own Auth and Decide.
	req, err := http.NewRequestWithContext(context.Background(), local.Method, local.Endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	local.Auth(req, "the-value")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return local.Decide(resp.StatusCode, buf[:n])
}

// The direction that must never be wrong.
//
// A network failure, a proxy, a rate limit, an endpoint that moved: every
// one is "could not tell". Reporting any of them as revoked would have
// somebody read that a live key is dead and leave it in place, which is
// the whole harm this feature could do.
func TestNothingUnreachableIsEverCalledRevoked(t *testing.T) {
	c, ok := checkFor(string(detect.ClassOpenAIKey))
	if !ok {
		t.Fatal("no check for OpenAI keys")
	}
	// A host that does not resolve, reached through the real path.
	c.Endpoint = "https://lyntway-no-such-host.invalid/v1/models"
	if got := checkOne(context.Background(), c, "the-value"); got != livenessUnknown {
		t.Errorf("an unreachable provider reported %s, want unknown", got)
	}

	// And every non-authentication status, through the table's own reader.
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusTooManyRequests, http.StatusNotFound, http.StatusRequestTimeout} {
		got := checkAgainst(t, c, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		if got == livenessRevoked {
			t.Errorf("status %d was read as revoked", status)
		}
	}
}

func TestAProviderSayingNoIsRevokedAndYesIsLive(t *testing.T) {
	c, _ := checkFor(string(detect.ClassOpenAIKey))
	if got := checkAgainst(t, c, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}); got != livenessRevoked {
		t.Errorf("401 reported %s, want revoked", got)
	}
	if got := checkAgainst(t, c, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}); got != livenessLive {
		t.Errorf("200 reported %s, want live", got)
	}
}

// Slack answers 200 to everything and puts the verdict in the body.
// Reading the status alone would report every revoked token as live.
func TestSlackIsReadFromTheBodyNotTheStatus(t *testing.T) {
	c, ok := checkFor(string(detect.ClassSlackToken))
	if !ok {
		t.Fatal("no check for Slack tokens")
	}
	bad := checkAgainst(t, c, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	})
	if bad != livenessRevoked {
		t.Errorf("a 200 carrying invalid_auth reported %s, want revoked", bad)
	}
	good := checkAgainst(t, c, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"user":"someone"}`))
	})
	if good != livenessLive {
		t.Errorf("a 200 carrying ok:true reported %s, want live", good)
	}
}

// The credential must only ever be able to travel to the provider that
// issued it, over https, to a host nothing about the value can influence.
func TestEveryEndpointIsAFixedHTTPSURL(t *testing.T) {
	seen := map[detect.Class]bool{}
	for _, c := range providerChecks {
		if seen[c.Class] {
			t.Errorf("%s has two checks; which one runs is then an accident", c.Class)
		}
		seen[c.Class] = true

		u, err := url.Parse(c.Endpoint)
		if err != nil {
			t.Errorf("%s: %v", c.Class, err)
			continue
		}
		if u.Scheme != "https" {
			t.Errorf("%s sends the credential to a %s URL", c.Class, u.Scheme)
		}
		if u.Host == "" || strings.Contains(c.Endpoint, "%s") || strings.Contains(c.Endpoint, "{") {
			t.Errorf("%s's endpoint is not a fixed URL: %q", c.Class, c.Endpoint)
		}
		if c.Auth == nil || c.Decide == nil {
			t.Errorf("%s is missing Auth or Decide", c.Class)
		}
		if detect.Label(c.Class) == string(c.Class) {
			t.Errorf("%s has no label, so the notice would print an identifier", c.Class)
		}
	}
}

// checkOne refuses a plaintext endpoint rather than sending the key.
func TestAPlaintextEndpointIsRefused(t *testing.T) {
	c, _ := checkFor(string(detect.ClassOpenAIKey))
	c.Endpoint = "http://api.openai.com/v1/models"
	if got := checkOne(context.Background(), c, "the-value"); got != livenessUnknown {
		t.Errorf("a plaintext endpoint reported %s; it must refuse rather than send", got)
	}
}

// Nothing is checked unless the flag asked, and the value is not even
// kept otherwise.
func TestAValueIsNotRetainedUnlessCheckingAsked(t *testing.T) {
	prev := retainValues
	t.Cleanup(func() { retainValues = prev })

	retainValues = false
	for _, h := range findKeys("OPENAI_API_KEY="+tOpenAI, 1) {
		if h.value != "" {
			t.Error("the credential was retained when nothing asked for it")
		}
	}

	retainValues = true
	kept := false
	for _, h := range findKeys("OPENAI_API_KEY="+tOpenAI, 1) {
		if h.value != "" {
			kept = true
		}
	}
	if !kept {
		t.Error("the credential was not retained when --check needs it")
	}
}

// A hit with no value, or of a kind nothing can check, says so rather
// than reporting unknown — "we have no check for this" and "we tried and
// could not tell" are different facts.
func TestWhatCannotBeCheckedSaysSo(t *testing.T) {
	hits := []keyHit{
		{Class: string(detect.ClassOpenAIKey)},      // no value
		{Class: "secret.teams_webhook", value: "x"}, // no check exists
	}
	checkHits(context.Background(), hits)
	for i, h := range hits {
		if h.Live != livenessUnsupported {
			t.Errorf("hit %d reported %s, want %s", i, h.Live, livenessUnsupported)
		}
	}
}

// The summary must tell somebody that unknown is not safe.
func TestTheSummarySaysUnknownIsNotSafe(t *testing.T) {
	s := liveSummary([]keyHit{{Live: livenessUnknown}, {Live: livenessLive}})
	if !strings.Contains(s, "treat it as live") {
		t.Errorf("summary does not say what an unchecked key means: %q", s)
	}
}

// The notice has to be printed before anything leaves, and has to say
// where it goes.
func TestTheNoticeSaysWhereTheKeysGo(t *testing.T) {
	n := liveNotice()
	for _, want := range []string{"never to Lyntway", "HTTPS", "audit log"} {
		if !strings.Contains(n, want) {
			t.Errorf("the notice does not mention %q", want)
		}
	}
}

// Piped answers must reach the prompts they were written for.
//
// Every prompt used to construct its own bufio.Reader. A bufio.Reader
// fills a four-kilobyte buffer from the file, hands back one line, and
// takes the rest of the buffer with it when it goes out of scope — so
// `printf 'y\nm\nn\n' | lyntway setup` read "y" and discarded "m" and
// "n". Every prompt after the first got an empty line and took its
// default, which recorded a run that answered "just me" as an
// organisation. Invisible at a terminal, where there is never a second
// line waiting, and wrong in every Dockerfile, CI step and install
// script.
func TestPipedAnswersAreNotSwallowed(t *testing.T) {
	prevIn, prevFrom, prevOut := input, inputFrom, stdout
	t.Cleanup(func() { input, inputFrom, stdout = prevIn, prevFrom, prevOut })

	stdin = strings.NewReader("first\nsecond\nthird\n")
	input, inputFrom = nil, nil
	stdout = io.Discard

	for i, want := range []string{"first", "second", "third"} {
		if got := askLine("? "); got != want {
			t.Fatalf("answer %d was %q, want %q — the reader is dropping what it buffered", i+1, got, want)
		}
	}
}

// [Y/n] and [y/N] must not share one implementation that guesses.
func TestTheTwoDefaultsAreOppositeOnAnEmptyAnswer(t *testing.T) {
	prevIn, prevFrom, prevOut := input, inputFrom, stdout
	t.Cleanup(func() { input, inputFrom, stdout = prevIn, prevFrom, prevOut })
	stdout = io.Discard

	stdin = strings.NewReader("\n")
	input, inputFrom = nil, nil
	if !askYes("[Y/n] ") {
		t.Error("askYes said no to an empty answer; its prompt says the default is yes")
	}

	stdin = strings.NewReader("\n")
	input, inputFrom = nil, nil
	if ask("[y/N] ") {
		t.Error("ask said yes to an empty answer; its prompt says the default is no")
	}
}

// An answer whose case matters must not be lowercased.
func TestARawAnswerKeepsItsCase(t *testing.T) {
	prevIn, prevFrom, prevOut := input, inputFrom, stdout
	t.Cleanup(func() { input, inputFrom, stdout = prevIn, prevFrom, prevOut })
	stdout = io.Discard

	stdin = strings.NewReader("lynt_sk_AbCdEf\n")
	input, inputFrom = nil, nil
	if got := askRaw("key: "); got != "lynt_sk_AbCdEf" {
		t.Errorf("askRaw returned %q; an API key that has been lowercased does not work", got)
	}
}

// The check must use the machine's own proxy settings.
//
// A custom http.Transport starts with no Proxy function — unlike
// http.DefaultTransport, which reads the environment — so this client
// ignored HTTPS_PROXY and dialled providers directly. Verified on
// 2 November 2026 with a recording proxy: with HTTPS_PROXY set, five
// keys were checked against the real providers and the proxy saw
// nothing.
//
// Wrong twice. Where egress goes through a proxy it would simply fail
// and report "could not tell" without naming the reason; and where a
// company routes outbound traffic deliberately, a security tool going
// around that is worse than the feature is worth.
func TestTheLivenessClientHonoursTheEnvironmentProxy(t *testing.T) {
	tr, ok := liveClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the client's transport is %T, so the proxy setting cannot be read", liveClient.Transport)
	}
	if tr.Proxy == nil {
		t.Fatal("Proxy is nil, so HTTP_PROXY and HTTPS_PROXY are ignored and egress controls are bypassed")
	}

	// And it is the environment's, not a hardcoded one.
	//
	// Compared by function pointer rather than by setting HTTPS_PROXY and
	// watching what it resolves to. http.ProxyFromEnvironment reads the
	// environment once and caches it for the life of the process, so a
	// test that sets the variable passes alone and fails in a suite where
	// anything resolved a proxy first — which is what this test did on
	// its first run. A flaky test is worse than none: it teaches people
	// to re-run until green.
	if reflect.ValueOf(tr.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		t.Error("Proxy is set to something other than http.ProxyFromEnvironment")
	}
}

// Nothing may be sent anywhere but the provider that issued the key.
//
// Asserted against the table rather than the network, so it holds in CI:
// the recording-proxy run that proved it is in the commit message.
func TestTheOnlyDestinationsAreTheProviders(t *testing.T) {
	allowed := map[string]bool{
		"api.openai.com": true, "api.anthropic.com": true, "api.github.com": true,
		"api.stripe.com": true, "slack.com": true, "api.sendgrid.com": true,
		"registry.npmjs.org": true, "huggingface.co": true,
		"api.digitalocean.com": true, "api.groq.com": true,
	}
	for _, c := range providerChecks {
		u, err := url.Parse(c.Endpoint)
		if err != nil {
			t.Errorf("%s: %v", c.Class, err)
			continue
		}
		if !allowed[u.Host] {
			t.Errorf("%s would send a credential to %s, which is not a provider in this list", c.Class, u.Host)
		}
		if strings.Contains(u.Host, "lyntway") {
			t.Errorf("%s sends a credential to us; the whole point is that it does not", c.Class)
		}
	}
}
