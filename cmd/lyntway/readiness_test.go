package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The scope is the whole safety model. An endpoint the operator did not
// name is not checked, however plainly it appears in their own traffic —
// because a host in our records is not the same as a host they are
// authorised to send requests to.
func TestNothingOutsideTheTypedScopeIsEverProbed(t *testing.T) {
	endpoints := []surfaceEndpoint{
		{Surface: "http", Destination: "api.acme.test", Method: "GET /v1/orders"},
		{Surface: "http", Destination: "api.someone-else.test", Method: "GET /v1/orders"},
	}
	plan, skipped := planProbes(endpoints, hostSet("api.acme.test"), "https")

	if len(plan) != 1 || !strings.Contains(plan[0].Detail, "api.acme.test") {
		t.Fatalf("planned %d probe(s), want only the host in scope: %+v", len(plan), plan)
	}
	for _, p := range plan {
		if strings.Contains(p.Detail, "someone-else") {
			t.Fatal("a host outside the scope was planned")
		}
	}
	if len(skipped) != 1 || skipped[0].Detail != "not in scope" {
		t.Errorf("the out-of-scope endpoint was not reported as skipped: %+v", skipped)
	}
}

// A replayed write can create an order, send an email or charge a card. No
// flag turns this off, so there is no combination of arguments that sends
// one.
func TestOnlyMethodsThatChangeNothingAreEverSent(t *testing.T) {
	var endpoints []surfaceEndpoint
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"} {
		endpoints = append(endpoints, surfaceEndpoint{
			Surface: "http", Destination: "api.acme.test", Method: m + " /v1/things",
		})
	}
	plan, skipped := planProbes(endpoints, hostSet("api.acme.test"), "https")

	if len(plan) != 3 {
		t.Fatalf("planned %d probe(s), want 3 (GET, HEAD, OPTIONS): %+v", len(plan), plan)
	}
	for _, p := range plan {
		for _, unsafe := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			if strings.HasPrefix(p.Detail, unsafe+" ") {
				t.Fatalf("%s was planned; only methods that repeat safely may be sent", unsafe)
			}
		}
	}
	for _, s := range skipped {
		if !strings.Contains(s.Detail, "changes things") {
			t.Errorf("a write was skipped without saying why: %+v", s)
		}
	}
}

// "{id}" is not an address. Asking for it literally tests a path nobody
// serves and would report a 404 as though it meant something.
func TestATemplatedPathIsNotProbed(t *testing.T) {
	plan, skipped := planProbes([]surfaceEndpoint{
		{Surface: "http", Destination: "api.acme.test", Method: "GET /v1/orders/{id}"},
		{Surface: "model", Destination: "api.openai.com", Method: "tools/call"},
		{Surface: "database", Destination: "db.internal"},
	}, hostSet("api.acme.test,api.openai.com,db.internal"), "https")

	if len(plan) != 0 {
		t.Fatalf("planned %d probe(s), want none: %+v", len(plan), plan)
	}
	if len(skipped) != 3 {
		t.Fatalf("skipped %d, want 3", len(skipped))
	}
	joined := skipped[0].Detail + " " + skipped[1].Detail + " " + skipped[2].Detail
	for _, want := range []string{"template", "nothing to ask for"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no reason mentioning %q was given:\n%s", want, joined)
		}
	}
}

// A host typed with a scheme is what everybody types.
func TestScopeAcceptsAHostTypedTheWayPeopleTypeIt(t *testing.T) {
	got := hostSet(" https://API.Acme.test , api.other.test ,, ")
	if !got["api.acme.test"] {
		t.Errorf("a host typed with a scheme and capitals was not accepted: %v", got)
	}
	if !got["api.other.test"] || len(got) != 2 {
		t.Errorf("scope parsed to %v, want exactly two hosts", got)
	}
}

// What an endpoint answers decides the verdict, and only 401 or 403 counts
// as asking for a credential. A 404 is not a pass: it means this address
// did not answer, which says nothing about whether anything checks a key.
func TestTheVerdictFollowsWhatTheEndpointAnswered(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   string
	}{
		{"open", http.StatusOK, verdictOpen},
		{"created", http.StatusNoContent, verdictOpen},
		{"unauthorised", http.StatusUnauthorized, verdictProtected},
		{"forbidden", http.StatusForbidden, verdictProtected},
		{"missing", http.StatusNotFound, verdictOther},
		{"wrong method", http.StatusMethodNotAllowed, verdictOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sawAuth bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					sawAuth = true
				}
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			got := probeEndpoint(probeResult{
				Endpoint: "GET /x", Host: "test", Detail: "GET " + srv.URL + "/x",
			})
			if got.Verdict != tc.want {
				t.Errorf("a %d was read as %q, want %q", tc.status, got.Verdict, tc.want)
			}
			if sawAuth {
				t.Error("the probe carried a credential; the entire question is what answers without one")
			}
		})
	}
}

// Whoever reads their own logs tomorrow should be able to tell what this
// was without asking anybody.
func TestTheProbeSaysWhatItIsInTheUserAgent(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	probeEndpoint(probeResult{Endpoint: "GET /x", Host: "test", Detail: "GET " + srv.URL + "/x"})
	if !strings.Contains(ua, "lyntway-readiness") || !strings.Contains(ua, "no credential") {
		t.Errorf("user agent is %q; it should name the tool and say no credential was attached", ua)
	}
}

// A required flag that is missing has to fail, even on a machine that is
// not signed in.
//
// It did not. Not signed in, the command read the lockfile, printed that
// the endpoints were not read, and returned nil — so `lyntway readiness`
// with no --scope exited 0. The safety property held (nothing was probed,
// because nothing was read), but the exit code said the run had succeeded.
//
// That is the shape this product exists to refuse. A nightly job whose
// token has expired runs no check at all, exits 0, and the pipeline stays
// green while a security team believes readiness is running. The dashboard
// would read stronger than the truth.
//
// The signed-in path already did the right thing: it does the work it can,
// saves it, and then returns the error. This makes both paths agree.
func TestMissingScopeFailsEvenWhenNotSignedIn(t *testing.T) {
	// A home with no config, so loadConfig takes the not-signed-in path.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(prev)

	var buf bytes.Buffer
	prevOut := stdout
	stdout = &buf
	defer func() { stdout = prevOut }()

	err = readiness(nil)
	if err == nil {
		t.Fatalf("readiness with no --scope returned nil, so the command exits 0:\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "--scope is required") {
		t.Errorf("the error does not name the missing flag: %v", err)
	}
}

// The half that needs no scope still runs, and a run that named its hosts
// still succeeds without an account. Making the flag mandatory must not
// turn "not signed in" into a failure on its own.
func TestAScopedRunStillSucceedsWithoutAnAccount(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(prev)

	var buf bytes.Buffer
	prevOut := stdout
	stdout = &buf
	defer func() { stdout = prevOut }()

	if err := readiness([]string{"--scope", "api.acme.test"}); err != nil {
		t.Fatalf("a scoped run without an account failed: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "Not signed in") {
		t.Errorf("the run did not say the endpoint half was skipped:\n%s", buf.String())
	}
}
