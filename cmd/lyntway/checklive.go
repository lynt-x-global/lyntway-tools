package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// Asking the provider whether a key still works.
//
// "A key is in this file" and "a key that still works is in this file"
// are different sentences, and only the second one makes somebody stop
// what they are doing. A report of forty findings where thirty-eight are
// rotated fixtures and two are live is a report nobody can triage; the
// same report with two marked LIVE is a morning's work with an obvious
// first step.
//
// # Three rules this is built around
//
// **The key never reaches us.** The check is an HTTPS request from the
// developer's own machine straight to the provider that issued the key.
// Nothing is proxied through Lyntway, nothing is reported to Lyntway, and
// no part of this needs an account. Any other arrangement would mean this
// tool receiving its customers' live production credentials, which is a
// thing to design against rather than secure.
//
// **It is opt-in and always will be.** Presenting a credential to its
// issuer is a side effect: it appears in that provider's audit log, it
// can trip a rate limit, and at some organisations it pages somebody. A
// scanner must not do that because it happened to run. The flag is the
// consent, and the one-line notice says where the keys are about to go
// before any of them goes there.
//
// **Unknown is never rendered as revoked.** A refused connection, a proxy,
// a rate limit, an endpoint that moved — every one of those is "could not
// tell", and the one failure this must never produce is somebody reading
// "revoked" over a key that is live and leaving it in place. Live and
// unknown both print; only an answer the provider actually gave prints as
// revoked.

// liveness is what the provider said about a credential.
type liveness int

const (
	// livenessUnknown is the default and the honest answer whenever the
	// provider did not clearly say otherwise.
	livenessUnknown liveness = iota
	livenessLive
	livenessRevoked
	// livenessUnsupported means there is no check for this kind of
	// credential, which is different from not having been able to run one.
	livenessUnsupported
)

func (l liveness) String() string {
	switch l {
	case livenessLive:
		return "LIVE"
	case livenessRevoked:
		return "revoked"
	case livenessUnsupported:
		return "no check"
	default:
		return "unknown"
	}
}

// providerCheck is how to ask one provider about one kind of key.
//
// Each endpoint is the cheapest read the provider offers that needs
// nothing but the credential: listing models, reading the current
// account, asking who the token belongs to. None of them changes
// anything, and none of them needs a scope beyond what any key has.
type providerCheck struct {
	Class detect.Class
	// Endpoint is a fixed https URL. Nothing about it is derived from the
	// value being checked, so no credential can be made to travel to a
	// host of somebody else's choosing.
	Endpoint string
	Method   string
	// Auth puts the credential on the request.
	Auth func(req *http.Request, value string)
	// Decide reads the provider's answer. It returns unknown for anything
	// it does not positively recognise.
	Decide func(status int, body []byte) liveness
}

// bearer is the common case: Authorization: Bearer <value>.
func bearer(req *http.Request, value string) {
	req.Header.Set("Authorization", "Bearer "+value)
}

// byStatus reads the ordinary REST answer: 2xx is live, 401 and 403 are
// the provider refusing the credential, anything else is unknown.
//
// 403 counts as refused because every provider below returns it for a
// disabled or revoked key rather than for a scope problem on these
// endpoints — they were chosen for needing no scope.
func byStatus(status int, _ []byte) liveness {
	switch {
	case status >= 200 && status < 300:
		return livenessLive
	case status == 401 || status == 403:
		return livenessRevoked
	default:
		return livenessUnknown
	}
}

// providerChecks is the table. Adding a provider is one entry.
var providerChecks = []providerCheck{
	{
		Class:    detect.ClassOpenAIKey,
		Endpoint: "https://api.openai.com/v1/models",
		Method:   http.MethodGet,
		Auth:     bearer,
		Decide:   byStatus,
	},
	{
		Class:    detect.ClassAnthropicKey,
		Endpoint: "https://api.anthropic.com/v1/models",
		Method:   http.MethodGet,
		Auth: func(req *http.Request, value string) {
			req.Header.Set("x-api-key", value)
			req.Header.Set("anthropic-version", "2023-06-01")
		},
		Decide: byStatus,
	},
	{
		Class:    detect.ClassGitHubToken,
		Endpoint: "https://api.github.com/user",
		Method:   http.MethodGet,
		Auth:     bearer,
		Decide:   byStatus,
	},
	{
		Class:    detect.ClassStripeKey,
		Endpoint: "https://api.stripe.com/v1/balance",
		Method:   http.MethodGet,
		// Stripe takes the key as the Basic username with no password.
		Auth: func(req *http.Request, value string) {
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(value+":")))
		},
		Decide: byStatus,
	},
	{
		Class:    detect.ClassSlackToken,
		Endpoint: "https://slack.com/api/auth.test",
		Method:   http.MethodPost,
		Auth:     bearer,
		// Slack answers 200 to everything and puts the verdict in the
		// body, so reading the status alone would report every revoked
		// token as live — the one direction this must never fail in.
		Decide: func(status int, body []byte) liveness {
			if status < 200 || status >= 300 {
				return livenessUnknown
			}
			switch {
			case bytes.Contains(body, []byte(`"ok":true`)):
				return livenessLive
			case bytes.Contains(body, []byte("invalid_auth")),
				bytes.Contains(body, []byte("account_inactive")),
				bytes.Contains(body, []byte("token_revoked")),
				bytes.Contains(body, []byte("token_expired")):
				return livenessRevoked
			default:
				return livenessUnknown
			}
		},
	},
	{
		Class:    detect.ClassSendGridKey,
		Endpoint: "https://api.sendgrid.com/v3/scopes",
		Method:   http.MethodGet,
		Auth:     bearer,
		Decide:   byStatus,
	},
	{
		Class:    detect.ClassNPMToken,
		Endpoint: "https://registry.npmjs.org/-/whoami",
		Method:   http.MethodGet,
		Auth:     bearer,
		Decide:   byStatus,
	},
	{
		Class:    detect.ClassHuggingFaceKey,
		Endpoint: "https://huggingface.co/api/whoami-v2",
		Method:   http.MethodGet,
		Auth:     bearer,
		Decide:   byStatus,
	},
	{
		Class:    detect.ClassDigitalOceanKey,
		Endpoint: "https://api.digitalocean.com/v2/account",
		Method:   http.MethodGet,
		Auth:     bearer,
		Decide:   byStatus,
	},
	{
		Class:    detect.ClassGroqKey,
		Endpoint: "https://api.groq.com/openai/v1/models",
		Method:   http.MethodGet,
		Auth:     bearer,
		Decide:   byStatus,
	},
}

func checkFor(class string) (providerCheck, bool) {
	for _, c := range providerChecks {
		if string(c.Class) == class {
			return c, true
		}
	}
	return providerCheck{}, false
}

// checkableClasses names what can be checked, for the notice.
func checkableClasses() []string {
	out := make([]string, 0, len(providerChecks))
	for _, c := range providerChecks {
		out = append(out, detect.Label(c.Class))
	}
	sort.Strings(out)
	return out
}

// liveClient is the client every check uses.
//
// Redirects are refused rather than followed. Go's default client copies
// the Authorization header across a redirect to the same host and would
// otherwise hand the credential to wherever a compromised or merely
// misconfigured provider pointed it — which is the one way a fixed
// endpoint could still send a key somewhere unintended.
var liveClient = &http.Client{
	Timeout: 8 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		// The machine's own proxy settings are honoured.
		//
		// A custom Transport starts with no Proxy function, which is not
		// the same as http.DefaultTransport — that one reads the
		// environment. Without this line the check ignored HTTPS_PROXY
		// and dialled the provider directly, which is wrong twice. In a
		// company where egress goes through a proxy it would simply
		// fail, and report "could not tell" without saying the proxy was
		// the reason. And in a company that routes outbound traffic on
		// purpose, a security tool quietly going around that is a worse
		// problem than the feature is worth.
		//
		// The credential stays encrypted either way: these are https
		// endpoints, so a proxy sees a CONNECT to a hostname and a TLS
		// stream it cannot read, unless the company terminates TLS
		// itself — which is their own infrastructure and their decision.
		Proxy: http.ProxyFromEnvironment,

		// https only, enforced at dial as well as in the table, so a
		// table entry that ever loses its scheme fails rather than
		// sending a credential in the clear.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 5 * time.Second,
	},
}

// checkOne asks one provider about one credential.
func checkOne(ctx context.Context, c providerCheck, value string) liveness {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return livenessUnknown
	}
	req, err := http.NewRequestWithContext(ctx, c.Method, c.Endpoint, nil)
	if err != nil {
		return livenessUnknown
	}
	req.Header.Set("User-Agent", "lyntway/"+version)
	c.Auth(req, value)

	resp, err := liveClient.Do(req)
	if err != nil {
		// Offline, behind a proxy, DNS refused: all of them are "could
		// not tell", never "revoked".
		return livenessUnknown
	}
	defer resp.Body.Close()
	// Enough to read a verdict and no more. A provider that answers with
	// a megabyte is not going to say anything useful in the rest of it.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	return c.Decide(resp.StatusCode, body)
}

// checkHits fills in the liveness of every hit that can be checked.
//
// The order of hits is not disturbed: each worker writes to its own
// index, for the reason the scan itself does.
func checkHits(ctx context.Context, hits []keyHit) {
	type job struct{ i int }
	var jobs []job
	for i := range hits {
		if hits[i].value == "" {
			hits[i].Live = livenessUnsupported
			continue
		}
		if _, ok := checkFor(hits[i].Class); !ok {
			hits[i].Live = livenessUnsupported
			continue
		}
		jobs = append(jobs, job{i})
	}
	if len(jobs) == 0 {
		return
	}

	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8 // politeness to the provider, not a throughput limit
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n := int(next.Add(1)) - 1
				if n >= len(jobs) {
					return
				}
				i := jobs[n].i
				c, _ := checkFor(hits[i].Class)
				hits[i].Live = checkOne(ctx, c, hits[i].value)
			}
		}()
	}
	wg.Wait()
}

// liveNotice is printed before any key leaves the machine.
func liveNotice() string {
	var b strings.Builder
	b.WriteString("Checking which of these still work. Each key is sent to the provider that\n")
	b.WriteString("issued it, over HTTPS, from this machine — never to Lyntway, which has no\n")
	b.WriteString("part in this and is not told the result. The requests are reads that change\n")
	b.WriteString("nothing, and they will appear in that provider's audit log.\n\n")
	b.WriteString("Checkable here: " + strings.Join(checkableClasses(), ", ") + ".\n")
	return b.String()
}

// errCheckNeedsValues is returned when a view cannot supply the
// credential a check needs.
var errCheckNeedsValues = errors.New(
	"--check needs the key itself, and a scan of history reports commits rather than values; " +
		"run it over the files instead")

func liveSummary(hits []keyHit) string {
	live, revoked, unknown := 0, 0, 0
	for _, h := range hits {
		switch h.Live {
		case livenessLive:
			live++
		case livenessRevoked:
			revoked++
		case livenessUnknown:
			unknown++
		}
	}
	var parts []string
	if live > 0 {
		parts = append(parts, fmt.Sprintf("%d still working", live))
	}
	if revoked > 0 {
		parts = append(parts, fmt.Sprintf("%d already revoked", revoked))
	}
	if unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d could not be checked", unknown))
	}
	if len(parts) == 0 {
		return ""
	}
	s := strings.Join(parts, ", ")
	if unknown > 0 {
		s += ".\nA key that could not be checked is not a key that is safe: treat it as live."
	} else {
		s += "."
	}
	return s
}
