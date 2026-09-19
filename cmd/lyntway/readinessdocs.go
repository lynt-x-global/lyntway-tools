package main

// Asks a public documentation site whether an agent can read it.
//
// Four of XitOK's docs checks came across, the four with a fact behind
// them. The rest did not: "a quickstart is mentioned", "the page has code
// blocks", "the page is under 500 KB" and "a sitemap exists" are each a
// guess about quality dressed as a measurement, and a report that passes
// them says nothing an assessor can rely on.
//
// Every request here is a GET for a public page, the same thing an agent
// fetching the docs on somebody's behalf does.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	defDocsText = checkDef{"docs.readable_without_js", "The docs can be read without running JavaScript",
		`The page answers 200 over https and its raw HTML carries at least 400 characters of visible text, without an "enable JavaScript" notice.`,
		"Only the page named was fetched. Other pages of the same site may be empty shells even when this one is not."}
	defDocsLLMS = checkDef{"docs.llms_txt", "An llms.txt index links to the docs",
		"/llms.txt at the site's origin answers 200 with text that is not HTML and contains at least one Markdown link.",
		"It does not show that the links are current or that the pages they point to answer."}
	defDocsSpec = checkDef{"docs.openapi_findable", "An API description can be found",
		"An OpenAPI or Swagger document is linked from the page or from llms.txt, or answers at /openapi.json, /openapi.yaml, /swagger.json or /api/openapi.json.",
		"It does not show that the document describes the API as it behaves today."}
	defDocsRobots = checkDef{"docs.agents_allowed", "Agents acting for a person are not turned away",
		"robots.txt does not disallow the whole site to the fetchers that act for a person in real time: Claude-User, ChatGPT-User and Perplexity-User.",
		"Training crawlers are a separate choice and are reported but not judged. A server can still refuse agents by other means — a firewall, a challenge page — that robots.txt does not show."}
)

var docsDefs = []checkDef{defDocsText, defDocsLLMS, defDocsSpec, defDocsRobots}

// userFetchers act for a person who asked a question just now. Blocking
// them blocks that person's agent from reading the docs at all.
var userFetchers = []string{"Claude-User", "ChatGPT-User", "Perplexity-User"}

// trainingCrawlers gather material for models. Keeping them out is a
// reasonable policy, and it does not stop an agent acting for a user.
var trainingCrawlers = []string{"ClaudeBot", "anthropic-ai", "GPTBot", "OAI-SearchBot", "Google-Extended", "PerplexityBot", "CCBot"}

const maxDocsBytes = 2 << 20

type docsGot struct {
	status int
	ctype  string
	body   string
	final  string
}

type docsFetcher struct {
	client   *http.Client
	requests int
}

func (f *docsFetcher) get(target, accept string) (docsGot, error) {
	if f.requests > 0 && agentPause > 0 {
		time.Sleep(agentPause)
	}
	f.requests++
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return docsGot{}, err
	}
	req.Header.Set("User-Agent", "lyntway-readiness/"+version+" (agent-readiness check of public docs)")
	req.Header.Set("Accept", accept)
	resp, err := f.client.Do(req)
	if err != nil {
		return docsGot{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxDocsBytes))
	return docsGot{status: resp.StatusCode, ctype: strings.ToLower(resp.Header.Get("Content-Type")),
		body: string(body), final: resp.Request.URL.String()}, nil
}

var (
	stripBlocks = regexp.MustCompile(`(?is)<(script|style|noscript|svg|template)[^>]*>.*?</(script|style|noscript|svg|template)>`)
	stripTags   = regexp.MustCompile(`(?s)<[^>]+>`)
	stripEnts   = regexp.MustCompile(`&[a-zA-Z#0-9]+;`)
	mdLink      = regexp.MustCompile(`\]\((https?://[^)\s]+|/[^)\s]*)\)`)
	specLink    = regexp.MustCompile(`(?i)(https?://[^\s"'()<>]+|/[^\s"'()<>]*)(openapi|swagger)[^\s"'()<>]*\.(json|ya?ml)`)
	jsNotice    = regexp.MustCompile(`(?i)(enable|requires?) javascript`)
)

// visibleText is what a reader that never runs a script sees.
func visibleText(html string) string {
	s := stripBlocks.ReplaceAllString(html, " ")
	s = stripTags.ReplaceAllString(s, " ")
	s = stripEnts.ReplaceAllString(s, " ")
	return strings.Join(strings.Fields(s), " ")
}

// checkDocs asks one docs site the four questions.
func checkDocs(page string) agentTarget {
	target := agentTarget{Kind: "docs", Target: page}
	f := &docsFetcher{client: &http.Client{Timeout: probeTimeout}}

	got, err := f.get(page, "text/html,*/*")
	if err != nil || got.status >= 400 {
		why := "no answer"
		if err != nil {
			why = err.Error()
		} else {
			why = fmt.Sprintf("answered %d", got.status)
		}
		target.Checks = append(target.Checks, defDocsText.result(checkFail,
			fmt.Sprintf("GET %s: %s. An agent that cannot fetch the page cannot read it.", page, why)))
		for _, d := range docsDefs[1:] {
			target.Checks = append(target.Checks, d.result(checkInconclusive, "The page itself could not be fetched, so the site was not asked anything further."))
		}
		return target
	}
	u, err := url.Parse(got.final)
	if err != nil {
		u, _ = url.Parse(page)
	}
	origin := u.Scheme + "://" + u.Host

	text := visibleText(got.body)
	switch {
	case u.Scheme != "https":
		target.Checks = append(target.Checks, defDocsText.result(checkFail,
			fmt.Sprintf("The page is served over %s; some agents refuse plain http.", u.Scheme)))
	case len(text) < 400 || jsNotice.MatchString(text):
		target.Checks = append(target.Checks, defDocsText.result(checkFail,
			fmt.Sprintf("The raw HTML carries %d characters of visible text; the content arrives only when a script runs.", len(text))))
	default:
		ev := fmt.Sprintf("The raw HTML carries %d characters of visible text.", len(text))
		if got.final != page {
			ev = "Redirected to " + got.final + ". " + ev
		}
		target.Checks = append(target.Checks, defDocsText.result(checkPass, ev))
	}

	llms, lerr := f.get(origin+"/llms.txt", "text/plain,text/markdown,*/*")
	llmsOK := lerr == nil && llms.status == 200 && !strings.Contains(llms.ctype, "html") && strings.TrimSpace(llms.body) != ""
	switch {
	case lerr != nil:
		target.Checks = append(target.Checks, defDocsLLMS.result(checkFail, "GET /llms.txt: "+lerr.Error()+"."))
	case !llmsOK:
		target.Checks = append(target.Checks, defDocsLLMS.result(checkFail,
			fmt.Sprintf("GET /llms.txt answered %d %s.", llms.status, orNone(llms.ctype))))
	default:
		n := len(mdLink.FindAllString(llms.body, -1))
		if n == 0 {
			target.Checks = append(target.Checks, defDocsLLMS.result(checkFail, "/llms.txt exists but links to nothing."))
		} else {
			target.Checks = append(target.Checks, defDocsLLMS.result(checkPass, fmt.Sprintf("/llms.txt links to %d %s.", n, plural(n, "page", "pages"))))
		}
	}

	haystack := got.body
	if llmsOK {
		haystack += "\n" + llms.body
	}
	if m := specLink.FindString(haystack); m != "" {
		ref, _ := url.Parse(m)
		target.Checks = append(target.Checks, defDocsSpec.result(checkPass, "Linked: "+u.ResolveReference(ref).String()+"."))
	} else {
		found := ""
		for _, p := range []string{"/openapi.json", "/openapi.yaml", "/swagger.json", "/api/openapi.json"} {
			r, err := f.get(origin+p, "application/json,application/yaml,*/*")
			head := r.body
			if len(head) > 2000 {
				head = head[:2000]
			}
			if err == nil && r.status == 200 && regexp.MustCompile(`(?m)"openapi"|^openapi:|"swagger"|^swagger:`).MatchString(head) {
				found = origin + p
				break
			}
		}
		if found != "" {
			target.Checks = append(target.Checks, defDocsSpec.result(checkPass, "Found at "+found+"."))
		} else {
			target.Checks = append(target.Checks, defDocsSpec.result(checkFail,
				"No OpenAPI document is linked from the page or llms.txt, and none answers at the four usual paths."))
		}
	}

	robots, rerr := f.get(origin+"/robots.txt", "text/plain")
	switch {
	case rerr != nil:
		target.Checks = append(target.Checks, defDocsRobots.result(checkInconclusive, "GET /robots.txt: "+rerr.Error()+"."))
	case robots.status != 200:
		target.Checks = append(target.Checks, defDocsRobots.result(checkPass,
			fmt.Sprintf("/robots.txt answered %d, so nothing is disallowed.", robots.status)))
	default:
		blocked := blockedAgents(robots.body, userFetchers)
		training := blockedAgents(robots.body, trainingCrawlers)
		trainNote := ""
		if len(training) > 0 {
			trainNote = " Training crawlers kept out, which is a separate choice: " + strings.Join(training, ", ") + "."
		}
		if len(blocked) > 0 {
			target.Checks = append(target.Checks, defDocsRobots.result(checkFail,
				"robots.txt disallows the whole site to "+strings.Join(blocked, ", ")+", so an agent acting for a person is turned away."+trainNote))
		} else {
			target.Checks = append(target.Checks, defDocsRobots.result(checkPass,
				"robots.txt lets the fetchers that act for a person in."+trainNote))
		}
	}
	return target
}

func orNone(s string) string {
	if s == "" {
		return "with no content type"
	}
	return s
}

// blockedAgents returns the agents robots.txt shuts out of the whole site:
// "Disallow: /" in their own group, or in the "*" group when they have
// none, with no "Allow: /" beside it.
func blockedAgents(robots string, agents []string) []string {
	type group struct {
		agents []string
		rules  []string
	}
	var groups []*group
	var cur *group
	for _, raw := range strings.Split(robots, "\n") {
		line := raw
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "user-agent":
			if cur == nil || len(cur.rules) > 0 {
				cur = &group{}
				groups = append(groups, cur)
			}
			cur.agents = append(cur.agents, strings.ToLower(v))
		case "allow", "disallow":
			if cur != nil {
				cur.rules = append(cur.rules, k+":"+v)
			}
		}
	}
	blocksAll := func(g *group) bool {
		all, allowed := false, false
		for _, r := range g.rules {
			if r == "disallow:/" {
				all = true
			}
			if r == "allow:/" {
				allowed = true
			}
		}
		return all && !allowed
	}
	find := func(name string) *group {
		for _, g := range groups {
			for _, a := range g.agents {
				if a == name {
					return g
				}
			}
		}
		return nil
	}
	star := find("*")
	var out []string
	for _, a := range agents {
		if g := find(strings.ToLower(a)); g != nil {
			if blocksAll(g) {
				out = append(out, a)
			}
		} else if star != nil && blocksAll(star) {
			out = append(out, a)
		}
	}
	return out
}
