package main

// Checks the packages a project actually installs against the public
// vulnerability database.
//
// # Why this belongs next to the endpoint check
//
// An agent writing an integration picks a version from what it learned,
// not from what is current, and the gap between those two is measured in
// years. Around a fifth of the packages a model names do not exist at all,
// which is its own problem — somebody registers the name and waits. So the
// question "what did the agent install" is worth asking on a schedule, and
// it is the half of an assessment nobody needs permission to run: reading
// a lockfile touches nothing.
//
// # What leaves this machine
//
// Package names and versions, to api.osv.dev, and nothing else. No paths,
// no source, no account, no identifier of who asked. Said out loud before
// it happens, and --offline skips it entirely — a check that quietly
// posted a customer's dependency list somewhere would be the disclosure
// this product exists to prevent, in miniature.
//
// # What a clean answer means
//
// "Nothing known today." A package with no advisory is not a safe package;
// it is a package nobody has published a finding about yet, and the
// difference matters enough to print.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// osvBase is the public vulnerability database. A variable so a test can
// point it somewhere that is not the internet.
var osvBase = "https://api.osv.dev"

// maxOSVDetails bounds how many advisories are fetched in full. A project
// with two hundred findings does not need two hundred round trips to make
// the point; the rest are named and counted.
const maxOSVDetails = 30

// dependency is one installed package, at one exact version.
type dependency struct {
	Ecosystem string // OSV's name for the registry: npm, PyPI, Go
	Name      string
	Version   string
	Source    string // the file it was read from, for a person to go and look
}

// advisory is what the database says about one of them.
type advisory struct {
	ID       string `json:"id"`
	Summary  string `json:"summary,omitempty"`
	Affected []struct {
		Ranges []struct {
			// Type is SEMVER, ECOSYSTEM or GIT. A GIT range fixes the
			// problem in a commit, and a commit is not something anybody
			// installs — printed as a version it reads like one.
			Type   string `json:"type"`
			Events []struct {
				Fixed string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges,omitempty"`
	} `json:"affected,omitempty"`
}

// fixedIn returns the first version the advisory says the problem is fixed
// in, which is the only part of it anybody acts on.
func (a advisory) fixedIn() string {
	for _, aff := range a.Affected {
		for _, r := range aff.Ranges {
			// Commits are skipped: OSV answers for a package version, and
			// "fixed in c45d7c49…" alongside "fixed in 2.32.4" invites a
			// reader to try installing a commit hash.
			if strings.EqualFold(r.Type, "GIT") {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// depFinding pairs a package with what is known about it.
type depFinding struct {
	Dep        dependency
	Advisories []advisory
}

// readDependencies finds the lockfiles and manifests in a directory and
// returns every package pinned to an exact version.
//
// Exact versions only. A range in a manifest is a statement about what may
// be installed, not about what is; asking the database about "^1.2.0"
// would produce an answer about a version that may not be on the machine.
// Those are reported as unchecked rather than guessed at.
func readDependencies(dir string) (deps []dependency, unpinned int, err error) {
	// The lockfile first where there is one: it says what is installed,
	// which is the question.
	if lock := filepath.Join(dir, "package-lock.json"); exists(lock) {
		got, err := readNPMLock(lock)
		if err != nil {
			return nil, 0, err
		}
		deps = append(deps, got...)
	} else if pkg := filepath.Join(dir, "package.json"); exists(pkg) {
		got, loose, err := readPackageJSON(pkg)
		if err != nil {
			return nil, 0, err
		}
		deps = append(deps, got...)
		unpinned += loose
	}

	if req := filepath.Join(dir, "requirements.txt"); exists(req) {
		got, loose, err := readRequirements(req)
		if err != nil {
			return nil, 0, err
		}
		deps = append(deps, got...)
		unpinned += loose
	}

	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Ecosystem != deps[j].Ecosystem {
			return deps[i].Ecosystem < deps[j].Ecosystem
		}
		return deps[i].Name < deps[j].Name
	})
	return deps, unpinned, nil
}

type npmLock struct {
	Packages map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev,omitempty"`
	} `json:"packages"`
}

func readNPMLock(path string) ([]dependency, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(body, &lock); err != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath.Base(path), err)
	}
	var out []dependency
	for key, entry := range lock.Packages {
		// The root project is the empty key, and it is not a dependency.
		if key == "" || entry.Version == "" {
			continue
		}
		name := key
		if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
			name = key[i+len("node_modules/"):]
		}
		out = append(out, dependency{
			Ecosystem: "npm", Name: name, Version: entry.Version,
			Source: filepath.Base(path),
		})
	}
	return out, nil
}

func readPackageJSON(path string) (deps []dependency, unpinned int, err error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var doc struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("reading %s: %w", filepath.Base(path), err)
	}
	for _, set := range []map[string]string{doc.Dependencies, doc.DevDependencies} {
		for name, spec := range set {
			if isExactVersion(spec) {
				deps = append(deps, dependency{
					Ecosystem: "npm", Name: name, Version: spec, Source: filepath.Base(path),
				})
				continue
			}
			unpinned++
		}
	}
	return deps, unpinned, nil
}

func readRequirements(path string) (deps []dependency, unpinned int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		name, version, found := strings.Cut(line, "==")
		if !found {
			// >=, ~=, or a bare name: a statement about what may be
			// installed rather than what is.
			unpinned++
			continue
		}
		name = strings.TrimSpace(name)
		if i := strings.IndexAny(name, "[ ;"); i >= 0 {
			name = strings.TrimSpace(name[:i])
		}
		version = strings.TrimSpace(version)
		if i := strings.IndexAny(version, " ;"); i >= 0 {
			version = strings.TrimSpace(version[:i])
		}
		if name == "" || version == "" {
			unpinned++
			continue
		}
		deps = append(deps, dependency{
			Ecosystem: "PyPI", Name: name, Version: version, Source: filepath.Base(path),
		})
	}
	return deps, unpinned, sc.Err()
}

// isExactVersion is true for a version with no range operator in it. npm
// treats a bare "1.2.3" as exact and everything else as a range.
func isExactVersion(spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return false
	}
	if strings.ContainsAny(spec, "^~*<> |xX") || strings.Contains(spec, " - ") {
		return false
	}
	// A dist-tag, a URL or a git reference is not a version either.
	if strings.ContainsAny(spec, ":/") {
		return false
	}
	return spec[0] >= '0' && spec[0] <= '9'
}

// queryOSV asks the database about every dependency at once, then fetches
// the advisories it named.
func queryOSV(client *http.Client, deps []dependency) ([]depFinding, error) {
	type pkg struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	}
	type query struct {
		Package pkg    `json:"package"`
		Version string `json:"version"`
	}
	batch := struct {
		Queries []query `json:"queries"`
	}{}
	for _, d := range deps {
		batch.Queries = append(batch.Queries, query{
			Package: pkg{Name: d.Name, Ecosystem: d.Ecosystem}, Version: d.Version,
		})
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(osvBase+"/v1/querybatch", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("asking the vulnerability database: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the vulnerability database answered %d", resp.StatusCode)
	}

	var batchResult struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &batchResult); err != nil {
		return nil, fmt.Errorf("reading the vulnerability database's answer: %w", err)
	}

	// The answer comes back positionally, so a short list means the two
	// have drifted apart and matching them up would attach one package's
	// advisories to another.
	if len(batchResult.Results) != len(deps) {
		return nil, fmt.Errorf("the vulnerability database answered about %d package(s) and was asked about %d",
			len(batchResult.Results), len(deps))
	}

	details := map[string]advisory{}
	fetched := 0
	var out []depFinding
	for i, res := range batchResult.Results {
		if len(res.Vulns) == 0 {
			continue
		}
		f := depFinding{Dep: deps[i]}
		for _, v := range res.Vulns {
			adv, ok := details[v.ID]
			if !ok && fetched < maxOSVDetails {
				adv = fetchAdvisory(client, v.ID)
				details[v.ID] = adv
				fetched++
			}
			if adv.ID == "" {
				adv = advisory{ID: v.ID}
			}
			f.Advisories = append(f.Advisories, adv)
		}
		out = append(out, f)
	}
	return out, nil
}

// fetchAdvisory reads one advisory. A failure here is not a failure of the
// check: the identifier is still reported, and an empty summary is better
// than a run that stops because one lookup timed out.
func fetchAdvisory(client *http.Client, id string) advisory {
	resp, err := client.Get(osvBase + "/v1/vulns/" + id)
	if err != nil {
		return advisory{ID: id}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return advisory{ID: id}
	}
	var a advisory
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&a); err != nil {
		return advisory{ID: id}
	}
	if a.ID == "" {
		a.ID = id
	}
	return a
}

// reportDependencies prints the dependency section of a readiness run.
func reportDependencies(dir string, offline bool) ([]depState, error) {
	deps, unpinned, err := readDependencies(dir)
	if err != nil {
		return nil, err
	}
	if len(deps) == 0 && unpinned == 0 {
		fmt.Fprintln(stdout, "\nNo package-lock.json, package.json or requirements.txt here, so no dependencies were read.")
		return nil, nil
	}

	fmt.Fprintf(stdout, "\n%d package(s) pinned to an exact version", len(deps))
	if unpinned > 0 {
		fmt.Fprintf(stdout, "; %d more give a range rather than a version and were not checked", unpinned)
	}
	fmt.Fprintln(stdout, ".")

	if offline {
		fmt.Fprintln(stdout, "Skipped the vulnerability database: --offline was given, so nothing left this machine.")
		// Nothing was asked, so nothing is known: recording these as clean
		// would make the next run report advisories as newly appeared when
		// they had simply not been looked for.
		return nil, nil
	}
	if len(deps) == 0 {
		return nil, nil
	}

	// Said before it happens, not in a policy somewhere.
	fmt.Fprintln(stdout, "Asking api.osv.dev about those names and versions. Nothing else leaves this machine;")
	fmt.Fprintln(stdout, "pass --offline to skip it.")

	client := &http.Client{Timeout: 30 * time.Second}
	findings, err := queryOSV(client, deps)
	if err != nil {
		return nil, err
	}

	// Every package that was asked about, with what came back, so the next
	// run can tell a new advisory from one that was always there.
	byKey := map[string][]string{}
	for _, f := range findings {
		for _, a := range f.Advisories {
			byKey[f.Dep.Ecosystem+":"+f.Dep.Name] = append(byKey[f.Dep.Ecosystem+":"+f.Dep.Name], a.ID)
		}
	}
	states := make([]depState, 0, len(deps))
	for _, d := range deps {
		states = append(states, depState{
			Ecosystem: d.Ecosystem, Name: d.Name, Version: d.Version,
			Advisories: byKey[d.Ecosystem+":"+d.Name],
		})
	}

	if len(findings) == 0 {
		fmt.Fprintf(stdout, "\nNothing known today about any of the %d. That is not the same as safe:\n"+
			"it means nobody has published a finding about these versions yet.\n", len(deps))
		return states, nil
	}

	fmt.Fprintf(stdout, "\n%d package(s) have a published advisory:\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(stdout, "  ! %s %s  (%s)\n", f.Dep.Name, f.Dep.Version, f.Dep.Source)
		for _, a := range f.Advisories {
			line := "      " + a.ID
			if fixed := a.fixedIn(); fixed != "" {
				line += "  fixed in " + fixed
			}
			if a.Summary != "" {
				line += "  " + firstLine(a.Summary)
			}
			fmt.Fprintln(stdout, line)
		}
	}
	return states, nil
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 96 {
		s = s[:95] + "…"
	}
	return s
}
