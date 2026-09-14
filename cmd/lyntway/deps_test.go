package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The lockfile says what is installed; the manifest says what may be. When
// both are there the lockfile is the one that answers the question.
func TestTheLockfileIsPreferredToTheManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"axios":"^1.6.0"}}`)
	writeFile(t, dir, "package-lock.json", `{"packages":{
		"": {"version":"1.0.0"},
		"node_modules/axios": {"version":"0.21.1"},
		"node_modules/left-pad": {"version":"1.3.0"}
	}}`)

	deps, unpinned, err := readDependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("read %d package(s), want 2 from the lockfile: %+v", len(deps), deps)
	}
	for _, d := range deps {
		if d.Version == "^1.6.0" {
			t.Fatal("a range from package.json was read while a lockfile was present")
		}
		if d.Name == "axios" && d.Version != "0.21.1" {
			t.Errorf("axios is %s, want the installed 0.21.1", d.Version)
		}
	}
	if unpinned != 0 {
		t.Errorf("unpinned is %d, want 0: the lockfile pins everything", unpinned)
	}
}

// A range is a statement about what may be installed. Asking the database
// about "^1.2.0" would return an answer about a version that may not be on
// the machine, so those are counted and left alone.
func TestARangeIsReportedRatherThanGuessedAt(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{
		"axios":"^1.6.0", "left-pad":"1.3.0", "react":"~18.2.0",
		"tar":"latest", "local":"file:../thing", "ranged":">=2 <3",
		"wild":"1.2.x", "star":"1.2.*", "hyphen":"1.2.3 - 2.0.0"
	}}`)
	writeFile(t, dir, "requirements.txt", `
# a comment
requests==2.31.0
urllib3>=1.26
flask
django==4.2.1 ; python_version >= "3.8"
`)

	deps, unpinned, err := readDependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range deps {
		names = append(names, d.Ecosystem+":"+d.Name+"@"+d.Version)
	}
	got := strings.Join(names, " ")
	for _, want := range []string{"npm:left-pad@1.3.0", "PyPI:requests@2.31.0", "PyPI:django@4.2.1"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s was not read as pinned; got %s", want, got)
		}
	}
	for _, unwanted := range []string{"axios", "react", "latest", "file:", "urllib3", "flask", "wild", "star", "hyphen"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("%q was treated as an exact version: %s", unwanted, got)
		}
	}
	if unpinned != 10 {
		t.Errorf("counted %d unpinned, want 10 — every one that was skipped has to be reported", unpinned)
	}
}

// The batch answer comes back positionally. If the two lists ever drift,
// one package's advisories would be attached to another — a wrong finding
// about the wrong thing, which is worse than no finding at all.
func TestAMismatchedBatchAnswerIsRefusedRatherThanMatchedUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Asked about two, answers about one.
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-aaaa"}]}]}`))
	}))
	defer srv.Close()
	old := osvBase
	osvBase = srv.URL
	defer func() { osvBase = old }()

	_, err := queryOSV(srv.Client(), []dependency{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "b", Version: "1.0.0"},
	})
	if err == nil {
		t.Fatal("a short answer was accepted; advisories would be attached to the wrong package")
	}
	if !strings.Contains(err.Error(), "asked about 2") {
		t.Errorf("the error does not say what went wrong: %v", err)
	}
}

// The identifier and the version that fixes it are the two things anybody
// acts on.
func TestAnAdvisoryIsReportedWithTheVersionThatFixesIt(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/querybatch") {
			var body struct {
				Queries []struct {
					Package struct{ Name, Ecosystem string }
					Version string
				}
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, q := range body.Queries {
				asked = append(asked, q.Package.Ecosystem+":"+q.Package.Name+"@"+q.Version)
			}
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-4w2v-q235-vp99"}]},{}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"GHSA-4w2v-q235-vp99","summary":"Server-side request forgery in axios",
			"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"0.21.2"}]}]}]}`))
	}))
	defer srv.Close()
	old := osvBase
	osvBase = srv.URL
	defer func() { osvBase = old }()

	findings, err := queryOSV(srv.Client(), []dependency{
		{Ecosystem: "npm", Name: "axios", Version: "0.21.1"},
		{Ecosystem: "PyPI", Name: "requests", Version: "2.31.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d finding(s), want 1 — the clean package is not a finding", len(findings))
	}
	if findings[0].Dep.Name != "axios" {
		t.Fatalf("the finding is against %s, want axios", findings[0].Dep.Name)
	}
	adv := findings[0].Advisories[0]
	if adv.fixedIn() != "0.21.2" {
		t.Errorf("fixed version is %q, want 0.21.2", adv.fixedIn())
	}
	if !strings.Contains(adv.Summary, "request forgery") {
		t.Errorf("summary was not carried through: %q", adv.Summary)
	}
	// Only names and versions are sent, and both packages are asked about.
	if len(asked) != 2 || !strings.Contains(strings.Join(asked, " "), "npm:axios@0.21.1") {
		t.Errorf("the query sent %v, want exactly the names and versions", asked)
	}
}

// OSV answers with SEMVER, ECOSYSTEM and GIT ranges. A GIT range fixes the
// problem in a commit, and printing "fixed in c45d7c49…" beside "fixed in
// 2.32.4" invites somebody to try installing a hash. Found by running the
// check against the real database.
func TestACommitIsNotOfferedAsTheVersionThatFixesIt(t *testing.T) {
	var a advisory
	if err := json.Unmarshal([]byte(`{"id":"PYSEC-2018-28","affected":[
		{"ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"c45d7c49ea75133e52ab22a8e9e13173938e36ff"}]}]},
		{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.20.0"}]}]}]}`), &a); err != nil {
		t.Fatal(err)
	}
	if got := a.fixedIn(); got != "2.20.0" {
		t.Errorf("fixedIn is %q, want the installable 2.20.0", got)
	}

	// And where a commit is all there is, nothing is offered at all.
	var onlyGit advisory
	if err := json.Unmarshal([]byte(`{"id":"PYSEC-2023-74","affected":[
		{"ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"74ea7cf7a6a2"}]}]}]}`), &onlyGit); err != nil {
		t.Fatal(err)
	}
	if got := onlyGit.fixedIn(); got != "" {
		t.Errorf("fixedIn is %q, want empty: a commit is not a version anybody installs", got)
	}
}
