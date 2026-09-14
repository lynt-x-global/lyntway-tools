package main

// Remembers what the last readiness run found, and says what changed.
//
// # Why the difference is the product
//
// A list of findings is read once. The same list next week is read by
// nobody, because the eye slides over a wall it has already seen and the
// one new line in the middle of it goes unread — which is precisely the
// line that mattered. An assessment is a photograph; what a team acts on
// is motion: a package that acquired an advisory overnight, an endpoint
// that stopped asking for a key after Tuesday's deploy.
//
// So every run is compared with the last one and reported as change. The
// snapshot lives on the machine that ran it, under the directory it was
// run in, because the comparison is between two states of one project and
// needs no account to be useful.
//
// # Why a fixed finding is printed as loudly as a new one
//
// A tool that only ever reports bad news trains people to dread running
// it. It is also the half that shows the work: somebody upgraded that
// package, and the run is the record that they did.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// snapshotVersion guards the stored shape. A snapshot written by an older
// build is discarded rather than misread, because a wrong "what changed"
// is worse than none.
const snapshotVersion = 1

type endpointState struct {
	Endpoint string `json:"endpoint"`
	Verdict  string `json:"verdict"`
	Status   int    `json:"status,omitempty"`
}

type depState struct {
	Ecosystem  string   `json:"ecosystem"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Advisories []string `json:"advisories,omitempty"`
}

type readinessSnapshot struct {
	Version   int             `json:"version"`
	TakenAt   string          `json:"taken_at"`
	Dir       string          `json:"dir"`
	Endpoints []endpointState `json:"endpoints,omitempty"`
	Deps      []depState      `json:"deps,omitempty"`

	// Checked says whether each half ran. A half that was skipped must not
	// read as a half where everything disappeared.
	EndpointsChecked bool `json:"endpoints_checked"`
	DepsChecked      bool `json:"deps_checked"`
}

// snapshotPath is per directory, unless the caller names a file. A runner
// that starts with an empty home every time has no history of its own, so
// it points --state at something it restores: without that, every nightly
// run is a first run and "what changed" never says anything.
func snapshotPath(dir, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(h, ".lyntway", "readiness", hex.EncodeToString(sum[:8])+".json"), nil
}

func loadSnapshot(dir, override string) (readinessSnapshot, bool) {
	path, err := snapshotPath(dir, override)
	if err != nil {
		return readinessSnapshot{}, false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return readinessSnapshot{}, false
	}
	var snap readinessSnapshot
	if err := json.Unmarshal(body, &snap); err != nil || snap.Version != snapshotVersion {
		return readinessSnapshot{}, false
	}
	return snap, true
}

func saveSnapshot(snap readinessSnapshot, override string) error {
	path, err := snapshotPath(snap.Dir, override)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	// 0600: it names the endpoints and packages of somebody's project.
	return os.WriteFile(path, append(body, '\n'), 0o600)
}

// change is one difference between two runs.
type change struct {
	Worse bool // a new finding rather than a resolved one
	Text  string
}

// diffSnapshots reports what moved between two runs.
//
// Only halves that ran in both are compared. A run made with --no-deps
// says nothing about dependencies, and reporting every package as "gone"
// because nobody looked would be the loudest possible lie.
func diffSnapshots(old, now readinessSnapshot) []change {
	var out []change

	if old.EndpointsChecked && now.EndpointsChecked {
		before := map[string]endpointState{}
		for _, e := range old.Endpoints {
			before[e.Endpoint] = e
		}
		seen := map[string]bool{}
		for _, e := range now.Endpoints {
			seen[e.Endpoint] = true
			was, known := before[e.Endpoint]
			switch {
			case !known && e.Verdict == verdictOpen:
				out = append(out, change{true, fmt.Sprintf("%s is new, and answers with no credential (%d)", e.Endpoint, e.Status)})
			case !known:
				out = append(out, change{false, fmt.Sprintf("%s is new, and %s", e.Endpoint, e.Verdict)})
			case was.Verdict != verdictOpen && e.Verdict == verdictOpen:
				out = append(out, change{true, fmt.Sprintf("%s used to ask for a credential and now answers without one (%d)", e.Endpoint, e.Status)})
			case was.Verdict == verdictOpen && e.Verdict != verdictOpen:
				out = append(out, change{false, fmt.Sprintf("%s now asks for a credential; it did not before", e.Endpoint)})
			}
		}
		for _, e := range old.Endpoints {
			if !seen[e.Endpoint] {
				out = append(out, change{false, fmt.Sprintf("%s was not reached this time", e.Endpoint)})
			}
		}
	}

	if old.DepsChecked && now.DepsChecked {
		before := map[string]depState{}
		for _, d := range old.Deps {
			before[d.Ecosystem+":"+d.Name] = d
		}
		seen := map[string]bool{}
		for _, d := range now.Deps {
			k := d.Ecosystem + ":" + d.Name
			seen[k] = true
			was, known := before[k]
			if !known {
				if len(d.Advisories) > 0 {
					out = append(out, change{true, fmt.Sprintf("%s %s is new, with %d %s", d.Name, d.Version, len(d.Advisories), plural(len(d.Advisories), "advisory", "advisories"))})
				}
				continue
			}
			// A version change with the advisories gone is somebody having
			// done the work, and it is worth saying so.
			if was.Version != d.Version {
				switch {
				case len(was.Advisories) > 0 && len(d.Advisories) == 0:
					out = append(out, change{false, fmt.Sprintf("%s went %s → %s and no longer has a published advisory", d.Name, was.Version, d.Version)})
				case len(d.Advisories) > len(was.Advisories):
					out = append(out, change{true, fmt.Sprintf("%s went %s → %s and now has %d %s", d.Name, was.Version, d.Version, len(d.Advisories), plural(len(d.Advisories), "advisory", "advisories"))})
				default:
					out = append(out, change{false, fmt.Sprintf("%s went %s → %s", d.Name, was.Version, d.Version)})
				}
				continue
			}
			// Same version, new advisory: nobody changed anything, the
			// world did. This is the line the whole feature exists for.
			fresh := notIn(d.Advisories, was.Advisories)
			for _, id := range fresh {
				out = append(out, change{true, fmt.Sprintf("%s %s has a new advisory since the last run: %s", d.Name, d.Version, id)})
			}
		}
		for _, d := range old.Deps {
			if !seen[d.Ecosystem+":"+d.Name] {
				out = append(out, change{false, fmt.Sprintf("%s is no longer in this project", d.Name)})
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Worse && !out[j].Worse })
	return out
}

func notIn(now, before []string) []string {
	had := map[string]bool{}
	for _, b := range before {
		had[b] = true
	}
	var out []string
	for _, n := range now {
		if !had[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// plural returns the word only, never the number, because that is what the
// same helper does elsewhere in this codebase and two spellings of one idea
// is how somebody ends up printing "3 3 advisories".
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// reportChange prints the comparison and returns how many of the changes
// were for the worse.
func reportChange(old readinessSnapshot, now readinessSnapshot, hadPrevious bool) int {
	if !hadPrevious {
		fmt.Fprintln(stdout, "\nFirst run here, so there is nothing to compare with. The next one will say what changed.")
		return 0
	}
	changes := diffSnapshots(old, now)
	since := old.TakenAt
	if t, err := time.Parse(time.RFC3339, old.TakenAt); err == nil {
		since = t.Local().Format("2 Jan 15:04")
	}
	if len(changes) == 0 {
		fmt.Fprintf(stdout, "\nNothing has changed since %s.\n", since)
		return 0
	}

	worse := 0
	fmt.Fprintf(stdout, "\nWhat changed since %s:\n", since)
	for _, c := range changes {
		mark := "·"
		if c.Worse {
			mark = "!"
			worse++
		}
		fmt.Fprintf(stdout, "  %s %s\n", mark, c.Text)
	}
	return worse
}
