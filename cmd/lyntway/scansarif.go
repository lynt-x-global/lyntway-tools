package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/detect"
)

// SARIF, so a finding becomes a line in the pull request rather than a
// line in a log nobody opens.
//
// The GitHub annotations `--format github` writes are attached to one
// workflow run and vanish with it. SARIF is uploaded to code scanning,
// which keeps the finding against the line, carries it across runs, shows
// it inline in the pull request's diff, and closes it when the line goes
// away. It is also what an enterprise's security team already has a
// process for, which is most of why it matters: it puts this scanner
// inside the tool they are already looking at rather than asking them to
// look somewhere new.
//
// Version 2.1.0, the one GitHub's upload accepts.
//
// # What is deliberately not in here
//
// Not the key. SARIF files are uploaded, stored, indexed and shown in a
// web interface by default, which makes them the single worst place in
// this tool to put a credential. `snippet` is the field a SARIF producer
// would normally fill with the matching text, and it is left empty for
// that reason — the message carries the label and the last four
// characters, which is what identifies the key to revoke without being
// enough to use it.

const sarifVersion = "2.1.0"

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifText        `json:"shortDescription"`
	FullDescription  sarifText        `json:"fullDescription"`
	HelpURI          string           `json:"helpUri,omitempty"`
	Properties       *sarifRuleProps  `json:"properties,omitempty"`
	DefaultConfig    *sarifRuleConfig `json:"defaultConfiguration,omitempty"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
	// PartialFingerprints let code scanning recognise the same finding
	// across runs when the line it sits on has moved, so a key that was
	// already triaged does not reappear as new because something above it
	// grew by a line.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// sarifURI makes a path something code scanning can map to a file in the
// repository.
//
// GitHub resolves artifactLocation.uri against the checkout root and
// rejects — or silently fails to display — an absolute one. A CI step
// that passes an absolute path, which is the ordinary thing for a
// workflow to do, would otherwise produce a document that uploads
// successfully and shows every finding against a file nobody can open.
//
// A path that cannot be made relative is left as it is rather than
// mangled: a wrong relative path points at a real file that is not the
// one with the key in it, which is worse than a path the UI cannot
// resolve.
func sarifURI(file string) string {
	if !filepath.IsAbs(file) {
		return filepath.ToSlash(file)
	}
	wd, err := os.Getwd()
	if err != nil {
		return filepath.ToSlash(file)
	}
	// Both sides are resolved first. On macOS /tmp is a symlink to
	// /private/tmp and Getwd answers with the resolved form while a path
	// handed in on the command line usually is not, so comparing them
	// unresolved produces a "../../.." relative path for a file sitting
	// in the working directory — which is then left absolute, and shows
	// in code scanning against nothing. Containers and home directories
	// on network mounts do the same thing.
	if resolved, err := filepath.EvalSymlinks(wd); err == nil {
		wd = resolved
	}
	target := file
	if resolved, err := filepath.EvalSymlinks(file); err == nil {
		target = resolved
	}
	rel, err := filepath.Rel(wd, target)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(file)
	}
	return filepath.ToSlash(rel)
}

// printScanSARIF writes a SARIF 2.1.0 document for a file or diff scan.
func printScanSARIF(found []keyHit, version string) error {
	// One rule per class present, because code scanning groups, filters
	// and lets a team dismiss by rule — a single "secret found" rule would
	// make "we accept Stripe test keys in fixtures" impossible to express
	// without dismissing everything.
	rules := make([]sarifRule, 0, 8)
	seen := map[string]bool{}
	results := make([]sarifResult, 0, len(found))

	for _, h := range found {
		id := h.Class
		if id == "" {
			id = "secret.unknown"
		}
		if !seen[id] {
			seen[id] = true
			label := h.Label
			if label == "" {
				label = detect.Label(detect.Class(id))
			}
			rules = append(rules, sarifRule{
				ID:               id,
				Name:             label,
				ShortDescription: sarifText{Text: label + " committed to this repository"},
				FullDescription: sarifText{Text: label + " found in a file. A key in a file is a key in " +
					"every copy of the file, including every clone of this repository. Revoke it where it was issued; " +
					"removing the line does not reach the copies."},
				HelpURI:       "https://lyntway.com/docs",
				Properties:    &sarifRuleProps{Tags: []string{"security", "secret"}},
				DefaultConfig: &sarifRuleConfig{Level: "error"},
			})
		}

		line := h.Line
		if line < 1 {
			line = 1
		}
		results = append(results, sarifResult{
			RuleID:  id,
			Level:   "error",
			Message: sarifText{Text: fmt.Sprintf("%s ending …%s. Revoke it; it is in every clone of this repository.", h.Label, h.Last4)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: sarifURI(h.File)},
					Region:           sarifRegion{StartLine: line},
				},
			}},
			// The class and the last four characters, which identify the
			// credential without carrying it. The line number is
			// deliberately absent from the fingerprint: it is what moves.
			PartialFingerprints: map[string]string{
				"lyntwayCredential/v1": id + ":" + h.Last4,
			},
		})
	}

	doc := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "lyntway", InformationURI: "https://lyntway.com", Version: version, Rules: rules}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("writing the report: %w", err)
	}
	return nil
}
