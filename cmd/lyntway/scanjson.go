package main

import (
	"encoding/json"
	"fmt"
)

// Machine-readable output.
//
// `history` has had --json since it was written and `scan` had text and
// GitHub annotations, which are both for a person reading a terminal or a
// pull request. Anything else — a dashboard, a ticket, a policy gate that
// wants more than an exit code — had to parse a tab-separated line whose
// shape nobody had promised to keep.
//
// What is deliberately not in here is the value. The text output prints
// the last four characters and a label because that is what identifies
// which key to revoke without being enough to use it, and a JSON document
// is more likely to be written to a log, a ticket or an artifact store
// than the terminal is. The same rule, more strictly.

type scanJSONFinding struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Label string `json:"label"`
	Class string `json:"class"`
	Last4 string `json:"last4"`
	// Upstream is set when the gateway could hold this key instead.
	Upstream string `json:"upstream,omitempty"`

	// Live is what the provider said when --check asked: "LIVE",
	// "revoked", "unknown", or "no check" where none exists. Absent when
	// nothing asked, so a consumer can tell "not checked" from "checked
	// and could not tell" — which are different facts and only one of
	// them is a reason to relax.
	Live string `json:"live,omitempty"`
}

type scanJSONReport struct {
	Findings []scanJSONFinding `json:"findings"`
	// Declared are values a secret-scanner configuration in this
	// repository says are not secrets. Reported separately rather than
	// dropped, because "a scanner was told to ignore this" is a fact a
	// reader may want and is not the same as "this is not a key".
	Declared []scanJSONFinding `json:"declared,omitempty"`
	Scanned  int               `json:"scanned"`
	Unit     string            `json:"unit"`

	// Skipped are the files nothing opened — binary, or over the size
	// limit. Present so a consumer can tell "clean" from "clean as far as
	// anything looked", which are different answers and were the same one
	// until 2 November 2026.
	Skipped []scanJSONSkip `json:"skipped,omitempty"`
}

type scanJSONSkip struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

func toJSONFindings(hits []keyHit) []scanJSONFinding {
	out := make([]scanJSONFinding, 0, len(hits))
	for _, h := range hits {
		f := scanJSONFinding{
			File: h.File, Line: h.Line, Label: h.Label,
			Class: h.Class, Last4: h.Last4, Upstream: h.Upstream,
		}
		if h.Live != livenessUnknown {
			f.Live = h.Live.String()
		}
		out = append(out, f)
	}
	return out
}

func printScanJSON(found, declared []keyHit, scanned int, unit string, skips []skippedFile) error {
	rep := scanJSONReport{
		Findings: toJSONFindings(found),
		Declared: toJSONFindings(declared),
		Scanned:  scanned,
		Unit:     unit,
	}
	for _, s := range skips {
		rep.Skipped = append(rep.Skipped, scanJSONSkip{File: s.Path, Reason: s.Reason})
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("writing the report: %w", err)
	}
	return nil
}

type historyJSONFinding struct {
	Label string   `json:"label"`
	Class string   `json:"class"`
	Last4 string   `json:"last4"`
	Files []string `json:"files"`
	// Commits carrying it, oldest first. The first is the one that
	// introduced it, which is the only one worth reading.
	Commits []string `json:"commits"`
	// InWorkingTree false is the dangerous case: a scan of the files on
	// disk calls this repository clean while the key is still in it.
	InWorkingTree bool `json:"in_working_tree"`
}

type historyJSONReport struct {
	Findings []historyJSONFinding `json:"findings"`
	// Commits that added content. A commit whose only change is a
	// deletion adds no lines and is not listed under --diff-filter=ACMR.
	Commits int `json:"commits_scanned"`
}

func printHistoryJSON(found []historyFinding, commits int) error {
	rep := historyJSONReport{Commits: commits, Findings: make([]historyJSONFinding, 0, len(found))}
	for _, f := range found {
		rep.Findings = append(rep.Findings, historyJSONFinding{
			Label: f.Label, Class: f.Class, Last4: f.Last4,
			Files: f.Files, Commits: f.Commits, InWorkingTree: f.InWorkingTree,
		})
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("writing the report: %w", err)
	}
	return nil
}
