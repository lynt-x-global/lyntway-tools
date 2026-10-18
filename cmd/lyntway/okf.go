package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Open Knowledge Format bundles — the files agents read for context.
//
// OKF is Google's specification, published October 2026: a directory of
// markdown files with YAML frontmatter, one file per "concept" — a table,
// a dataset, a metric, a runbook, an API. The spec requires exactly one
// field of every concept, `type`, and suggests `resource` for where the
// thing actually lives.
//
// # Why the scanner cares
//
// It already read these files. Every text file under the path is scanned,
// so a key in a concept document was always found. What was missing is
// what finding one *means*.
//
// A bundle is built to be portable and shared — that is the entire
// argument for having a format rather than a service. So a credential in
// one is not like a credential in a local .env: it travels to every team
// and every agent that consumes the bundle, and `resource` is precisely
// the field the format invites somebody to put a connection string in.
//
// This file does not scan anything. It recognises that a file is part of
// an OKF bundle so the report can say so.

// okfConcept is what a scanned file turns out to be, when it is one.
type okfConcept struct {
	// Bundle is the directory the concept belongs to.
	Bundle string
	// Type is the concept's required `type` field, verbatim.
	Type string
	// Title is its `title`, when it has one. The spec does not require it.
	Title string
}

// okfConceptOf reads the frontmatter of a markdown file and reports the
// concept it declares, if it declares one.
//
// The test is the presence of a `type` field in YAML frontmatter, because
// that is the one thing OKF requires. No YAML parser: the root module has
// no third-party dependencies, and the fields this needs are flat scalars
// on their own lines. A frontmatter block this cannot read yields no
// concept, which costs a sentence of context and never a finding — the
// scanning itself does not go through here.
func okfConceptOf(path string, body []byte) (okfConcept, bool) {
	if !strings.EqualFold(filepath.Ext(path), ".md") {
		return okfConcept{}, false
	}
	text := string(body)
	if !strings.HasPrefix(text, "---\n") && !strings.HasPrefix(text, "---\r\n") {
		return okfConcept{}, false
	}
	rest := text[strings.Index(text, "\n")+1:]
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return okfConcept{}, false
	}

	var c okfConcept
	for _, line := range strings.Split(rest[:end], "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		// Only top-level keys. An indented line belongs to a nested
		// structure and "  type: x" under something else is not the
		// concept's type.
		if key != strings.TrimLeft(key, " \t") {
			continue
		}
		value = strings.TrimSpace(strings.Trim(strings.TrimSpace(value), `"'`))
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "type":
			c.Type = value
		case "title":
			c.Title = value
		}
	}
	if c.Type == "" {
		return okfConcept{}, false
	}
	c.Bundle = okfBundleOf(path)
	return c, true
}

// okfBundleOf names the bundle a concept belongs to.
//
// The nearest ancestor directory holding an index.md, which the spec names
// for navigation; failing that the file's own directory. A guess, and it
// is only ever used to print a name, so a wrong one costs a word.
func okfBundleOf(path string) string {
	dir := filepath.Dir(path)
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "index.md")); err == nil {
			return filepath.ToSlash(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return filepath.ToSlash(filepath.Dir(path))
}

// okfSentence is what the scan report adds when any finding sits in an
// OKF concept document.
//
// It says what is different about these files rather than repeating the
// advice above it. The rotate advice already applies; what a reader does
// not know is that this particular copy is one the format exists to
// distribute.
func okfSentence(concepts []okfConcept) string {
	if len(concepts) == 0 {
		return ""
	}
	bundles := map[string]bool{}
	for _, c := range concepts {
		bundles[c.Bundle] = true
	}
	what := "an Open Knowledge Format bundle"
	if len(bundles) > 1 {
		what = "Open Knowledge Format bundles"
	}
	return "Some of these are in " + what + " — the context files agents read. A bundle is " +
		"built to be copied between teams and tools, so a key in one travels with it; the " +
		"`resource` field in particular is where the format invites a connection string."
}
