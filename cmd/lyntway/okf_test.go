package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOKFConceptIsRecognised(t *testing.T) {
	const body = `---
type: BigQuery Table
title: Orders
description: One row per completed customer order.
resource: postgresql://analytics:Wr3housePw22@warehouse.acme.internal:5432/sales
---
# Schema
`
	c, ok := okfConceptOf("knowledge/tables/orders.md", []byte(body))
	if !ok {
		t.Fatal("not recognised as a concept")
	}
	if c.Type != "BigQuery Table" {
		t.Errorf("type is %q, want %q", c.Type, "BigQuery Table")
	}
	if c.Title != "Orders" {
		t.Errorf("title is %q, want %q", c.Title, "Orders")
	}
}

// `type` is the only field OKF requires of a concept, so it is the only
// thing the test can be. Everything else is optional and a bundle in the
// wild will be missing most of it.
func TestOKFNeedsOnlyType(t *testing.T) {
	if _, ok := okfConceptOf("a.md", []byte("---\ntype: Runbook\n---\nbody\n")); !ok {
		t.Error("a concept with only a type was not recognised")
	}
}

func TestOKFDoesNotClaimEveryMarkdownFile(t *testing.T) {
	cases := []struct{ name, path, body string }{
		// Jekyll, Hugo and every static site generator put frontmatter in
		// markdown. Without a `type` it is not an OKF concept, and calling
		// it one would put the bundle sentence under a finding in a blog
		// post.
		{"blog post frontmatter", "post.md", "---\nlayout: post\ntitle: Hello\n---\n# Hi\n"},
		{"no frontmatter", "README.md", "# A readme\n\nSome prose.\n"},
		{"unterminated frontmatter", "x.md", "---\ntype: Thing\nnever closed\n"},
		{"not markdown", "config.yaml", "---\ntype: Thing\n---\n"},
		// An indented key belongs to something nested. "  type:" under a
		// list item is not the document's type.
		{"nested type only", "y.md", "---\nspec:\n  type: nested\n---\nbody\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, ok := okfConceptOf(c.path, []byte(c.body)); ok {
				t.Errorf("claimed %q as an OKF concept of type %q", c.path, got.Type)
			}
		})
	}
}

// The bundle is the nearest ancestor with an index.md, which is what the
// spec names for navigation. It is only ever printed, so being wrong costs
// a word — but being wrong in the obvious case would be sloppy.
func TestOKFBundleIsTheDirectoryWithTheIndex(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "knowledge", "tables")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "knowledge", "index.md"), []byte("---\ntype: Index\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := okfBundleOf(filepath.Join(deep, "orders.md"))
	want := filepath.ToSlash(filepath.Join(dir, "knowledge"))
	if got != want {
		t.Errorf("bundle is %q, want %q", got, want)
	}
}

// The sentence appears only when a finding is actually in a bundle. Adding
// it to every scan would be noise, and noise is how advice gets skipped.
func TestOKFSentenceOnlyWhenThereIsABundle(t *testing.T) {
	if s := okfSentence(nil); s != "" {
		t.Errorf("sentence with no concepts: %q", s)
	}
	one := okfSentence([]okfConcept{{Bundle: "knowledge"}})
	if !strings.Contains(one, "an Open Knowledge Format bundle") {
		t.Errorf("singular reads wrong: %q", one)
	}
	two := okfSentence([]okfConcept{{Bundle: "a"}, {Bundle: "b"}})
	if !strings.Contains(two, "Open Knowledge Format bundles") {
		t.Errorf("plural reads wrong: %q", two)
	}
	// Two concepts in ONE bundle is still one bundle.
	same := okfSentence([]okfConcept{{Bundle: "a"}, {Bundle: "a"}})
	if !strings.Contains(same, "an Open Knowledge Format bundle") {
		t.Errorf("two concepts in one bundle read as plural: %q", same)
	}
}

// The end-to-end claim: a password in a concept document's resource field
// is found, and the report says why that copy matters.
func TestScanFindsACredentialInAnOKFBundleAndSaysWhatItIs(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "knowledge")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "index.md"), []byte("---\ntype: Index\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	concept := "---\ntype: BigQuery Table\ntitle: Orders\nresource: postgresql://analytics:Wr3housePw22@warehouse.acme.internal:5432/sales\n---\n# Schema\n"
	if err := os.WriteFile(filepath.Join(bundle, "orders.md"), []byte(concept), 0o600); err != nil {
		t.Fatal(err)
	}

	hits, _, err := scanPaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 finding, got %d", len(hits))
	}
	if hits[0].Concept == nil {
		t.Fatal("the finding does not know it is in an OKF concept")
	}
	if hits[0].Concept.Title != "Orders" {
		t.Errorf("concept title is %q", hits[0].Concept.Title)
	}
	if advice := scanAdvice(hits); !strings.Contains(advice, "Open Knowledge Format") {
		t.Errorf("the advice does not mention the bundle:\n%s", advice)
	}
}

// A finding outside any bundle must not drag the sentence in with it.
func TestScanOfAPlainEnvSaysNothingAboutOKF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("DATABASE_URL=postgres://appuser:S3cretPassw0rd@db.internal:5432/prod\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hits, _, err := scanPaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 finding, got %d — a password in a DSN is the most common secret in a repository", len(hits))
	}
	if strings.Contains(scanAdvice(hits), "Open Knowledge Format") {
		t.Error("the bundle sentence appeared for a plain .env")
	}
}
