package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A stray argument used to fall through and start the gateway: three
// listeners, a generated key and a receipts file in whatever directory the
// person was standing in, with nothing printed. `lyntway-dbgateway version`
// is the form the main CLI takes, so it is the one a person types.
func TestStrayArgumentIsRefusedRatherThanStartingTheGateway(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })

	// Run from an empty directory, so anything the gateway would create on
	// starting is visible as a file that should not be there.
	dir := t.TempDir()
	t.Chdir(dir)

	for _, arg := range []string{"version", "-version", "--version"} {
		os.Args = []string{"lyntway-dbgateway", arg}
		if code := run(); code != 0 {
			t.Errorf("%s: exit %d, want 0 — it should print the version", arg, code)
		}
	}
	for _, arg := range []string{"help", "-h", "-help", "--help"} {
		os.Args = []string{"lyntway-dbgateway", arg}
		if code := run(); code != 0 {
			t.Errorf("%s: exit %d, want 0 — it should print the usage", arg, code)
		}
	}
	for _, arg := range []string{"strt", "start", "--recipts", "postgres://host/db"} {
		os.Args = []string{"lyntway-dbgateway", arg}
		if code := run(); code != 2 {
			t.Errorf("%s: exit %d, want 2 — an unrecognised argument must be refused", arg, code)
		}
	}

	left, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		names := make([]string, 0, len(left))
		for _, e := range left {
			names = append(names, e.Name())
		}
		t.Fatalf("answering an argument created %v in the working directory; it started the gateway", names)
	}
}

// The position file beside the receipts is what lets a restart continue a
// chain instead of writing a second genesis receipt for it. A
// working-directory default made that conditional on being started twice
// from the same directory, which a service manager does not promise.
func TestDefaultReceiptsPathDoesNotDependOnTheWorkingDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())

	got := defaultReceiptsPath()
	want := filepath.Join(home, ".lyntway", "receipts", "dbgateway", "receipts.jsonl")
	if got != want {
		t.Fatalf("default receipts path is %q, want %q", got, want)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("%q is relative, so the chain position moves with the working directory", got)
	}
}

// Moving a running installation's receipts would cause the very split this
// change exists to prevent: the old file keeps its position, the new one
// starts another chain at seq 0, and one database's history sits in two
// files that each look complete.
func TestAnExistingReceiptsFileInTheWorkingDirectoryIsStillUsed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "receipts.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := defaultReceiptsPath(); got != "./receipts.jsonl" {
		t.Fatalf("default receipts path is %q; an installation already appending to ./receipts.jsonl must keep its chain", got)
	}
}
