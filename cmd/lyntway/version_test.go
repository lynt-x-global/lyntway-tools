package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// flag.Parse owns every argument beginning with a dash and answers an
// undefined one with "flag provided but not defined" and exit 2. The
// dispatch listed -v, --version, -h and --help as aliases, so the code read
// as though it handled them while flag.Parse made them unreachable:
// `lyntway --version` answered a version question with a parse error.
//
// Built and run as a binary because the forms under test are decided before
// flag.Parse, which exits the process on its own.
func TestVersionAndHelpAnswerEveryFormAPersonTypes(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "lyntway")
	build := exec.Command("go", "build", "-ldflags", "-X main.version=9.9.9-test", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the CLI: %v\n%s", err, out)
	}

	for _, arg := range []string{"version", "-v", "-version", "--version"} {
		out, err := exec.Command(bin, arg).CombinedOutput()
		if err != nil {
			t.Errorf("lyntway %s: %v\n%s", arg, err, out)
			continue
		}
		if got := strings.TrimSpace(string(out)); got != "9.9.9-test" {
			t.Errorf("lyntway %s printed %q, want the version", arg, got)
		}
	}

	for _, arg := range []string{"help", "-h", "-help", "--help"} {
		out, err := exec.Command(bin, arg).CombinedOutput()
		if err != nil {
			t.Errorf("lyntway %s: %v\n%s", arg, err, out)
			continue
		}
		if !strings.Contains(string(out), "Usage") {
			t.Errorf("lyntway %s did not print the usage:\n%s", arg, out)
		}
	}
}
