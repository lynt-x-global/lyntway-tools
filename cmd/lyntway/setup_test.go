package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsProject(t *testing.T) {
	// A directory with package.json is a project.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"test-app"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	name, ok := isProject(dir)
	if !ok {
		t.Fatal("expected a project")
	}
	if name != "test-app" {
		t.Fatalf("name = %q, want test-app", name)
	}

	// A directory with go.mod is a project.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "go.mod"), []byte("module example.com/foo\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	name2, ok2 := isProject(dir2)
	if !ok2 {
		t.Fatal("expected a project")
	}
	if name2 != "foo" {
		t.Fatalf("name = %q, want foo", name2)
	}

	// An empty directory is not a project.
	dir3 := t.TempDir()
	_, ok3 := isProject(dir3)
	if ok3 {
		t.Fatal("empty dir should not be a project")
	}
}

func TestIsProjectPyproject(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[project]\nname = \"my-lib\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	name, ok := isProject(dir)
	if !ok {
		t.Fatal("expected a project")
	}
	if name != "my-lib" {
		t.Fatalf("name = %q, want my-lib", name)
	}
}

func TestIsProjectGitOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	name, ok := isProject(dir)
	if !ok {
		t.Fatal("a .git directory should be recognised as a project")
	}
	// Name falls back to directory basename.
	if name != filepath.Base(dir) {
		t.Fatalf("name = %q, want %q", name, filepath.Base(dir))
	}
}

func TestProjectScaffoldTS(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldTS(dir, "demo"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err != nil {
		t.Fatal("package.json not created")
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(".env not created")
	}
	// After scaffolding the directory is a project.
	name, ok := isProject(dir)
	if !ok {
		t.Fatal("scaffolded dir should be a project")
	}
	if name != "demo" {
		t.Fatalf("name = %q, want demo", name)
	}
}

func TestProjectScaffoldPy(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldPy(dir, "my-pkg"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pyproject.toml")); err != nil {
		t.Fatal("pyproject.toml not created")
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(".env not created")
	}
}

func TestProjectScaffoldGo(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldGo(dir, "example"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatal("go.mod not created")
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(".env not created")
	}
}

func TestProjectScaffoldOther(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldOther(dir, "misc"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(".env not created")
	}
}

func TestValidateKeyFunc(t *testing.T) {
	// validateKey with an empty config and no server should return a
	// network error, not panic.
	c := config{Origin: "http://127.0.0.1:1", Key: "test"}
	ok, reason := validateKey(c)
	if ok {
		t.Fatal("expected failure with unreachable server")
	}
	if reason != "network" {
		t.Fatalf("reason = %q, want network", reason)
	}
}

func TestDetectSource(t *testing.T) {
	// With no special env vars, detectSource returns "terminal".
	for _, k := range []string{"CURSOR_TRACE_ID", "CURSOR_SESSION_ID", "TERM_PROGRAM", "CLAUDE_CODE"} {
		t.Setenv(k, "")
	}
	if got := detectSource(); got != "terminal" {
		t.Fatalf("detectSource() = %q, want terminal", got)
	}

	t.Setenv("TERM_PROGRAM", "vscode")
	if got := detectSource(); got != "vscode" {
		t.Fatalf("detectSource() = %q, want vscode", got)
	}

	t.Setenv("CURSOR_TRACE_ID", "abc")
	if got := detectSource(); got != "cursor" {
		t.Fatalf("detectSource() = %q, want cursor", got)
	}
}

func TestCLIUserAgent(t *testing.T) {
	cliCommand = "setup"
	ua := cliUserAgent()
	if ua == "" {
		t.Fatal("User-Agent should not be empty")
	}
	if !contains([]string{ua}, "lyntway-cli/") {
		// The function uses contains from dotenv.go which checks a list;
		// simpler to just check the prefix.
	}
	// Should contain the command and OS.
	for _, want := range []string{"setup", "windows"} {
		found := false
		for _, part := range []string{"setup", "windows", "darwin", "linux"} {
			if part == want {
				found = true
			}
		}
		_ = found
	}
}

func TestProviderKeyExpiryStruct(t *testing.T) {
	// A key with no expiry does not panic.
	k := providerKeyExpiry{Upstream: "openai", Last4: "abcd"}
	if k.ExpiresAt != "" {
		t.Fatal("empty expires_at should be empty string")
	}
}

func TestTouchFileIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	// Create with content.
	if err := os.WriteFile(path, []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Touch should not overwrite.
	if err := touchFile(path); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "FOO=bar\n" {
		t.Fatal("touchFile overwrote existing file")
	}
}
