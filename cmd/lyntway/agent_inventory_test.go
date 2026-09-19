package main

import (
	"os"
	"path/filepath"
	"testing"
)

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o755); err != nil {
		t.Fatal(err)
	}
}

func appsByName(apps []aiApp) map[string]aiApp {
	out := map[string]aiApp{}
	for _, a := range apps {
		out[a.Name] = a
	}
	return out
}

func TestInventoryOnEachOS(t *testing.T) {
	t.Run("windows", func(t *testing.T) {
		h := fixtureHost(t, "windows")
		touch(t, filepath.Join(h.LocalAppData, "Programs", "cursor", "Cursor.exe"))
		_ = os.MkdirAll(filepath.Join(h.LocalAppData, "Packages", "OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0"), 0o755)
		touch(t, filepath.Join(h.AppData, "npm", "claude.cmd"))
		procs := []procInfo{
			{PID: 1, Name: "Cursor", Path: `C:\Users\someone\AppData\Local\Programs\cursor\Cursor.exe`},
			{PID: 2, Name: "claude", Path: `C:\Users\someone\AppData\Local\AnthropicClaude\app-1.0\claude.exe`},
		}
		got := appsByName(inventory(h, procs))
		if a := got["Cursor"]; !a.Running || a.Kind != "desktop" {
			t.Errorf("Cursor: %+v", a)
		}
		if _, ok := got["ChatGPT"]; !ok {
			t.Error("a Store install of ChatGPT was missed")
		}
		// claude.exe under AnthropicClaude is the desktop app, not Claude
		// Code, whose own claude.cmd is installed but not running.
		if a := got["Claude"]; !a.Running {
			t.Errorf("Claude desktop: %+v", a)
		}
		if a, ok := got["Claude Code"]; !ok || a.Running {
			t.Errorf("Claude Code: %+v, %v", a, ok)
		}
	})

	t.Run("linux", func(t *testing.T) {
		h := fixtureHost(t, "linux")
		touch(t, filepath.Join(h.Root, "usr", "local", "bin", "ollama"))
		_ = os.MkdirAll(filepath.Join(h.Root, "opt", "Cursor"), 0o755)
		touch(t, filepath.Join(h.Home, ".local", "bin", "claude"))
		_ = os.MkdirAll(filepath.Join(h.Home, ".local", "share", "claude", "versions", "2.1.9"), 0o755)
		_ = os.MkdirAll(filepath.Join(h.Home, ".local", "share", "claude", "versions", "2.1.10"), 0o755)
		got := appsByName(inventory(h, []procInfo{{PID: 7, Name: "ollama", Path: "/usr/local/bin/ollama"}}))
		if a := got["Ollama"]; !a.Running || a.Kind != "local_model" {
			t.Errorf("Ollama: %+v", a)
		}
		if _, ok := got["Cursor"]; !ok {
			t.Error("Cursor in /opt was missed")
		}
		if a := got["Claude Code"]; a.Version != "2.1.10" {
			t.Errorf("Claude Code version %q: 2.1.10 is newer than 2.1.9", a.Version)
		}
	})

	t.Run("darwin extensions", func(t *testing.T) {
		h := fixtureHost(t, "darwin")
		ext := filepath.Join(h.Home, ".vscode", "extensions")
		for _, d := range []string{"github.copilot-1.200.0", "github.copilot-1.99.0", "continue.continue-1.0.5-darwin-arm64", "saoudrizwan.claude-dev-3.0.0", "ms-python.python-2025.1.0"} {
			_ = os.MkdirAll(filepath.Join(ext, d), 0o755)
		}
		// Cline was uninstalled; VS Code has not deleted the folder yet.
		_ = os.WriteFile(filepath.Join(ext, ".obsolete"), []byte(`{"saoudrizwan.claude-dev-3.0.0": true}`), 0o644)
		got := appsByName(inventory(h, []procInfo{{PID: 1, Name: "Electron", Path: "/Applications/Visual Studio Code.app/Contents/MacOS/Electron"}}))
		if a := got["GitHub Copilot in VS Code"]; a.Version != "1.200.0" || !a.Running {
			t.Errorf("Copilot: %+v", a)
		}
		if a := got["Continue in VS Code"]; a.Version != "1.0.5" {
			t.Errorf("Continue: %+v", a)
		}
		if _, ok := got["Cline in VS Code"]; ok {
			t.Error("an uninstalled extension awaiting deletion was reported as installed")
		}
		if len(got) != 2 {
			t.Errorf("only AI extensions belong in the list: %v", got)
		}
	})
}

func TestAnEditorsLauncherOnPathIsNotACLI(t *testing.T) {
	h := fixtureHost(t, "darwin")
	shim := filepath.Join(h.Home, "Library", "Application Support", "Code", "User", "globalStorage", "github.copilot-chat", "copilotCli")
	touch(t, filepath.Join(shim, "copilot"))
	h.Path = []string{shim}
	if _, ok := appsByName(inventory(h, nil))["GitHub Copilot CLI"]; ok {
		t.Error("Copilot Chat's launcher on the terminal PATH was reported as the Copilot CLI")
	}
}

func TestParseOSRelease(t *testing.T) {
	if got := parseOSRelease("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"); got != "Ubuntu 24.04" {
		t.Errorf("got %q", got)
	}
}
