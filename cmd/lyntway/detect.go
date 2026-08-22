package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Finding what is on this machine, and being honest about what is not.
//
// Every tool here keeps its settings somewhere different and changes where
// without warning. So detection is deliberately conservative: a file that
// is missing, unreadable or shaped unexpectedly is reported as "not found"
// rather than guessed at, because the failure mode of guessing is a
// rewritten config and a developer whose editor stopped working.
//
// The list is also deliberately short. Six tools somebody actually uses
// beats forty they do not, and each one here has been chosen because its
// settings file is documented and stable enough to edit.

// target is something on this machine that can be pointed at us.
type target struct {
	// Name is what a person calls it.
	Name string

	// Path is the file that would be changed, when there is one.
	Path string

	// Kind decides how it is configured.
	Kind targetKind

	// Found reports whether it is on this machine.
	Found bool

	// Why explains a target that cannot be used, in the terms of somebody
	// who is going to have to solve it another way.
	Why string
}

type targetKind string

const (
	kindEnv    targetKind = "shell"  // environment variables in a profile
	kindJSON   targetKind = "json"   // a JSON settings file
	kindMCP    targetKind = "mcp"    // MCP servers to wrap
	kindManual targetKind = "manual" // cannot be automated
)

func home() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// exists reports whether a path is a readable file.
func exists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// claudeCodeConfig is where Claude Code keeps its MCP servers.
// Same mcpServers structure as Claude Desktop, single location on all platforms.
func claudeCodeConfig() string {
	h := home()
	if h == "" {
		return ""
	}
	return filepath.Join(h, ".claude", "settings.json")
}

// claudeDesktopConfig is where Claude Desktop keeps its MCP servers.
func claudeDesktopConfig() string {
	h := home()
	if h == "" {
		return ""
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(h, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "Claude", "claude_desktop_config.json")
	default:
		return filepath.Join(h, ".config", "Claude", "claude_desktop_config.json")
	}
}

// shellProfile picks the file where environment variables belong.
//
// The login shell decides, not the operating system: somebody running zsh
// on Linux is not helped by having their bashrc edited.
func shellProfile() string {
	h := home()
	if h == "" {
		return ""
	}
	shell := filepath.Base(os.Getenv("SHELL"))
	switch shell {
	case "zsh":
		return filepath.Join(h, ".zshrc")
	case "bash":
		// .bash_profile on macOS, .bashrc elsewhere — which one a login
		// shell reads differs, and editing the wrong one leaves somebody
		// wondering why nothing happened.
		if runtime.GOOS == "darwin" {
			return filepath.Join(h, ".bash_profile")
		}
		return filepath.Join(h, ".bashrc")
	case "fish":
		return filepath.Join(h, ".config", "fish", "config.fish")
	default:
		return ""
	}
}

// scan looks at this machine and reports what it found.
func scan() []target {
	h := home()
	var found []target

	// The shell, which covers anything using the standard SDKs.
	profile := shellProfile()
	found = append(found, target{
		Name:  "Your shell (any app using the standard SDKs)",
		Path:  profile,
		Kind:  kindEnv,
		Found: profile != "",
		Why: func() string {
			if profile == "" {
				return "the shell in $SHELL is not one this knows how to edit; set OPENAI_BASE_URL yourself"
			}
			return ""
		}(),
	})

	// Claude Desktop, and the MCP servers it spawns.
	cd := claudeDesktopConfig()
	found = append(found, target{
		Name:  "Claude Desktop",
		Path:  cd,
		Kind:  kindMCP,
		Found: exists(cd),
	})

	// Claude Code, same MCP structure in a different file.
	cc := claudeCodeConfig()
	found = append(found, target{
		Name:  "Claude Code",
		Path:  cc,
		Kind:  kindMCP,
		Found: exists(cc),
	})

	// Cursor keeps its settings in the VS Code layout.
	cursor := ""
	if h != "" {
		switch runtime.GOOS {
		case "darwin":
			cursor = filepath.Join(h, "Library", "Application Support", "Cursor", "User", "settings.json")
		case "windows":
			cursor = filepath.Join(os.Getenv("APPDATA"), "Cursor", "User", "settings.json")
		default:
			cursor = filepath.Join(h, ".config", "Cursor", "User", "settings.json")
		}
	}
	found = append(found, target{
		Name:  "Cursor",
		Path:  cursor,
		Kind:  kindManual,
		Found: exists(cursor),
		Why: "only the models you add with your own key can be routed. Whatever " +
			"comes with Cursor's own subscription goes to their servers and " +
			"nothing here changes that. Two lines to paste, printed below.",
	})

	// Continue, in VS Code or JetBrains.
	cont := ""
	if h != "" {
		cont = filepath.Join(h, ".continue", "config.json")
	}
	found = append(found, target{
		Name:  "Continue",
		Path:  cont,
		Kind:  kindJSON,
		Found: exists(cont),
	})

	// Said out loud rather than omitted. Somebody whose team uses this
	// needs to know it is not covered, and finding that out later is worse.
	found = append(found, target{
		Name:  "JetBrains AI Assistant",
		Kind:  kindManual,
		Found: false,
		Why: "cannot be pointed anywhere else, so its traffic is invisible to this. " +
			"Nothing you configure changes that.",
	})

	return found
}

// mcpServers reads the servers a config declares.
func mcpServers(path string) (map[string]json.RawMessage, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Servers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("this file is not JSON this understands: %w", err)
	}
	return doc.Servers, nil
}

// alreadyWrapped reports whether a server entry already runs through us.
//
// Checked so running init twice does not nest the shim inside itself,
// which would work by accident and be impossible to reason about.
func alreadyWrapped(entry json.RawMessage) bool {
	var s struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(entry, &s); err != nil {
		return false
	}
	return strings.Contains(s.Command, "lyntway-mcp")
}
