package agentsecrets

import "path/filepath"

// Host is the machine being looked at, passed in rather than read from the
// environment so a test can describe a laptop it is not running on. Every
// path below is derived from these fields and nothing else.
type Host struct {
	// GOOS is the runtime.GOOS value for the machine.
	GOOS string

	// Home is the user's home directory.
	Home string

	// AppData and LocalAppData are the Windows roaming and local
	// application-data directories. Empty elsewhere, and a source that
	// needs one is omitted rather than guessed at.
	AppData      string
	LocalAppData string
}

func (h Host) join(parts ...string) string {
	if h.Home == "" {
		return ""
	}
	return filepath.Join(append([]string{h.Home}, parts...)...)
}

// appSupport is where a desktop application keeps per-user state. The same
// three-way split cmd/lyntway's inventory uses, repeated here rather than
// shared because this package must not import the CLI.
func (h Host) appSupport(parts ...string) string {
	switch h.GOOS {
	case "darwin":
		return h.join(append([]string{"Library", "Application Support"}, parts...)...)
	case "windows":
		if h.AppData == "" {
			return ""
		}
		return filepath.Join(append([]string{h.AppData}, parts...)...)
	default:
		return h.join(append([]string{".config"}, parts...)...)
	}
}

// Sources lists every place a coding agent is known to leave something a
// credential can be in.
//
// # How this list was made
//
// By reading a machine that has these tools on it, not from
// documentation. None of these layouts is a published interface and all of
// them change; a path that has moved produces no finding and is counted as
// a source that did not exist, never as a clean result. That is why Scan
// reports what it read rather than a verdict.
//
// # Why it is deliberately wider than "the transcript"
//
// The transcript is the obvious file and not the only one. On the machine
// this was written against, Claude Code alone keeps eleven directories of
// state beside it: the prompt history, snapshots of files it edited — a
// .env it opened lands there — the shell it captured, the paste buffer,
// and per-session environment directories. Each is a plain file on disk
// that no linter reads and no pre-commit hook sees.
//
// Listing a path here does not assert a secret is in it. It asserts that
// if one were, nothing else would find it.
func Sources(h Host) []Source {
	if h.Home == "" {
		return nil
	}
	var out []Source
	add := func(tool string, kind Kind, format Format, dir bool, why, path string) {
		if path == "" {
			return
		}
		out = append(out, Source{Tool: tool, Kind: kind, Format: format, Path: path, Dir: dir, Why: why})
	}

	// ---- Claude Code -------------------------------------------------
	//
	// Transcripts are one JSONL file per session under a directory named
	// for the project path. 401 of them on the machine this was written
	// against, going back months.
	add("Claude Code", KindTranscript, FormatJSONL, true,
		"every session's messages and tool output, one file per session",
		h.join(".claude", "projects"))
	add("Claude Code", KindPrompts, FormatJSONL, false,
		"what you typed, across every project",
		h.join(".claude", "history.jsonl"))
	add("Claude Code", KindFileCopy, FormatOpaque, true,
		"the agent's own copies of files it edited, kept so an edit can be undone",
		h.join(".claude", "file-history"))
	add("Claude Code", KindShellState, FormatText, true,
		"a captured shell, including anything exported in it",
		h.join(".claude", "shell-snapshots"))
	add("Claude Code", KindPasteCache, FormatOpaque, true,
		"content pasted into a session, held apart from the transcript",
		h.join(".claude", "paste-cache"))
	add("Claude Code", KindShellState, FormatOpaque, true,
		"per-session environment captured at launch",
		h.join(".claude", "session-env"))
	add("Claude Code", KindLog, FormatText, true,
		"diagnostic output, which records request and response bodies on some settings",
		h.join(".claude", "debug"))
	add("Claude Code", KindConfig, FormatJSON, false,
		"MCP servers and their arguments, where an API key is passed as a command-line flag or an env entry",
		h.join(".claude.json"))
	add("Claude Code", KindConfig, FormatJSON, false,
		"settings, including MCP servers",
		h.join(".claude", "settings.json"))

	// ---- Codex -------------------------------------------------------
	add("Codex", KindPrompts, FormatJSONL, false,
		"what you typed",
		h.join(".codex", "history.jsonl"))
	add("Codex", KindConfig, FormatText, false,
		"configuration, including MCP servers",
		h.join(".codex", "config.toml"))
	add("Codex", KindLog, FormatText, true,
		"diagnostic output",
		h.join(".codex", "log"))
	add("Codex", KindTranscript, FormatOpaque, false,
		"a session store this does not parse; scanned as bytes and never written to",
		h.join(".codex", "goals_1.sqlite"))

	// ---- Cursor ------------------------------------------------------
	//
	// Cursor keeps its chat in a SQLite database. Scanned as bytes: the
	// text of a conversation is stored readable inside it, so a key in a
	// conversation is findable without a SQL driver — which this module
	// cannot have, because it carries no third-party dependency. Reported
	// without a line number and never rewritten.
	add("Cursor", KindTranscript, FormatOpaque, false,
		"the chat database; found by scanning its bytes, so there is no line to point at",
		h.appSupport("Cursor", "User", "globalStorage", "state.vscdb"))
	add("Cursor", KindConfig, FormatJSON, false,
		"MCP servers",
		h.join(".cursor", "mcp.json"))

	// ---- Windsurf ----------------------------------------------------
	add("Windsurf", KindConfig, FormatJSON, false,
		"MCP servers",
		h.join(".codeium", "windsurf", "mcp_config.json"))

	// ---- Gemini CLI --------------------------------------------------
	add("Gemini CLI", KindConfig, FormatJSON, false,
		"settings, including MCP servers",
		h.join(".gemini", "settings.json"))
	add("Gemini CLI", KindPrompts, FormatText, true,
		"session state",
		h.join(".gemini", "tmp"))

	// ---- Cline / Aider / Continue ------------------------------------
	add("Cline", KindTranscript, FormatOpaque, true,
		"task history",
		h.join(".cline", "data"))
	add("Aider", KindPrompts, FormatText, false,
		"what you typed",
		h.join(".aider.input.history"))
	add("Aider", KindTranscript, FormatText, false,
		"the conversation, as Aider writes it alongside a project",
		h.join(".aider.chat.history.md"))
	add("Continue", KindConfig, FormatJSON, false,
		"configuration, including model credentials",
		h.join(".continue", "config.json"))

	return out
}

// ProjectSources are the per-project files, which live beside the code
// rather than under a home directory.
//
// Separate from Sources because they are found by being in a directory
// somebody names, not by existing in a known place, and because a repo's
// .mcp.json is committed — a key in one is already shared with everybody
// who cloned it, which is a different sentence from a key in a file only
// this laptop has.
func ProjectSources(dir string) []Source {
	if dir == "" {
		return nil
	}
	return []Source{
		{Tool: "Claude Code", Kind: KindConfig, Format: FormatJSON, Path: filepath.Join(dir, ".mcp.json"),
			Why: "MCP servers for this project, and this file is usually committed"},
		{Tool: "Cursor", Kind: KindConfig, Format: FormatJSON, Path: filepath.Join(dir, ".cursor", "mcp.json"),
			Why: "MCP servers for this project"},
		{Tool: "VS Code", Kind: KindConfig, Format: FormatJSON, Path: filepath.Join(dir, ".vscode", "mcp.json"),
			Why: "MCP servers for this project"},
		{Tool: "Aider", Kind: KindTranscript, Format: FormatText, Path: filepath.Join(dir, ".aider.chat.history.md"),
			Why: "the conversation Aider kept in this project"},
	}
}
