// Package agentsecrets finds credentials an AI coding agent has already
// seen.
//
// # Why this exists apart from `lyntway scan`
//
// `lyntway scan` reads the project: the .env files and source a key gets
// committed from. That is the leak everybody already looks for, and it is
// not where the measured growth is. GitGuardian's State of Secrets Sprawl
// 2026 counted 24,008 unique secrets in MCP configuration files, and found
// public commits co-authored by a coding agent leaking at 3.2% against a
// 1.5% baseline. The files in this package are the other half of that: the
// transcripts, prompt histories, pasted buffers and shell snapshots an
// agent writes to disk as a side effect of being used.
//
// A key in a .env can be rotated and the file rewritten. A key in a
// transcript is in a file nobody edits, that no linter reads, that no
// pre-commit hook sees, and that is often synced to a laptop backup. It
// outlives the .env it came from.
//
// # What it will not do
//
// Nothing here sends anything anywhere. There is no switch that changes
// that: the package has no network code and the module it lives in has no
// third-party dependency that could acquire any.
//
// Nothing here is reported as a value. A finding carries the class, the
// label and the last four characters, which is what a person needs to go
// and revoke the right credential, and is not enough to use it. Printing
// a found key to a terminal puts it in the scrollback, the terminal's own
// buffer file, and whatever agent is reading that terminal — which is the
// problem this package is about.
//
// Nothing here rewrites a file it cannot parse. See redact.go: a SQLite
// store or an opaque cache is reported and left alone, because a
// byte-level substitution inside a database file corrupts it, and a
// corrupted agent history is somebody's working session destroyed by a
// security tool. The rule this whole repository is under — never be the
// reason somebody cannot use their own machine — applies hardest here,
// because this code runs on a laptop and touches files the owner did not
// write and cannot repair.
package agentsecrets

// Kind is what a file is to the person reading the report.
//
// It is not a parsing hint — Format is that. It exists because "a key in
// your prompt history" and "a key in a shell snapshot" are different
// sentences to act on: the first was typed by a person and the second was
// captured from an environment, and they are revoked and prevented
// differently.
type Kind string

const (
	// KindTranscript is the conversation: what was said, what tools ran,
	// and what those tools printed back.
	KindTranscript Kind = "transcript"

	// KindPrompts is what a person typed, kept for history and recall.
	KindPrompts Kind = "prompt history"

	// KindConfig is a settings or MCP configuration file. The 24,008
	// figure above is this one.
	KindConfig Kind = "configuration"

	// KindFileCopy is the agent's own copy of a file it edited, kept so a
	// change can be undone. A .env it opened lands here.
	KindFileCopy Kind = "file snapshot"

	// KindShellState is a captured shell: functions, aliases and, on some
	// setups, exported variables.
	KindShellState Kind = "shell state"

	// KindPasteCache is what was pasted in, held separately from the
	// transcript.
	KindPasteCache Kind = "paste cache"

	// KindLog is diagnostic output.
	KindLog Kind = "log"
)

// Format says how a file may be handled, which is a narrower question
// than what it contains.
type Format int

const (
	// FormatText is scanned line by line and may be redacted in place.
	FormatText Format = iota

	// FormatJSONL is one JSON object per line: scanned as text, and
	// redacted by rewriting string values so each line stays valid JSON.
	FormatJSONL

	// FormatJSON is a single JSON document, redacted the same way.
	FormatJSON

	// FormatOpaque is a store this package does not understand — SQLite,
	// a binary cache. It is scanned as bytes, because a credential in it
	// is still a credential, and it is never written to.
	FormatOpaque
)

// Source is one place to look.
type Source struct {
	// Tool is the agent's name as its own users say it.
	Tool string

	Kind   Kind
	Format Format

	// Path is a file, or a directory to walk.
	Path string

	// Dir reports whether Path is a directory whose contents are all of
	// this Kind.
	Dir bool

	// Why is one sentence on what this file is, shown when a finding is
	// in it. A person who has never heard of ~/.claude/shell-snapshots
	// cannot judge a finding there without it.
	Why string
}
