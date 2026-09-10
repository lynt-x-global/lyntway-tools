package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Reading a project's .env files, and rewriting the lines that hold a
// provider key.
//
// The parser is deliberately small. Every dotenv loader disagrees with
// every other about escapes, interpolation and multi-line values, and a
// parser that tried to match one of them would silently mis-read files
// written for another. What is needed here is narrower: find the lines
// that assign a provider key, read the value well enough to recognise
// its shape and send it to the server, and change nothing else. A line
// this cannot read is left exactly as it was.

// envFiles are the files looked at, in the order most loaders read them.
// .env.example is excluded on purpose: it holds placeholders, and a
// placeholder migrated to the server would be a stored key that is wrong.
var envFiles = []string{".env", ".env.local", ".env.development", ".env.development.local", ".env.production", ".env.production.local"}

// envLine is one line of a .env file as this understands it.
type envLine struct {
	// Raw is the line exactly as read, used for everything not rewritten.
	Raw string

	// Key and Value are set when the line is an assignment this can read.
	Key   string
	Value string

	// Export records a leading `export`, so the rewritten line keeps it.
	Export bool
}

// parseEnv splits a file into lines, reading the assignments it can.
func parseEnv(body string) []envLine {
	raw := strings.Split(body, "\n")
	out := make([]envLine, 0, len(raw))
	for _, line := range raw {
		l := envLine{Raw: line}
		l.Key, l.Value, l.Export = parseEnvLine(line)
		out = append(out, l)
	}
	return out
}

// parseEnvLine reads KEY=VALUE with the forms found in practice: an
// optional `export`, single or double quotes, and a trailing comment on an
// unquoted value. ok is false for blank lines, comments and anything
// shaped differently.
func parseEnvLine(line string) (key, value string, export bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", "", false
	}
	if rest, ok := strings.CutPrefix(s, "export "); ok {
		export = true
		s = strings.TrimSpace(rest)
	}
	k, v, found := strings.Cut(s, "=")
	if !found {
		return "", "", false
	}
	k = strings.TrimSpace(k)
	if !validEnvKey(k) {
		return "", "", false
	}
	v = strings.TrimSpace(v)
	switch {
	case len(v) >= 2 && (v[0] == '"' || v[0] == '\''):
		q := v[0]
		if end := strings.IndexByte(v[1:], q); end >= 0 {
			v = v[1 : end+1]
		}
		// An unterminated quote is read as the literal text: better to
		// see a wrong last4 in the plan than to skip a real key.
	default:
		// A comment after an unquoted value starts at a # preceded by
		// whitespace. A # inside the value is part of it.
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		} else if i := strings.Index(v, "\t#"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
	}
	return k, v, export
}

func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// providerShape is one provider's key as it appears in a .env file.
//
// Detection is by variable name and by value prefix where the provider
// has one. A value prefix that names a different provider than the
// variable does is a conflict, reported rather than resolved: storing an
// Anthropic key under "openai" produces a 401 on every call and a plan
// that looked right.
type providerShape struct {
	Upstream string
	Vars     []string
	Prefix   string
}

// providerShapes is checked in order, so that the more specific prefix
// (sk-ant-) is matched before the one it also begins with (sk-).
var providerShapes = []providerShape{
	{Upstream: "anthropic", Vars: []string{"ANTHROPIC_API_KEY"}, Prefix: "sk-ant-"},
	{Upstream: "openai", Vars: []string{"OPENAI_API_KEY"}, Prefix: "sk-"},
	{Upstream: "gemini", Vars: []string{"GEMINI_API_KEY", "GOOGLE_API_KEY"}, Prefix: "AIza"},
	{Upstream: "xai", Vars: []string{"XAI_API_KEY"}, Prefix: "xai-"},
	{Upstream: "mistral", Vars: []string{"MISTRAL_API_KEY"}},
	{Upstream: "composio", Vars: []string{"COMPOSIO_API_KEY"}},
	{Upstream: "arcade", Vars: []string{"ARCADE_API_KEY"}},
}

// candidate is a provider key found in a file.
type candidate struct {
	File     string
	Line     int // index into the parsed lines
	Var      string
	Upstream string
	Value    string // never printed; last4 is what a person sees
	Export   bool

	// Skip explains a line that was recognised but will not be migrated.
	Skip string
}

func (c candidate) last4() string {
	if len(c.Value) <= 4 {
		return strings.Repeat("•", len(c.Value))
	}
	return c.Value[len(c.Value)-4:]
}

// classify decides which upstream a variable holds a key for.
//
// extra are upstream names the server lists for this account, matched
// against the prefix of a *_API_KEY variable: LAWMATICS_API_KEY for an
// upstream called lawmatics. lyntwayKey is what a line already migrated
// carries, and is skipped so running this twice changes nothing.
func classify(key, value string, extra []string, lyntwayKey string) (upstream, skip string, ok bool) {
	byName := ""
	for _, p := range providerShapes {
		for _, v := range p.Vars {
			if v == key {
				byName = p.Upstream
			}
		}
	}
	byValue := ""
	for _, p := range providerShapes {
		if p.Prefix != "" && strings.HasPrefix(value, p.Prefix) {
			byValue = p.Upstream
			break
		}
	}
	if byName == "" {
		if name, isKey := strings.CutSuffix(key, "_API_KEY"); isKey {
			lower := strings.ToLower(name)
			for _, e := range extra {
				if strings.EqualFold(e, lower) {
					byName = e
				}
			}
		}
	}
	if byName == "" && byValue == "" {
		return "", "", false
	}

	switch {
	case value == "":
		return "", "", false
	case lyntwayKey != "" && (value == lyntwayKey || strings.HasPrefix(value, lyntwayKey+"~")):
		return "", "already routed through Lyntway", true
	case strings.Contains(value, "~"):
		return "", "looks like two keys joined by a tilde; store only the provider's", true
	case len(value) < 8 || strings.ContainsAny(value, " <>$") || looksLikePlaceholder(value):
		return "", "looks like a placeholder, not a key", true
	case byName != "" && byValue != "" && byName != byValue:
		return "", fmt.Sprintf("named for %s but shaped like a %s key; not guessed at", byName, byValue), true
	case byName != "":
		return byName, "", true
	default:
		return byValue, "", true
	}
}

// looksLikePlaceholder catches the values people leave in a checked-in
// .env so the shape of the file is known: they are not keys, and storing
// one on the server would be a stored key that fails on first use.
func looksLikePlaceholder(value string) bool {
	lower := strings.ToLower(value)
	for _, w := range []string{"your-key", "your_key", "yourkey", "xxxx", "changeme", "change-me", "change_me", "placeholder", "example", "..."} {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// findCandidates reads every .env file in dir and reports what it holds.
func findCandidates(dir string, extra []string, lyntwayKey string) ([]candidate, error) {
	var out []candidate
	var seen int
	for _, name := range envFiles {
		path := filepath.Join(dir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		seen++
		for i, l := range parseEnv(string(body)) {
			if l.Key == "" {
				continue
			}
			upstream, skip, ok := classify(l.Key, l.Value, extra, lyntwayKey)
			if !ok {
				continue
			}
			out = append(out, candidate{File: path, Line: i, Var: l.Key, Upstream: upstream, Value: l.Value, Export: l.Export, Skip: skip})
		}
	}
	if seen == 0 {
		return nil, fmt.Errorf("no .env file in %s", dir)
	}
	return out, nil
}

// gatewayURL is where an SDK for this upstream should point.
//
// OpenAI's SDK expects the versioned path in its base URL; the others
// append their own. Getting this wrong is a 404 on every call, so it is
// kept in one place and shared with the shell block.
func gatewayURL(origin, upstream string) string {
	if upstream == "openai" {
		return origin + "/gw/openai/v1"
	}
	return origin + "/gw/" + upstream
}

// providerBaseURLs maps upstream names to the base URLs the provider's own
// documentation tells people to set. A base URL pointing here is not a
// deliberate choice — it is the default, and the migration should replace
// it. A URL pointing anywhere else was set on purpose and is left alone.
var providerBaseURLs = map[string][]string{
	"openai":    {"https://api.openai.com/v1", "https://api.openai.com"},
	"anthropic": {"https://api.anthropic.com", "https://api.anthropic.com/v1"},
	"gemini":    {"https://generativelanguage.googleapis.com", "https://generativelanguage.googleapis.com/v1"},
	"xai":       {"https://api.x.ai", "https://api.x.ai/v1"},
	"mistral":   {"https://api.mistral.ai", "https://api.mistral.ai/v1"},
}

// isProviderURL reports whether url is the provider's own address for this
// upstream. Compared case-insensitively with trailing slashes stripped.
func isProviderURL(upstream, url string) bool {
	url = strings.TrimRight(strings.ToLower(strings.TrimSpace(url)), "/")
	for _, p := range providerBaseURLs[upstream] {
		if url == strings.TrimRight(strings.ToLower(p), "/") {
			return true
		}
	}
	return false
}

// rewriteEnv replaces the provider-key lines in one file and adds the
// base URLs the SDKs need, inside the fenced block.
//
// The key line is changed in place rather than moved into the block,
// because loaders differ on whether the first or last definition of a
// variable wins, and a file with two definitions would route through us
// under one loader and not the other. Base URL lines that point at the
// provider's own address are rewritten in place to the gateway; a URL
// pointing anywhere else was set on purpose and is left alone. Missing
// base URLs are added in the fenced block.
//
// Anthropic is the exception to `VAR=<lyntway key>`. Its SDK sends
// ANTHROPIC_API_KEY as x-api-key, which the gateway forwards to the
// provider and does not authenticate. The Lyntway key has to arrive as a
// bearer, and that SDK reads it from ANTHROPIC_AUTH_TOKEN, so the original
// variable is emptied and the token line is added instead.
func rewriteEnv(path string, items []candidate, c config) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	saved, err := backup(path)
	if err != nil {
		return "", err
	}

	lines := parseEnv(string(body))
	defined := map[string]bool{}
	for _, l := range lines {
		if l.Key != "" {
			defined[l.Key] = true
		}
	}

	var add []string
	for _, it := range items {
		if it.Line >= len(lines) || lines[it.Line].Key != it.Var {
			return "", fmt.Errorf("%s changed while this was running; nothing written", path)
		}
		prefix := ""
		if it.Export {
			prefix = "export "
		}
		value := c.Key
		if it.Upstream == "anthropic" {
			value = ""
		}
		lines[it.Line] = envLine{Raw: fmt.Sprintf("%s%s=%s", prefix, it.Var, value), Key: it.Var, Value: value, Export: it.Export}

		base := strings.TrimSuffix(it.Var, "_API_KEY") + "_BASE_URL"
		gw := gatewayURL(c.Origin, it.Upstream)
		if !defined[base] {
			add = append(add, fmt.Sprintf("%s=%s", base, gw))
			defined[base] = true
		} else {
			// A base URL pointing at the provider's own address is the
			// default, not a deliberate choice. Leaving it means the
			// migration says "done" while traffic still goes direct.
			for i, l := range lines {
				if l.Key == base && isProviderURL(it.Upstream, l.Value) {
					lines[i] = envLine{Raw: fmt.Sprintf("%s=%s", base, gw), Key: base, Value: gw}
					break
				}
			}
		}
		if it.Upstream == "anthropic" && !defined["ANTHROPIC_AUTH_TOKEN"] {
			add = append(add, "ANTHROPIC_AUTH_TOKEN="+c.Key)
			defined["ANTHROPIC_AUTH_TOKEN"] = true
		}
	}

	raws := make([]string, len(lines))
	for i, l := range lines {
		raws[i] = l.Raw
	}
	text := strings.Join(raws, "\n")

	// A block from an earlier run keeps its lines; the new ones join it.
	existing := blockLines(text)
	text = removeBlock(text)
	block := []string{
		markerStart,
		"# Added by `lyntway keys migrate`. Remove with `lyntway undo`.",
		"# Provider keys are held by Lyntway; the SDKs are pointed at the gateway.",
	}
	block = append(block, existing...)
	for _, a := range add {
		if !contains(existing, a) {
			block = append(block, a)
		}
	}
	block = append(block, markerEnd, "")

	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	// Written with the mode the file had: a .env is often 0600 already,
	// and one that was 0644 is not made stricter behind the owner's back.
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(path, []byte(text+strings.Join(block, "\n")), mode); err != nil {
		return "", err
	}
	return saved, nil
}

// blockLines returns the assignments inside an existing fenced block.
func blockLines(body string) []string {
	start := strings.Index(body, markerStart)
	if start < 0 {
		return nil
	}
	end := strings.Index(body[start:], markerEnd)
	if end < 0 {
		return nil
	}
	var out []string
	for _, l := range strings.Split(body[start+len(markerStart):start+end], "\n") {
		if k, _, _ := parseEnvLine(l); k != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// gitignoreBackupLine is the pattern that keeps backups out of a commit.
// A backup holds the original key, which is the one thing this whole
// command exists to keep out of the repository.
const gitignoreBackupLine = ".env*.lyntway-backup-*"

// ignoreBackups adds the pattern to an existing .gitignore. A project
// without one is left without one: creating files a person did not ask
// for is a different decision from editing one they have.
func ignoreBackups(dir string) (added bool, err error) {
	path := filepath.Join(dir, ".gitignore")
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	for _, l := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(l) == gitignoreBackupLine {
			return false, nil
		}
	}
	text := string(body)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return true, os.WriteFile(path, []byte(text+gitignoreBackupLine+"\n"), 0o644)
}

// unignoreBackups removes the line ignoreBackups added, and nothing else.
func unignoreBackups(dir string) (removed bool, err error) {
	path := filepath.Join(dir, ".gitignore")
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var keep []string
	for _, l := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(l) == gitignoreBackupLine {
			removed = true
			continue
		}
		keep = append(keep, l)
	}
	if !removed {
		return false, nil
	}
	return true, os.WriteFile(path, []byte(strings.Join(keep, "\n")), 0o644)
}

// sortedFiles lists the distinct files a set of candidates touches, in
// the order they were found.
func sortedFiles(items []candidate) []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		if !seen[it.File] {
			seen[it.File] = true
			out = append(out, it.File)
		}
	}
	sort.Strings(out)
	return out
}
