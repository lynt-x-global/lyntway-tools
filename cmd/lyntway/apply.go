package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Changing somebody's machine, reversibly.
//
// This edits files a developer depends on to work. That earns a standard
// higher than "it worked on mine": nothing is written without a backup
// beside it, every change is fenced by markers so it can be found again,
// and `lyntway undo` puts everything back. A tool that can break your
// editor and cannot unbreak it is not one anybody should run.
//
// Nothing is written at all until the person has seen the list and said
// yes. A tool that reconfigures a machine on launch is a tool people
// uninstall.

const (
	markerStart = "# >>> lyntway >>>"
	markerEnd   = "# <<< lyntway <<<"
)

// backup copies a file beside itself before it is changed.
//
// Named with the time rather than overwritten, so running init twice does
// not destroy the original state the first run preserved.
func backup(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	dest := fmt.Sprintf("%s.lyntway-backup-%s", path, time.Now().UTC().Format("20060102-150405"))
	if err := os.WriteFile(dest, body, 0o600); err != nil {
		return "", err
	}
	return dest, nil
}

// writeEnv adds the environment variables to a shell profile.
func writeEnv(path, origin, key string) (string, error) {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}

	var saved string
	if len(existing) > 0 {
		if saved, err = backup(path); err != nil {
			return "", err
		}
	}

	// Any previous block is removed rather than appended to, so running
	// this twice does not leave two blocks disagreeing about the base URL.
	body := removeBlock(string(existing))

	block := strings.Join([]string{
		markerStart,
		"# Added by `lyntway init`. Remove with `lyntway undo`.",
		"# Your AI traffic is routed through Lyntway so it can be recorded.",
		fmt.Sprintf("export OPENAI_BASE_URL=%q", origin+"/gw/openai/v1"),
		fmt.Sprintf("export ANTHROPIC_BASE_URL=%q", origin+"/gw/anthropic"),
		fmt.Sprintf("export LYNTWAY_KEY=%q", key),
		markerEnd,
		"",
	}, "\n")

	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	if err := os.WriteFile(path, []byte(body+block), 0o600); err != nil {
		return "", err
	}
	return saved, nil
}

// removeBlock strips a previously written block, markers included.
func removeBlock(body string) string {
	start := strings.Index(body, markerStart)
	if start < 0 {
		return body
	}
	end := strings.Index(body[start:], markerEnd)
	if end < 0 {
		// A start with no end means somebody edited by hand and left it
		// broken. Truncating to the marker is the least destructive
		// reading: everything before it was theirs.
		return strings.TrimRight(body[:start], "\n") + "\n"
	}
	end += start + len(markerEnd)
	rest := strings.TrimLeft(body[end:], "\n")
	return strings.TrimRight(body[:start], "\n") + "\n" + rest
}

// wrapMCP rewrites a config so every server runs through the shim.
//
// The original command and arguments are preserved after `--`, so undoing
// this is a matter of removing the wrapper rather than reconstructing what
// was there.
func wrapMCP(path string) (changed []string, saved string, err error) {
	servers, err := mcpServers(path)
	if err != nil {
		return nil, "", err
	}
	if len(servers) == 0 {
		return nil, "", nil
	}

	body, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", err
	}

	wrapped := map[string]json.RawMessage{}
	for name, entry := range servers {
		if alreadyWrapped(entry) {
			continue
		}
		var s struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env,omitempty"`
		}
		if err := json.Unmarshal(entry, &s); err != nil || s.Command == "" {
			// Left exactly as it was. A server shaped in a way this does
			// not understand is one to leave alone, not to guess at.
			continue
		}

		next := map[string]any{
			"command": "lyntway-mcp",
			"args":    append([]string{"--"}, append([]string{s.Command}, s.Args...)...),
		}
		if len(s.Env) > 0 {
			next["env"] = s.Env
		}
		encoded, err := json.Marshal(next)
		if err != nil {
			return nil, "", err
		}
		wrapped[name] = encoded
		changed = append(changed, name)
	}

	if len(changed) == 0 {
		return nil, "", nil
	}

	if saved, err = backup(path); err != nil {
		return nil, "", err
	}
	for name, entry := range wrapped {
		servers[name] = entry
	}
	encoded, err := json.Marshal(servers)
	if err != nil {
		return nil, "", err
	}
	doc["mcpServers"] = encoded

	// Indented, because a person reads this file and a single line of JSON
	// is a worse config than the one they had.
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		return nil, "", err
	}
	return changed, saved, nil
}

// restore puts back the most recent backup of a file.
func restore(path string) (bool, error) {
	matches, err := filepath.Glob(path + ".lyntway-backup-*")
	if err != nil || len(matches) == 0 {
		return false, err
	}
	// Sorted by name, which sorts by time because the stamp is ordered.
	newest := matches[len(matches)-1]
	body, err := os.ReadFile(newest)
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return false, err
	}
	return true, nil
}
