package main

// Polls .env files for changes and notifies the MCP client when new
// provider keys appear. No fsnotify — os.Stat polling keeps the root
// module dependency-free, which is a promise made to security reviewers.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type envSnapshot struct {
	modTime time.Time
	size    int64
}

// envWatcher polls .env files in a directory and sends MCP logging
// notifications when new provider keys appear.
type envWatcher struct {
	dir      string
	interval time.Duration
	writer   io.Writer   // stdout (JSON-RPC transport)
	writeMu  *sync.Mutex // shared with dispatch loop
	lyntKey  string      // for findCandidates filtering
	extra    []string    // custom upstream names from the server
	baseline map[string]envSnapshot
	// knownVars holds the variables that held a live provider key at the
	// last look — not every name ever seen. A migrated line is not live,
	// so a raw key pasted back into it later is reported again, which is
	// the commonest way a key comes back.
	knownVars map[string]bool
}

func newEnvWatcher(dir string, interval time.Duration, lyntKey string, extra []string, w io.Writer, mu *sync.Mutex) *envWatcher {
	ew := &envWatcher{
		dir:      dir,
		interval: interval,
		writer:   w,
		writeMu:  mu,
		lyntKey:  lyntKey,
		extra:    extra,
	}
	ew.baseline = ew.snapshot()
	ew.knownVars = ew.currentVars()
	return ew
}

// snapshot reads os.Stat for each known .env filename in the watch directory.
func (ew *envWatcher) snapshot() map[string]envSnapshot {
	snap := make(map[string]envSnapshot)
	for _, name := range envFiles {
		path := filepath.Join(ew.dir, name)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		snap[path] = envSnapshot{modTime: info.ModTime(), size: info.Size()}
	}
	return snap
}

// currentVars returns the variables that hold a live provider key now.
// A skipped line — already routed, a placeholder — is not live.
func (ew *envWatcher) currentVars() map[string]bool {
	vars := make(map[string]bool)
	cands, err := findCandidates(ew.dir, ew.extra, ew.lyntKey)
	if err != nil {
		return vars
	}
	for _, c := range cands {
		if c.Skip == "" {
			vars[c.Var] = true
		}
	}
	return vars
}

// check compares the current snapshot against the baseline. If any file
// is new or has a newer mtime/different size, it rescans for candidates
// and returns only newly found ones.
func (ew *envWatcher) check() []candidate {
	current := ew.snapshot()
	changed := false
	for path, snap := range current {
		old, ok := ew.baseline[path]
		if !ok || snap.modTime != old.modTime || snap.size != old.size {
			changed = true
			break
		}
	}
	// A file that existed before but is now gone also counts.
	if !changed {
		for path := range ew.baseline {
			if _, ok := current[path]; !ok {
				changed = true
				break
			}
		}
	}
	if !changed {
		return nil
	}

	cands, err := findCandidates(ew.dir, ew.extra, ew.lyntKey)
	if err != nil {
		ew.baseline = current
		return nil
	}

	// Fresh is a variable live now that was not live last time: a new name,
	// or a known one whose key came back. Live-and-already-reported stays
	// quiet, so an unchanged key is not announced on every tick.
	var fresh []candidate
	live := make(map[string]bool)
	for _, c := range cands {
		if c.Skip != "" {
			continue
		}
		live[c.Var] = true
		if !ew.knownVars[c.Var] {
			fresh = append(fresh, c)
		}
	}

	ew.baseline = current
	ew.knownVars = live
	return fresh
}

// run is the goroutine body. It checks for existing keys on startup,
// then ticks at ew.interval watching for new ones, and stops when ctx
// is cancelled.
func (ew *envWatcher) run(ctx context.Context) {
	// Initial check: if the directory already has provider keys when the
	// editor opens, notify immediately so the agent knows without waiting.
	if initial := ew.initialCandidates(); len(initial) > 0 {
		ew.notify(initial)
	}

	ticker := time.NewTicker(ew.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if found := ew.check(); len(found) > 0 {
				ew.notify(found)
			}
		}
	}
}

// initialCandidates returns all unmigrated provider keys already present
// when the watcher starts. These are in knownVars (so check() won't
// re-report them) but the agent has not seen them yet.
func (ew *envWatcher) initialCandidates() []candidate {
	cands, err := findCandidates(ew.dir, ew.extra, ew.lyntKey)
	if err != nil {
		return nil
	}
	var found []candidate
	for _, c := range cands {
		if c.Skip == "" {
			found = append(found, c)
		}
	}
	return found
}

// notify sends a notification listing the newly detected provider keys.
// Written to both stderr (which Claude Code captures and surfaces) and
// the JSON-RPC transport as a logging notification for older hosts.
func (ew *envWatcher) notify(found []candidate) {
	var parts []string
	for _, c := range found {
		parts = append(parts, c.Var+" ("+c.Upstream+")")
	}
	msg := "New provider keys detected in .env: " +
		joinWords(parts) +
		". Call lyntway_migrate to secure them."

	// stderr — Claude Code captures this and can surface it.
	fmt.Fprintln(os.Stderr, "[lyntway] "+msg)

	// JSON-RPC notification — older hosts and protocol revisions.
	writeJSONRPCNotification(ew.writeMu, ew.writer, "notifications/message", map[string]any{
		"level":  "warning",
		"logger": "lyntway",
		"data":   msg,
	})
}

// writeJSONRPCNotification sends a JSON-RPC notification (no id) under mutex.
func writeJSONRPCNotification(mu *sync.Mutex, w io.Writer, method string, params any) {
	mu.Lock()
	defer mu.Unlock()
	msg := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
	body, _ := json.Marshal(msg)
	_, _ = w.Write(append(body, '\n'))
}

// joinWords joins a slice with commas and "and" before the last element.
func joinWords(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	default:
		s := ""
		for i, p := range parts {
			if i == len(parts)-1 {
				s += "and " + p
			} else {
				s += p + ", "
			}
		}
		return s
	}
}
