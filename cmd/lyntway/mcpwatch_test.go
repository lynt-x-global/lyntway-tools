package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnvWatcherDetectsNewFile(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	var mu sync.Mutex

	// Start with no .env — baseline is empty.
	ew := newEnvWatcher(dir, 50*time.Millisecond, "", nil, &buf, &mu)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ew.run(ctx)

	// Write a .env with a recognisable provider key after the watcher starts.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-openai0000ABCD\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Wait for at least one tick to fire.
	time.Sleep(200 * time.Millisecond)
	cancel()

	mu.Lock()
	output := buf.String()
	mu.Unlock()

	if !strings.Contains(output, "notifications/message") {
		t.Fatalf("expected notification, got: %q", output)
	}
	if !strings.Contains(output, "OPENAI_API_KEY") {
		t.Fatalf("expected OPENAI_API_KEY in notification, got: %q", output)
	}

	// Verify the notification is valid JSON-RPC.
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("notification is not valid JSON: %v\n%s", err, line)
		}
		if msg["jsonrpc"] != "2.0" {
			t.Errorf("expected jsonrpc 2.0, got %v", msg["jsonrpc"])
		}
	}
}

func TestEnvWatcherDetectsModifiedFile(t *testing.T) {
	dir := t.TempDir()

	// Start with a .env that has one key.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-openai0000ABCD\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	var mu sync.Mutex

	ew := newEnvWatcher(dir, 50*time.Millisecond, "", nil, &buf, &mu)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ew.run(ctx)

	// The initial scan fires a notification for the existing key.
	// Drain it so the test checks only what comes after the modification.
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	buf.Reset()
	mu.Unlock()

	// Add a second key after the initial scan has settled.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-openai0000ABCD\nANTHROPIC_API_KEY=sk-ant-api03-anthropicWXYZ\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)
	cancel()

	mu.Lock()
	output := buf.String()
	mu.Unlock()

	if !strings.Contains(output, "ANTHROPIC_API_KEY") {
		t.Fatalf("expected notification for ANTHROPIC_API_KEY, got: %q", output)
	}
}

func TestEnvWatcherIgnoresUnchangedFile(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-openai0000ABCD\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	var mu sync.Mutex

	ew := newEnvWatcher(dir, 50*time.Millisecond, "", nil, &buf, &mu)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ew.run(ctx)

	// The initial scan fires once for the existing key. Drain it.
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	buf.Reset()
	mu.Unlock()

	// Let several ticks pass without changing anything.
	time.Sleep(200 * time.Millisecond)
	cancel()

	mu.Lock()
	output := buf.String()
	mu.Unlock()

	if output != "" {
		t.Fatalf("expected no notification after initial scan for unchanged file, got: %q", output)
	}
}

func TestEnvWatcherStopsOnCancel(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	var mu sync.Mutex

	ew := newEnvWatcher(dir, 50*time.Millisecond, "", nil, &buf, &mu)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ew.run(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Goroutine exited cleanly.
	case <-time.After(2 * time.Second):
		t.Fatal("watcher goroutine did not exit after cancel")
	}
}

func TestCheckReturnsOnlyNewCandidates(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-openai0000ABCD\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	var mu sync.Mutex

	ew := newEnvWatcher(dir, time.Hour, "", nil, &buf, &mu)

	// First check: baseline was taken at creation, no changes yet.
	got := ew.check()
	if len(got) != 0 {
		t.Fatalf("expected no new candidates on unchanged file, got %d", len(got))
	}

	// Modify .env to add a key.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY=sk-proj-openai0000ABCD\nGEMINI_API_KEY=AIzaSy000gemini00ABCD\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got = ew.check()
	if len(got) != 1 {
		t.Fatalf("expected 1 new candidate, got %d", len(got))
	}
	if got[0].Var != "GEMINI_API_KEY" {
		t.Errorf("expected GEMINI_API_KEY, got %s", got[0].Var)
	}

	// Second check after the same change: nothing new.
	got = ew.check()
	if len(got) != 0 {
		t.Fatalf("expected no new candidates on second check, got %d", len(got))
	}
}

func TestWatcherDetectsCustomUpstreamByName(t *testing.T) {
	dir := t.TempDir()

	// A key whose value has no recognisable prefix, but whose variable
	// name matches a custom upstream the account added.
	if err := os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("PORTKEY_API_KEY=pk-test-00000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	var mu sync.Mutex

	// Without extra: key is invisible.
	ew := newEnvWatcher(dir, time.Hour, "", nil, &buf, &mu)
	if init := ew.initialCandidates(); len(init) != 0 {
		t.Fatalf("without extra, expected 0 candidates, got %d", len(init))
	}

	// With extra containing "portkey": detected.
	buf.Reset()
	ew = newEnvWatcher(dir, time.Hour, "", []string{"portkey"}, &buf, &mu)
	init := ew.initialCandidates()
	if len(init) != 1 {
		t.Fatalf("with extra=[portkey], expected 1 candidate, got %d", len(init))
	}
	if init[0].Upstream != "portkey" {
		t.Errorf("upstream = %q, want portkey", init[0].Upstream)
	}
}

// The commonest way a key comes back: a variable that was migrated gets a
// raw provider key pasted into it again, to "make it work". The name was
// seen before, so a watcher that only reports new names says nothing — at
// exactly the moment it exists for.
func TestWatcherReportsAKeyPastedBackIntoAMigratedVariable(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(env, []byte("OPENAI_API_KEY=$LYNTWAY_KEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	ew := newEnvWatcher(dir, time.Hour, "", nil, io.Discard, &mu)
	if got := ew.initialCandidates(); len(got) != 0 {
		t.Fatalf("a migrated line was reported as a key: %v", got)
	}

	time.Sleep(20 * time.Millisecond) // a different mtime, whatever the filesystem's resolution
	if err := os.WriteFile(env, []byte("OPENAI_API_KEY=sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	found := ew.check()
	if len(found) != 1 || found[0].Var != "OPENAI_API_KEY" {
		t.Fatalf("the re-pasted key was not reported: %v", found)
	}

	// And once reported, the same unchanged key is not reported again on
	// every tick — that would train people to ignore it.
	time.Sleep(20 * time.Millisecond)
	now := time.Now()
	if err := os.Chtimes(env, now, now); err != nil {
		t.Fatal(err)
	}
	if again := ew.check(); len(again) != 0 {
		t.Fatalf("an already-reported key was reported again: %v", again)
	}
}
