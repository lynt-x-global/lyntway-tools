//go:build !windows

package main

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO where a config file should be would block a read until something
// wrote to it, which for an agent is for ever. readLocal refuses it.
func TestReadLocalDoesNotBlockOnAFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readLocal(path, 1<<20)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was read as a file")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readLocal blocked on a FIFO")
	}
}
