package main

import (
	"errors"
	"fmt"
	"os"
)

// errNotLocal is a file whose bytes are in cloud storage, not on this disk.
var errNotLocal = errors.New("in cloud storage and not downloaded")

// readLocal reads a regular file whose bytes are on this disk, up to max.
//
// Everything the agent reads from somebody's files goes through here. A
// FIFO would block a read for ever, and a file evicted to iCloud or
// OneDrive blocks it until the fetch finishes — which, on the agent's first
// real run, was minutes, on a project somebody keeps in iCloud Drive. A
// report that never arrives is worth less than one that says a file was
// skipped, and downloading somebody's file to look inside it is not the
// agent's business anyway.
func readLocal(path string, max int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if isDataless(info) {
		return nil, errNotLocal
	}
	if max > 0 && info.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return os.ReadFile(path)
}
