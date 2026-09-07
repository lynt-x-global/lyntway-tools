package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Remembering what `keys migrate` changed, so `undo` can find it.
//
// `init` needs no record: it edits files at known locations and finds
// them again by scanning. A .env file can be anywhere on the disk, so the
// path and its backup are written down at the moment the file is changed.
// The record holds paths only — the original values are in the backups,
// which sit beside the files under the owner's permissions.

type undoRecord struct {
	Files []changedFile `json:"files"`

	// Gitignores are directories whose .gitignore gained the backup
	// pattern, so undo can take the line out again.
	Gitignores []string `json:"gitignores,omitempty"`
}

type changedFile struct {
	Path   string `json:"path"`
	Backup string `json:"backup"`
	At     string `json:"at"`
}

func recordPath() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".lyntway", "undo.json"), nil
}

func loadRecord() (undoRecord, error) {
	path, err := recordPath()
	if err != nil {
		return undoRecord{}, err
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return undoRecord{}, nil
	}
	if err != nil {
		return undoRecord{}, err
	}
	var r undoRecord
	if err := json.Unmarshal(body, &r); err != nil {
		return undoRecord{}, fmt.Errorf("the record of changes at %s is unreadable: %w", path, err)
	}
	return r, nil
}

func saveRecord(r undoRecord) error {
	path, err := recordPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

// undoRecorded restores every file the record names from its backup and
// returns how many were put back.
//
// The backup is copied rather than renamed, so the backup stays: a second
// undo is harmless, and the person decides when the originals go.
func undoRecorded() (int, error) {
	r, err := loadRecord()
	if err != nil {
		return 0, err
	}
	var restored int
	var remaining []changedFile
	for _, f := range r.Files {
		body, err := os.ReadFile(f.Backup)
		if err != nil {
			fmt.Fprintf(stdout, "  ✗ %s — its backup %s is gone; restore it by hand\n", f.Path, filepath.Base(f.Backup))
			remaining = append(remaining, f)
			continue
		}
		mode := os.FileMode(0o600)
		if info, err := os.Stat(f.Path); err == nil {
			mode = info.Mode().Perm()
		}
		if err := os.WriteFile(f.Path, body, mode); err != nil {
			fmt.Fprintf(stdout, "  ✗ %s — %v\n", f.Path, err)
			remaining = append(remaining, f)
			continue
		}
		fmt.Fprintf(stdout, "  ✓ %s (from %s)\n", f.Path, filepath.Base(f.Backup))
		restored++
	}
	for _, dir := range r.Gitignores {
		if ok, err := unignoreBackups(dir); err != nil {
			fmt.Fprintf(stdout, "  ✗ %s — %v\n", filepath.Join(dir, ".gitignore"), err)
		} else if ok {
			fmt.Fprintf(stdout, "  ✓ %s — backup pattern removed\n", filepath.Join(dir, ".gitignore"))
		}
	}
	r.Files = remaining
	r.Gitignores = nil
	if err := saveRecord(r); err != nil {
		return restored, err
	}
	return restored, nil
}
