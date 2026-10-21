package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A record whose file and backup are both gone needs nothing done.
//
// A Windows tester ran undo and got fourteen "restore it by hand" lines
// in a row, every one naming a Go test's temporary directory from three
// weeks earlier. The directories had been swept and the backups with
// them, so there was nothing to restore anywhere — but the output said
// otherwise fourteen times, and a successful undo read as a broken one.
func TestUndoDropsRecordsWithNothingLeftToRestore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	work := t.TempDir()

	// One real pair, which must be restored.
	live := filepath.Join(work, "live.env")
	liveBackup := filepath.Join(work, "live.env.backup")
	if err := os.WriteFile(live, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(liveBackup, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	// One where both sides are gone, as a swept temp directory leaves.
	gone := filepath.Join(work, "swept", "gone.env")

	// And one where the file survives but the backup does not. Something
	// was changed and cannot be put back, so it is a real problem and
	// must still be named.
	orphan := filepath.Join(work, "orphan.env")
	if err := os.WriteFile(orphan, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := saveRecord(undoRecord{Files: []changedFile{
		{Path: live, Backup: liveBackup},
		{Path: gone, Backup: filepath.Join(work, "swept", "gone.env.backup")},
		{Path: orphan, Backup: filepath.Join(work, "orphan.env.backup")},
	}}); err != nil {
		t.Fatal(err)
	}

	out := capture(t, "", func() {
		if _, err := undoRecorded(); err != nil {
			t.Fatal(err)
		}
	})

	if body, _ := os.ReadFile(live); string(body) != "original" {
		t.Errorf("the live file was not restored: %q", body)
	}
	if strings.Contains(out, "gone.env") {
		t.Errorf("a record with nothing left to restore was reported as a failure:\n%s", out)
	}
	if !strings.Contains(out, "1 record dropped") {
		t.Errorf("the dropped record was not counted:\n%s", out)
	}
	if !strings.Contains(out, "orphan.env") || !strings.Contains(out, "restore it by hand") {
		t.Errorf("a file whose backup is missing was not reported:\n%s", out)
	}

	// The dropped one is gone from the record; the orphan is kept, so a
	// later undo can still put it back if the backup reappears.
	r, err := loadRecord()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Files {
		if f.Path == gone {
			t.Error("the dropped record is still in the file")
		}
	}
	var keptOrphan bool
	for _, f := range r.Files {
		if f.Path == orphan {
			keptOrphan = true
		}
	}
	if !keptOrphan {
		t.Error("a file that could not be restored was forgotten rather than kept")
	}
}
