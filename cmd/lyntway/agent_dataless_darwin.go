//go:build darwin

package main

import (
	"os"
	"syscall"
)

// sfDataless is SF_DATALESS from <sys/stat.h>: the file's bytes are in
// iCloud (or another File Provider) and not on this disk.
const sfDataless = 0x40000000

// isDataless reports a file whose contents are not on disk. Reading one
// makes the OS fetch it, and a read blocked on a fetch hung the agent's
// first real run for minutes on a project kept in iCloud Drive.
func isDataless(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Flags&sfDataless != 0
}
