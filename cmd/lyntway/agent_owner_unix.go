//go:build !windows

package main

import (
	"os"
	"syscall"
)

// fileOwnerUID reads a file's owner. Unix only: Windows has owners by SID,
// and the console user is found another way there.
func fileOwnerUID(info os.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
