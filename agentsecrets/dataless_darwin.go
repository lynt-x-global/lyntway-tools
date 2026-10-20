package agentsecrets

import (
	"io/fs"
	"syscall"
)

// isDataless reports whether macOS has evicted this file's contents.
//
// A file in iCloud Drive that has been evicted keeps its size in the
// directory entry and has no blocks allocated. Reading it blocks while
// the system fetches it, which on a synced project is minutes — and
// pulling somebody's files down to look inside them is not this tool's
// business. Zero blocks with a non-zero size is the test.
func isDataless(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return info.Size() > 0 && st.Blocks == 0
}
