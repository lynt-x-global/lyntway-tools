//go:build !darwin

package agentsecrets

import "io/fs"

// isDataless reports whether a file is a cloud placeholder.
//
// Only macOS is checked, where iCloud Drive evicts file contents and
// leaves the metadata. Elsewhere this answers false: OneDrive and Dropbox
// placeholders are reparse points that read as ordinary files here, and a
// wrong guess would skip a file that is present.
func isDataless(fs.FileInfo) bool { return false }
