//go:build windows

package main

import (
	"os"
	"syscall"
)

// OneDrive's Files On-Demand placeholders carry these attributes; reading
// one downloads it.
const (
	fileAttributeOffline            = 0x1000
	fileAttributeRecallOnOpen       = 0x40000
	fileAttributeRecallOnDataAccess = 0x400000
)

func isDataless(info os.FileInfo) bool {
	d, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&(fileAttributeOffline|fileAttributeRecallOnOpen|fileAttributeRecallOnDataAccess) != 0
}
