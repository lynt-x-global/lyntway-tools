//go:build !darwin && !windows

package main

import "os"

func isDataless(os.FileInfo) bool { return false }
