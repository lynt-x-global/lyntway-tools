//go:build windows

package main

import "os"

func fileOwnerUID(os.FileInfo) (int, bool) { return 0, false }
