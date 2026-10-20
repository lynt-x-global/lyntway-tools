package agentsecrets

// PlatformCaveat returns the sentence a report owes the reader on a
// platform where the location table has not been checked against a real
// machine, or "" where it has.
//
// This is not a disclaimer for its own sake. Sources() is a list of paths,
// and a path that is wrong for the platform produces no finding and is
// counted as a source that did not exist — which leaves Complete() true.
// Every other way this package can come up short makes Complete() false
// and says so; a location table mapped on the wrong operating system is
// the one failure that looks exactly like a clean machine.
//
// Cursor keeps state.vscdb under Library/Application Support on macOS,
// AppData/Roaming on Windows and .config on Linux, and Claude Code's
// directory moves with it. Those are written out in locations.go and are
// believed right, but believed is the operative word: the table was built
// by reading a macOS machine, and only macOS has had the whole flow run
// on it end to end.
//
// It takes goos rather than reading runtime.GOOS so the message can be
// tested for every platform from any one of them.
func PlatformCaveat(goos string) string {
	if goos == "darwin" {
		return ""
	}
	return "Checked end to end on macOS only. The places these tools keep their history " +
		"on " + platformName(goos) + " are written from their documentation, not from a machine we have " +
		"run this on — so a path that has moved reads here as a tool that is not " +
		"installed. Treat a low count as unverified rather than as a clean machine."
}

func platformName(goos string) string {
	switch goos {
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	case "darwin":
		return "macOS"
	default:
		return goos
	}
}
