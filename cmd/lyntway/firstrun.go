package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The first thing a person sees.
//
// `lyntway` with no arguments used to go straight to `setup`, whose first
// step is signing in. That ordering put every piece of value behind an
// account: somebody who installed us to find out what their agents could
// reach was asked for a key before being told anything. The scan that
// answers their question needs no account and no network, so it now runs
// first and the account is offered afterwards, as a way to start recording
// rather than as the price of looking.
//
// Nothing here reaches the network. Every fact below comes from this
// machine's own configuration files and its process list, which is also
// why the closing paragraph says so: the report is worth less than the
// sentence explaining what it did not do.
//
// This prints a picture and exits 0. It is deliberately not a check that
// fails — `lyntway scan` is the one built to gate a commit, and giving two
// commands the same exit semantics would make the gate ambiguous.

// firstRunReport is what the first run found, separated from printing so
// every branch can be exercised without a machine that happens to have
// the right tools on it.
type firstRunReport struct {
	Hostname string
	OS       string
	User     string

	Apps []aiApp
	MCP  mcpDiscovery

	// Keys are provider keys in the directory the command was run in.
	// ScannedFiles is how many files were read; KeyScanError is set when
	// the directory could not be walked in full, so "no keys" is never
	// said about files that were never opened.
	Keys         []keyHit
	ScannedFiles int
	KeyScanError error
}

// credentialCount is how many configured MCP servers have a credential
// sitting in the file beside them. It is the one number on this screen
// that tends to surprise the person reading it.
func (r firstRunReport) credentialCount() int {
	var n int
	for _, s := range r.MCP.Servers {
		if s.HasCredentials {
			n++
		}
	}
	return n
}

func takeFirstRunReport(dir string) firstRunReport {
	h := currentHost(false)
	procs, _ := listProcesses(h.GOOS)

	r := firstRunReport{
		Hostname: hostname(),
		OS:       reportOS(h.GOOS),
		User:     h.User,
		Apps:     inventory(h, procs),
		MCP:      discoverMCP(mcpSources(h, projectRoots(h))),
	}
	if v := osVersion(h.GOOS); v != "" {
		r.OS += " " + v
	}

	// Only the directory the command was run in, never the home folder.
	// A first run that walked everything would take minutes and read
	// files nobody asked us to open.
	if dir != "" {
		hits, scanned, err := scanPaths([]string{dir})
		for i := range hits {
			hits[i].File = relativePath(dir, hits[i].File)
		}
		r.Keys, r.ScannedFiles, r.KeyScanError = hits, scanned, err
	}
	return r
}

func printFirstRun(r firstRunReport) {
	fmt.Fprintf(stdout, "\nlyntway — what is on this machine\n\n")

	where := r.Hostname
	for _, part := range []string{r.OS, r.User} {
		if part != "" {
			where += " · " + part
		}
	}
	fmt.Fprintf(stdout, "  %s\n", where)

	printFirstRunApps(r)
	printFirstRunMCP(r)
	printFirstRunKeys(r)

	fmt.Fprint(stdout, "\nNothing left this machine. Everything above was read from this\n"+
		"computer's own configuration files and its process list: no traffic was\n"+
		"watched, no value was copied out of any file, and no account was needed.\n")

	fmt.Fprint(stdout, "\nNothing here is being recorded yet.\n\n")
	if len(r.Keys) > 0 {
		fmt.Fprint(stdout, "  lyntway keys migrate      move those keys out of the files\n")
	}
	fmt.Fprint(stdout, "  lyntway setup             route these tools through Lyntway, and\n"+
		"                            start recording what they send\n"+
		"  lyntway agent --explain   exactly what is collected, and what never is\n")
}

func printFirstRunApps(r firstRunReport) {
	if len(r.Apps) == 0 {
		fmt.Fprint(stdout, "\nAI tools\n"+
			"  None found. Application folders, editor extensions and the process\n"+
			"  list are where this looks; anything installed somewhere else is not\n"+
			"  seen from here.\n")
		return
	}

	fmt.Fprintf(stdout, "\nAI tools (%d)\n", len(r.Apps))
	for _, a := range r.Apps {
		state := "installed"
		if a.Running {
			state = "running"
		}
		version := a.Version
		if version == "" {
			version = "version unknown"
		}
		fmt.Fprintf(stdout, "  %-40s %-10s %s\n", a.Name, state, version)
	}
}

func printFirstRunMCP(r firstRunReport) {
	// What could not be read is said before what was found, so a short
	// list is never mistaken for a complete one.
	var caveats []string
	if n := len(r.MCP.Unreadable); n > 0 {
		caveats = append(caveats, fmt.Sprintf("%d config file%s could not be read", n, pluralS(n)))
	}
	if r.MCP.NotLocal > 0 {
		caveats = append(caveats, fmt.Sprintf("%d is in cloud storage and was not fetched", r.MCP.NotLocal))
	}

	if len(r.MCP.Servers) == 0 {
		fmt.Fprint(stdout, "\nMCP servers\n")
		// "None configured in 0 files read" states a fact about nothing.
		// When no client file was found at all, that is what to say, and
		// it means something different: not that the agents reach
		// nothing, but that nothing here has told us either way.
		if r.MCP.Read == 0 {
			fmt.Fprint(stdout, "  No MCP client config file was found on this machine, so there is\n"+
				"  nothing here that says what your agents can reach.\n")
		} else {
			fmt.Fprintf(stdout, "  None configured in the %d client file%s read.\n",
				r.MCP.Read, pluralS(r.MCP.Read))
		}
		if len(caveats) > 0 {
			fmt.Fprintf(stdout, "  %s.\n", capitalise(strings.Join(caveats, ", and ")))
		}
		return
	}

	fmt.Fprintf(stdout, "\nMCP servers your agents are configured to reach (%d)\n", len(r.MCP.Servers))

	// Credentialled servers last, where the eye lands, and in a stable
	// order so two runs on an unchanged machine print the same screen.
	servers := make([]mcpServerInfo, len(r.MCP.Servers))
	copy(servers, r.MCP.Servers)
	sort.SliceStable(servers, func(i, j int) bool {
		return !servers[i].HasCredentials && servers[j].HasCredentials
	})

	for _, s := range servers {
		client := r.MCP.Labels[s]
		if client == "" {
			client = s.Client
		}
		host := s.Host
		if host == "" {
			host = "local process"
		}
		note := ""
		if s.HasCredentials {
			note = "   credential in config"
		}
		line := fmt.Sprintf("  %-22s %-24s %-22s%s", client, s.Name, host, note)
		fmt.Fprintln(stdout, strings.TrimRight(line, " "))
	}

	if n := r.credentialCount(); n > 0 {
		has, them := "have", "them"
		if n == 1 {
			has, them = "has", "it"
		}
		fmt.Fprintf(stdout, "\n  %d of these %s a credential written into the config file beside\n"+
			"  %s. Anything that can read that file can read the credential.\n", n, has, them)
	}
	if len(caveats) > 0 {
		fmt.Fprintf(stdout, "\n  %s.\n", capitalise(strings.Join(caveats, ", and ")))
	}
}

func printFirstRunKeys(r firstRunReport) {
	if r.KeyScanError != nil {
		fmt.Fprintf(stdout, "\nProvider keys in this directory\n"+
			"  Not fully read: %v\n"+
			"  Run `lyntway scan` in a directory you can read.\n", r.KeyScanError)
		return
	}
	if len(r.Keys) == 0 {
		fmt.Fprintf(stdout, "\nProvider keys in this directory\n  None in the %d file%s read.\n",
			r.ScannedFiles, pluralS(r.ScannedFiles))
		return
	}

	fmt.Fprintf(stdout, "\nProvider keys in this directory (%d)\n", len(r.Keys))
	const shown = 5
	for i, h := range r.Keys {
		if i == shown {
			fmt.Fprintf(stdout, "  …and %d more — `lyntway scan` lists them all.\n", len(r.Keys)-shown)
			break
		}
		fmt.Fprintf(stdout, "  %s:%d\t%s\t…%s\n", h.File, h.Line, h.Label, h.Last4)
	}
}

// firstRun is the no-argument command for a machine that has never signed
// in. dir is the directory to look for keys in; empty skips that section.
func firstRun(dir string) error {
	printFirstRun(takeFirstRunReport(dir))
	return nil
}

// firstRunWanted reports whether this machine has never been signed in,
// which is the only state in which the opening picture should stand in for
// a command.
//
// The test is for the config file's absence, not for loadConfig failing.
// A file that exists and will not parse is a different state with a
// different fix, and showing the picture there would tell somebody they
// have no account when what they have is damaged settings — the same
// mistake as a receipt reading stronger than the truth, in the other
// direction.
//
// It asks the disk only. A network check here would make the opening
// screen wait on a timeout, and `setup` and `status` both verify the key
// against the service anyway.
func firstRunWanted() bool {
	path, err := configPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}

func hostname() string {
	n, err := os.Hostname()
	if err != nil || n == "" {
		return "this machine"
	}
	return n
}

// relativePath shows a finding's file relative to where the command was
// run. An absolute path is unreadable on a screen that has to be taken in
// at a glance, and it is the same file either way. A path outside the
// directory keeps its absolute form, because ../../.. is worse than both.
func relativePath(dir, file string) string {
	rel, err := filepath.Rel(dir, filepath.FromSlash(file))
	if err != nil || strings.HasPrefix(rel, "..") {
		return file
	}
	return filepath.ToSlash(rel)
}
