package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// `lyntway connect` — the one command between finding out and being set up.
//
// # Why it is not a picker
//
// Connecting used to mean opening a console, browsing 385 provider cards,
// clicking one, and pasting a key. Every step of that asks the person to
// tell us something we can already see: the keys are on their disk, the
// MCP servers are in their editor's config, and the catalog knows which
// provider a key belongs to from the characters it starts with.
//
// So this asks nothing and offers a list. The person confirms or does not.
// The only question they answer is the one nobody else can: yes or no.
//
// # Why it changes nothing itself
//
// Every mutation here is `lyntway init` or `lyntway keys migrate`, called
// as they are. That is deliberate twice over: both are already tested
// against the files they rewrite, and `lyntway undo` already knows how to
// reverse exactly those two. A connect command that wrote its own changes
// would be a new thing for undo to miss, and the rule this tool is held to
// is that nobody is ever stuck with a machine they cannot put back.

// connectFindings is what one machine offers to connect.
type connectFindings struct {
	// Migratable are keys `keys migrate` can move into Lyntway.
	Migratable []keyHit
	// Named is every other key found: recognised by the deterministic
	// rules or by the catalog, and not movable from here — nothing in
	// this tool holds a Stripe key for anybody.
	//
	// It is everything that is not migratable, deliberately. The first
	// version bucketed by Upstream and Catalog and silently dropped
	// anything with neither, which is how a live Stripe key found by the
	// gateway's own rules appeared in `lyntway scan` and not here. A
	// screen that shows fewer keys than the scanner found teaches people
	// the scanner is wrong.
	Named []keyHit
	// Routable are the tools `init` can point at Lyntway.
	Routable []target
	// MCP is what the agents on this machine are configured to reach.
	MCP mcpDiscovery
}

func (f connectFindings) nothingToDo() bool {
	return len(f.Migratable) == 0 && len(f.Named) == 0 && len(f.Routable) == 0
}

func takeConnectFindings(dir string) connectFindings {
	var f connectFindings

	hits, _, err := scanPaths([]string{dir})
	if err == nil {
		for _, h := range hits {
			if h.Upstream != "" {
				f.Migratable = append(f.Migratable, relativeTo(dir, h))
				continue
			}
			f.Named = append(f.Named, relativeTo(dir, h))
		}
	}

	for _, t := range scan() {
		if t.Found && t.Kind != kindManual {
			f.Routable = append(f.Routable, t)
		}
	}

	h := currentHost(false)
	f.MCP = discoverMCP(mcpSources(h, projectRoots(h)))
	return f
}

func printConnectFindings(f connectFindings) {
	fmt.Fprint(stdout, "\nlyntway connect\n\n")

	if len(f.Migratable) > 0 || len(f.Named) > 0 {
		fmt.Fprintf(stdout, "Provider keys in this directory (%d)\n", len(f.Migratable)+len(f.Named))
		for _, h := range f.Migratable {
			fmt.Fprintf(stdout, "  %-28s %-26s …%s   can be moved into Lyntway\n",
				fmt.Sprintf("%s:%d", h.File, h.Line), h.Label, h.Last4)
		}
		for _, h := range f.Named {
			fmt.Fprintf(stdout, "  %-28s %-26s …%s   recognised, not moved from here\n",
				fmt.Sprintf("%s:%d", h.File, h.Line), h.Label, h.Last4)
		}
		fmt.Fprintln(stdout)
	}

	if len(f.MCP.Servers) > 0 {
		withCred := 0
		for _, s := range f.MCP.Servers {
			if s.HasCredentials {
				withCred++
			}
		}
		fmt.Fprintf(stdout, "MCP servers your agents are configured to reach: %d", len(f.MCP.Servers))
		if withCred > 0 {
			fmt.Fprintf(stdout, ", %d with a credential in the config", withCred)
		}
		fmt.Fprint(stdout, "\n\n")
	}

	if len(f.Routable) > 0 {
		fmt.Fprintf(stdout, "Tools that can be pointed at Lyntway (%d)\n", len(f.Routable))
		for _, t := range f.Routable {
			fmt.Fprintf(stdout, "  %s\n", t.Name)
		}
		fmt.Fprintln(stdout)
	}
}

// printConnectPlan says what yes means, in the order it will happen.
//
// Written out rather than summarised because this is the screen somebody
// agrees on, and "set up Lyntway" is not something anybody can agree to.
func printConnectPlan(f connectFindings) {
	fmt.Fprint(stdout, "Connecting will:\n")
	if n := len(f.Migratable); n > 0 {
		fmt.Fprintf(stdout, "  · move %d key%s out of the file%s it is in and into Lyntway, leaving\n"+
			"    the file pointing at the gateway instead\n", n, pluralS(n), pluralS(n))
	}
	if n := len(f.Routable); n > 0 {
		fmt.Fprintf(stdout, "  · point %d tool%s here, so what %s sends is recorded\n",
			n, pluralS(n), map[bool]string{true: "it", false: "they"}[n == 1])
	}
	if n := len(f.Named); n > 0 {
		fmt.Fprintf(stdout, "\n%d key%s named above %s not moved. Nothing here holds a credential\n"+
			"for those providers; they are routed in the console, against the same\n"+
			"catalog entry this used to name them.\n",
			n, pluralS(n), map[bool]string{true: "is", false: "are"}[n == 1])
	}
	fmt.Fprint(stdout, "\nEvery file changed is backed up beside itself, and `lyntway undo`\n"+
		"puts all of it back.\n")
}

func connectCommand(args []string) error {
	yes := false
	for _, a := range args {
		switch a {
		case "--yes", "-y":
			yes = true
		case "--help", "-h":
			fmt.Fprint(os.Stderr, "lyntway connect — find what is here and route it, in one step\n\n"+
				"Usage:\n  lyntway connect [--yes]\n\n"+
				"Looks for provider keys in this directory, the MCP servers your agents\n"+
				"are configured to reach, and the tools on this machine that can be\n"+
				"pointed at Lyntway. Shows all of it, then asks once.\n\n"+
				"Nothing is changed until you agree, every file changed is backed up\n"+
				"beside itself, and `lyntway undo` reverses all of it.\n")
			return nil
		default:
			return fmt.Errorf("lyntway connect takes --yes or nothing, not %q", a)
		}
	}

	dir, _ := os.Getwd()
	f := takeConnectFindings(dir)
	printConnectFindings(f)

	if f.nothingToDo() {
		fmt.Fprint(stdout, "Nothing here to connect. `lyntway status` says what was looked at\n"+
			"and what is not covered.\n")
		return nil
	}

	// The discovery above needs no account. What follows does, and saying
	// so here — with the list already on the screen — is the difference
	// between an answer and a sign-up wall.
	if firstRunWanted() {
		printConnectPlan(f)
		fmt.Fprint(stdout, "\nRouting needs an account, because a receipt has to be signed by a key\n"+
			"that is not kept on the machine being recorded. `lyntway login` and then\n"+
			"this command again.\n")
		return nil
	}

	printConnectPlan(f)

	if !yes {
		fmt.Fprint(stdout, "\nConnect? [Y/n] ")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		switch strings.TrimSpace(strings.ToLower(line)) {
		case "", "y", "yes":
		default:
			fmt.Fprintln(stdout, "Stopped. Nothing was changed.")
			return nil
		}
	}

	// Keys first. Routing a tool whose key is still in a .env leaves the
	// key in the file, and somebody reading the console would see traffic
	// arriving and assume the file had been dealt with.
	if len(f.Migratable) > 0 {
		if err := keysMigrate([]string{"--yes", dir}); err != nil {
			return err
		}
	}
	if len(f.Routable) > 0 {
		if err := initialise([]string{"--yes"}); err != nil {
			return err
		}
	}
	return nil
}

// relativeTo rewrites a finding's path for a screen, leaving the finding
// otherwise as it was.
func relativeTo(dir string, h keyHit) keyHit {
	h.File = relativePath(dir, h.File)
	return h
}
