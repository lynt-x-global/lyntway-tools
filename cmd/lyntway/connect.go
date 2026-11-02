package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/detect"
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

	hits, _, _, err := scanPaths([]string{dir})
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

	// The databases among them have somewhere to go now, and this screen
	// is where somebody is looking. Before the gateway could be reached
	// without an account they were listed under "not moved" and that was
	// the end of it, which is how a working 4,814-line database proxy
	// stayed invisible to everybody who ran this command.
	if urls := connectableURLs(f.Named); len(urls) > 0 {
		noun := "are database connection strings"
		if len(urls) == 1 {
			noun = "is a database connection string"
		}
		fmt.Fprintf(stdout, "\n%d of those %s, and those can be proxied from\n"+
			"here with no account — the receipts are signed on this machine:\n",
			len(urls), noun)
		for i, u := range urls {
			if i == 3 {
				fmt.Fprintf(stdout, "  … and %d more.\n", len(urls)-3)
				break
			}
			fmt.Fprintf(stdout, "  lyntway connect %s\n", u)
		}
	}

	fmt.Fprint(stdout, "\nEvery file changed is backed up beside itself, and `lyntway undo`\n"+
		"puts all of it back.\n")
}

// connectableURLs names the database connection strings among the keys
// that cannot be migrated, as a command somebody can paste.
//
// Reads the value's own file rather than the finding, because the scanner
// deliberately keeps the credential out of keyHit — so the line printed
// here has to be a redacted form rebuilt from the file, and a file that
// has changed since the scan simply yields nothing.
func connectableURLs(named []keyHit) []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range named {
		if h.Class != string(detect.ClassURLPassword) {
			continue
		}
		body, err := os.ReadFile(h.File)
		if err != nil {
			continue
		}
		lines := strings.Split(string(body), "\n")
		if h.Line < 1 || h.Line > len(lines) {
			continue
		}
		for _, field := range strings.Fields(lines[h.Line-1]) {
			if i := strings.Index(field, "://"); i <= 0 {
				continue
			}
			// Strip an assignment, quotes and a trailing comma, which is
			// what a .env line and a source literal respectively put
			// around the value.
			if i := strings.IndexByte(field, '='); i >= 0 && !strings.Contains(field[:i], "://") {
				field = field[i+1:]
			}
			field = strings.Trim(field, `"',;`)
			c, err := readConnectable(field)
			if err != nil || c.Kind != kindDatabase {
				continue
			}
			if red := c.Redacted(); !seen[red] {
				seen[red] = true
				out = append(out, red)
			}
		}
	}
	return out
}

func connectCommand(args []string) error {
	yes := false
	var named []string
	for _, a := range args {
		switch a {
		case "--yes", "-y":
			yes = true
		case "--help", "-h":
			fmt.Fprint(os.Stderr, "lyntway connect — find what is here and route it, in one step\n\n"+
				"Usage:\n  lyntway connect [--yes]            find everything here and route it\n"+
				"  lyntway connect <url> [--yes]      put Lyntway in front of one thing\n\n"+
				"With no argument: looks for provider keys in this directory, the MCP\n"+
				"servers your agents are configured to reach, and the tools on this\n"+
				"machine that can be pointed at Lyntway. Shows all of it, then asks once.\n\n"+
				"With a URL: a PostgreSQL, MySQL or MongoDB connection string, or an\n"+
				"HTTP API's base address. Needs no account — the receipts are signed on\n"+
				"this machine.\n\n"+
				"Nothing is changed until you agree, every file changed is backed up\n"+
				"beside itself, and `lyntway undo` reverses all of it.\n")
			return nil
		default:
			if strings.HasPrefix(a, "-") {
				return fmt.Errorf("lyntway connect takes a URL or --yes, not %q", a)
			}
			named = append(named, a)
		}
	}

	// A named target is a different command from discovery: the person
	// has already decided what they want, so nothing is searched for and
	// nothing else on the machine is touched.
	if len(named) > 0 {
		if len(named) > 1 {
			return fmt.Errorf("one thing at a time: %d were named", len(named))
		}
		return connectOne(named[0], yes)
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
		switch askLine("\nConnect? [Y/n] ") {
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

// connectOne puts Lyntway in front of a single thing named on the
// command line.
//
// # Why this needs no account when the rest of connect does
//
// Routing a model call needs an account because the receipt has to be
// signed by a key that is not kept on the machine being recorded. The
// database gateway signs on the machine, with the key at
// ~/.lyntway/dbgateway-signing.key — the same arrangement `lyntway proxy`
// already has. So this works offline and says what that costs: a receipt
// that says a laptop signed it, which is evidence of a different weight
// from one the service signed. Never implied either way; the plan below
// prints it.
//
// # Why the connection string is not rewritten here
//
// Pointing an application at 127.0.0.1:15432 before anything listens
// there stops the application working, and the failure looks like the
// database being down. That is the shape of the two lockouts this tool
// has already caused. So the gateway is registered and started first, and
// the application's own configuration is the person's next step with the
// line printed for them to paste.
func connectOne(arg string, yes bool) error {
	c, err := readConnectable(arg)
	if err != nil {
		return err
	}

	switch c.Kind {
	case kindRefused:
		// The reason is the whole of the message, so it goes in the
		// error and main prints it once. Printing the detail here and
		// returning a short error as well — the pattern the scan
		// commands use, where the summary is a count — produced a bare
		// "lyntway:" line under the explanation.
		return errors.New(c.Why)

	case kindHTTP:
		// Honest about which half exists. An HTTP API is governed by
		// pointing its SDK at the gateway, which is `init`'s job and
		// needs an account — and saying so is better than a plan that
		// cannot be carried out.
		fmt.Fprintf(stdout, "\n%s is an HTTP API.\n\n", c.Host)
		fmt.Fprint(stdout, "Those are governed by pointing the SDK at the gateway rather than by a\n"+
			"listener on this machine, which is what `lyntway init` does and what needs\n"+
			"an account:\n  lyntway login\n  lyntway init\n\n"+
			"`lyntway connect` with no argument finds the ones already on this machine.\n")
		return nil

	case kindDatabase:
		return connectDatabase(c, yes)
	}
	return fmt.Errorf("unrecognised target kind %q", c.Kind)
}

// connectDatabase registers one database with the local gateway.
func connectDatabase(c connectable, yes bool) error {
	name := upstreamName(c)

	upstream := c.Host
	if c.Port != "" {
		upstream += ":" + c.Port
	}

	fmt.Fprintf(stdout, "\n%s at %s\n\n", driverLabel(c.Driver), upstream)
	fmt.Fprint(stdout, "Lyntway would sit between your application and it:\n\n")
	fmt.Fprintf(stdout, "  your app connects to    127.0.0.1:%s\n", c.LocalPort)
	fmt.Fprintf(stdout, "  Lyntway connects to     %s\n", upstream)
	fmt.Fprint(stdout, "  every statement         read, checked, and a receipt signed\n\n")

	// The provenance, before the question and not after it.
	fmt.Fprint(stdout, "The receipts say this machine signed them. That is not the same as\n"+
		"evidence the service signed — `lyntway login` makes it so, and this works\n"+
		"without an account either way.\n")

	if !yes {
		switch askLine("\nConnect? [Y/n] ") {
		case "", "y", "yes":
		default:
			fmt.Fprintln(stdout, "Stopped. Nothing was changed.")
			return nil
		}
	}

	path, err := upstreamsPath()
	if err != nil {
		return err
	}
	lines, err := writeUpstream(path, c.Upstream(name))
	if err != nil {
		return fmt.Errorf("registering the database: %w", err)
	}

	fmt.Fprintf(stdout, "\nRegistered %q in %s.\n", name, relativeToHome(path))
	if len(lines) > 1 {
		fmt.Fprintf(stdout, "%d databases are registered now.\n", len(lines))
	}

	fmt.Fprint(stdout, "\nStart the gateway:\n  lyntway-dbgateway\n\n")
	fmt.Fprintf(stdout, "Then point your application at it, and keep your own credentials — the\n"+
		"gateway dials the upstream with whatever the client presents:\n\n"+
		"  %s\n\n", exampleDSN(c))
	fmt.Fprint(stdout, "Change that only once the gateway is running. Pointing an application\n"+
		"at a port nothing is listening on looks exactly like the database being\n"+
		"down.\n")
	return nil
}

// upstreamName is what to call this database in the gateway and on a
// receipt.
//
// Taken from the host rather than asked for. The first label of a managed
// database's hostname is the thing a person recognises — "ep-cool-shape"
// for Neon, "cluster0" for Atlas — and a name nobody chose is better than
// a prompt nobody wanted.
func upstreamName(c connectable) string {
	host := c.Host
	if i := strings.IndexByte(host, '.'); i > 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "-")
	if host == "" || host == "localhost" || host == "127" {
		return c.Driver
	}
	return host
}

func driverLabel(driver string) string {
	switch driver {
	case "postgresql":
		return "PostgreSQL"
	case "mysql":
		return "MySQL"
	case "mongodb":
		return "MongoDB"
	}
	return driver
}

// exampleDSN is the connection string to paste, with the password left as
// the person's own to fill in rather than echoed back from the one they
// typed.
func exampleDSN(c connectable) string {
	switch c.Driver {
	case "postgresql":
		return "postgres://USER:PASSWORD@127.0.0.1:" + c.LocalPort + "/DATABASE"
	case "mysql":
		return "mysql://USER:PASSWORD@127.0.0.1:" + c.LocalPort + "/DATABASE"
	case "mongodb":
		return "mongodb://USER:PASSWORD@127.0.0.1:" + c.LocalPort + "/DATABASE"
	}
	return "127.0.0.1:" + c.LocalPort
}

func relativeToHome(path string) string {
	if h := home(); h != "" && strings.HasPrefix(path, h) {
		return "~" + path[len(h):]
	}
	return path
}
