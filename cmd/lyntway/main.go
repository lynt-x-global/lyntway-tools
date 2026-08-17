// Command lyntway points this machine's AI tools at Lyntway.
//
// # Why a command rather than a page of instructions
//
// The alternative is documentation: eight tools, eight settings screens,
// and a developer who gives up at the third. Nobody adopts a governance
// layer they have to install eight times, so the install is one command
// and the tool finds what is here.
//
//	lyntway login          store a key for this machine
//	lyntway init           find what is installed and route it through us
//	lyntway status         what is configured, and what is not covered
//	lyntway undo           put everything back
//
// # What it will not do
//
// It will not change anything before showing you the list and asking. It
// will not write to a file without leaving a backup beside it. It will not
// claim to cover a tool it cannot reach — JetBrains AI Assistant is named
// in the output precisely because nothing here can help with it, and
// finding that out later is worse than reading it now.
//
// # Where detection happens
//
// Two different answers, and the difference matters.
//
// Traffic to a model provider is routed through the gateway, so it is
// inspected there. That content was already leaving this machine for
// OpenAI or Anthropic; it now passes through us on the way.
//
// Tool results from MCP servers are inspected here, on this machine, by
// the shim. That content might never have left at all — a database tool
// returning a customer record — and sending it anywhere to be checked
// would be the disclosure this exists to prevent.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// version is stamped at link time by the release workflow. "dev" means a
// build from source, which is a useful thing for a support conversation to
// be able to establish in one line.
var version = "dev"

func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	var err error
	switch args[0] {
	case "login":
		err = login(args[1:])
	case "init":
		err = initialise(args[1:])
	case "status":
		err = status()
	case "undo":
		err = undo()
	case "version", "-v", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "lyntway: no command called %q\n\n", args[0])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "lyntway: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `lyntway — point this machine's AI tools at Lyntway

Usage:
  lyntway login    store a key for this machine
  lyntway init     find what is installed and route it through us
  lyntway status   what is configured, and what is not covered
  lyntway undo     put everything back
  lyntway version  which build this is

Nothing is changed until you have seen the list and agreed, and every file
that is changed is backed up beside itself first.
`)
}

// config is what this machine remembers.
type config struct {
	Origin string `json:"origin"`
	Key    string `json:"key"`
}

func configPath() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("this machine has no home directory: %w", err)
	}
	return filepath.Join(h, ".lyntway", "config.json"), nil
}

func loadConfig() (config, error) {
	path, err := configPath()
	if err != nil {
		return config{}, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("not signed in on this machine — run `lyntway login` first")
	}
	var c config
	if err := json.Unmarshal(body, &c); err != nil {
		return config{}, fmt.Errorf("the saved settings are unreadable; run `lyntway login` again")
	}
	return c, nil
}

func login(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	origin := fs.String("url", "", "the Lyntway address to use")
	key := fs.String("key", "", "an API key from your console")
	_ = fs.Parse(args)

	c := config{Origin: strings.TrimRight(*origin, "/"), Key: *key}

	in := bufio.NewReader(os.Stdin)
	if c.Origin == "" {
		fmt.Print("Lyntway address (e.g. https://lyntway.com): ")
		line, _ := in.ReadString('\n')
		c.Origin = strings.TrimRight(strings.TrimSpace(line), "/")
	}
	if c.Key == "" {
		// Read as ordinary input rather than hidden. This is a key the
		// person just copied from their own console, and a hidden field
		// somebody cannot see they have pasted into causes more failed
		// logins than it prevents shoulder surfing.
		fmt.Print("API key: ")
		line, _ := in.ReadString('\n')
		c.Key = strings.TrimSpace(line)
	}
	if c.Origin == "" || c.Key == "" {
		return fmt.Errorf("both an address and a key are needed")
	}

	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// 0600: this file holds a credential.
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return err
	}

	fmt.Printf("\nSaved to %s\nRun `lyntway init` to route this machine's tools through it.\n", path)
	return nil
}

func initialise(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask before changing anything")
	_ = fs.Parse(args)

	c, err := loadConfig()
	if err != nil {
		return err
	}

	targets := scan()

	fmt.Print("\nLooking at this machine…\n\n")
	var actionable []target
	for _, t := range targets {
		switch {
		case t.Found && t.Kind != kindManual:
			fmt.Printf("  ✓ %-46s found\n", t.Name)
			actionable = append(actionable, t)
		case t.Found && t.Kind == kindManual:
			fmt.Printf("  ~ %-46s found, needs two lines from you\n", t.Name)
		default:
			reason := t.Why
			if reason == "" {
				reason = "not installed"
			}
			fmt.Printf("  ✗ %-46s %s\n", t.Name, reason)
		}
	}

	if len(actionable) == 0 {
		fmt.Println("\nNothing here can be configured automatically.")
		printManual(c, targets)
		return nil
	}

	if !*yes {
		fmt.Print("\nRoute these through Lyntway? Every file is backed up first. [y/N] ")
		in := bufio.NewReader(os.Stdin)
		line, _ := in.ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Println("Nothing was changed.")
			return nil
		}
	}

	fmt.Println()
	for _, t := range actionable {
		switch t.Kind {
		case kindEnv:
			saved, err := writeEnv(t.Path, c.Origin, c.Key)
			if err != nil {
				fmt.Printf("  ✗ %s — %v\n", t.Name, err)
				continue
			}
			fmt.Printf("  ✓ %s\n", t.Path)
			if saved != "" {
				fmt.Printf("      backup: %s\n", filepath.Base(saved))
			}

		case kindMCP:
			changed, saved, err := wrapMCP(t.Path)
			if err != nil {
				fmt.Printf("  ✗ %s — %v\n", t.Name, err)
				continue
			}
			if len(changed) == 0 {
				fmt.Printf("  · %s — already routed, or nothing to route\n", t.Name)
				continue
			}
			fmt.Printf("  ✓ %s — %s\n", t.Name, strings.Join(changed, ", "))
			if saved != "" {
				fmt.Printf("      backup: %s\n", filepath.Base(saved))
			}

		case kindJSON:
			fmt.Printf("  ~ %s — set its base URL to %s/gw/openai/v1\n", t.Name, c.Origin)
		}
	}

	printManual(c, targets)

	fmt.Println("\nWatching only. Nothing is blocked and nothing is changed in your traffic,")
	fmt.Println("until you turn that on in Settings.")
	fmt.Println("\nOpen a new terminal for the shell settings to take effect.")
	fmt.Println("Undo everything with `lyntway undo`.")
	return nil
}

// printManual explains the tools that cannot be automated.
//
// Printed every time rather than only on failure, because somebody whose
// team uses JetBrains needs to see it in the output rather than discover
// it when an auditor asks why that traffic is missing.
func printManual(c config, targets []target) {
	var manual []target
	for _, t := range targets {
		if t.Kind == kindManual {
			manual = append(manual, t)
		}
	}
	if len(manual) == 0 {
		return
	}

	fmt.Println("\nNot done automatically:")
	for _, t := range manual {
		fmt.Printf("\n  %s\n    %s\n", t.Name, t.Why)
		if t.Name == "Cursor" {
			fmt.Printf("\n    Settings → Models → Override OpenAI Base URL:\n")
			fmt.Printf("      %s/gw/openai/v1\n", c.Origin)
			fmt.Printf("    API key:\n")
			fmt.Printf("      %s~YOUR_OPENAI_KEY\n", c.Key)
			fmt.Printf("    (the two keys joined by a tilde — Cursor has only one field)\n")
		}
	}
}

func status() error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	fmt.Printf("\nSigned in to %s\n\n", c.Origin)

	for _, t := range scan() {
		fmt.Println(statusLineFor(t))
	}

	fmt.Println("\nAnything not listed here is not being recorded. That is what the")
	fmt.Println("coverage page in your console is for.")
	return nil
}

// statusLineFor says where one target stands, in one line.
//
// Separated from status so every branch can be exercised without a machine
// that happens to have the right tools installed. The branch that was
// missing — a JSON-configured tool that is present — was missing precisely
// because nothing could reach it from a test.
func statusLineFor(t target) string {
	switch {
	case t.Kind == kindEnv && t.Path != "":
		body, _ := os.ReadFile(t.Path)
		if strings.Contains(string(body), markerStart) {
			return fmt.Sprintf("  ✓ %-46s routed", t.Name)
		}
		return fmt.Sprintf("  ✗ %-46s not routed", t.Name)

	case t.Kind == kindMCP && t.Found:
		servers, err := mcpServers(t.Path)
		if err != nil {
			return fmt.Sprintf("  ? %-46s unreadable", t.Name)
		}
		var wrapped int
		for _, entry := range servers {
			if alreadyWrapped(entry) {
				wrapped++
			}
		}
		return fmt.Sprintf("  %s %-46s %d of %d tools routed",
			tick(wrapped == len(servers) && wrapped > 0), t.Name, wrapped, len(servers))

	case t.Kind == kindJSON && t.Found:
		// Installed, and waiting on a step only a person can take. Without
		// this branch it fell through to "not installed", which is the
		// worst thing status could say about it: somebody reads that as
		// nothing to do, and an unrouted tool sits there until an auditor
		// asks why its traffic is missing.
		return fmt.Sprintf("  ~ %-46s found, needs its base URL set by hand", t.Name)

	case t.Kind == kindManual:
		return fmt.Sprintf("  ~ %-46s not covered by this command", t.Name)

	default:
		return fmt.Sprintf("  ✗ %-46s not installed", t.Name)
	}
}

func tick(ok bool) string {
	if ok {
		return "✓"
	}
	return "·"
}

func undo() error {
	fmt.Print("\nPutting things back…\n\n")
	var restored int

	for _, t := range scan() {
		if t.Path == "" || !exists(t.Path) {
			continue
		}
		switch t.Kind {
		case kindEnv:
			body, err := os.ReadFile(t.Path)
			if err != nil {
				continue
			}
			if !strings.Contains(string(body), markerStart) {
				continue
			}
			// The block is removed rather than the backup restored, so
			// anything else added to the profile since is kept.
			if err := os.WriteFile(t.Path, []byte(removeBlock(string(body))), 0o600); err != nil {
				fmt.Printf("  ✗ %s — %v\n", t.Path, err)
				continue
			}
			fmt.Printf("  ✓ %s\n", t.Path)
			restored++

		case kindMCP:
			ok, err := restore(t.Path)
			if err != nil {
				fmt.Printf("  ✗ %s — %v\n", t.Name, err)
				continue
			}
			if ok {
				fmt.Printf("  ✓ %s\n", t.Name)
				restored++
			}
		}
	}

	if restored == 0 {
		fmt.Println("  Nothing to put back.")
		return nil
	}
	fmt.Printf("\nDone. Backups are left in place; delete them when you are satisfied.\n")
	fmt.Println("Open a new terminal for the shell settings to take effect.")
	return nil
}
