// Command lyntway points this machine's AI tools at Lyntway.
//
// # Why a command rather than a page of instructions
//
// The alternative is documentation: eight tools, eight settings screens,
// and a developer who gives up at the third. Nobody adopts a governance
// layer they have to install eight times, so the install is one command
// and the tool finds what is here.
//
//	lyntway login          connect this machine to an account
//	lyntway init           find what is installed and route it through us
//	lyntway keys migrate   move provider keys out of a project's .env files
//	lyntway keys sign      give this key a signing keypair
//	lyntway hook install   refuse a prompt that carries a provider key
//	lyntway scan           find provider keys in files or a diff
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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// stdout and stdin are swapped by tests, which capture everything a command
// prints and assert that no key value is in it. Printing straight to
// os.Stdout would make that assertion impossible to write.
var (
	stdout io.Writer = os.Stdout
	stdin  io.Reader = os.Stdin
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
	case "keys":
		err = keys(args[1:])
	case "hook":
		err = hook(args[1:])
	case "scan":
		err = scanCommand(args[1:])
	case "proxy":
		err = proxyCmd(args[1:])
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
  lyntway login          connect this machine to an account
  lyntway init           find what is installed and route it through us
  lyntway keys migrate   move provider keys out of a project's .env files
  lyntway keys sign      give this key a signing keypair
  lyntway hook install   have Claude Code or Cursor refuse a prompt that carries a key
  lyntway scan           find provider keys in files, or in a diff before it is pushed
  lyntway proxy          govern Ollama or LM Studio on this machine
  lyntway status         what is configured, and what is not covered
  lyntway undo           put everything back
  lyntway version        which build this is

Nothing is changed until you have seen the list and agreed, and every file
that is changed is backed up beside itself first.
`)
}

// defaultOrigin is where `login` goes when no address is given. Self-hosted
// deployments pass --url.
const defaultOrigin = "https://lyntway.com"

// config is what this machine remembers.
type config struct {
	Origin string `json:"origin"`
	Key    string `json:"key"`

	// KeyID is the identifier of Key, when it is known. A key approved
	// through a device link arrives with its id; one pasted from the
	// console does not, so `keys sign` asks for it then.
	KeyID string `json:"key_id,omitempty"`

	// SigningKey is the path of the private key `keys sign` wrote. The
	// path, never the key: the key is on disk under 0600 and this file
	// is read by `status`, which must not need it.
	SigningKey string `json:"signing_key,omitempty"`
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

// saveConfig writes what this machine remembers, and returns where.
func saveConfig(c config) (string, error) {
	path, err := configPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	// 0600: this file holds a credential.
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func login(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	origin := fs.String("url", defaultOrigin, "the Lyntway address to use")
	key := fs.String("key", "", "an API key from your console; without one, this machine is linked from the browser")
	keyID := fs.String("key-id", "", "the id of that key, shown beside it at /api-keys (only needed later, by `keys sign`)")
	_ = fs.Parse(args)

	c := config{Origin: strings.TrimRight(strings.TrimSpace(*origin), "/"), Key: strings.TrimSpace(*key), KeyID: strings.TrimSpace(*keyID)}
	if c.Origin == "" {
		return fmt.Errorf("an address is needed: --url https://lyntway.com")
	}

	if c.Key == "" {
		// No key given: link this machine from the browser. The server
		// issues the key once somebody signed in there approves, so
		// nothing is pasted and the key's id is known from the start.
		got, err := linkLogin(c.Origin, hostLabel(), openBrowser, nil)
		switch {
		case err == nil:
			c.Key, c.KeyID = got.APIKey, got.KeyID
			if got.Origin != "" {
				c.Origin = strings.TrimRight(got.Origin, "/")
			}
		case errors.Is(err, errLinkUnsupported):
			// An older or self-hosted server without self-service signup
			// cannot issue a key this way; the console still can.
			fmt.Fprintf(stdout, "%s does not offer browser linking, so a key from its console is needed.\n", c.Origin)
		default:
			return err
		}
	}

	if c.Key == "" {
		// Read as ordinary input rather than hidden. This is a key the
		// person just copied from their own console, and a hidden field
		// somebody cannot see they have pasted into causes more failed
		// logins than it prevents shoulder surfing.
		fmt.Fprint(stdout, "API key: ")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		c.Key = strings.TrimSpace(line)
	}
	if c.Key == "" {
		return fmt.Errorf("a key is needed")
	}

	// A machine signing in again keeps its signing key: the keypair
	// belongs to the key id, and a fresh login with the same id must not
	// silently drop it.
	if prev, err := loadConfig(); err == nil && prev.SigningKey != "" && (c.KeyID == "" || c.KeyID == prev.KeyID) {
		c.SigningKey = prev.SigningKey
		if c.KeyID == "" {
			c.KeyID = prev.KeyID
		}
	}

	path, err := saveConfig(c)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\nSaved to %s\nRun `lyntway init` to route this machine's tools through it.\n", path)
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

	// Install to ~/.lyntway/bin/ so `lyntway undo` works from any terminal
	// without remembering where the download was extracted.
	binDir, installErr := installSelf()
	if installErr != nil {
		fmt.Printf("  ~ could not install to ~/.lyntway/bin: %v\n", installErr)
	} else {
		fmt.Printf("  ✓ Installed to %s\n", binDir)
		if err := addToUserPath(binDir); err != nil {
			fmt.Printf("    (could not add to PATH automatically — add %s yourself)\n", binDir)
		}
	}

	for _, t := range actionable {
		switch t.Kind {
		case kindEnv:
			saved, err := writeEnv(t.Path, c)
			if err != nil {
				fmt.Printf("  ✗ %s — %v\n", t.Name, err)
				continue
			}
			fmt.Printf("  ✓ %s — base URLs and LYNTWAY_KEY written\n", t.Path)
			if saved != "" {
				fmt.Printf("      backup: %s\n", filepath.Base(saved))
			}
			// Not "routed". The base URL is half of it; the other half is
			// a credential the gateway accepts, and whether the shell will
			// have one is only knowable once a shell has read the block.
			if os.Getenv("OPENAI_API_KEY") != "" {
				fmt.Println("      OPENAI_API_KEY is paired with your Lyntway key when a new shell starts,")
				fmt.Println("      provided it is set before this block.")
			} else {
				fmt.Println("      No OPENAI_API_KEY is set in this shell. When you set one, pair it:")
				fmt.Printf("        export OPENAI_API_KEY=\"%s~YOUR_OPENAI_KEY\"\n", c.Key)
			}
			fmt.Println("      ANTHROPIC_AUTH_TOKEN carries your Lyntway key; ANTHROPIC_API_KEY stays your own.")
			fmt.Println("      Run `lyntway status` in a new terminal to confirm before relying on it.")

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
			fmt.Printf("\n    This covers models you add with your own key. Anything\n")
			fmt.Printf("    included in Cursor's subscription goes to their servers\n")
			fmt.Printf("    and cannot be routed here by any setting.\n")
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
		fmt.Println(statusLineFor(t, c, os.Getenv))
	}
	fmt.Println(signingStatusLine(c, os.Getenv))
	if pidPath, err := proxyPIDPath(); err == nil {
		fmt.Println(proxyStatusLine(pidPath, probeProxy))
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
func statusLineFor(t target, c config, getenv func(string) string) string {
	switch {
	case t.Kind == kindEnv && t.Path != "":
		body, _ := os.ReadFile(t.Path)
		if !strings.Contains(string(body), markerStart) {
			return fmt.Sprintf("  ✗ %-46s not routed", t.Name)
		}
		return shellStatusLine(t, c, getenv)

	case t.Kind == kindMCP && t.Found:
		servers, err := mcpServers(t.Path)
		if err != nil {
			return fmt.Sprintf("  ? %-46s unreadable", t.Name)
		}
		var wrapped, total int
		for name, entry := range servers {
			if name == "lyntway" {
				continue // our own remote connection, not a tool to wrap
			}
			total++
			if alreadyWrapped(entry) {
				wrapped++
			}
		}
		return fmt.Sprintf("  %s %-46s %d of %d tools routed",
			tick(wrapped == total && wrapped > 0), t.Name, wrapped, total)

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

// shellStatusLine reports the shell this command is running in.
//
// The block being in the profile used to be the whole test, and it was
// the wrong test: a profile can hold the block while the shell reading it
// has no provider key, or has one set after the block, or has the pair in
// a header the gateway never authenticates. Each of those returns 401 on
// every call, and "routed" was the last word anybody would have used for
// it. So the live environment is what is checked — which also means a
// terminal opened before init honestly reads as not yet routed.
func shellStatusLine(t target, c config, getenv func(string) string) string {
	var routed, broken []string
	var detail []string

	// OpenAI: one field, so the two keys travel joined in the bearer.
	switch {
	case getenv("OPENAI_BASE_URL") != c.Origin+"/gw/openai/v1":
		// Not pointed at us in this shell; nothing to say about the key.
	case getenv("OPENAI_API_KEY") == "":
		detail = append(detail, "OpenAI: no OPENAI_API_KEY in this shell. When you set one, pair it:",
			fmt.Sprintf(`  export OPENAI_API_KEY="%s~YOUR_OPENAI_KEY"`, c.Key))
	case !paired(getenv("OPENAI_API_KEY"), c.Key):
		broken = append(broken, "OpenAI")
		detail = append(detail, "OpenAI: OPENAI_API_KEY is not paired with your Lyntway key, so every call is refused (401). Set:",
			fmt.Sprintf(`  export OPENAI_API_KEY="%s~YOUR_OPENAI_KEY"`, c.Key))
	default:
		routed = append(routed, "OpenAI")
	}

	// Anthropic: its SDK sends ANTHROPIC_API_KEY in x-api-key and
	// ANTHROPIC_AUTH_TOKEN as the bearer. The gateway authenticates the
	// bearer alone, so the Lyntway key goes in the token and the provider
	// key stays where it was.
	switch {
	case getenv("ANTHROPIC_BASE_URL") != c.Origin+"/gw/anthropic":
	case strings.Contains(getenv("ANTHROPIC_API_KEY"), "~"):
		broken = append(broken, "Anthropic")
		detail = append(detail, "Anthropic: ANTHROPIC_API_KEY carries the tilde pair, but Anthropic's SDK sends it in a header",
			"  the gateway does not authenticate, so every call is refused (401). Keep your own key there and set:",
			fmt.Sprintf(`  export ANTHROPIC_AUTH_TOKEN="%s"`, c.Key))
	case getenv("ANTHROPIC_API_KEY") == "":
		detail = append(detail, "Anthropic: no ANTHROPIC_API_KEY in this shell; nothing to route until one is set.")
	case getenv("ANTHROPIC_AUTH_TOKEN") != c.Key:
		broken = append(broken, "Anthropic")
		detail = append(detail, "Anthropic: ANTHROPIC_AUTH_TOKEN is not your Lyntway key, so every call is refused (401). Set:",
			fmt.Sprintf(`  export ANTHROPIC_AUTH_TOKEN="%s"`, c.Key))
	default:
		routed = append(routed, "Anthropic")
	}

	var mark, summary string
	switch {
	case len(broken) > 0:
		mark, summary = "✗", strings.Join(broken, " and ")+" refused — see below"
	case len(routed) > 0:
		mark, summary = "✓", strings.Join(routed, " and ")+" routed"
	case len(detail) > 0:
		mark, summary = "·", "pointed at Lyntway; no provider key in this shell yet"
	default:
		mark, summary = "·", "configured; open a new terminal for it to take effect"
	}

	lines := []string{fmt.Sprintf("  %s %-46s %s", mark, t.Name, summary)}
	for _, d := range detail {
		lines = append(lines, "      "+d)
	}
	return strings.Join(lines, "\n")
}

// paired reports whether value is our key joined to a non-empty provider
// key. Ours alone with a trailing tilde authenticates and then forwards no
// credential, which the provider reports as a failure on our side.
func paired(value, key string) bool {
	return strings.HasPrefix(value, key+"~") && len(value) > len(key)+1
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

	// Files `keys migrate` rewrote are restored from their backups, since
	// the rewrite changed lines outside the fenced block.
	n, err := undoRecorded()
	if err != nil {
		fmt.Printf("  ✗ %v\n", err)
	}
	restored += n

	// After the settings restore above, not before: a backup that
	// predates `hook install` has no hook in it, and one written after it
	// has, so the entry is taken out of whatever was just put back.
	restored += removeHooksEverywhere()

	if restored == 0 {
		fmt.Println("  Nothing to put back.")
		return nil
	}
	fmt.Printf("\nDone. Backups are left in place; delete them when you are satisfied.\n")
	fmt.Println("Open a new terminal for the shell settings to take effect.")
	return nil
}
