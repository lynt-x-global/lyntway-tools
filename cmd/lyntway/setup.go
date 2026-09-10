package main

// The unified setup command: one line to sign in, scan, migrate keys,
// route tools and confirm. Each step reuses the existing commands
// (login, findCandidates, runMigrate, initialise, status) and every
// step shows what it will do and asks first.

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// projectSignals are the files whose presence means "this is a project
// directory". Checked in order; the first match names the project.
var projectSignals = []struct {
	file string
	name func(string) string // reads the file to extract a project name
}{
	{"package.json", projectNameFromPackageJSON},
	{"go.mod", projectNameFromGoMod},
	{"pyproject.toml", projectNameFromPyproject},
	{"Cargo.toml", nil},
	{"requirements.txt", nil},
	{"Gemfile", nil},
	{"pom.xml", nil},
	{".git", nil},
	{".env", nil},
}

func projectNameFromPackageJSON(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var doc struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &doc) == nil && doc.Name != "" {
		return doc.Name
	}
	return ""
}

func projectNameFromGoMod(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			parts := strings.Split(strings.TrimSpace(rest), "/")
			return parts[len(parts)-1]
		}
	}
	return ""
}

func projectNameFromPyproject(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "name"); ok {
			rest = strings.TrimSpace(rest)
			if rest, ok = strings.CutPrefix(rest, "="); ok {
				rest = strings.TrimSpace(rest)
				rest = strings.Trim(rest, "\"'")
				if rest != "" {
					return rest
				}
			}
		}
	}
	return ""
}

// isProject reports whether dir looks like a project directory, and
// returns its name when one can be extracted from a manifest.
func isProject(dir string) (name string, ok bool) {
	for _, sig := range projectSignals {
		path := filepath.Join(dir, sig.file)
		if _, err := os.Stat(path); err == nil {
			n := ""
			if sig.name != nil {
				n = sig.name(path)
			}
			if n == "" {
				n = filepath.Base(dir)
			}
			return n, true
		}
	}
	return "", false
}

// Scaffold functions create a minimal project structure so the directory
// is recognised and .env is ready for key migration.
func scaffoldTS(dir, name string) error {
	pkg := fmt.Sprintf(`{
  "name": %q,
  "version": "0.1.0",
  "private": true
}
`, name)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
		return err
	}
	return touchFile(filepath.Join(dir, ".env"))
}

func scaffoldPy(dir, name string) error {
	py := fmt.Sprintf(`[project]
name = %q
version = "0.1.0"
`, name)
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(py), 0o644); err != nil {
		return err
	}
	return touchFile(filepath.Join(dir, ".env"))
}

func scaffoldGo(dir, name string) error {
	mod := fmt.Sprintf("module %s\n\ngo 1.22\n", name)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		return err
	}
	return touchFile(filepath.Join(dir, ".env"))
}

func scaffoldOther(dir, _ string) error {
	return touchFile(filepath.Join(dir, ".env"))
}

func touchFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, nil, 0o644)
}

var scaffolds = map[string]func(dir, name string) error{
	"typescript": scaffoldTS,
	"python":     scaffoldPy,
	"go":         scaffoldGo,
	"other":      scaffoldOther,
}

// validateKey checks whether the saved key is still accepted by the server.
func validateKey(c config) (ok bool, reason string) {
	signer, _ := loadRequestSigner(c)
	status, raw, err := doAPI(statusClient, c, signer, http.MethodGet, "/v1/keys/providers", nil)
	switch {
	case err != nil:
		return false, "network"
	case status == http.StatusUnauthorized:
		return false, "revoked"
	case status == http.StatusOK:
		return true, ""
	default:
		return false, apiMessage(status, raw)
	}
}

// expiryWarningDays is how many days before a provider key expires the
// CLI starts warning. 30 days gives a team time to rotate without panic.
const expiryWarningDays = 30

// providerKeyExpiry is the subset of ProviderKey the CLI reads back.
type providerKeyExpiry struct {
	Upstream  string `json:"upstream"`
	Last4     string `json:"last4"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// checkProviderKeyExpiry fetches stored provider keys and prints a
// warning for any that expire within expiryWarningDays.
func checkProviderKeyExpiry(c config) {
	signer, _ := loadRequestSigner(c)
	st, raw, err := doAPI(statusClient, c, signer, http.MethodGet, "/v1/keys/providers", nil)
	if err != nil || st != http.StatusOK {
		return
	}
	printProviderKeyExpiry(raw, c.Origin)
}

// printProviderKeyExpiry warns about provider keys approaching expiry.
// raw is the JSON response body from GET /v1/keys/providers.
func printProviderKeyExpiry(raw []byte, origin string) {
	var resp struct {
		Keys []providerKeyExpiry `json:"keys"`
	}
	if json.Unmarshal(raw, &resp) != nil {
		return
	}
	now := time.Now().UTC()
	threshold := now.Add(time.Duration(expiryWarningDays) * 24 * time.Hour)
	for _, k := range resp.Keys {
		if k.ExpiresAt == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339, k.ExpiresAt)
		if err != nil {
			continue
		}
		if at.Before(now) {
			fmt.Fprintf(stdout, "\n   Warning: your %s key (...%s) has expired.\n", k.Upstream, k.Last4)
			fmt.Fprintf(stdout, "     Replace it at %s or with `lyntway keys migrate`.\n", origin)
		} else if at.Before(threshold) {
			days := int(at.Sub(now).Hours() / 24)
			if days <= 0 {
				days = 1
			}
			fmt.Fprintf(stdout, "\n   Warning: your %s key (...%s) expires in %d day%s.\n", k.Upstream, k.Last4, days, pluralS(days))
			fmt.Fprintf(stdout, "     Rotate it before %s.\n", at.Format("2 January 2006"))
		}
	}
}

func setup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	yes := fs.Bool("yes", false, "skip all confirmations")
	keyFlag := fs.String("key", "", "an API key from the console")
	urlFlag := fs.String("url", defaultOrigin, "the Lyntway address")
	if args != nil {
		_ = fs.Parse(args)
	}

	fmt.Fprintln(stdout, "\nlyntway setup")
	fmt.Fprintln(stdout, strings.Repeat("─", 50))

	// ── Step 1: Login check + key validation ──

	fmt.Fprintln(stdout, "\n1. Sign in")
	c, loadErr := loadConfig()
	needLogin := false

	// When --url is given explicitly, use it instead of whatever the
	// saved config remembers — the user is telling us where to go.
	urlExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "url" {
			urlExplicit = true
		}
	})
	if urlExplicit {
		c.Origin = *urlFlag
	}

	if loadErr != nil || c.Key == "" {
		needLogin = true
	} else {
		ok, reason := validateKey(c)
		switch {
		case ok:
			prefix := c.Key
			if len(prefix) > 12 {
				prefix = prefix[:12]
			}
			fmt.Fprintf(stdout, "   Signed in to %s (%s…)\n", c.Origin, prefix)
			checkProviderKeyExpiry(c)
			if !*yes {
				fmt.Fprint(stdout, "   Continue? [Y/n] ")
				line, _ := bufio.NewReader(stdin).ReadString('\n')
				a := strings.TrimSpace(strings.ToLower(line))
				if a != "" && a != "y" && a != "yes" {
					fmt.Fprintln(stdout, "   Stopped.")
					return nil
				}
			}
		case reason == "revoked":
			fmt.Fprintln(stdout, "   Key is revoked or invalid. Signing in again…")
			needLogin = true
		case reason == "network":
			fmt.Fprintf(stdout, "   Cannot reach %s.\n", c.Origin)
			if !*yes {
				fmt.Fprint(stdout, "   Continue offline? [Y/n] ")
				line, _ := bufio.NewReader(stdin).ReadString('\n')
				a := strings.TrimSpace(strings.ToLower(line))
				if a != "" && a != "y" && a != "yes" {
					fmt.Fprintln(stdout, "   Stopped.")
					return nil
				}
			}
		default:
			fmt.Fprintf(stdout, "   Key check: %s. Signing in again…\n", reason)
			needLogin = true
		}
	}

	if needLogin {
		var loginArgs []string
		if *urlFlag != defaultOrigin {
			loginArgs = append(loginArgs, "--url", *urlFlag)
		}
		if *keyFlag != "" {
			loginArgs = append(loginArgs, "--key", *keyFlag)
		}
		if err := login(loginArgs); err != nil {
			return err
		}
		c, loadErr = loadConfig()
		if loadErr != nil {
			return loadErr
		}
	}

	// ── Step 2: Project detection ──

	fmt.Fprintln(stdout, "\n2. Project")
	dir, _ := os.Getwd()
	projName, isProj := isProject(dir)

	if isProj {
		fmt.Fprintf(stdout, "   Found project: %s (%s)\n", projName, dir)
		if !*yes {
			fmt.Fprint(stdout, "   Set up Lyntway here? [Y/n] ")
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			a := strings.TrimSpace(strings.ToLower(line))
			if a != "" && a != "y" && a != "yes" {
				dir = ""
			}
		}
	} else {
		fmt.Fprintln(stdout, "   No project found in this directory.")
		if !*yes {
			fmt.Fprintln(stdout, "     1. Enter a path to an existing project")
			fmt.Fprintln(stdout, "     2. Create a new project")
			fmt.Fprintln(stdout, "     3. Continue without a project")
			fmt.Fprint(stdout, "   Choice [3]: ")
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			choice := strings.TrimSpace(line)
			switch choice {
			case "1":
				fmt.Fprint(stdout, "   Path: ")
				pLine, _ := bufio.NewReader(stdin).ReadString('\n')
				p := strings.TrimSpace(pLine)
				if p != "" {
					absP, err := filepath.Abs(p)
					if err != nil {
						return fmt.Errorf("bad path: %w", err)
					}
					if info, err := os.Stat(absP); err != nil || !info.IsDir() {
						return fmt.Errorf("%s is not a directory", absP)
					}
					dir = absP
				}
			case "2":
				fmt.Fprint(stdout, "   Project name: ")
				nLine, _ := bufio.NewReader(stdin).ReadString('\n')
				pName := strings.TrimSpace(nLine)
				if pName == "" {
					pName = "my-project"
				}
				fmt.Fprintln(stdout, "   Type:")
				fmt.Fprintln(stdout, "     1. TypeScript")
				fmt.Fprintln(stdout, "     2. Python")
				fmt.Fprintln(stdout, "     3. Go")
				fmt.Fprintln(stdout, "     4. Other")
				fmt.Fprint(stdout, "   Choice [4]: ")
				tLine, _ := bufio.NewReader(stdin).ReadString('\n')
				tChoice := strings.TrimSpace(tLine)
				typeMap := map[string]string{"1": "typescript", "2": "python", "3": "go"}
				projType := typeMap[tChoice]
				if projType == "" {
					projType = "other"
				}
				newDir := filepath.Join(dir, pName)
				if err := os.MkdirAll(newDir, 0o755); err != nil {
					return err
				}
				if fn, ok := scaffolds[projType]; ok {
					if err := fn(newDir, pName); err != nil {
						return err
					}
				}
				dir = newDir
				fmt.Fprintf(stdout, "   Created %s (%s)\n", pName, dir)
			default:
				dir = ""
			}
		} else {
			dir = ""
		}
	}

	// ── Step 3: Scan + migrate keys ──

	if dir != "" {
		fmt.Fprintln(stdout, "\n3. Keys")
		absDir, err := filepath.Abs(dir)
		if err == nil {
			dir = absDir
		}
		extra, _ := serverUpstreams(c)
		found, scanErr := findCandidates(dir, extra, c.Key)
		if scanErr != nil {
			if !strings.Contains(scanErr.Error(), "no .env file") {
				fmt.Fprintf(stdout, "   %v\n", scanErr)
			} else {
				envPath := filepath.Join(dir, ".env")
				fmt.Fprintln(stdout, "   No .env files found.")
				create := *yes
				if !*yes {
					fmt.Fprint(stdout, "   Create an empty .env? [Y/n] ")
					line, _ := bufio.NewReader(stdin).ReadString('\n')
					a := strings.TrimSpace(strings.ToLower(line))
					create = a == "" || a == "y" || a == "yes"
				}
				if create {
					if err := touchFile(envPath); err != nil {
						fmt.Fprintf(stdout, "   Could not create .env: %v\n", err)
					} else {
						fmt.Fprintf(stdout, "   Created %s\n", envPath)
						fmt.Fprintln(stdout, "   Add your provider keys there and run `lyntway keys migrate` to move them.")
					}
				}
			}
		} else {
			var actionable []candidate
			for _, it := range found {
				if it.Skip == "" {
					actionable = append(actionable, it)
				}
			}
			if len(actionable) == 0 {
				fmt.Fprintln(stdout, "   No provider keys to migrate.")
			} else {
				for _, it := range actionable {
					fmt.Fprintf(stdout, "   → %-24s %-12s …%s\n", it.Var, it.Upstream, it.last4())
				}
				doMigrate := *yes
				if !*yes {
					fmt.Fprint(stdout, "   Migrate these to Lyntway? [y/N] ")
					line, _ := bufio.NewReader(stdin).ReadString('\n')
					a := strings.TrimSpace(strings.ToLower(line))
					doMigrate = a == "y" || a == "yes"
				}
				if doMigrate {
					if err := runMigrate(dir, c, migrateOptions{Yes: true, Replace: true, Started: time.Now()}); err != nil {
						fmt.Fprintf(stdout, "   Migration: %v\n", err)
					}
				} else {
					fmt.Fprintln(stdout, "   Skipped.")
				}
			}
		}
	} else {
		fmt.Fprintln(stdout, "\n3. Keys — skipped (no project directory)")
	}

	// ── Step 4: Route tools ──

	fmt.Fprintln(stdout, "\n4. Tools")
	targets := scan()
	var actionable []target
	for _, t := range targets {
		if t.Found && t.Kind != kindManual {
			actionable = append(actionable, t)
		}
	}
	if len(actionable) == 0 {
		fmt.Fprintln(stdout, "   No tools found to route automatically.")
	} else {
		for _, t := range targets {
			if t.Found {
				fmt.Fprintf(stdout, "   %s %s\n", tick(t.Kind != kindManual), t.Name)
			}
		}
		doRoute := *yes
		if !*yes {
			fmt.Fprint(stdout, "   Route these through Lyntway? [y/N] ")
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			a := strings.TrimSpace(strings.ToLower(line))
			doRoute = a == "y" || a == "yes"
		}
		if doRoute {
			if err := initialise([]string{"--yes"}); err != nil {
				fmt.Fprintf(stdout, "   Routing: %v\n", err)
			}
		} else {
			fmt.Fprintln(stdout, "   Skipped.")
		}
	}

	if ollamaRunning() {
		fmt.Fprintln(stdout, "\n   Ollama is running on this machine.")
		fmt.Fprintln(stdout, "   Run `lyntway proxy` in another terminal to govern its traffic.")
	}

	// ── Step 5: Summary ──

	fmt.Fprintln(stdout, "\n5. Summary")
	fmt.Fprintln(stdout, strings.Repeat("─", 50))
	if err := status(); err != nil {
		fmt.Fprintf(stdout, "   %v\n", err)
	}
	fmt.Fprintln(stdout, "\nLyntway is ready. Undo everything with `lyntway undo`.")
	return nil
}
