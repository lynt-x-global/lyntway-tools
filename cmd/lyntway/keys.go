package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Moving provider keys out of a project, and giving this machine's key a
// signature.
//
// `keys migrate` exists because the first thing every team does with a
// gateway is nothing: the provider keys are in twelve .env files and
// nobody is going to edit twelve files. So this edits them, after showing
// the list, with a backup beside each one and `undo` to put them back.
// The original values go to the server and to the backup and nowhere
// else — not to the terminal, where last4 is all that is shown.
//
// `keys sign` gives the key a private half. A bearer token proves that
// whoever sent the request held the token; a signature proves they held
// a private key that never leaves this machine, and the receipt records
// the difference. The private key is a file under 0600. It is not in the
// keychain or the Secure Enclave, and this build does not pretend
// otherwise: a file can be copied, and the help text says so.

func keys(args []string) error {
	if len(args) == 0 {
		keysUsage()
		return fmt.Errorf("say which: migrate or sign")
	}
	switch args[0] {
	case "migrate":
		return keysMigrate(args[1:])
	case "sign":
		return keysSign(args[1:])
	case "help", "-h", "--help":
		keysUsage()
		return nil
	default:
		keysUsage()
		return fmt.Errorf("no keys command called %q", args[0])
	}
}

func keysUsage() {
	fmt.Fprint(os.Stderr, "lyntway keys — the keys a project holds, and the one this machine signs with\n"+
		"\n"+
		"Usage:\n"+
		"  lyntway keys migrate [dir] [--yes] [--replace]\n"+
		"      Find provider keys in the project's .env files, store each with\n"+
		"      Lyntway, and point the SDKs at the gateway. Nothing is written until\n"+
		"      you have seen the plan and agreed; every file is backed up beside\n"+
		"      itself first, and the backup is the only place the original value is\n"+
		"      kept. Undo with `lyntway undo`. The migration itself is receipted:\n"+
		"      the command ends by reporting what it did to your account and\n"+
		"      printing the signed receipt's id and where to verify it.\n"+
		"\n"+
		"  lyntway keys sign [--key-id ID] [--force] [--keychain]\n"+
		"      Generate an Ed25519 keypair for this machine's Lyntway key, register\n"+
		"      the public half, and export the private half's path for the SDKs so\n"+
		"      requests are signed. The private key is a file under ~/.lyntway/keys\n"+
		"      with mode 0600: a file with the right permissions can still be copied\n"+
		"      by anyone who can read your home directory. Treat it as you would an\n"+
		"      SSH key.\n"+
		"\n"+
		"      --keychain (macOS only) also stores a copy in your login keychain, as\n"+
		"      the backup of record: service \"lyntway\", account <key id>, holding the\n"+
		"      PKCS#8 key base64-encoded on one line. The SDKs still read the 0600\n"+
		"      file — none of them can open the keychain — so the file stays, and\n"+
		"      the keychain copy is what you restore it from if it is lost:\n"+
		"        security find-generic-password -s lyntway -a <key id> -w\n"+
		"      gives the base64 body to put between the PRIVATE KEY lines of a PEM.\n")
}

// apiClient bounds calls to the console API. Storing a key is quick; a
// call that takes longer than this is a network problem to report.
var apiClient = &http.Client{Timeout: 30 * time.Second}

// api makes one authenticated call and returns the status and body.
func api(c config, method, path string, body any) (int, []byte, error) {
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.Origin+path, payload)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := apiClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("reaching %s: %w", c.Origin, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}

// input reads prompts. One reader for the life of the process, so a
// second prompt does not lose the line the first one buffered.
var (
	input     *bufio.Reader
	inputFrom io.Reader
)

func ask(prompt string) bool {
	if input == nil || inputFrom != stdin {
		input, inputFrom = bufio.NewReader(stdin), stdin
	}
	fmt.Fprint(stdout, prompt)
	line, _ := input.ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}

type migrateOptions struct {
	Yes     bool // do not ask before writing
	Replace bool // do not ask before replacing a key the server already holds

	// Started is when the command began, so the receipt line at the end
	// can say how long the whole thing took. Zero means now.
	Started time.Time
}

func keysMigrate(args []string) error {
	fs := flag.NewFlagSet("keys migrate", flag.ExitOnError)
	opts := migrateOptions{Started: time.Now()}
	fs.BoolVar(&opts.Yes, "yes", false, "do not ask before writing")
	fs.BoolVar(&opts.Replace, "replace", false, "replace a key the server already holds for the same upstream without asking")
	_ = fs.Parse(flagsFirst(fs, args))

	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	return runMigrate(dir, c, opts)
}

// flagsFirst moves flags ahead of positional arguments.
//
// The flag package stops reading at the first argument that is not a
// flag, so `keys migrate ./api --yes` parsed the directory and silently
// dropped --yes — and then asked a question, which in a script reads an
// empty answer as no. Found by running the binary, not by any test of
// runMigrate, which is handed its options already parsed.
//
// A flag that takes a value keeps its value beside it. The first version
// moved every dash-prefixed word and nothing else, so `--diff main
// --format github` became `--diff --format main github`: --diff was read
// as "--format", and the GitHub Action, which runs exactly that, failed
// on its first use. Which flags take values is what the FlagSet knows,
// so it is asked rather than guessed at; the `--name=value` form needs
// no help and is left alone.
func flagsFirst(fs *flag.FlagSet, args []string) []string {
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			// Kept, so fs.Parse also stops there and what follows stays
			// positional even when it starts with a dash.
			rest = append(rest, args[i:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || len(a) == 1 {
			rest = append(rest, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // fs.Parse will report the unknown flag itself
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, rest...)
}

// runMigrate is the whole of `keys migrate` after the flags are read.
func runMigrate(dir string, c config, opts migrateOptions) error {
	if opts.Started.IsZero() {
		opts.Started = time.Now()
	}
	// What the server can hold, and what it already holds. Both are read
	// before any file is opened, so a deployment that stores no keys is
	// reported before anything else is said.
	extra, err := serverUpstreams(c)
	if err != nil {
		return err
	}
	stored, err := storedProviderKeys(c)
	if err != nil {
		return err
	}

	found, err := findCandidates(dir, extra, c.Key)
	if err != nil {
		return err
	}

	var plan []candidate
	fmt.Fprintf(stdout, "\nLooking at %s…\n", dir)
	for _, file := range sortedFiles(found) {
		fmt.Fprintf(stdout, "\n  %s\n", filepath.Base(file))
		for _, it := range found {
			if it.File != file {
				continue
			}
			if it.Skip != "" {
				fmt.Fprintf(stdout, "    · %-24s %s\n", it.Var, it.Skip)
				continue
			}
			note := ""
			if last, ok := stored[it.Upstream]; ok {
				note = fmt.Sprintf("  (the server already holds a key for %s ending %s)", it.Upstream, last)
			}
			fmt.Fprintf(stdout, "    → %-24s %-12s …%s%s\n", it.Var, it.Upstream, it.last4(), note)
			plan = append(plan, it)
		}
	}
	if len(plan) == 0 {
		fmt.Fprintln(stdout, "\nNothing to migrate.")
		return nil
	}

	fmt.Fprintf(stdout, "\nEach key is stored with %s and the variable is rewritten to your Lyntway key.\n", c.Origin)
	fmt.Fprintln(stdout, "A backup is written beside each file; that backup is the only place the original value is kept.")
	if !opts.Yes && !ask("\nGo ahead? [y/N] ") {
		fmt.Fprintln(stdout, "Nothing was changed.")
		return nil
	}

	// A key the server already holds is replaced only with consent, and
	// asked per upstream: the second project to be migrated must not
	// silently overwrite the key the first one stored.
	kept := plan[:0]
	for _, it := range plan {
		if last, ok := stored[it.Upstream]; ok && !opts.Replace {
			if !ask(fmt.Sprintf("Replace the stored %s key ending %s with the one ending %s? [y/N] ", it.Upstream, last, it.last4())) {
				fmt.Fprintf(stdout, "  · %s left as it is\n", it.Var)
				continue
			}
		}
		kept = append(kept, it)
	}
	plan = kept
	if len(plan) == 0 {
		fmt.Fprintln(stdout, "Nothing was changed.")
		return nil
	}

	fmt.Fprintln(stdout)

	// Stored first, rewritten second. A file rewritten to point at a key
	// the server refused would break the application it belongs to.
	stored = map[string]string{}
	var migrated []candidate
	for _, it := range plan {
		if last, done := stored[it.Upstream]; done {
			// Two files with a key for the same upstream: the first is
			// stored, and the second is rewritten to use it. Said out
			// loud, because if the two values differed the second one
			// is now in its backup and nowhere else.
			fmt.Fprintf(stdout, "  ✓ %-24s uses the %s key already stored this run (…%s)\n", it.Var, it.Upstream, last)
			migrated = append(migrated, it)
			continue
		}
		note := fmt.Sprintf("migrated from %s on %s", filepath.Base(it.File), hostLabel())
		status, raw, err := api(c, http.MethodPost, "/v1/keys/providers", map[string]string{
			"upstream": it.Upstream, "key": it.Value, "note": note,
		})
		if err != nil {
			return err
		}
		if status != http.StatusOK && status != http.StatusCreated {
			fmt.Fprintf(stdout, "  ✗ %-24s not stored: %s\n", it.Var, apiMessage(status, raw))
			continue
		}
		stored[it.Upstream] = it.last4()
		migrated = append(migrated, it)
		fmt.Fprintf(stdout, "  ✓ %-24s stored for %s (…%s)\n", it.Var, it.Upstream, it.last4())
	}
	if len(migrated) == 0 {
		fmt.Fprintln(stdout, "\nNo file was changed.")
		return nil
	}

	record, err := loadRecord()
	if err != nil {
		return err
	}
	for _, file := range sortedFiles(migrated) {
		var items []candidate
		for _, it := range migrated {
			if it.File == file {
				items = append(items, it)
			}
		}
		saved, err := rewriteEnv(file, items, c)
		if err != nil {
			fmt.Fprintf(stdout, "  ✗ %s — %v\n", file, err)
			continue
		}
		record.Files = append(record.Files, changedFile{Path: file, Backup: saved, At: time.Now().UTC().Format(time.RFC3339)})
		fmt.Fprintf(stdout, "  ✓ %s rewritten\n      backup: %s\n", filepath.Base(file), filepath.Base(saved))
	}
	if added, err := ignoreBackups(dir); err != nil {
		fmt.Fprintf(stdout, "  ✗ .gitignore — %v\n", err)
	} else if added {
		record.Gitignores = append(record.Gitignores, dir)
		fmt.Fprintf(stdout, "  ✓ .gitignore now ignores %s, so the backups cannot be committed\n", gitignoreBackupLine)
	} else if !exists(filepath.Join(dir, ".gitignore")) {
		fmt.Fprintf(stdout, "  · no .gitignore here; keep the backups out of version control yourself\n")
	}
	if err := saveRecord(record); err != nil {
		return err
	}

	fmt.Fprintln(stdout, "\nThe original values are in the backups and on the server, and nowhere else.")
	fmt.Fprintln(stdout, "Delete the backups when the application has been seen working. Undo with `lyntway undo`.")

	migrationReceipt(c, migrated, opts.Started)
	return nil
}

// migrationReceipt ends the command with a receipt of the command.
//
// Nothing has passed through the gateway yet — that needs an application
// to make a call — so the first receipt this account sees is of the
// migration itself: a report, posted to /v1/log, that this tool moved n
// keys. The service signs it and it verifies like any other. It is an
// attested receipt, since the service is recording what this command
// said it did, and the line printed says so rather than letting it read
// as the service having watched anything.
//
// The report carries upstream names and a count. Never the keys, never
// the last4s, never the file paths: a receipt is designed to be handed to
// somebody else, and a path is a fact about a machine that a stranger has
// no business holding.
func migrationReceipt(c config, migrated []candidate, started time.Time) {
	seen := map[string]bool{}
	var upstreams []string
	for _, it := range migrated {
		if !seen[it.Upstream] {
			seen[it.Upstream] = true
			upstreams = append(upstreams, it.Upstream)
		}
	}
	n := len(upstreams)
	statement := fmt.Sprintf("keys migrated: %d upstream%s (%s)", n, pluralS(n), strings.Join(upstreams, ", "))

	// Surface "primitive": the service's name for content handed to it
	// directly rather than intercepted, which is what a report is. The
	// first build said "tool", which the fake server in the tests took
	// and the real one refused — the fake now refuses it too.
	report := map[string]any{
		"tool":     "lyntway-cli",
		"chain_id": "lyntway-cli",
		"action": map[string]string{
			"surface":     "primitive",
			"direction":   "request",
			"method":      "keys migrate",
			"target":      hostLabel(),
			"destination": c.Origin,
		},
		// No decision is claimed. The service records a report with no
		// decision as log_only, which is what happened: something was
		// noted, nothing was allowed or refused.
		"reference": statement,
	}
	status, raw, err := api(c, http.MethodPost, "/v1/log", report)
	elapsed := time.Since(started).Round(100 * time.Millisecond)
	switch {
	case err != nil:
		fmt.Fprintf(stdout, "\nNo receipt for this migration: %v. Done in %s.\n", err, elapsed)
		return
	case status != http.StatusOK && status != http.StatusCreated:
		fmt.Fprintf(stdout, "\nNo receipt for this migration: %s did not record it (%s). Done in %s.\n", c.Origin, apiMessage(status, raw), elapsed)
		return
	}
	var res struct {
		Receipt   json.RawMessage `json:"receipt"`
		VerifyURL string          `json:"verify_url"`
	}
	var head struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &res) != nil || json.Unmarshal(res.Receipt, &head) != nil || head.ID == "" {
		fmt.Fprintf(stdout, "\nNo receipt for this migration: %s answered with something this build does not understand. Done in %s.\n", c.Origin, elapsed)
		return
	}

	fmt.Fprintf(stdout, "\nReceipt %s — %q, signed by %s. Done in %s.\n", head.ID, statement, c.Origin, elapsed)
	if path, err := saveReceipt(head.ID, res.Receipt); err == nil {
		fmt.Fprintf(stdout, "  saved:  %s\n", path)
	}
	if res.VerifyURL != "" {
		fmt.Fprintf(stdout, "  verify: %s  (paste the file; it checks with no account)\n", res.VerifyURL)
	}
	fmt.Fprintln(stdout, "  This receipt records what this command reported, so it reads as attested, not observed.")
}

// saveReceipt keeps the receipt where lyntway-verify can be pointed at it.
func saveReceipt(id string, body json.RawMessage) (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if !validKeyID(id) {
		return "", fmt.Errorf("receipt id %q cannot name a file", id)
	}
	dir := filepath.Join(h, ".lyntway", "receipts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, id+".json")
	return path, os.WriteFile(path, append(bytes.TrimSpace(body), '\n'), 0o600)
}

// serverUpstreams lists the upstreams this account added, whose names
// extend what a *_API_KEY variable can be matched against. A deployment
// that has none, or does not let accounts add them, answers 404.
func serverUpstreams(c config) ([]string, error) {
	status, raw, err := api(c, http.MethodGet, "/v1/upstreams", nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("%s does not accept this key; run `lyntway login` again", c.Origin)
	default:
		return nil, fmt.Errorf("listing upstreams: %s", apiMessage(status, raw))
	}
	var list []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, nil
	}
	var names []string
	for _, u := range list {
		if u.Name != "" {
			names = append(names, u.Name)
		}
	}
	return names, nil
}

// storedProviderKeys reports which upstreams already have a key on the
// server, by last4, so a replacement is a decision rather than a surprise.
func storedProviderKeys(c config) (map[string]string, error) {
	status, raw, err := api(c, http.MethodGet, "/v1/keys/providers", nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("%s does not accept this key; run `lyntway login` again", c.Origin)
	default:
		return nil, fmt.Errorf("%s cannot list stored keys: %s", c.Origin, apiMessage(status, raw))
	}
	var list struct {
		Available bool `json:"available"`
		Keys      []struct {
			Upstream string `json:"upstream"`
			Last4    string `json:"last4"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("%s answered /v1/keys/providers with something this build does not understand", c.Origin)
	}
	if !list.Available {
		return nil, fmt.Errorf("%s does not store provider keys, so there is nowhere to move them to", c.Origin)
	}
	out := map[string]string{}
	for _, k := range list.Keys {
		out[k.Upstream] = k.Last4
	}
	return out, nil
}

func keysSign(args []string) error {
	fs := flag.NewFlagSet("keys sign", flag.ExitOnError)
	keyID := fs.String("key-id", "", "the id of this machine's Lyntway key, shown beside it at /api-keys")
	force := fs.Bool("force", false, "replace a private key this machine already holds for that id")
	keychain := fs.Bool("keychain", false, "macOS: also keep a copy in the login keychain (service lyntway, account <key id>)")
	_ = fs.Parse(flagsFirst(fs, args))

	c, err := loadConfig()
	if err != nil {
		return err
	}
	id := strings.TrimSpace(*keyID)
	if id == "" {
		id = c.KeyID
	}
	if id == "" {
		return fmt.Errorf("which key? A key linked from the browser knows its id; one pasted in does not. Pass --key-id, from /api-keys")
	}
	if !validKeyID(id) {
		return fmt.Errorf("%q is not a key id this can name a file after", id)
	}
	return runSign(c, id, *force, *keychain)
}

// validKeyID admits only what can safely become a file name.
func validKeyID(id string) bool {
	if id == "" || len(id) > 80 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// runSign generates, stores, registers and exports a signing key.
func runSign(c config, id string, force, keychain bool) error {
	if keychain && goos != "darwin" {
		return fmt.Errorf("--keychain stores the key in the macOS login keychain; on %s the key is the 0600 file and nothing else", goos)
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(h, ".lyntway", "keys")
	path := filepath.Join(dir, id+".pem")
	if exists(path) && !force {
		return fmt.Errorf("a private key for %s already exists at %s; pass --force to replace it (the server will then trust only the new one)", id, path)
	}

	priv, pub, err := generateSigningKey(path)
	if err != nil {
		return err
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	fmt.Fprintf(stdout, "\nPrivate key written to %s (mode 0600).\nPublic key (ed25519, base64): %s\n", path, pubB64)

	// A failed keychain copy is reported at the end rather than stopping
	// here: the key is already on disk, and registering it and saving the
	// config are what make it work. Stopping would leave a key file the
	// config does not know about and `status` calling signing "not set
	// up", which was the first build's behaviour when the keychain was
	// not reachable.
	var keychainErr error
	if keychain {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return err
		}
		if keychainErr = keychainStore(id, base64.StdEncoding.EncodeToString(der)); keychainErr != nil {
			fmt.Fprintf(stdout, "  ✗ keychain copy not made: %v\n", keychainErr)
		} else {
			fmt.Fprintf(stdout, "Copy kept in the login keychain: service \"lyntway\", account %q. The file above is what the SDKs read.\n", id)
		}
	}

	body := map[string]string{"public_key": pubB64, "alg": "ed25519"}
	registerPath := "/v1/keys/" + id + "/signing"
	fmt.Fprintf(stdout, "\nRegistering it: POST %s%s\n", c.Origin, registerPath)
	status, raw, err := api(c, http.MethodPost, registerPath, body)
	registered := false
	switch {
	case err != nil:
		fmt.Fprintf(stdout, "  ✗ %v\n", err)
	case status == http.StatusOK || status == http.StatusCreated:
		registered = true
		fmt.Fprintf(stdout, "  ✓ registered; requests signed with this key are recorded as verified\n")
	case status == http.StatusNotFound || status == http.StatusMethodNotAllowed:
		fmt.Fprintf(stdout, "  · %s does not register signing keys yet\n", c.Origin)
	default:
		fmt.Fprintf(stdout, "  ✗ not registered: %s\n", apiMessage(status, raw))
	}
	if !registered {
		encoded, _ := json.Marshal(body)
		fmt.Fprintf(stdout, "\nUntil it is registered, signatures are sent and not checked. Register it later with:\n\n  curl -X POST %s%s \\\n    -H \"Authorization: Bearer $LYNTWAY_KEY\" -H 'Content-Type: application/json' \\\n    -d '%s'\n", c.Origin, registerPath, encoded)
	}

	c.KeyID, c.SigningKey = id, path
	if _, err := saveConfig(c); err != nil {
		return err
	}

	// The SDKs read the two variables from the environment. They join the
	// block `init` writes when it is there; when it is not, writing a
	// block nobody agreed to is init's decision to ask, not this one's.
	profile := shellProfile()
	if profile != "" {
		if prev, _ := os.ReadFile(profile); strings.Contains(string(prev), markerStart) {
			if _, err := writeEnv(profile, c); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "\nLYNTWAY_SIGNING_KEY and LYNTWAY_KEY_ID added to %s. Open a new terminal for them to take effect.\n", profile)
			return keychainOutcome(keychainErr, path)
		}
	}
	fmt.Fprintf(stdout, "\nExport these where your application runs (or run `lyntway init` to add them to your shell):\n\n  export LYNTWAY_SIGNING_KEY=%q\n  export LYNTWAY_KEY_ID=%q\n", path, id)
	return keychainOutcome(keychainErr, path)
}

// keychainOutcome turns a failed keychain copy into the command's exit
// status, after everything else has been done and said.
func keychainOutcome(err error, path string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("the key at %s is set up and signs; the keychain copy was not made (%v). The login keychain belongs to the user running this, and is not reachable from a session without one", path, err)
}

// generateSigningKey writes a fresh Ed25519 private key as PKCS#8 PEM.
//
// PKCS#8 because it is what every language's crypto library opens
// without a format argument; the raw seed would need the reader to know
// it was Ed25519. The directory is 0700 and the file 0600, created with
// those modes rather than chmod'd afterwards, so there is no moment at
// which the key is readable by anyone else.
func generateSigningKey(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if _, err := f.Write(block); err != nil {
		f.Close()
		return nil, nil, err
	}
	if err := f.Close(); err != nil {
		return nil, nil, err
	}
	// An existing file keeps its old mode through O_CREATE; --force
	// replacing a key must not inherit a loosened one.
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// goos is runtime.GOOS, a variable so the refusal on other platforms can
// be exercised from a test on this one.
var goos = runtime.GOOS

// keychainStore is what `--keychain` calls: swapped by tests, which must
// not write to the keychain of whoever runs them.
var keychainStore = storeInLoginKeychain

// storeInLoginKeychain writes one generic-password item with `security`.
//
// The secret travels on stdin, through the tool's interactive mode, not
// on the command line: an argument to `security add-generic-password -w`
// is visible to every process on the machine through `ps` for as long as
// the command runs, and a private key that was on the process list is not
// a private key. The item is stored as base64 of the PKCS#8 DER, one line,
// because the interactive parser reads a line and a PEM is several. -U
// replaces an existing item, which is what --force means.
func storeInLoginKeychain(id, secret string) error {
	line, err := keychainCommand(id, secret)
	if err != nil {
		return err
	}
	cmd := exec.Command("security", "-i")
	cmd.Stdin = strings.NewReader(line)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("security: %s", msg)
	}
	return nil
}

// keychainCommand is the one line fed to `security -i`.
//
// The interactive parser reads a line at a time and honours double
// quotes, so a secret with a quote, a backslash or a newline in it would
// end the command early or start a second one. Base64 has none of those;
// anything else is refused rather than escaped, because an escaping rule
// guessed at is how a secret ends up in a command it was not meant for.
func keychainCommand(id, secret string) (string, error) {
	if !validKeyID(id) {
		return "", fmt.Errorf("%q is not an id this will put in a keychain command", id)
	}
	if secret == "" || strings.ContainsAny(secret, "\"\n\r\\") || strings.ContainsAny(secret, " \t") {
		return "", fmt.Errorf("refusing to build a keychain command from a secret that is not one base64 line")
	}
	return fmt.Sprintf("add-generic-password -a %q -s lyntway -l %q -D %q -U -w %q\n",
		id, "Lyntway signing key "+id, "Lyntway signing key", secret), nil
}

// signingStatusLine says whether requests from this shell will be signed.
//
// Registration with the server is not reported here because this cannot
// know it without a call, and a status line that says "signed" when the
// server has no public key to check against would be the overclaim this
// product exists to avoid.
func signingStatusLine(c config, getenv func(string) string) string {
	const name = "Request signing"
	switch {
	case c.SigningKey == "":
		return fmt.Sprintf("  · %-46s not set up — `lyntway keys sign`", name)
	case !exists(c.SigningKey):
		return fmt.Sprintf("  ✗ %-46s the private key at %s is missing; run `lyntway keys sign --force`", name, c.SigningKey)
	case getenv("LYNTWAY_SIGNING_KEY") == c.SigningKey && getenv("LYNTWAY_KEY_ID") == c.KeyID:
		return fmt.Sprintf("  ✓ %-46s key %s signs from this shell", name, c.KeyID)
	default:
		return fmt.Sprintf("  · %-46s key %s at %s; not exported in this shell (open a new terminal)", name, c.KeyID, c.SigningKey)
	}
}
