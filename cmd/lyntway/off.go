package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// `lyntway off` — the way out, in one command.
//
// # Why this exists when `undo` already did most of it
//
// `undo` reverses what was done to a person's own files: the editor
// configuration, the shell profile, the .env files `keys migrate`
// rewrote, the hooks, the MCP entries, ~/.lyntway/bin on PATH. It
// deliberately leaves Lyntway's own directory alone, because somebody
// putting one change back has not asked to lose their key or their
// receipts.
//
// What it does not do is remove the on-device agent, and it does not
// remove the state this tool wrote for itself. So "uninstall it" was two
// commands and a directory to delete by hand, and the promise on the box
// is that unplugging leaves nothing behind. A security tool that is hard
// to remove is a security tool people are right not to install.
//
// # Why the agent goes first
//
// The agent is the only part that can take a machine off the network.
// It has done it twice: an untrusted CA on 1 October and HTTP_PROXY
// exports stranded in the login profiles on 26 October, where it sets the
// proxy two ways and the recovery path knew one. If anything here fails
// it has to be the thing that happens after the network is back, not
// before — so the agent is removed first and a failure is reported and
// carried on from rather than returned.
//
// # What is kept, and said
//
// Receipts. They are the evidence; they are the one thing in this
// directory that is not ours to throw away, and a tool that deleted an
// audit trail on the way out would be the opposite of this product.
// Printed as a path, so somebody who does want them gone knows where.
func offCommand(args []string) error {
	keepReceipts := true
	for _, a := range args {
		switch a {
		case "--help", "-h":
			fmt.Fprint(stdout, "lyntway off — remove everything this tool did\n\n"+
				"Usage:\n  lyntway off [--receipts]\n\n"+
				"Puts back every file that was changed, removes the on-device agent,\n"+
				"the prompt hooks, the PATH entry and the registered databases.\n\n"+
				"Receipts are kept unless --receipts is given: they are evidence, and\n"+
				"nothing here deletes an audit trail without being asked.\n\n"+
				"Flags:\n  --receipts   delete the signed receipts as well\n")
			return nil
		case "--receipts":
			keepReceipts = false
		default:
			return fmt.Errorf("lyntway off takes --receipts or nothing, not %q", a)
		}
	}

	fmt.Fprint(stdout, "\nTaking Lyntway off this machine.\n")

	// The agent first, and its failure is not fatal: see above.
	if sidecarHealthy() || agentInstalled() {
		fmt.Fprint(stdout, "\nThe on-device agent:\n")
		if err := deviceUninstall([]string{"--local"}); err != nil {
			fmt.Fprintf(stdout, "  ✗ %v\n", err)
			fmt.Fprint(stdout, "  `lyntway device uninstall` on its own reports more. "+
				"Carrying on with the rest.\n")
		}
	}

	// Lyntway's own state, which undo leaves alone on purpose — before
	// undo rather than after, so undo's own closing summary is the last
	// thing on the screen instead of being followed by a second "Done".
	if !keepReceipts {
		if n := removeReceipts(); n > 0 {
			fmt.Fprintf(stdout, "\n  ✓ %d receipt file(s) deleted\n", n)
		}
	}
	for _, f := range ownStateBeforeUndo() {
		remove(f.path, f.what)
	}

	if err := undo(); err != nil {
		return err
	}

	// The record of what was changed goes last, and only after undo has
	// read it. Deleting it first — which the first version of this did —
	// leaves undo with nothing to restore and every migrated .env still
	// pointing at the gateway, which is the opposite of what the command
	// says on the box.
	remove(filepath.Join(home(), ".lyntway", "undo.json"), "the record of what was changed")

	if keepReceipts {
		if dir := receiptsDir(); dir != "" && isDir(dir) {
			// Stated from authority, not humility. "Verifies without us"
			// is on this repository's never-say list: it invites the
			// question of why anybody would need to, and the fact is
			// simply that the signature and the key are both in the
			// directory.
			// `lyntway-verify` is a separate binary, not a subcommand —
			// there is no `lyntway verify`, and printing one would send
			// somebody to a command that does not exist at the moment
			// they are trying to check their own evidence.
			fmt.Fprintf(stdout, "\nThe receipts are still in %s, and the public key\n"+
				"that signed them is in the same directory. Anyone can check them\n"+
				"there:\n\n"+
				"  lyntway-verify -keys %s/keys.json %s/<file>.jsonl\n\n"+
				"`lyntway off --receipts` deletes them instead.\n",
				relativeToHome(dir), relativeToHome(dir), relativeToHome(dir))
		}
	}
	return nil
}

// ownStateBeforeUndo is the state this tool wrote for itself that undo
// does not need, which `undo` is right to leave alone and `off` has to
// take.
//
// The signing seed goes even when the receipts stay. It is a private key,
// and leaving one behind after "remove everything" would be wrong whatever
// it signs; the receipts it already signed still verify, because what a
// verifier needs is the public key, and that is written beside them.
func ownStateBeforeUndo() []struct{ path, what string } {
	h := home()
	if h == "" {
		return nil
	}
	dir := filepath.Join(h, ".lyntway")
	return []struct{ path, what string }{
		{filepath.Join(dir, upstreamsFile), "registered databases removed"},
		{filepath.Join(dir, "dbgateway-signing.key"), "local signing key deleted"},
	}
}

// remove deletes one path and says so, treating an absent file as
// nothing to report rather than as a failure.
func remove(path, what string) {
	if path == "" {
		return
	}
	if err := os.Remove(path); err == nil {
		fmt.Fprintf(stdout, "  ✓ %s — %s\n", relativeToHome(path), what)
	} else if !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(stdout, "  ✗ %s — %v\n", relativeToHome(path), err)
	}
}

// receiptsDir is where the local signers write.
func receiptsDir() string {
	h := home()
	if h == "" {
		return ""
	}
	return filepath.Join(h, ".lyntway", "receipts")
}

// removeReceipts deletes the receipt directory and reports how many files
// went with it.
//
// Counted before the delete rather than after, so the number printed is
// what was actually there.
func removeReceipts() int {
	dir := receiptsDir()
	if dir == "" {
		return 0
	}
	n := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	if err := os.RemoveAll(dir); err != nil {
		fmt.Printf("  ✗ %s — %v\n", relativeToHome(dir), err)
		return 0
	}
	return n
}

// agentInstalled reports whether the agent left anything behind, so `off`
// can run its uninstall on a machine where the agent is not currently
// answering.
//
// Health is not the question. An agent that is installed and stopped is
// exactly the case that most needs removing: it is the one that comes
// back at the next login with a proxy nobody remembers setting.
func agentInstalled() bool {
	h := home()
	if h == "" {
		return false
	}
	for _, p := range []string{
		filepath.Join(h, ".lyntway", "sidecar"),
		filepath.Join(h, ".lyntway", "agent"),
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
