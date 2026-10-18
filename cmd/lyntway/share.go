package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// Turn one receipt into a link somebody else can check.
//
// # Why this is not an upload
//
// The obvious build is a share endpoint: post the receipt, get a short
// link. It is also the wrong one. It would make us hold other people's
// evidence, which contradicts the sentence the whole product rests on —
// that a receipt verifies with no account, no network call to us, and no
// cooperation from us. A link that stops working when we do is not proof.
//
// So the receipt rides in the URL's fragment, and a fragment is never sent
// to any server. We cannot see what was shared, how often it was opened,
// or by whom, and the page that checks it does so in the reader's own
// browser against a key carried in the same fragment. The link works if
// this company disappears tomorrow, which is the only version of it worth
// handing to a security reviewer.
//
// # What a reader can conclude, and what they cannot
//
// Everything here is honest about one limit. A receipt written by `guard`
// or `proxy` is signed by a key on the machine that wrote it. The link
// carries that key, so the reader can check the signature — which proves
// the receipt has not been altered since it was made.
//
// It does not prove that an independent party saw anything. The key
// belongs to whoever sent the link, exactly as lyntway-mcp's does. Said
// plainly here, printed plainly beside the link, and said again on the
// page that opens it, because a reader who concludes more than that has
// been misled by us rather than by the sender.

const defaultShareOrigin = "https://lyntway.com"

func shareUsage() {
	fmt.Fprint(os.Stderr, "lyntway share — turn a receipt into a link anyone can check\n"+
		"\n"+
		"Usage:\n"+
		"  lyntway share [FILE] [--index N] [--origin URL]\n"+
		"\n"+
		"With no FILE, the newest receipt from the newest `lyntway guard` session.\n"+
		"FILE may be a .json receipt or a .jsonl chain; --index picks one from a\n"+
		"chain, counting from 0, and a negative number counts from the end.\n"+
		"\n"+
		"The receipt rides in the link's fragment, which is never sent to any\n"+
		"server — not even ours. Nothing is uploaded, we cannot see what you\n"+
		"shared, and the link keeps working whatever happens to us.\n"+
		"\n"+
		"What the reader can conclude is printed with the link, and it is less\n"+
		"than you might assume: a receipt written on your machine is signed by a\n"+
		"key on your machine, so the check proves it has not been altered, not\n"+
		"that anyone independent saw it happen.\n")
}

type shareOptions struct {
	File   string
	Index  int
	Origin string
	hasIdx bool
}

func shareCmd(args []string) error {
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	fs.Usage = shareUsage
	var opts shareOptions
	fs.IntVar(&opts.Index, "index", -1, "which receipt in a chain file; negative counts from the end")
	fs.StringVar(&opts.Origin, "origin", defaultShareOrigin, "where the verify page is served from")
	_ = fs.Parse(flagsFirst(fs, args))
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "index" {
			opts.hasIdx = true
		}
	})
	if rest := fs.Args(); len(rest) > 0 {
		opts.File = rest[0]
	}
	return runShare(opts, stdout)
}

func runShare(opts shareOptions, out io.Writer) error {
	path := opts.File
	if path == "" {
		var err error
		if path, err = newestGuardReceiptFile(); err != nil {
			return err
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	line, err := receiptLineAt(raw, opts.Index)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	var r receipt.Receipt
	if err := json.Unmarshal(line, &r); err != nil {
		return fmt.Errorf("%s does not hold a receipt: %w", path, err)
	}
	if r.Signature == nil || r.Signature.KeyID == "" {
		return fmt.Errorf("%s holds a receipt with no signature; there is nothing for a reader to check", path)
	}

	keys, keyErr := shareKeys(filepath.Join(filepath.Dir(path), "keys.json"), r.Signature.KeyID)

	link, err := shareLink(opts.Origin, line, keys)
	if err != nil {
		return err
	}

	shareSummary(out, &r, keys != nil, keyErr)
	fmt.Fprintf(out, "\n%s\n\n", link)
	return nil
}

// shareSummary says what is in the link before the link, so nobody pastes
// something they have not read. Content is not in a receipt at all, which
// is the first thing worth saying to somebody about to share one.
func shareSummary(out io.Writer, r *receipt.Receipt, haveKey bool, keyErr error) {
	fmt.Fprintf(out, "\nThis link carries one receipt. A reader will see:\n\n")
	fmt.Fprintf(out, "  receipt   %s\n", r.ID)
	if r.Action.Method != "" {
		fmt.Fprintf(out, "  action    %s → %s\n", r.Action.Method, orDefaultName(r.Action.Destination, "(none recorded)"))
	}
	fmt.Fprintf(out, "  decision  %s, governance %s\n", r.Governance.Decision, r.Governance.Mode)
	if len(r.Governance.Findings) > 0 {
		for _, f := range sortedFindings(r.Governance.Findings) {
			fmt.Fprintf(out, "  found     %s (%s) ×%d\n", detect.Label(detect.Class(f.Class)), f.Class, f.Count)
		}
	} else {
		fmt.Fprintf(out, "  found     nothing\n")
	}
	fmt.Fprintf(out, "  signed by %s\n", r.Issuer.KeyID)
	fmt.Fprintf(out, "\n  No content. A receipt records classes, counts and digests; the text\n"+
		"  that was governed is not in it and never was.\n")

	switch {
	case r.Issuer.KeyAttestation != nil:
		fmt.Fprintf(out, "\n  This key is attested by a deployment, so the reader can check it\n"+
			"  against that deployment's published key and weigh the result as\n"+
			"  evidence from a party that is not you.\n")
	case haveKey:
		// The honest limit, said before they paste it anywhere.
		fmt.Fprintf(out, "\n  The key travels with the link, because it is a key on this machine\n"+
			"  and nobody else publishes it. So the reader can prove this receipt\n"+
			"  has not been altered since you made it — not that an independent\n"+
			"  party saw it happen. The page says the same.\n")
	default:
		fmt.Fprintf(out, "\n  The verifying key could not be read (%v), so the reader will need\n"+
			"  it from elsewhere before the signature can be checked.\n", keyErr)
	}
}

func sortedFindings(in []receipt.Finding) []receipt.Finding {
	out := append([]receipt.Finding(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Class < out[j].Class })
	return out
}

// shareLink builds the URL. The receipt and the key go in the fragment,
// which browsers do not send to the server: following this link tells us
// nothing, which is the property that makes it worth sharing at all.
func shareLink(origin string, line []byte, keys []byte) (string, error) {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	if origin == "" {
		return "", errors.New("--origin is empty")
	}
	// Compacted first: a pretty-printed receipt would spend a third of the
	// link on whitespace, and some chat clients cut a long URL in half.
	var compact bytes.Buffer
	if err := json.Compact(&compact, line); err != nil {
		return "", fmt.Errorf("compacting the receipt: %w", err)
	}
	link := origin + "/verify#receipt=" + base64.RawURLEncoding.EncodeToString(compact.Bytes())
	if keys != nil {
		link += "&key=" + base64.RawURLEncoding.EncodeToString(keys)
	}
	return link, nil
}

// shareKeys reads the published key file beside a receipt and keeps only
// the key that signed it. The others are nobody's business: a file can
// accumulate several, and a link is about one receipt.
func shareKeys(path, keyID string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf struct {
		Keys       map[string]string `json:"keys"`
		Algorithms map[string]string `json:"algorithms"`
	}
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("%s is not a key file", path)
	}
	pub, ok := kf.Keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%s does not hold the key %s", path, keyID)
	}
	one := struct {
		Keys       map[string]string `json:"keys"`
		Algorithms map[string]string `json:"algorithms"`
	}{Keys: map[string]string{keyID: pub}, Algorithms: map[string]string{}}
	if alg, ok := kf.Algorithms[keyID]; ok {
		one.Algorithms[keyID] = alg
	}
	return json.Marshal(one)
}

// receiptLineAt picks one receipt out of a file that may hold several.
func receiptLineAt(raw []byte, index int) ([]byte, error) {
	var lines [][]byte
	for _, l := range strings.Split(string(raw), "\n") {
		if t := strings.TrimSpace(l); t != "" {
			lines = append(lines, []byte(t))
		}
	}
	if len(lines) == 0 {
		return nil, errors.New("holds no receipts")
	}
	i := index
	if i < 0 {
		i += len(lines)
	}
	if i < 0 || i >= len(lines) {
		return nil, fmt.Errorf("--index %d is outside the %d %s in this file", index, len(lines), plural(len(lines), "receipt", "receipts"))
	}
	return lines[i], nil
}

// newestGuardReceiptFile finds what the last `lyntway guard` session wrote.
func newestGuardReceiptFile() (string, error) {
	base := defaultReceiptsDir()
	if base == "" {
		return "", errors.New("this machine has no home directory, so there are no receipts to share; name a file")
	}
	dir := filepath.Join(base, guardLabel)
	sessions, err := os.ReadDir(dir)
	if err != nil || len(sessions) == 0 {
		return "", fmt.Errorf("no guard session has written receipts yet (looked in %s); run `lyntway guard -- claude`, or name a file", dir)
	}
	// The session directories are named by a UTC timestamp, so the last in
	// name order is the last in time.
	names := make([]string, 0, len(sessions))
	for _, s := range sessions {
		if s.IsDir() {
			names = append(names, s.Name())
		}
	}
	sort.Strings(names)
	for i := len(names) - 1; i >= 0; i-- {
		files, _ := filepath.Glob(filepath.Join(dir, names[i], guardLabel+"-*.jsonl"))
		sort.Strings(files)
		for j := len(files) - 1; j >= 0; j-- {
			if fi, err := os.Stat(files[j]); err == nil && fi.Size() > 0 {
				return files[j], nil
			}
		}
	}
	return "", fmt.Errorf("no session in %s holds a receipt yet", dir)
}
