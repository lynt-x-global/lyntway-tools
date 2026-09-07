// Command lyntway-verify checks Lyntway action receipts offline.
//
// It makes no network calls, requires no Lyntway account, and shares no code
// path with the issuer beyond the receipt package itself. Anyone handed a
// receipt and a public key can confirm what it says — which is the entire
// point of signing receipts rather than hosting a lookup service.
//
// Exit codes:
//
//	0  receipt verified
//	1  receipt did not verify
//	2  usage or input error
//
// A degraded or bypassed receipt exits 0: it verified, and it honestly
// reports partial governance. Use -require-full to treat that as a failure.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lynt-x-global/lyntway-tools/anchor"
	"github.com/lynt-x-global/lyntway-tools/cose"
	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
)

const usage = `lyntway-verify — verify Lyntway action receipts offline

Usage:
  lyntway-verify [flags] <receipt.json>
  lyntway-verify [flags] -            read the receipt from stdin

Keys:
  -key ID=VALUE      public key as ID=<base64-or-hex>, repeatable
                     ID may carry an algorithm: -key "k1:es256=BFq..."
  -keys FILE         JSON key file, as published at
                     /.well-known/lyntway-keys.json:
                     {"keys": {"<id>": "..."}, "algorithms": {"<id>": "es256"}}

Options:
  -chain             input is a chain of receipts — a JSON array or one
                     receipt per line, as the local tools write — and the
                     links between them are verified
  -require-full      exit non-zero unless governance ran at full strength
  -max-age DURATION  reject receipts older than this (e.g. 720h)
  -json              emit machine-readable JSON instead of text

Both serialisations are accepted. A COSE_Sign1 envelope is recognised by its
tag, so nobody handed a receipt needs to know which form it is first.

Transparency:
  -inclusion FILE    a COSE Receipt (RFC 9942) from the transparency log,
                     raw or hex, proving this receipt is in the log; the
                     tree size and root it reconstructs are printed
  -log-keys FILE     key file for the log's signing key; the keys given
                     with -key and -keys are used when absent
  -h, -help          show this message

Exit codes:
  0  verified   1  not verified   2  usage or input error
`

// keyMaterial is a public key together with the scheme it belongs to.
type keyMaterial struct {
	raw       []byte
	algorithm string
}

// keyFlag collects repeated -key ID=VALUE arguments.
type keyFlag map[string]keyMaterial

func (k keyFlag) String() string { return "" }

func (k keyFlag) Set(v string) error {
	id, encoded, ok := strings.Cut(v, "=")
	if !ok || id == "" || encoded == "" {
		return errors.New(`expected ID=VALUE, for example "key-1=3b6a..."`)
	}
	// The algorithm may be appended as ID:alg=VALUE. Ed25519 is assumed
	// otherwise, since it is what every deployment issues unless it has
	// deliberately moved its key into hardware.
	alg := "ed25519"
	if name, suffix, found := strings.Cut(id, ":"); found {
		id, alg = name, suffix
	}
	raw, err := decodeKey(encoded, alg)
	if err != nil {
		return err
	}
	k[id] = keyMaterial{raw: raw, algorithm: alg}
	return nil
}

// decodeKey accepts a public key as base64 (standard or URL-safe, padded or
// not) or as hex. Accepting several encodings costs little and removes a
// tedious class of "it looked right" support conversation.
// keySizes are the raw encoded lengths of the public keys this tool
// accepts. An Ed25519 key is 32 bytes; a P-256 key is an uncompressed
// point — one 0x04 tag byte and two 32-byte coordinates.
var keySizes = map[string]int{"ed25519": 32, "es256": 65}

func decodeKey(s, algorithm string) ([]byte, error) {
	s = strings.TrimSpace(s)
	want, ok := keySizes[algorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported key algorithm %q", algorithm)
	}

	if raw, err := hex.DecodeString(s); err == nil && len(raw) == want {
		return raw, nil
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil && len(raw) == want {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("not a %d-byte %s public key in hex or base64", want, algorithm)
}

type keyFile struct {
	Keys map[string]string `json:"keys"`

	// Algorithms names the scheme for each key. A deployment publishes it
	// alongside the key, and without it a P-256 key is indistinguishable
	// from a corrupt Ed25519 one — which is exactly how it used to be
	// reported.
	Algorithms map[string]string `json:"algorithms"`
}

// version is stamped at link time by the release workflow. "dev" means a
// build from source.
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	keys := keyFlag{}
	fs := flag.NewFlagSet("lyntway-verify", flag.ContinueOnError)
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.SetOutput(io.Discard)
	fs.Var(keys, "key", "public key as ID=<base64-or-hex>, repeatable")
	keysPath := fs.String("keys", "", "path to a JSON key file")
	asChain := fs.Bool("chain", false, "input is an array of receipts")
	requireFull := fs.Bool("require-full", false, "require full-strength governance")
	maxAge := fs.Duration("max-age", 0, "reject receipts older than this")
	asJSON := fs.Bool("json", false, "emit JSON output")
	inclusionPath := fs.String("inclusion", "", "path to a COSE Receipt proving inclusion in the transparency log")
	logKeysPath := fs.String("log-keys", "", "path to a JSON key file for the transparency log")
	help := fs.Bool("help", false, "show usage")
	fs.BoolVar(help, "h", false, "show usage")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(os.Stdout, usage)
			return 0
		}
		fmt.Fprintf(os.Stderr, "lyntway-verify: %v\n\n%s", err, usage)
		return 2
	}
	if *showVersion {
		fmt.Println(version)
		return 0
	}
	if *help {
		fmt.Fprint(os.Stdout, usage)
		return 0
	}

	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	if *keysPath != "" {
		if err := loadKeyFile(*keysPath, keys); err != nil {
			fmt.Fprintf(os.Stderr, "lyntway-verify: %v\n", err)
			return 2
		}
	}
	if len(keys) == 0 {
		fmt.Fprintf(os.Stderr, "lyntway-verify: no public keys supplied; use -key or -keys\n")
		return 2
	}

	data, err := readInput(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "lyntway-verify: %v\n", err)
		return 2
	}

	resolver, err := buildResolver(keys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lyntway-verify: %v\n", err)
		return 2
	}

	opts := receipt.VerifyOptions{
		MaxAge:              *maxAge,
		RequireFullStrength: *requireFull,
	}

	if *asChain {
		if *inclusionPath != "" {
			fmt.Fprintf(os.Stderr, "lyntway-verify: -inclusion proves one receipt; it cannot be combined with -chain\n")
			return 2
		}
		return verifyChain(data, resolver, opts, *asJSON)
	}

	var incl *inclusionOutput
	if *inclusionPath != "" {
		logResolver := resolver
		if *logKeysPath != "" {
			logKeys := keyFlag{}
			if err := loadKeyFile(*logKeysPath, logKeys); err != nil {
				fmt.Fprintf(os.Stderr, "lyntway-verify: %v\n", err)
				return 2
			}
			if logResolver, err = buildResolver(logKeys); err != nil {
				fmt.Fprintf(os.Stderr, "lyntway-verify: %v\n", err)
				return 2
			}
		}
		var code int
		if incl, code = verifyInclusion(data, *inclusionPath, resolver, logResolver, *asJSON); code != 0 {
			return code
		}
	}
	return verifyOne(data, resolver, opts, *asJSON, incl)
}

// inclusionOutput is what a verified COSE Receipt established.
type inclusionOutput struct {
	// Entry is the receipt digest as logged: the value a verifier hands to
	// the log to ask for a proof, and the one a successor receipt records
	// as its prev_hash.
	Entry    string `json:"entry"`
	TreeSize uint64 `json:"tree_size"`
	Root     string `json:"root"`
}

// verifyInclusion checks a COSE Receipt from the transparency log against
// the receipt's digest.
//
// The digest is taken over the document as read, exactly as the signature
// is, so a receipt carrying fields this build does not know about is still
// looked up under the digest the log holds for it.
func verifyInclusion(data []byte, proofPath string, keys, logKeys receipt.KeyResolver, jsonOut bool) (*inclusionOutput, int) {
	proof, err := readProof(proofPath)
	if err != nil {
		return nil, fail(jsonOut, err, 2)
	}
	entry, err := receiptEntry(data, keys)
	if err != nil {
		return nil, fail(jsonOut, fmt.Errorf("computing the receipt's digest: %w", err), 2)
	}
	size, root, err := cose.VerifyInclusionReceipt(proof, entry, logKeys)
	if err != nil {
		// The receipt itself may be perfectly sound; what failed is its
		// claim to be in the log. The headline says which, because
		// "NOT VERIFIED" alone reads as forgery.
		if jsonOut {
			emitJSON(output{Status: "NOT VERIFIED — INCLUSION NOT PROVEN", Valid: false, Error: err.Error()})
			return nil, 1
		}
		fmt.Printf("%s\n\n  the log's receipt does not prove that entry %s is in the log:\n  %v\n\n",
			statusLine("NOT VERIFIED — INCLUSION NOT PROVEN", false), entry, err)
		return nil, 1
	}
	return &inclusionOutput{Entry: string(entry), TreeSize: size, Root: hex.EncodeToString(root)}, 0
}

// readProof reads a COSE Receipt, accepting hex because that is how the log
// hands it over in JSON and how a person pastes it.
func readProof(path string) ([]byte, error) {
	raw, err := readInput(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(raw)
	if decoded, err := hex.DecodeString(string(trimmed)); err == nil && len(decoded) > 0 {
		return decoded, nil
	}
	return raw, nil
}

// receiptEntry returns the bytes the transparency log hashed for this
// receipt: its digest, as 64 characters of lowercase hex.
//
// The digest is SHA-256 over the receipt's signing input, derived from the
// document as it arrived rather than from a parsed struct, for the same
// reason the signature is: a field this build does not know must not
// change which entry is looked up.
func receiptEntry(data []byte, keys receipt.KeyResolver) ([]byte, error) {
	raw := data
	if looksLikeCOSE(data) {
		res, err := cose.Verify1(data, keys)
		if err != nil {
			return nil, err
		}
		raw = res.Payload
	} else {
		raw, _ = unwrapEnvelope(data)
	}
	input, err := receipt.SigningInputFromJSON(raw)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(input)
	return []byte(hex.EncodeToString(sum[:])), nil
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		return data, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, nil
}

func loadKeyFile(path string, into keyFlag) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading key file: %w", err)
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return fmt.Errorf("parsing key file: %w", err)
	}
	if len(kf.Keys) == 0 {
		return fmt.Errorf("key file %s contains no keys", path)
	}
	for id, encoded := range kf.Keys {
		alg := kf.Algorithms[id]
		if alg == "" {
			alg = "ed25519"
		}
		decoded, err := decodeKey(encoded, alg)
		if err != nil {
			return fmt.Errorf("key %q in %s: %w", id, path, err)
		}
		into[id] = keyMaterial{raw: decoded, algorithm: alg}
	}
	return nil
}

// output is the machine-readable shape emitted under -json.
type output struct {
	Status       string `json:"status"`
	Valid        bool   `json:"valid"`
	FullStrength bool   `json:"full_strength"`
	Mode         string `json:"mode,omitempty"`
	Decision     string `json:"decision,omitempty"`
	// Approval is who resolved a held action and which way. Without it a
	// require_approval decision with a digest of released content reads
	// as a hold that was quietly waved through.
	Approval   *receipt.Approval `json:"approval,omitempty"`
	KeyID      string            `json:"key_id,omitempty"`
	Provenance string            `json:"provenance,omitempty"`
	Vantage    string            `json:"vantage,omitempty"`
	Algorithm  string            `json:"algorithm,omitempty"`
	IssuedAt   string            `json:"issued_at,omitempty"`
	Digest     string            `json:"digest,omitempty"`
	// Subject is what the digest was taken over. Absent from the receipt
	// means the payload; anything else means a record about the traffic,
	// and a consumer reading the digest without this field would take it
	// for a hash of the data.
	Subject string `json:"subject,omitempty"`
	// Truncated means the digests cover the prefix of a stream that policy
	// cut; the remainder never reached the caller.
	Truncated   bool     `json:"truncated,omitempty"`
	ChainID     string   `json:"chain_id,omitempty"`
	ChainLength int      `json:"chain_length,omitempty"`
	ChainHead   string   `json:"chain_head,omitempty"`
	Degraded    int      `json:"degraded_count,omitempty"`
	Bypassed    int      `json:"bypassed_count,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Error       string   `json:"error,omitempty"`

	// Inclusion is present when -inclusion was given and the log's receipt
	// verified. Its absence means nothing was checked, not that the
	// receipt is absent from the log.
	Inclusion *inclusionOutput `json:"inclusion,omitempty"`
}

// looksLikeCOSE reports whether the input is a COSE_Sign1 rather than JSON.
//
// Detected rather than declared by a flag. Somebody handed a receipt should
// not have to know which serialisation it is before they can check it —
// and the two are trivially distinguishable, since a COSE_Sign1 begins with
// its tag and JSON with a brace.
func looksLikeCOSE(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case 0xd2: // tag 18, the COSE_Sign1 tag
			return true
		default:
			return false
		}
	}
	return false
}

// unwrapEnvelope returns the receipt inside a document that carries one.
//
// Detected rather than declared, for the same reason looksLikeCOSE is:
// somebody handed a file should not have to know its shape before they can
// check it. /v1/demo answers with the governed content, the decision, the
// findings and the receipt together, because a person looking at the demo
// wants all four. Piping that straight into this tool is the obvious next
// move, and it used to fail with a type error about Receipt.content — which
// reads as "your receipt is malformed" rather than "look one level down".
// Our own analyst brief shipped that exact broken sequence.
//
// The bytes returned are the inner document verbatim. The signature covers
// those and not the envelope, and re-encoding here would drop any field
// this build has never heard of and report a good receipt as tampered.
func unwrapEnvelope(data []byte) ([]byte, bool) {
	var envelope struct {
		Receipt json.RawMessage `json:"receipt"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return data, false
	}
	inner := bytes.TrimSpace(envelope.Receipt)
	if len(inner) == 0 || inner[0] != '{' {
		return data, false
	}
	// A receipt nested under "receipt" inside something that is itself a
	// receipt would be a different document; only unwrap when the outer one
	// is not already valid on its own terms.
	var outer receipt.Receipt
	if err := json.Unmarshal(data, &outer); err == nil && outer.Version != "" {
		return data, false
	}
	return inner, true
}

func verifyOne(data []byte, keys receipt.KeyResolver, opts receipt.VerifyOptions, jsonOut bool, incl *inclusionOutput) int {
	if looksLikeCOSE(data) {
		r, err := cose.DecodeReceipt(data, keys)
		if err != nil {
			fmt.Printf("%s\n\n  %v\n\n", statusLine("NOT VERIFIED", false), err)
			return 1
		}
		// The COSE signature already covers these exact bytes, so what
		// remains is to report what the receipt says — the schema checks
		// and the policy options still apply.
		encoded, err := json.Marshal(r)
		if err != nil {
			fmt.Printf("%s\n\n  %v\n\n", statusLine("NOT VERIFIED", false), err)
			return 1
		}
		fmt.Println("  (COSE_Sign1 envelope verified; reporting the receipt inside)")
		data = encoded
	}

	// Say so when the receipt came out of something larger. The signature
	// covers the receipt and nothing around it, so a person who edits the
	// surrounding fields and sees VERIFIED has been told the truth by a tool
	// that failed to make it obvious — and the demo in our own analyst brief
	// invites exactly that edit.
	data, unwrapped := unwrapEnvelope(data)
	if unwrapped && !jsonOut {
		fmt.Println("  (verifying the receipt inside this document; the fields around it" +
			" are not covered by its signature)")
	}

	var r receipt.Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return fail(jsonOut, fmt.Errorf("parsing receipt: %w", err), 2)
	}

	// Verified over the document as read from disk, not over the struct
	// this build parsed it into. A receipt from a newer deployment can
	// carry fields this binary has never heard of, and hashing the parsed
	// struct would drop them and report a perfectly good receipt as
	// tampered — the one failure that would make an old verifier worse than
	// useless.
	// A signature proves the document is intact. It says nothing about
	// whether this build understood every claim in it, and the field it
	// could not read might be the one that matters.
	if unknown, uerr := receipt.UnknownFields(data); uerr == nil && len(unknown) > 0 {
		defer func() {
			fmt.Printf("\n  ! this receipt carries fields this verifier does not understand: %s\n"+
				"    the signature covers them, so nothing is wrong with the receipt — but a newer\n"+
				"    build of this tool would tell you what they say.\n",
				strings.Join(unknown, ", "))
		}()
	}

	res, err := receipt.VerifyJSON(data, keys, opts)
	if err != nil {
		// A result alongside an error means the receipt verified
		// cryptographically but was refused by policy, typically
		// -require-full. Say so precisely rather than implying forgery.
		if res != nil {
			return reportWith(jsonOut, res, &r, err, incl)
		}
		return fail(jsonOut, err, 1)
	}
	return reportWith(jsonOut, res, &r, nil, incl)
}

func verifyChain(data []byte, keys receipt.KeyResolver, opts receipt.VerifyOptions, jsonOut bool) int {
	rs, err := decodeReceipts(data)
	if err != nil {
		return fail(jsonOut, err, 2)
	}

	chain, err := receipt.VerifyChain(rs, keys, opts)
	if err != nil {
		return fail(jsonOut, err, 1)
	}

	out := output{
		Status:       "VERIFIED",
		Valid:        true,
		FullStrength: chain.Degraded == 0 && chain.Bypassed == 0,
		ChainID:      chain.ChainID,
		ChainLength:  chain.Length,
		ChainHead:    chain.Head,
		Degraded:     chain.Degraded,
		Bypassed:     chain.Bypassed,
	}
	if chain.Bypassed > 0 {
		out.Status = "VERIFIED — CONTAINS BYPASSED ACTIONS"
	} else if chain.Degraded > 0 {
		out.Status = "VERIFIED — CONTAINS DEGRADED GOVERNANCE"
	}

	if jsonOut {
		emitJSON(out)
		return 0
	}

	fmt.Printf("%s\n\n", statusLine(out.Status, out.FullStrength))
	fmt.Printf("  chain          %s\n", chain.ChainID)
	fmt.Printf("  receipts       %d (links intact, no gaps)\n", chain.Length)
	fmt.Printf("  head           %s\n", chain.Head)
	if chain.Degraded > 0 {
		fmt.Printf("  degraded       %d of %d actions ran with reduced detection\n", chain.Degraded, chain.Length)
	}
	if chain.Bypassed > 0 {
		fmt.Printf("  bypassed       %d of %d actions passed unexamined\n", chain.Bypassed, chain.Length)
	}
	fmt.Println()
	return 0
}

func report(jsonOut bool, res *receipt.Result, r *receipt.Receipt, policyErr error) int {
	return reportWith(jsonOut, res, r, policyErr, nil)
}

// reportWith is report with the result of an inclusion check, when one
// was asked for.
func reportWith(jsonOut bool, res *receipt.Result, r *receipt.Receipt, policyErr error, incl *inclusionOutput) int {
	out := output{
		Inclusion:    incl,
		Valid:        res.Valid,
		FullStrength: res.FullStrength,
		Mode:         string(res.Mode),
		Decision:     string(res.Decision),
		Approval:     r.Governance.Approval,
		KeyID:        res.KeyID,
		Provenance:   string(res.Provenance),
		Vantage:      res.Vantage,
		Algorithm:    string(res.Algorithm),
		IssuedAt:     res.IssuedAt.UTC().Format(time.RFC3339),
		Digest:       res.Digest,
		Subject:      string(r.EffectiveSubject()),
		ChainID:      r.Chain.ID,
		Warnings:     res.Warnings,
	}
	// The receipt library's warnings say nothing about the subject, and a
	// JSON consumer that only reads warnings would otherwise take a
	// metadata digest for a hash of the data.
	if note := subjectWarning(r.EffectiveSubject()); note != "" {
		out.Warnings = append(append([]string(nil), out.Warnings...), note)
	}
	if r.Content.Truncated {
		// A cut stream carries "block" beside an output digest, which on
		// any other receipt would be a contradiction. Said plainly so a
		// reader neither takes the prefix for the whole response nor
		// takes the pairing for tampering.
		out.Truncated = true
		out.Warnings = append(append([]string(nil), out.Warnings...), truncatedWarning)
	}

	// Anchors are checked before the headline is chosen. A token that
	// provably commits to different content is not a curiosity to mention
	// further down the page — it is evidence the receipt was interfered
	// with after signing, in the one region a signature cannot cover.
	anchorResults, anchorErr := anchor.VerifyAll(r)

	switch {
	case policyErr != nil:
		out.Status = "REJECTED BY POLICY"
		out.Error = policyErr.Error()
	case anchorErr != nil:
		// The signature is still sound, and saying otherwise would be
		// inaccurate. What failed is the receipt's claim to independent
		// corroboration of its time, so the headline says exactly that and
		// the exit code is non-zero so automation cannot miss it.
		out.Status = "VERIFIED — ANCHOR NOT VALID"
		out.Error = anchorErr.Error()
	case res.Mode == receipt.ModeBypassed:
		out.Status = "VERIFIED — GOVERNANCE BYPASSED"
	case res.Mode == receipt.ModeDegraded:
		out.Status = "VERIFIED — GOVERNANCE DEGRADED"
	default:
		out.Status = "VERIFIED"
	}

	if jsonOut {
		emitJSON(out)
		if policyErr != nil || anchorErr != nil {
			return 1
		}
		return 0
	}

	fmt.Printf("%s\n\n", statusLine(out.Status, out.FullStrength))
	fmt.Printf("  action         %s %s\n", r.Action.Method, r.Action.Target)
	if r.Action.Destination != "" {
		fmt.Printf("  destination    %s\n", r.Action.Destination)
	}
	fmt.Printf("  actor          %s (%s", r.Actor.ID, r.Actor.Source)
	if r.Actor.Verified {
		fmt.Print(", verified)")
	} else {
		fmt.Print(", unverified)")
	}
	fmt.Println()
	for _, hop := range r.Actor.Delegation {
		fmt.Printf("  on behalf of   %s (%s)\n", hop.ID, hop.Source)
	}
	fmt.Printf("  decision       %s\n", res.Decision)
	if a := r.Governance.Approval; a != nil {
		// Directly under the decision, because it changes what the
		// decision means: require_approval with content released is a
		// person's doing, and the person is named here or nowhere.
		switch a.Outcome {
		case receipt.ApprovalApproved:
			fmt.Printf("  approval       released by %s at %s (%s)\n", a.DecidedBy, a.DecidedAt, a.ID)
		case receipt.ApprovalDenied:
			fmt.Printf("  approval       denied by %s at %s (%s)\n", a.DecidedBy, a.DecidedAt, a.ID)
		default:
			fmt.Printf("  approval       nobody decided by %s (%s)\n", a.DecidedAt, a.ID)
		}
	}
	if len(r.Governance.Findings) > 0 {
		var parts []string
		for _, f := range r.Governance.Findings {
			// Named as well as identified. Whoever is reading this is
			// often an auditor rather than an engineer, and they are the
			// least likely person in the chain to know that
			// "injection.instruction_override" describes somebody trying
			// to talk the assistant out of its instructions. The
			// identifier stays so the line can still be matched against
			// the receipt it came from.
			parts = append(parts, fmt.Sprintf("%s (%s) ×%d → %s",
				detect.Label(detect.Class(f.Class)), f.Class, f.Count, f.Decision))
		}
		fmt.Printf("  findings       %s\n", strings.Join(parts, ", "))
	}
	fmt.Printf("  detector       %s %s / ruleset %s (%s)\n",
		r.Governance.Detector.Engine,
		r.Governance.Detector.EngineVersion,
		r.Governance.Detector.RulesetVersion,
		r.Governance.Detector.Health)
	// The version already carries its own "v" in every ruleset shipped so
	// far, so prefixing another produced "vv1". Printing it verbatim is
	// right regardless: the value is the policy's, not ours to reformat.
	fmt.Printf("  policy         %s %s\n", r.Governance.Policy.ID, r.Governance.Policy.Version)
	fmt.Printf("  signed by      %s (%s)\n", res.KeyID, res.Algorithm)
	// Printed high, next to the action rather than among the footnotes: a
	// reader deciding what a receipt is worth needs to know whether the
	// issuer saw this or was told about it before they read the details.
	switch res.Provenance {
	case receipt.ProvenanceObserved:
		if r.EffectiveSubject() != receipt.SubjectPayload {
			// A tunnel receipt is first-hand about the connection and
			// blind to its content. "Observed" on its own reads as
			// observation of the bytes, which is the one thing the
			// issuer never did.
			fmt.Printf("  evidence       first-hand, observed at %s (the connection only; the content was not read)\n", res.Vantage)
		} else {
			fmt.Printf("  evidence       first-hand, observed at %s\n", res.Vantage)
		}
	case receipt.ProvenanceAttested:
		fmt.Printf("  evidence       second-hand, reported by %s\n", res.Vantage)
	default:
		fmt.Printf("  evidence       the caller described its own action\n")
	}

	reportAnchors(r, anchorResults, anchorErr)
	if att := r.Issuer.KeyAttestation; att != nil {
		// Without this line the key ID is an opaque string and the reader
		// has no way to see that the deployment vouched for it, which is
		// the entire basis on which they just accepted the receipt.
		fmt.Printf("  authorised by  %s for chains under %q\n", att.RootKeyID, att.Scope)
	}
	fmt.Printf("  issued         %s\n", res.IssuedAt.UTC().Format(time.RFC3339))
	if incl != nil {
		// Stated as what was checked: the log's own signature over a root
		// this receipt's digest leads to. Nothing here says the log is
		// honest, only that it has committed to this entry.
		fmt.Printf("  logged         proven by the log's receipt at tree size %d\n                 root %s\n", incl.TreeSize, incl.Root)
	}
	if r.EffectiveSubject() != receipt.SubjectPayload {
		// Without this a reader sees a digest and reasonably assumes the
		// data was hashed, when what was hashed is a record describing it.
		fmt.Printf("  digest         %s\n                 (covers a record about the traffic, not the traffic itself)\n", res.Digest)
	} else {
		fmt.Printf("  digest         %s\n", res.Digest)
	}

	if len(out.Warnings) > 0 {
		fmt.Println()
		for _, w := range out.Warnings {
			fmt.Printf("  ! %s\n", w)
		}
	}
	if policyErr != nil {
		fmt.Printf("\n  rejected: %v\n", policyErr)
	}
	if anchorErr != nil {
		fmt.Printf("\n  the receipt's claim of independent timestamping does not hold:\n  %v\n", anchorErr)
	}
	fmt.Println()

	if policyErr != nil || anchorErr != nil {
		return 1
	}
	return 0
}

// truncatedWarning is shared word for word with the SDKs and the verify page.
const truncatedWarning = "stream cut by policy — digests cover the delivered prefix only"

// subjectWarning states what a digest covers when it is not the data.
//
// Every value other than payload is treated as "a record about the traffic",
// including values this build has never heard of. A future subject that
// this verifier does not recognise must read weak, not strong: an unknown
// word next to a digest would otherwise be taken for a hash of the data.
func subjectWarning(subject receipt.ContentSubject) string {
	const head = "the digests cover a record about the traffic, not the traffic itself: "
	switch subject {
	case receipt.SubjectPayload:
		return ""
	case receipt.SubjectMetadata:
		return head + "the issuer carried the bytes without reading them, so nothing here attests to what they contained"
	case receipt.SubjectTelemetry:
		return head + "another system reported the action, so nothing here attests to what it carried"
	default:
		return head + fmt.Sprintf("subject %q is not one this verifier knows, so nothing here attests to what the traffic contained", string(subject))
	}
}

func fail(jsonOut bool, err error, code int) int {
	if jsonOut {
		emitJSON(output{Status: "NOT VERIFIED", Valid: false, Error: err.Error()})
		return code
	}
	fmt.Printf("%s\n\n  %v\n\n", statusLine("NOT VERIFIED", false), err)
	return code
}

// statusLine renders the headline verdict, colourised when attached to a
// terminal that is not suppressing colour.
//
// Degraded and bypassed receipts deliberately do not get the green treatment.
// A reader scanning for a green tick must not be shown one by a receipt that
// admits governance was partial — the badge would then assert more than the
// evidence does, which is the failure this whole design exists to avoid.
func statusLine(status string, full bool) string {
	const (
		reset  = "\x1b[0m"
		green  = "\x1b[1;32m"
		yellow = "\x1b[1;33m"
		red    = "\x1b[1;31m"
	)
	if !useColour() {
		return status
	}
	switch {
	case strings.HasPrefix(status, "NOT VERIFIED"), strings.HasPrefix(status, "REJECTED"):
		return red + status + reset
	case full:
		return green + status + reset
	default:
		return yellow + status + reset
	}
}

func useColour() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func emitJSON(o output) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(o)
}

// buildResolver turns the collected key material into a resolver.
//
// Parsing is delegated to the receipt package rather than repeated here, so
// the one place that knows how each algorithm encodes a public key stays
// the one place that decides.
func buildResolver(keys keyFlag) (receipt.KeyResolver, error) {
	out := receipt.StaticKeyResolver{}
	for id, material := range keys {
		pub, err := receipt.ParsePublicKey(receipt.Algorithm(material.algorithm), material.raw)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", id, err)
		}
		out[id] = pub
	}
	return out, nil
}

// reportAnchors checks any timestamp tokens and says what they prove.
//
// A receipt that carries an anchor is claiming its time is corroborated by
// someone other than its issuer. Printing "anchored" without checking would
// pass that claim straight through, which is the opposite of what this tool
// is for.
func reportAnchors(r *receipt.Receipt, results []anchor.AnchorResult, err error) {
	if len(r.Anchors) == 0 {
		return
	}
	if err != nil {
		fmt.Printf("  anchors        %d present, NOT VALID: %v\n", len(r.Anchors), err)
		return
	}
	for _, res := range results {
		fmt.Printf("  anchored       %s by %s\n",
			res.GenTime.Format(time.RFC3339), string(res.Type))
		if res.SerialNumber != "" {
			// The serial is what an auditor quotes when asking the
			// authority to confirm the token independently.
			fmt.Printf("                 authority serial %s\n", res.SerialNumber)
		}
	}
}

// decodeReceipts accepts a chain as a JSON array or as one receipt per line.
//
// The local tools append a line per receipt, because a file that is
// rewritten as an array on every event is a file that is corrupt whenever
// the process dies mid-write. Asking a person to convert the format before
// they can check it is one more reason not to check.
func decodeReceipts(data []byte) ([]*receipt.Receipt, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var rs []*receipt.Receipt
		if err := json.Unmarshal(trimmed, &rs); err != nil {
			return nil, fmt.Errorf("parsing receipt array: %w", err)
		}
		return rs, nil
	}
	var rs []*receipt.Receipt
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	for {
		var r receipt.Receipt
		if err := dec.Decode(&r); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parsing receipt %d: %w", len(rs)+1, err)
		}
		rs = append(rs, &r)
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("no receipts in input")
	}
	return rs, nil
}
