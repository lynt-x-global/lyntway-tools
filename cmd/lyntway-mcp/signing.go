package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// What a receipt from this machine can be checked against.
//
// The shim used to sign with a key generated at start-up and forgotten at
// exit. Every receipt it wrote was signed by a key that existed nowhere but
// in that process's memory, so `lyntway-verify` on any of them could only
// say "no public keys supplied" — there were none to supply. The receipts
// were evidence of nothing.
//
// Three things make them evidence: the key survives the process, its public
// half is written where the verifier can be pointed at it, and each chain
// continues from where the last run left it rather than starting again at
// zero, which a verifier would report as a break.
//
// None of this reaches lyntway.com. The key is generated here and stays
// here; the issuer named on the receipt says so, so a verifier is sent to
// the file beside the receipts rather than to a key directory that has
// never held this key.

// issuerName is what a receipt from this machine says issued it.
//
// Not "Lyntway (lyntway.com)": that name points a reader at a key directory
// this key is not in, and a signature that fails to verify against the
// directory it names reads as forged rather than as local.
const issuerName = "lyntway-mcp (local key)"

// signingKeyPath is where the private half lives. One key per machine,
// under the same directory the CLI keeps its configuration in.
func signingKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("this machine has no home directory to keep the signing key in: %w", err)
	}
	return filepath.Join(home, ".lyntway", "mcp-signing.key"), nil
}

// loadOrCreateSigner returns the machine's signing key, generating it the
// first time.
//
// The file holds the 32-byte seed as hex, and nothing else. A seed is all
// Ed25519 needs to reconstruct the key pair, and a format with no structure
// has no version to get wrong.
func loadOrCreateSigner() (*receipt.Ed25519Signer, error) {
	path, err := signingKeyPath()
	if err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(seed) != ed25519.SeedSize {
			// Refused rather than replaced. Silently generating a new key
			// over a corrupt one would leave every receipt already on
			// disk signed by a key that no longer exists anywhere.
			return nil, fmt.Errorf("%s is not a signing key; move it aside to generate a new one", path)
		}
		return signerFromSeed(seed)
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, fmt.Errorf("reading the signing key: %w", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generating a signing key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	// O_EXCL, so two shims starting at once on a fresh machine cannot both
	// write a key and leave one of them signing with a seed the file no
	// longer holds. The loser reads the winner's.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateSigner()
	}
	if err != nil {
		return nil, fmt.Errorf("creating the signing key: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%x\n", seed); err != nil {
		f.Close()
		return nil, fmt.Errorf("writing the signing key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("writing the signing key: %w", err)
	}
	return signerFromSeed(seed)
}

// signerFromSeed derives the key pair and names it after the public half.
//
// A key ID derived from the key itself cannot collide between machines and
// cannot be edited apart from the key, which is what a verifier needs when
// several laptops' receipt files end up in one place.
func signerFromSeed(seed []byte) (*receipt.Ed25519Signer, error) {
	priv := ed25519.NewKeyFromSeed(seed)
	sum := sha256.Sum256(priv.Public().(ed25519.PublicKey))
	return receipt.NewEd25519Signer("local-"+hex.EncodeToString(sum[:8]), priv)
}

// besideReceipts names a companion file for the receipts file, keeping the
// stem so receipts.jsonl, receipts-keys.json and receipts-chain.json sort
// together.
func besideReceipts(receiptsPath, suffix string) string {
	return strings.TrimSuffix(receiptsPath, filepath.Ext(receiptsPath)) + suffix
}

// publishKey writes the public key in the format lyntway-verify -keys
// reads, which is the format lyntway.com publishes its own keys in. Keys
// already in the file are kept: a receipt written under a previous key is
// still verifiable only while that key is still published.
func publishKey(path string, signer receipt.Signer) error {
	var kf struct {
		Keys       map[string]string `json:"keys"`
		Algorithms map[string]string `json:"algorithms"`
	}
	if raw, err := os.ReadFile(path); err == nil {
		// An unreadable file is overwritten rather than kept: it cannot
		// have been verifying anything.
		_ = json.Unmarshal(raw, &kf)
	}
	if kf.Keys == nil {
		kf.Keys = map[string]string{}
	}
	if kf.Algorithms == nil {
		kf.Algorithms = map[string]string{}
	}

	pub, err := receipt.RawPublicKey(signer)
	if err != nil {
		return err
	}
	kf.Keys[signer.KeyID()] = base64.StdEncoding.EncodeToString(pub)
	kf.Algorithms[signer.KeyID()] = string(signer.Algorithm())

	encoded, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomically(path, append(encoded, '\n'), 0o644)
}

// fileChainStore keeps each chain's position in a JSON file beside the
// receipts, so a restart continues the chain instead of forking it.
//
// The whole file is rewritten on every save. A shim handles one server's
// traffic at a conversational pace, and a file of a few chains is smaller
// than one receipt; the simplicity is worth more than the write.
type fileChainStore struct {
	path string
	mu   sync.Mutex
}

type chainPosition struct {
	NextSeq uint64 `json:"next_seq"`
	Head    string `json:"head"`
}

type chainFile struct {
	Chains map[string]chainPosition `json:"chains"`
}

func (s *fileChainStore) read() (chainFile, error) {
	var cf chainFile
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return chainFile{Chains: map[string]chainPosition{}}, nil
	}
	if err != nil {
		return cf, err
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		// Not silently reset. A chain file that cannot be read would
		// restart every chain at zero, which is the fork this exists to
		// prevent — better the shim refuses to start and says why.
		return cf, fmt.Errorf("%s is not a chain file; move it aside to start new chains", s.path)
	}
	if cf.Chains == nil {
		cf.Chains = map[string]chainPosition{}
	}
	return cf, nil
}

func (s *fileChainStore) LoadChain(chainID string) (uint64, string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cf, err := s.read()
	if err != nil {
		return 0, "", false, err
	}
	pos, ok := cf.Chains[chainID]
	if !ok {
		return 0, "", false, nil
	}
	return pos.NextSeq, pos.Head, true, nil
}

func (s *fileChainStore) SaveChain(chainID string, nextSeq uint64, head string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cf, err := s.read()
	if err != nil {
		return err
	}
	cf.Chains[chainID] = chainPosition{NextSeq: nextSeq, Head: head}
	encoded, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomically(s.path, append(encoded, '\n'), 0o600)
}

// writeAtomically replaces a file's content in one rename, so a shim killed
// mid-write leaves the previous version rather than half of the new one.
func writeAtomically(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// newReceiptID returns an identifier that is unique across processes.
//
// A per-process counter restarted at one every time the shim did, so two
// runs against the same server both wrote rcpt_mcp_1 — one identifier,
// two receipts, and a reader with no way to say which was meant.
func newReceiptID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating a receipt ID: %w", err)
	}
	return "rcpt_" + hex.EncodeToString(b[:]), nil
}
