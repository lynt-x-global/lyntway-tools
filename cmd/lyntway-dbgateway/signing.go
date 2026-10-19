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

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// The key this gateway signs with, and where a verifier finds it.
//
// An audit found receipts signed with a key generated at start-up and
// thrown away at exit, under an issuer name that pointed at lyntway.com —
// where that key had never been published. Nobody could verify them, and
// a reader who tried would have concluded they were forged. A signature
// that cannot be checked is not evidence; it is decoration.
//
// So the seed is generated once and kept, the public key is written beside
// the receipts in the format lyntway-verify -keys reads, and the issuer
// says plainly that a local key signed this.

// localIssuer is what the receipts say about who signed them. It must not
// name lyntway.com: that is a directory this key is not in.
const localIssuer = "lyntway-dbgateway (local key)"

// signingKeyFile is the on-disk form of the seed. Named by algorithm so a
// second scheme later is a new field, not a guess about 32 bytes.
type signingKeyFile struct {
	Algorithm string `json:"algorithm"`
	Seed      string `json:"seed"`
}

// loadOrCreateSigner returns the signer for the seed at path, generating
// and storing one if the file does not exist.
//
// An empty path means an ephemeral key, kept for tests that do not care
// about verification. Nothing in the binary passes one.
func loadOrCreateSigner(path string) (receipt.Signer, error) {
	if path == "" {
		return receipt.GenerateEd25519Signer("local-ephemeral")
	}

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var kf signingKeyFile
		if err := json.Unmarshal(raw, &kf); err != nil {
			return nil, fmt.Errorf("the signing key at %s is unreadable: %w", path, err)
		}
		if kf.Algorithm != string(receipt.AlgEd25519) {
			return nil, fmt.Errorf("the signing key at %s uses %q, which this build cannot sign with", path, kf.Algorithm)
		}
		seed, err := base64.StdEncoding.DecodeString(kf.Seed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("the signing key at %s is not a %d-byte ed25519 seed", path, ed25519.SeedSize)
		}
		return signerFromSeed(seed)

	case errors.Is(err, os.ErrNotExist):
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("generating a signing key: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("creating the key directory: %w", err)
		}
		body, err := json.Marshal(signingKeyFile{
			Algorithm: string(receipt.AlgEd25519),
			Seed:      base64.StdEncoding.EncodeToString(seed),
		})
		if err != nil {
			return nil, err
		}
		// Exclusive create: two gateways starting at once must not both
		// believe they wrote the key and then sign under different ones.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateSigner(path)
		}
		if err != nil {
			return nil, fmt.Errorf("writing the signing key: %w", err)
		}
		if _, err := f.Write(append(body, '\n')); err != nil {
			f.Close()
			return nil, fmt.Errorf("writing the signing key: %w", err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("writing the signing key: %w", err)
		}
		return signerFromSeed(seed)

	default:
		return nil, fmt.Errorf("reading the signing key: %w", err)
	}
}

// signerFromSeed derives the key pair and names it after the public key,
// so the identifier a receipt carries can be checked against the key a
// reader is handed without trusting either file.
func signerFromSeed(seed []byte) (receipt.Signer, error) {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return receipt.NewEd25519Signer(keyIDFor(pub), priv)
}

func keyIDFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "local-" + hex.EncodeToString(sum[:])[:16]
}

// publishedKeys is the shape lyntway-verify -keys reads, and the same one
// the hosted service serves at /.well-known/lyntway-keys.json.
type publishedKeys struct {
	Keys       map[string]string `json:"keys"`
	Algorithms map[string]string `json:"algorithms"`
}

// keysPathFor names the key file kept beside a receipts file.
func keysPathFor(receipts string) string { return besideReceipts(receipts, "-keys.json") }

// besideReceipts names a companion file by the receipts file's stem, the
// same way lyntway-mcp does: receipts.jsonl, receipts-keys.json and
// receipts-chain.json sort together and read as one set.
func besideReceipts(receipts, suffix string) string {
	return strings.TrimSuffix(receipts, filepath.Ext(receipts)) + suffix
}

// publishKey writes the signer's public key beside the receipts.
//
// Merged into whatever is there rather than replacing it. If the seed file
// is ever lost and a new key generated, the receipts already in the file
// were signed under the old one, and the reader still needs it.
func publishKey(path string, signer receipt.Signer) error {
	pub, err := receipt.RawPublicKey(signer)
	if err != nil {
		return err
	}

	keys := publishedKeys{Keys: map[string]string{}, Algorithms: map[string]string{}}
	if raw, err := os.ReadFile(path); err == nil {
		// A key file we cannot parse is replaced, not preserved: keeping
		// it would leave the current key unpublished, which is the
		// failure this exists to prevent.
		_ = json.Unmarshal(raw, &keys)
		if keys.Keys == nil {
			keys.Keys = map[string]string{}
		}
		if keys.Algorithms == nil {
			keys.Algorithms = map[string]string{}
		}
	}
	keys.Keys[signer.KeyID()] = base64.StdEncoding.EncodeToString(pub)
	keys.Algorithms[signer.KeyID()] = string(signer.Algorithm())

	body, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(body, '\n'), 0o644)
}

// writeFileAtomic replaces path in one rename, so a reader never sees a
// half-written file and a crash never leaves one behind.
func writeFileAtomic(path string, body []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
