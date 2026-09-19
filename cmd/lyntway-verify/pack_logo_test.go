package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// A partner's logo travels beside the signed object and its digest inside
// it. The signature alone would still verify a pack whose picture had been
// replaced, so the tool compares the two, and refuses a picture that no
// signed digest names.
func TestAPackLogoMustMatchItsSignedDigest(t *testing.T) {
	picture := []byte("\x89PNG\r\n\x1a\nnot a real image, only bytes to hash")
	sum := sha256.Sum256(picture)
	digest := hex.EncodeToString(sum[:])
	uri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(picture)
	pack := func(logo, signed string) []byte {
		inner := ""
		if signed != "" {
			inner = fmt.Sprintf(`,"logo":{"media_type":"image/png","sha256":%q,"bytes":1}`, signed)
		}
		return []byte(fmt.Sprintf(`{"prepared_by_logo":%q,"attested":{"prepared_by":{"tenant_id":"t_p"%s}}}`, logo, inner))
	}

	if err := checkPackLogo(pack(uri, digest)); err != nil {
		t.Errorf("an intact logo was refused: %v", err)
	}
	if err := checkPackLogo([]byte(`{"attested":{"summary":{}}}`)); err != nil {
		t.Errorf("a pack with no logo was refused: %v", err)
	}
	other := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("somebody else's mark"))
	if err := checkPackLogo(pack(other, digest)); err == nil || !strings.Contains(err.Error(), "changed since it was signed") {
		t.Errorf("a swapped logo was accepted: %v", err)
	}
	// Refused for the right reason, and saying it: "changed since it was
	// signed" would send somebody looking for an edit that never happened.
	if err := checkPackLogo(pack(uri, "")); err == nil || !strings.Contains(err.Error(), "does not name") {
		t.Errorf("a logo that no signed digest names was not refused as such: %v", err)
	}
	if err := checkPackLogo(pack("data:image/svg+xml;base64,PHN2Zy8+", digest)); err == nil {
		t.Error("a logo that is not a PNG data URI was accepted")
	}
}

// testdata/pack-logo is a pack a running server signed for a partner's
// client, with the partner's logo, taken unaltered from its evidence
// bundle. Intact it verifies; with another picture in place of the logo
// the signature still checks, and this tool must say NOT VERIFIED anyway.
func TestARealPackWithALogoVerifiesAndASwappedOneDoesNot(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "pack-logo", "pack.json"))
	if err != nil {
		t.Fatal(err)
	}
	keys := keyFlag{}
	if _, err := loadKeyFile(filepath.Join("testdata", "pack-logo", "keys.json"), keys); err != nil {
		t.Fatalf("loading keys: %v", err)
	}
	resolver, err := buildResolver(keys)
	if err != nil {
		t.Fatal(err)
	}
	if code := verifyOne(data, resolver, receipt.VerifyOptions{}, true, nil, ""); code != 0 {
		t.Fatalf("an intact pack with a logo did not verify: exit %d", code)
	}
	var pack map[string]any
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatal(err)
	}
	if _, ok := pack["prepared_by_logo"].(string); !ok {
		t.Fatal("the testdata pack carries no logo; it no longer tests anything")
	}
	pack["prepared_by_logo"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("another mark"))
	swapped, _ := json.Marshal(pack)
	if code := verifyOne(swapped, resolver, receipt.VerifyOptions{}, true, nil, ""); code == 0 {
		t.Fatal("a pack whose logo was swapped after signing verified")
	}
}
