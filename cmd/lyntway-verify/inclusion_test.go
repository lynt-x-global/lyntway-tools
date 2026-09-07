package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// The SCITT vectors, exercised through the tool exactly as a person would
// run it: a receipt file, a key file, the log's receipt and the log's key.
const vectorsPath = "../../testdata/scitt/vectors.json"

type inclusionVectors struct {
	Issuer struct {
		PublicKey string `json:"public_key"`
		KeyID     string `json:"key_id"`
	} `json:"issuer"`
	Log struct {
		PublicKey string `json:"public_key"`
		KeyID     string `json:"key_id"`
	} `json:"log"`
	ReceiptJSON      string `json:"receipt_json"`
	SignedStatement  string `json:"signed_statement"`
	ReceiptDigest    string `json:"receipt_digest"`
	TreeSize         uint64 `json:"tree_size"`
	Root             string `json:"root"`
	InclusionReceipt string `json:"inclusion_receipt"`
}

func loadVectors(t *testing.T) (inclusionVectors, string) {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v inclusionVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("receipt.json", v.ReceiptJSON)
	statement, _ := hex.DecodeString(v.SignedStatement)
	write("receipt.cose", string(statement))
	write("keys.json", `{"keys":{"`+v.Issuer.KeyID+`":"`+v.Issuer.PublicKey+`"}}`)
	write("log-keys.json", `{"keys":{"`+v.Log.KeyID+`":"`+v.Log.PublicKey+`"}}`)
	write("inclusion.hex", v.InclusionReceipt+"\n")
	rcpt, _ := hex.DecodeString(v.InclusionReceipt)
	write("inclusion.cose", string(rcpt))
	return v, dir
}

func runWithArgs(t *testing.T, args ...string) (int, string) {
	t.Helper()
	orig := os.Args
	defer func() { os.Args = orig }()
	os.Args = append([]string{"lyntway-verify"}, args...)
	var code int
	out := captureStdout(t, func() { code = run() })
	return code, out
}

func TestInclusionIsVerifiedAgainstTheLogsKey(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	v, dir := loadVectors(t)
	in := func(name string) string { return filepath.Join(dir, name) }

	for _, tc := range []struct{ name, receipt, proof string }{
		{"json receipt, hex proof", "receipt.json", "inclusion.hex"},
		{"json receipt, raw proof", "receipt.json", "inclusion.cose"},
		{"cose receipt, hex proof", "receipt.cose", "inclusion.hex"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := runWithArgs(t, "-keys", in("keys.json"), "-log-keys", in("log-keys.json"),
				"-inclusion", in(tc.proof), in(tc.receipt))
			if code != 0 {
				t.Fatalf("exit %d:\n%s", code, out)
			}
			if !strings.Contains(out, "VERIFIED") || !strings.Contains(out, "tree size 5") || !strings.Contains(out, v.Root) {
				t.Errorf("the tree size and root are not reported:\n%s", out)
			}
		})
	}

	// -json carries the same facts for automation.
	code, out := runWithArgs(t, "-json", "-keys", in("keys.json"), "-log-keys", in("log-keys.json"),
		"-inclusion", in("inclusion.hex"), in("receipt.json"))
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var got output
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got.Inclusion == nil || got.Inclusion.TreeSize != v.TreeSize || got.Inclusion.Root != v.Root || got.Inclusion.Entry != v.ReceiptDigest {
		t.Errorf("inclusion in JSON = %+v", got.Inclusion)
	}

	// Without -log-keys, the receipt's own key file is tried, and the log
	// did not sign with it.
	code, out = runWithArgs(t, "-keys", in("keys.json"), "-inclusion", in("inclusion.hex"), in("receipt.json"))
	if code != 1 || !strings.Contains(out, "INCLUSION NOT PROVEN") {
		t.Errorf("a log receipt verified under the issuer's key: exit %d\n%s", code, out)
	}
}

// A log receipt is for one entry. The same receipt presented with a
// different receipt must fail, and fail as an inclusion failure rather
// than as a bad receipt — the receipt is fine, it is just not the one the
// log committed to.
func TestInclusionFailsForADifferentReceipt(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	_, dir := loadVectors(t)
	in := func(name string) string { return filepath.Join(dir, name) }

	// A different receipt from the same issuer ID under a fresh key, so
	// the receipt verifies on its own and only its logging is in question.
	v, _ := loadVectors(t)
	var r receipt.Receipt
	if err := json.Unmarshal([]byte(v.ReceiptJSON), &r); err != nil {
		t.Fatal(err)
	}
	r.ID, r.Signature = "rcpt_scitt_vector_0002", nil
	signer, err := receipt.GenerateEd25519Signer(r.Issuer.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Sign(&r, signer); err != nil {
		t.Fatal(err)
	}
	other, _ := json.Marshal(&r)
	if err := os.WriteFile(in("other.json"), other, 0o644); err != nil {
		t.Fatal(err)
	}
	pub, err := receipt.RawPublicKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in("other-keys.json"), []byte(`{"keys":{"`+r.Issuer.KeyID+`":"`+hex.EncodeToString(pub)+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	code, out := runWithArgs(t, "-keys", in("other-keys.json"), "-log-keys", in("log-keys.json"),
		"-inclusion", in("inclusion.hex"), in("other.json"))
	if code != 1 || !strings.Contains(out, "INCLUSION NOT PROVEN") {
		t.Errorf("a log receipt for another entry was accepted: exit %d\n%s", code, out)
	}

	code, _ = runWithArgs(t, "-chain", "-keys", in("keys.json"), "-inclusion", in("inclusion.hex"), in("receipt.json"))
	if code != 2 {
		t.Errorf("-inclusion with -chain exited %d, want a usage error", code)
	}
}

// The entry the tool hands to the verifier must be the receipt's digest
// as the library computes it, from either serialisation.
func TestReceiptEntryIsTheReceiptDigest(t *testing.T) {
	v, dir := loadVectors(t)
	keys, _ := receipt.NewEd25519Resolver(map[string][]byte{v.Issuer.KeyID: mustHex(t, v.Issuer.PublicKey)})

	fromJSON, err := receiptEntry([]byte(v.ReceiptJSON), keys)
	if err != nil {
		t.Fatal(err)
	}
	cosed, _ := os.ReadFile(filepath.Join(dir, "receipt.cose"))
	fromCOSE, err := receiptEntry(cosed, keys)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := receiptEntry([]byte(`{"decision":"allow","receipt":`+v.ReceiptJSON+`}`), keys)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{"json": fromJSON, "cose": fromCOSE, "wrapped": wrapped} {
		if string(got) != v.ReceiptDigest {
			t.Errorf("%s: entry %s, want %s", name, got, v.ReceiptDigest)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
