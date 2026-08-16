package receipt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// The failure this prevents happened for real: a field was added to the
// schema, and a verifier built the day before reported NOT VERIFIED for a
// perfectly good receipt. Read as tampering, which is the worst possible
// false alarm.
//
// The promise this package exists for is that an auditor can be handed a
// receipt and a binary and have the two work offline, indefinitely, with
// nobody's cooperation. A format that silently breaks that whenever it gains
// a field is not evidence; it is a version dependency wearing a signature.
func TestAReceiptVerifiesAgainstABuildThatDoesNotKnowItsFields(t *testing.T) {
	signer, err := GenerateEd25519Signer("key-test-1")
	if err != nil {
		t.Fatal(err)
	}
	keys := StaticKeyResolver{signer.KeyID(): signer.Public()}

	r := validReceipt()
	if err := Sign(r, signer); err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Serialise, then add a member this build has never heard of — exactly
	// what a receipt from a newer deployment looks like to an older
	// verifier.
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	document["jurisdiction"] = map[string]any{"regime": "eu-ai-act", "article": "50"}
	future, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	// Re-signed over the document including the new member, as the newer
	// deployment would have done.
	input, err := SigningInputFromJSON(future)
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}
	value, err := signer.Sign(input)
	if err != nil {
		t.Fatalf("signing the future document: %v", err)
	}
	document["signature"] = map[string]any{
		"algorithm":        string(signer.Algorithm()),
		"key_id":           signer.KeyID(),
		"canonicalization": string(CanonicalizationJCS),
		"value":            base64.StdEncoding.EncodeToString(value),
	}
	future, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	// The struct-based path drops the unknown member and fails, which is
	// the bug.
	var parsed Receipt
	if err := json.Unmarshal(future, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(&parsed, keys, VerifyOptions{}); err == nil {
		t.Log("note: struct-based verification happened to pass; the byte-based path is still the guarantee")
	}

	// The byte-based path verifies it, because the unknown member stayed in
	// the hash.
	result, err := VerifyJSON(future, keys, VerifyOptions{})
	if err != nil {
		t.Fatalf("an older build could not verify a newer receipt: %v", err)
	}
	if result == nil {
		t.Fatal("no result")
	}
}

// Verifying a signature is not the same as understanding the document. A
// verifier that checked one and not the other must say so, because the
// field it could not read might be the one that matters.
func TestUnknownFieldsAreReported(t *testing.T) {
	document := map[string]any{
		"version": "lyntway-receipt/1", "id": "r1", "issued_at": "2026-08-15T00:00:00Z",
		"issuer": map[string]any{}, "action": map[string]any{}, "actor": map[string]any{},
		"content": map[string]any{}, "governance": map[string]any{}, "chain": map[string]any{},
		"jurisdiction": map[string]any{}, "custody": []any{},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	unknown, err := UnknownFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 2 || unknown[0] != "custody" || unknown[1] != "jurisdiction" {
		t.Errorf("unknown = %v, want [custody jurisdiction]", unknown)
	}

	// And a receipt this build fully understands reports nothing.
	known, err := json.Marshal(validReceipt())
	if err != nil {
		t.Fatal(err)
	}
	if fields, err := UnknownFields(known); err != nil || len(fields) != 0 {
		t.Errorf("fields = %v, err = %v; want none for a receipt this build knows", fields, err)
	}
}

// Tampering must still be caught on the byte-based path, or the fix above
// would have bought compatibility by giving up the guarantee.
func TestTheByteBasedPathStillCatchesTampering(t *testing.T) {
	signer, err := GenerateEd25519Signer("key-test-1")
	if err != nil {
		t.Fatal(err)
	}
	keys := StaticKeyResolver{signer.KeyID(): signer.Public()}

	r := validReceipt()
	if err := Sign(r, signer); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}

	tampered := strings.Replace(string(encoded), `"decision":"tokenize"`, `"decision":"allow"`, 1)
	if tampered == string(encoded) {
		tampered = strings.Replace(string(encoded), r.Action.Destination, "elsewhere.example", 1)
	}
	if tampered == string(encoded) {
		t.Skip("could not construct a tampered document from this fixture")
	}

	if _, err := VerifyJSON([]byte(tampered), keys, VerifyOptions{}); err == nil {
		t.Fatal("a tampered receipt verified")
	}
}
