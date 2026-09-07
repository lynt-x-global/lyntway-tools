package main

import (
	"encoding/json"
	"testing"
)

// The local tools append one receipt per line; a person checking that file
// should not have to rewrite it as an array first.
func TestAChainMayBeOneReceiptPerLine(t *testing.T) {
	r, _ := signedReceipt(t, nil)
	one, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}

	asArray := []byte("[" + string(one) + "," + string(one) + "]")
	asLines := []byte("\n" + string(one) + "\n" + string(one) + "\n")

	fromArray, err := decodeReceipts(asArray)
	if err != nil {
		t.Fatalf("array: %v", err)
	}
	fromLines, err := decodeReceipts(asLines)
	if err != nil {
		t.Fatalf("lines: %v", err)
	}
	if len(fromArray) != 2 || len(fromLines) != 2 {
		t.Fatalf("decoded %d from the array and %d from the lines, want 2 and 2", len(fromArray), len(fromLines))
	}
	if fromArray[1].ID != fromLines[1].ID || fromLines[1].Signature == nil {
		t.Error("the line form did not decode the same receipts")
	}

	if _, err := decodeReceipts([]byte("  \n")); err == nil {
		t.Error("empty input decoded as a chain")
	}
	if _, err := decodeReceipts([]byte(string(one) + "\n{not json")); err == nil {
		t.Error("a corrupt second line was accepted")
	}
}
