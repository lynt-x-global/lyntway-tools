package main

import (
	"bytes"
	"os"
	"testing"
)

// The CLI carries its own copy of the signing vectors because the public
// module has no packages/ tree. A copy that drifted from the SDKs' would
// let the three implementations disagree while every suite stayed green.
func TestTheCLIsVectorsAreTheSDKsVectors(t *testing.T) {
	sdk, err := os.ReadFile("../../packages/lyntway-py/tests/testdata/signing_vectors.json")
	if err != nil {
		t.Skip("not in the core tree; the copy is checked there")
	}
	ours, err := os.ReadFile("testdata/signing_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sdk, ours) {
		t.Fatal("cmd/lyntway/testdata/signing_vectors.json differs from the SDKs' vectors; copy it again")
	}
}
