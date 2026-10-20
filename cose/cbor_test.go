package cose

import (
	"bytes"
	"errors"
	"testing"
)

// A verifier must answer, not die.
//
// decodeValue recursed once per nested tag with nothing bounding it but
// the goroutine stack, and exceeding that is a fatal error in Go: it
// cannot be recovered, so the process is killed. Two million nested tags
// is a 2MB file, and lyntway-verify is a binary anybody can hand a file
// to, so "fatal error: stack overflow" was the output instead of
// NOT VERIFIED. Being refused is an answer; being killed is not.
func TestDeeplyNestedInputIsRefusedRatherThanFatal(t *testing.T) {
	for _, n := range []int{maxNestingDepth + 1, 10_000, 2_000_000} {
		// 0xc0 is a tag whose content is the next item, so a run of them
		// nests once per byte.
		_, _, err := decodeValue(bytes.Repeat([]byte{0xc0}, n))
		if err == nil {
			t.Fatalf("%d nested tags decoded without error", n)
		}
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%d nested tags: err = %v, want ErrMalformed", n, err)
		}
	}

	// The bound must not refuse anything real: a tag over an array over a
	// map is the shape of every COSE_Sign1 this product issues.
	nested := Encode(Tag{Number: 18, Value: Array{
		Bytes(nil), Map{{Key: Uint(1), Value: Int(-8)}}, Bytes(nil), Bytes(nil),
	}})
	if _, _, err := decodeValue(nested); err != nil {
		t.Errorf("an ordinary Sign1 shape was refused: %v", err)
	}
}
