package receipt

import (
	"encoding/json"
	"strings"
	"testing"
)

// Exactly what a Windows tester did on 21 Oct: take a signed chain as the
// local tools write it, replace one decision with another, and verify it
// again. Their run printed VERIFIED, which has only two explanations —
// the signature does not cover the decision, or the replacement changed
// nothing. This settles which.
func TestEditingADecisionInAChainIsCaught(t *testing.T) {
	signer, keys := testSigner(t)

	var raws [][]byte
	var prev string
	for seq := uint64(0); seq < 3; seq++ {
		r := validReceipt()
		r.Governance.Decision = DecisionLogOnly
		r.Chain = Chain{ID: "proxy/ollama", Seq: seq, PrevHash: prev}
		mustSign(t, r, signer)
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
		res, err := Verify(r, keys, VerifyOptions{})
		if err != nil {
			t.Fatalf("seq %d did not verify when freshly signed: %v", seq, err)
		}
		prev = res.Digest
	}

	if _, err := VerifyChainJSON(raws, keys, VerifyOptions{}); err != nil {
		t.Fatalf("the untouched chain did not verify, so nothing below proves anything: %v", err)
	}

	// The tester's exact edit.
	var flipped int
	tampered := make([][]byte, len(raws))
	for i, raw := range raws {
		s := string(raw)
		if strings.Contains(s, `"log_only"`) {
			s = strings.Replace(s, `"log_only"`, `"allow"`, 1)
			flipped++
		}
		tampered[i] = []byte(s)
	}
	if flipped == 0 {
		t.Fatal("the fixture carries no log_only, so this test cannot tell the two explanations apart")
	}

	if _, err := VerifyChainJSON(tampered, keys, VerifyOptions{}); err == nil {
		t.Fatal("a chain with an edited decision VERIFIED — the signature does not cover the decision")
	}

	// Re-serialising without changing anything must still verify, so the
	// refusal above is about the edit and not about the file having been
	// rewritten. This is why a tester's -replace on a file that does not
	// contain the pattern comes back VERIFIED, correctly.
	rewritten := make([][]byte, len(raws))
	for i, raw := range raws {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		rewritten[i] = out
	}
	if _, err := VerifyChainJSON(rewritten, keys, VerifyOptions{}); err != nil {
		t.Errorf("re-serialising without changing anything broke verification: %v", err)
	}
}
