package anchor

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// Real tokens from DigiCert and Sectigo, obtained by the live service.
// Testing against tokens we minted ourselves would only prove the parser
// agrees with itself; these prove it agrees with what authorities emit.
type anchorFixture struct {
	Receipt        *receipt.Receipt `json:"receipt"`
	ForeignAnchors []receipt.Anchor `json:"foreignAnchors"`
}

func loadAnchorFixture(t *testing.T) *anchorFixture {
	t.Helper()
	raw, err := os.ReadFile("../testdata/anchor/rfc3161.json")
	if err != nil {
		t.Skipf("anchor fixture unavailable: %v", err)
	}
	var f anchorFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	if len(f.Receipt.Anchors) == 0 || len(f.ForeignAnchors) == 0 {
		t.Fatal("fixture is missing anchors")
	}
	return &f
}

func TestVerifyAcceptsGenuineAnchors(t *testing.T) {
	f := loadAnchorFixture(t)

	results, err := VerifyAll(f.Receipt)
	if err != nil {
		t.Fatalf("genuine anchors did not verify: %v", err)
	}
	if len(results) != len(f.Receipt.Anchors) {
		t.Fatalf("checked %d anchors, want %d", len(results), len(f.Receipt.Anchors))
	}
	for i, r := range results {
		if r.GenTime.IsZero() {
			t.Errorf("anchor %d has no timestamp", i)
		}
		if r.SerialNumber == "" {
			t.Errorf("anchor %d has no serial, so an auditor could not ask the authority about it", i)
		}
		// Two independent authorities timestamped the same receipt, so
		// their times should agree closely. A wide gap would mean one of
		// them is not timestamping what we think it is.
		if skew := r.Skew(); skew > MaxAnchorSkew {
			t.Errorf("anchor %d: claimed and recorded times are %s apart", i, skew)
		}
	}
}

// The failure that matters most: a token that is completely genuine, issued
// by a real authority, for a different receipt. Nothing about it is
// malformed — only the content it commits to is wrong.
func TestVerifyRejectsAGenuineTokenFromAnotherReceipt(t *testing.T) {
	f := loadAnchorFixture(t)

	borrowed := *f.Receipt
	borrowed.Anchors = f.ForeignAnchors

	_, err := VerifyAll(&borrowed)
	if !errors.Is(err, ErrAnchorDigestMismatch) {
		t.Fatalf("a token for different content was accepted: err = %v", err)
	}
}

// anchored_at is the one field in a receipt outside the signature, so it is
// the one field an attacker can rewrite freely.
func TestVerifyRejectsAnAnchorTimeTheTokenDoesNotSupport(t *testing.T) {
	f := loadAnchorFixture(t)

	backdated := *f.Receipt
	anchors := make([]receipt.Anchor, len(f.Receipt.Anchors))
	copy(anchors, f.Receipt.Anchors)
	anchors[0].AnchoredAt = "2020-01-01T00:00:00Z"
	backdated.Anchors = anchors

	if _, err := VerifyAll(&backdated); err == nil {
		t.Fatal("a receipt claiming an anchor time six years before the token verified")
	}
}

// Changing the receipt changes its digest, so anchors obtained for the
// original must stop matching. This is what ties an anchor to a receipt
// rather than to a moment.
func TestVerifyRejectsAnchorsAfterTheReceiptChanges(t *testing.T) {
	f := loadAnchorFixture(t)

	altered := *f.Receipt
	altered.ID = altered.ID + "-altered"

	if _, err := VerifyAll(&altered); !errors.Is(err, ErrAnchorDigestMismatch) {
		t.Fatalf("anchors still matched after the receipt was altered: err = %v", err)
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	f := loadAnchorFixture(t)

	for _, tc := range []struct {
		name  string
		value string
	}{
		{"not base64", "!!!not base64!!!"},
		{"empty", ""},
		{"valid base64, not a token", "aGVsbG8gd29ybGQ="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			junk := *f.Receipt
			junk.Anchors = []receipt.Anchor{{
				Type:       receipt.AnchorRFC3161,
				Value:      tc.value,
				AnchoredAt: receipt.FormatTime(time.Now()),
			}}
			if _, err := VerifyAll(&junk); err == nil {
				t.Error("a fabricated anchor verified")
			}
		})
	}
}

// An anchor type this build cannot check must be reported, never silently
// treated as checked.
func TestUnsupportedAnchorTypeIsReported(t *testing.T) {
	a := &receipt.Anchor{Type: "opentimestamps", Value: "AAAA"}

	if _, err := Verify(a, []byte{1, 2, 3}); !errors.Is(err, ErrAnchorUnsupported) {
		t.Fatalf("an unsupported anchor type was not reported: err = %v", err)
	}
}
