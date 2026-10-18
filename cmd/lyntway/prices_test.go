package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/usage"
)

// A cost figure is the number most likely to be copied somewhere on its
// own, so every test here is about it not being wrong in a way nobody
// notices: a price that did not load, a model quietly left out of a total,
// or a reply that reported nothing counted as free.

func writePrices(t *testing.T, body string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".lyntway"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".lyntway", "prices.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Longest key wins. A book holding gpt-4o and gpt-4o-mini must price
// gpt-4o-mini at the mini rate — and map iteration has no order, so a
// first-match rule would price it differently on different runs.
func TestTheLongestMatchingPriceKeyWins(t *testing.T) {
	pb := priceBook{Models: map[string]modelPrice{
		"gpt-4o":      {In: 2.5, Out: 10},
		"gpt-4o-mini": {In: 0.15, Out: 0.6},
		"claude":      {In: 3, Out: 15},
	}}
	for _, c := range []struct {
		model   string
		wantKey string
		wantIn  float64
	}{
		{"gpt-4o-mini-2024-07-18", "gpt-4o-mini", 0.15},
		{"gpt-4o-2024-11-20", "gpt-4o", 2.5},
		{"claude-opus-4-20250514", "claude", 3},
	} {
		t.Run(c.model, func(t *testing.T) {
			// Run it a few times: a first-match bug passes once and fails
			// on another day, which is the worst kind of defect to ship.
			for i := 0; i < 20; i++ {
				got, ok := pb.priceFor(c.model)
				if !ok {
					t.Fatal("no price matched")
				}
				if got.Upstream != c.wantKey || got.PricePerMillionIn != c.wantIn {
					t.Fatalf("matched %q at %v, want %q at %v", got.Upstream, got.PricePerMillionIn, c.wantKey, c.wantIn)
				}
			}
		})
	}
	if _, ok := pb.priceFor("gemini-2.5-flash"); ok {
		t.Error("a model with no key in the book was priced anyway")
	}
	if _, ok := pb.priceFor(""); ok {
		t.Error("a reply whose provider named no model was priced")
	}
}

// A price file that did not load must be an error about the file. Ignored,
// it would produce a session priced at nothing — which reads as free
// rather than as unconfigured.
func TestABrokenPriceFileIsRefusedRatherThanIgnored(t *testing.T) {
	writePrices(t, `{"models": not json`)
	if _, err := loadPriceBook(); err == nil {
		t.Fatal("a malformed price file loaded as an empty book")
	}

	writePrices(t, `{"models":{"gpt-4o":{"in":-3,"out":10}}}`)
	if _, err := loadPriceBook(); err == nil {
		t.Fatal("a negative price was accepted")
	}

	writePrices(t, `{"currency":"USD","models":{"gpt-4o":{"in":2.5,"out":10}}}`)
	pb, err := loadPriceBook()
	if err != nil {
		t.Fatalf("a valid file did not load: %v", err)
	}
	if pb.Currency != "USD" || pb.Models["gpt-4o"].Out != 10 {
		t.Errorf("loaded %+v", pb)
	}

	// No file at all is the ordinary case, not an error: the token counts
	// stand without a price.
	t.Setenv("HOME", t.TempDir())
	if pb, err := loadPriceBook(); err != nil || len(pb.Models) != 0 {
		t.Errorf("absent price file: %+v %v", pb, err)
	}
}

func TestPriceFlagsAreParsedAndValidated(t *testing.T) {
	for _, bad := range []string{"gpt-4o", "gpt-4o=3", "=3/15", "gpt-4o=a/b", "gpt-4o=-1/5"} {
		if _, err := applyPriceFlags(priceBook{}, []string{bad}, ""); err == nil {
			t.Errorf("--price %q was accepted", bad)
		}
	}
	pb, err := applyPriceFlags(priceBook{}, []string{"claude-opus-4=15/75"}, "USD")
	if err != nil {
		t.Fatal(err)
	}
	p, ok := pb.priceFor("claude-opus-4-20250514")
	if !ok || p.PricePerMillionIn != 15 || p.PricePerMillionOut != 75 || p.Currency != "USD" {
		t.Errorf("flag produced %+v (ok=%v)", p, ok)
	}
}

// A total that silently dropped the models it could not price would be
// read as the whole bill.
func TestAnUnpricedModelIsNamedRatherThanLeftOutQuietly(t *testing.T) {
	pb := priceBook{Currency: "USD", Models: map[string]modelPrice{"gpt-4o": {In: 2.5, Out: 10}}}
	cost, priced := costOf(pb, map[string]usage.TokenUsage{
		"gpt-4o-2024-11-20":      {Input: 1_000_000, Output: 1_000_000},
		"claude-opus-4-20250514": {Input: 500, Output: 500},
	})
	if !priced {
		t.Fatal("nothing was priced")
	}
	if cost.Amount != 12.5 {
		t.Errorf("amount %v, want 12.5 (1M in at 2.5 + 1M out at 10)", cost.Amount)
	}
	if len(cost.Unpriced) != 1 || !strings.Contains(cost.Unpriced[0], "claude-opus-4") {
		t.Errorf("unpriced %v, want the claude model named", cost.Unpriced)
	}

	var out bytes.Buffer
	guardTokenLines(&out, map[string]usage.TokenUsage{
		"gpt-4o-2024-11-20":      {Input: 1_000_000, Output: 1_000_000},
		"claude-opus-4-20250514": {Input: 500, Output: 500},
	}, 0, pb)
	if !strings.Contains(out.String(), "not included: claude-opus-4-20250514") {
		t.Errorf("the summary does not say what the total left out:\n%s", out.String())
	}
	if !strings.Contains(out.String(), usage.EstimateBasis) {
		t.Errorf("the summary presents an estimate as a figure:\n%s", out.String())
	}
}

// A reply that reported no figure is not a reply that cost nothing.
func TestARepliesWithNoFigureAreNamedAndNotCountedAsZero(t *testing.T) {
	var out bytes.Buffer
	guardTokenLines(&out, map[string]usage.TokenUsage{"gpt-4o": {Input: 100, Output: 10}}, 3, priceBook{})
	got := out.String()
	if !strings.Contains(got, "3 replies reported no figure") {
		t.Errorf("unmetered replies were not named:\n%s", got)
	}
	if !strings.Contains(got, "as the provider reported them") {
		t.Errorf("the token line does not say whose figure it is:\n%s", got)
	}
	if !strings.Contains(got, "no price set") {
		t.Errorf("with no price, the summary says nothing about cost:\n%s", got)
	}
	if strings.Contains(got, "0.0") {
		t.Errorf("an unpriced session printed a cost:\n%s", got)
	}

	// A model the provider did not name is said to be unnamed, never left
	// blank, so a line is not read as being about the one above it.
	out.Reset()
	guardTokenLines(&out, map[string]usage.TokenUsage{"": {Input: 5, Output: 5}}, 0, priceBook{})
	if !strings.Contains(out.String(), "not named by the provider") {
		t.Errorf("an unnamed model printed as a blank line:\n%s", out.String())
	}
}

func TestThousandsGroupsSoTheNumberCanBeRead(t *testing.T) {
	for in, want := range map[int64]string{0: "0", 7: "7", 999: "999", 1000: "1,000", 10475: "10,475", 1234567: "1,234,567"} {
		if got := thousands(in); got != want {
			t.Errorf("thousands(%d) = %q, want %q", in, got, want)
		}
	}
}
