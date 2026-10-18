package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/usage"
)

// What a session cost, at a price nobody here published.
//
// # Why there is no built-in table
//
// We do not know what anybody pays. Providers change list prices without
// notice, negotiated rates differ, discounts and committed-use agreements
// are private, and a figure produced from a stale table would be the one
// number on this tool a finance team would copy into a spreadsheet and
// never check again. A wrong cost is worse than no cost: it is believed.
//
// So the prices are the person's own, read from ~/.lyntway/prices.json or
// given for one run with --price. Every figure made from them is labelled
// as an estimate at a price they entered, and models with no price are
// named rather than quietly left out of the total — a total that silently
// dropped them would read as the whole bill.
//
// The token counts underneath are a separate matter and need no price at
// all. They are what the provider reported in its own response, which is
// useful on its own and is printed whether a price exists or not.

// priceBook is what the person said their models cost, per million tokens.
type priceBook struct {
	// Currency is a label echoed beside an estimate, nothing more.
	Currency string `json:"currency,omitempty"`

	// Models is keyed by a model name or any prefix of one, so
	// "claude-opus-4" prices "claude-opus-4-20250514" without anybody
	// having to track dated builds. The longest matching key wins.
	Models map[string]modelPrice `json:"models"`
}

type modelPrice struct {
	In  float64 `json:"in"`
	Out float64 `json:"out"`
}

func pricesPath() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".lyntway", "prices.json"), nil
}

// loadPriceBook reads the file if there is one. Absent is the ordinary
// case and not an error: the token counts stand on their own.
func loadPriceBook() (priceBook, error) {
	var pb priceBook
	path, err := pricesPath()
	if err != nil {
		return pb, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return pb, nil
	}
	if err != nil {
		return pb, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &pb); err != nil {
		// Refused rather than ignored. A price file that silently did not
		// load would produce a session priced at nothing, which reads as
		// free rather than as unconfigured.
		return pb, fmt.Errorf("%s is not a price file: %w", path, err)
	}
	for name, p := range pb.Models {
		if err := usage.ValidPrice(usage.Price{
			Upstream: name, PricePerMillionIn: p.In, PricePerMillionOut: p.Out, Currency: pb.Currency,
		}); err != nil {
			return priceBook{}, fmt.Errorf("%s: %s: %w", path, name, err)
		}
	}
	return pb, nil
}

// applyPriceFlags folds --price MODEL=IN/OUT into the book, overriding the
// file for this run only. Nothing is written back: a price typed to answer
// one question should not quietly become the standing one.
func applyPriceFlags(pb priceBook, flags []string, currency string) (priceBook, error) {
	if currency != "" {
		pb.Currency = currency
	}
	for _, f := range flags {
		name, rates, ok := strings.Cut(f, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return pb, fmt.Errorf("--price %q is not MODEL=IN/OUT", f)
		}
		in, out, ok := strings.Cut(rates, "/")
		if !ok {
			return pb, fmt.Errorf("--price %q: the rates are IN/OUT per million tokens, like 15/75", f)
		}
		inV, err1 := strconv.ParseFloat(strings.TrimSpace(in), 64)
		outV, err2 := strconv.ParseFloat(strings.TrimSpace(out), 64)
		if err1 != nil || err2 != nil {
			return pb, fmt.Errorf("--price %q: the rates must be numbers per million tokens", f)
		}
		p := usage.Price{Upstream: name, PricePerMillionIn: inV, PricePerMillionOut: outV, Currency: pb.Currency}
		if err := usage.ValidPrice(p); err != nil {
			return pb, fmt.Errorf("--price %s: %w", name, err)
		}
		if pb.Models == nil {
			pb.Models = map[string]modelPrice{}
		}
		pb.Models[name] = modelPrice{In: inV, Out: outV}
	}
	return pb, nil
}

// priceFor finds the longest key that prefixes this model's name.
//
// Longest rather than first, because a book holding both "gpt-4o" and
// "gpt-4o-mini" must price gpt-4o-mini at the mini rate — and map
// iteration has no order, so "first match" would price it differently on
// different runs.
func (pb priceBook) priceFor(model string) (usage.Price, bool) {
	if model == "" || len(pb.Models) == 0 {
		return usage.Price{}, false
	}
	best := ""
	for key := range pb.Models {
		if strings.HasPrefix(model, key) && len(key) > len(best) {
			best = key
		}
	}
	if best == "" {
		return usage.Price{}, false
	}
	p := pb.Models[best]
	return usage.Price{
		Upstream:           best,
		PricePerMillionIn:  p.In,
		PricePerMillionOut: p.Out,
		Currency:           pb.Currency,
	}, true
}

// sessionCost is what a run's token figures come to, and what they do not.
type sessionCost struct {
	Amount   float64
	Currency string

	// Priced and Unpriced name the models in each state. A total is only
	// readable beside the list of what it left out.
	Priced   []string
	Unpriced []string
}

// costOf prices what was counted. The bool is false when no model in the
// session had a price, which is the common case and not a failure.
func costOf(pb priceBook, tokens map[string]usage.TokenUsage) (sessionCost, bool) {
	out := sessionCost{Currency: pb.Currency}
	for model, u := range tokens {
		p, ok := pb.priceFor(model)
		if !ok {
			out.Unpriced = append(out.Unpriced, displayModel(model))
			continue
		}
		out.Amount += p.Estimate(u.Input, u.Output).Amount
		out.Priced = append(out.Priced, displayModel(model))
	}
	sort.Strings(out.Priced)
	sort.Strings(out.Unpriced)
	out.Amount = usage.RoundMoney(out.Amount)
	return out, len(out.Priced) > 0
}

// displayModel names a reply whose provider named no model. "unknown" is
// said rather than left blank, so a line is never read as being about the
// model above it.
func displayModel(model string) string {
	if model == "" {
		return "model not named by the provider"
	}
	return model
}
