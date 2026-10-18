package usage

import (
	"fmt"
	"math"
)

// Prices, and why none of them ships with the product.
//
// Nobody here knows what a customer pays. Providers publish list prices
// that change without notice, negotiated rates differ, and a figure
// produced from a stale table would be the one number a finance team
// copies into a spreadsheet and never checks. So there is no built-in
// price. Somebody who enters one gets an estimate labelled as such, at
// that price, and nothing more.

// Price is what somebody said a million tokens cost them.
type Price struct {
	Upstream           string  `json:"upstream"`
	PricePerMillionIn  float64 `json:"price_per_million_in"`
	PricePerMillionOut float64 `json:"price_per_million_out"`

	// Currency is a label and nothing more — a few letters they chose,
	// echoed beside every estimate made at this price. Optional, because
	// an estimate is still an estimate without it.
	Currency string `json:"currency,omitempty"`

	SetAt string `json:"set_at,omitempty"`
}

// Estimate is a token figure multiplied by a price somebody typed.
type Estimate struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency,omitempty"`

	// Basis says where the price came from, on every estimate, because
	// this is the number most likely to be copied somewhere on its own.
	Basis string `json:"basis"`

	// The price is on a per-upstream estimate, which was made at one.
	// Absent on a period total, which is a sum over several prices and has
	// none of its own: written out as zeros it would read as "priced at
	// nothing". Pointers rather than omitempty so a price that really is
	// zero is still shown on its line.
	PricePerMillionIn  *float64 `json:"price_per_million_in,omitempty"`
	PricePerMillionOut *float64 `json:"price_per_million_out,omitempty"`

	// Unpriced names the upstreams that had tokens in the period and no
	// price, on the total only. A total that silently left them out would
	// read as the whole bill.
	Unpriced []string `json:"unpriced_upstreams,omitempty"`
}

// EstimateBasis is printed and serialised beside every estimate.
const EstimateBasis = "estimate at the price you entered per million tokens; not a provider figure"

// Estimate multiplies out a token figure at this price.
func (p Price) Estimate(input, output int64) Estimate {
	amount := float64(input)/1e6*p.PricePerMillionIn + float64(output)/1e6*p.PricePerMillionOut
	in, out := p.PricePerMillionIn, p.PricePerMillionOut
	return Estimate{
		Amount:             RoundMoney(amount),
		Currency:           p.Currency,
		Basis:              EstimateBasis,
		PricePerMillionIn:  &in,
		PricePerMillionOut: &out,
	}
}

// RoundMoney keeps an estimate to four places. A price per million
// multiplied by a handful of tokens produces digits no invoice carries.
func RoundMoney(v float64) float64 { return math.Round(v*1e4) / 1e4 }

// ValidPrice checks what somebody typed.
func ValidPrice(p Price) error {
	for _, v := range []float64{p.PricePerMillionIn, p.PricePerMillionOut} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return fmt.Errorf("a price must be a number of zero or more")
		}
		if v > 1e6 {
			return fmt.Errorf("a price above 1,000,000 per million tokens is not one any provider charges; check the unit")
		}
	}
	if len(p.Currency) > 8 {
		return fmt.Errorf("the currency label must be at most 8 characters")
	}
	for _, r := range p.Currency {
		if r < 'A' || r > 'Z' {
			return fmt.Errorf("the currency label may contain only letters, like USD or EUR")
		}
	}
	return nil
}
