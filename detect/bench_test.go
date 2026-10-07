package detect

import (
	"strconv"
	"strings"
	"testing"
)

func benchText(n int) string {
	const prose = "We reviewed the quarterly figures and the migration plan is on track. "
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(prose)
	}
	return b.String()[:n]
}

// What a paste costs, so the next change to the ruleset can be compared against
// a number rather than a feeling.
//
// Measured 1 Oct 2026: about 2.8 MB/s on clean prose, flat across sizes — so
// roughly 0.36 ms per KB natively, and the same scan through the browser's
// WebAssembly build costs about 8 ms per KB, some twenty times more.
//
// Ten of the thirty-five rules carry no prefilter, and they are the digit-shape
// ones — card number, IBAN, Aadhaar, NINO, routing number, bank account, phone,
// IPv4. There is no literal to require for a run of digits, so each runs a full
// pass over every byte. A single cheap pre-pass for "is there a digit run of at
// least N here" would let all of them be skipped together on prose, which is
// nearly every message. That is the next thing worth doing, and it belongs with
// TestPrefiltersDoNotSuppressMatches extended to strip it too: a prefilter that
// wrongly skips a rule is a silent miss, not a slow scan.
func BenchmarkScanClean(b *testing.B) {
	rs := Default()
	for _, n := range []int{1024, 4096, 16384, 65536} {
		text := []byte(benchText(n))
		b.Run(sizeName(n), func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			for i := 0; i < b.N; i++ {
				rs.Scan(text)
			}
		})
	}
}

func BenchmarkScanWithFindings(b *testing.B) {
	rs := Default()
	for _, n := range []int{1024, 16384} {
		text := []byte(benchText(n) + " card 4111 1111 1111 1111 mail a@b.co key AKIAIOSFODNN7EXAMPLE")
		b.Run(sizeName(n), func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			for i := 0; i < b.N; i++ {
				rs.Scan(text)
			}
		})
	}
}

func sizeName(n int) string { return strconv.Itoa(n/1024) + "KB" }
