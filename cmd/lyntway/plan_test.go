package main

import (
	"strings"
	"testing"
)

// The urgent part comes first.
//
// A notice is the only thing in this output that is ever time-sensitive.
// Printed under the plan and the usage it is three lines down a screen
// somebody is scanning for a number, which is how a subscription ends
// while four warnings scroll past.
func TestAnOutstandingNoticeIsPrintedBeforeThePlan(t *testing.T) {
	var r planReport
	r.Plan, r.Label = "team", "Team"
	r.Actions, r.Limit, r.Period = 1284, 10000, "2026-10"
	r.Notice.Kind = "payment_failed"
	r.Notice.Summary = "A payment did not go through. Nothing has changed yet."

	out := capture(t, "", func() { printPlan(r, "https://lyntway.com") })

	notice := strings.Index(out, "A payment did not go through")
	plan := strings.Index(out, "Team")
	if notice < 0 {
		t.Fatalf("the notice was not printed at all:\n%s", out)
	}
	if plan >= 0 && notice > plan {
		t.Errorf("the notice is printed after the plan:\n%s", out)
	}
}

// Nothing nags.
//
// A tool that asks for money every time it is run gets run less, and this
// one is meant to be run often. The single line about upgrading appears
// only when something is actually constrained.
func TestAHealthyAccountIsNotAskedForMoney(t *testing.T) {
	var r planReport
	r.Plan, r.Label = "team", "Team"
	r.Actions, r.Limit = 120, 10000
	r.Manage = "https://lyntway.com/settings?tab=account"

	out := capture(t, "", func() { printPlan(r, "https://lyntway.com") })

	for _, nag := range []string{"Change it at", "% of the cap", "Upgrade", "upgrade"} {
		if strings.Contains(out, nag) {
			t.Errorf("an account at 1%% of its cap was asked for money (%q):\n%s", nag, out)
		}
	}
}

// Close to the cap, it says so once.
func TestNearTheCapItSaysSoOnce(t *testing.T) {
	var r planReport
	r.Plan, r.Label = "free", "Free"
	r.Actions, r.Limit = 9500, 10000
	r.Manage = "https://lyntway.com/settings?tab=account"

	out := capture(t, "", func() { printPlan(r, "https://lyntway.com") })

	if !strings.Contains(out, "90% of the cap") {
		t.Errorf("an account at 95%% of its cap was told nothing:\n%s", out)
	}
	if strings.Count(out, "settings?tab=account") != 1 {
		t.Errorf("the address to change it appears more than once:\n%s", out)
	}
}

// A deployment with no cap draws no bar.
//
// A bar with no end is a bar that means nothing, and a self-hosted install
// has no cap by design — quota.go says zero is the correct setting there.
func TestNoCapMeansNoBar(t *testing.T) {
	var r planReport
	r.Plan, r.Label = "paid", "Self-hosted"
	r.Actions = 41208

	out := capture(t, "", func() { printPlan(r, "https://lyntway.example") })

	if strings.Contains(out, "[") {
		t.Errorf("a bar was drawn against no limit:\n%s", out)
	}
	if !strings.Contains(out, "41,208") {
		t.Errorf("the count is not grouped, so it cannot be read at a glance:\n%s", out)
	}
	if !strings.Contains(out, "no cap") {
		t.Errorf("the output does not say there is no cap:\n%s", out)
	}
}

// The bar never draws outside its own frame.
//
// Usage can exceed a limit: the quota gate caches its reading, so a tenant
// can overrun by up to one refresh interval of traffic by design. A bar
// that grew past its brackets would wrap the terminal and look like a
// rendering bug rather than an overrun.
func TestTheBarCannotOverflowItsFrame(t *testing.T) {
	for _, c := range []struct{ used, limit int64 }{
		{0, 100}, {50, 100}, {100, 100}, {250, 100}, {-5, 100},
	} {
		got := bar(c.used, c.limit)
		open, close := strings.Index(got, "["), strings.Index(got, "]")
		if open < 0 || close < 0 {
			t.Fatalf("bar(%d, %d) = %q, which has no frame", c.used, c.limit, got)
		}
		if width := close - open - 1; width != 24 {
			t.Errorf("bar(%d, %d) drew %d characters inside a 24-wide frame: %q",
				c.used, c.limit, width, got)
		}
	}
	if bar(5, 0) != "" {
		t.Error("a bar was drawn against a zero limit")
	}
}

// Numbers are grouped the way a person reads them.
func TestCommasGroupsFromTheRight(t *testing.T) {
	for in, want := range map[int64]string{
		0: "0", 7: "7", 999: "999", 1000: "1,000",
		12418: "12,418", 1234567: "1,234,567",
	} {
		if got := commas(in); got != want {
			t.Errorf("commas(%d) = %q, want %q", in, got, want)
		}
	}
}
