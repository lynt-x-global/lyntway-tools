package detect

import (
	"strings"
	"testing"
)

// Every class the ruleset can emit must have a name a person would say
// aloud. A screen that shows "pci.card_number" makes a compliance reader
// translate, and one that shows "injection.instruction_override" tells a
// non-engineer nothing at all.
func TestEveryRuleClassHasAName(t *testing.T) {
	seen := map[Class]bool{}
	for _, r := range Default().Rules() {
		if seen[r.Class] {
			continue
		}
		seen[r.Class] = true

		label := Label(r.Class)
		if label == "" {
			t.Errorf("%s has no label at all", r.Class)
			continue
		}
		// Falling back to the identifier is the failure this exists to
		// prevent, so a class that lands there is not named.
		if label == string(r.Class) {
			t.Errorf("%s is shown as its identifier, which is what this table exists to replace", r.Class)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no rules found, so this test proves nothing")
	}
}

// The analyzer ships its own taxonomy and moves faster than this table.
// An unknown class must still read as something, or detection improving
// makes the screens worse.
func TestAnUnknownClassStillReads(t *testing.T) {
	got := Label("pii.uk_nhs")
	if got == "pii.uk_nhs" {
		t.Errorf("an unknown member of a known family fell back to the identifier: %q", got)
	}
	if !strings.Contains(got, "Personal data") {
		t.Errorf("the family is not named: %q", got)
	}
}

// A class from a family nobody has heard of is shown as itself rather than
// invented. Guessing would be worse than the identifier.
func TestACompletelyUnknownClassIsNotInvented(t *testing.T) {
	if got := Label("quux.frobnicate"); got != "quux.frobnicate" {
		t.Errorf("an unknown family was given a name it does not have: %q", got)
	}
}

// Never empty. A blank cell where a finding belongs reads as nothing
// found, which is the most expensive misreading these screens allow.
func TestALabelIsNeverEmpty(t *testing.T) {
	for _, class := range []Class{"", ".", "pii.", ".email", "no-dots"} {
		if Label(class) == "" && class != "" {
			t.Errorf("Label(%q) is empty", class)
		}
	}
}

func TestTheTableIsHandedOverWhole(t *testing.T) {
	all := Labels()
	if all["pci.card_number"] != "Payment card number" {
		t.Errorf("the exported table disagrees with Label: %q", all["pci.card_number"])
	}
	if all["secret"] == "" {
		t.Error("the families are missing, so the console cannot fall back the way we do")
	}
}
