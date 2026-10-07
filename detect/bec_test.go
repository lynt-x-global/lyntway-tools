package detect

import "testing"

// Business email compromise, in the words it actually arrives in.
//
// This is the attack a title or mortgage business loses money to, and an
// agent reading closing mail is the ideal victim: it has no sense that a
// wire instruction arriving late in a deal is unusual, and complying is
// what it was asked to do. The classes exist to hold the message for a
// person, so the bar for firing is deliberately lower than for an
// identifier — but not so low that ordinary correspondence trips it, which
// is what the second test is for.
func TestBECPhrasingIsFound(t *testing.T) {
	rs := Default()
	for _, tc := range []struct {
		content string
		want    Class
	}{
		{"Please note our bank details have changed.", ClassBECBankChange},
		{"We have updated our banking details for this closing.", ClassBECBankChange},
		{"Our payment instructions have been amended, see below.", ClassBECBankChange},
		{"Please use the new account details attached.", ClassBECBankChange},
		{"The wire instructions have changed since the last statement.", ClassBECBankChange},
		{"Revised beneficiary details are below.", ClassBECBankChange},

		{"Do not use the account on the previous invoice.", ClassBECPayeeRedirect},
		{"Please remit to the new account from today.", ClassBECPayeeRedirect},
		{"That IBAN is no longer used — pay into the following account.", ClassBECPayeeRedirect},
		{"Kindly transfer into the following bank account.", ClassBECPayeeRedirect},
	} {
		var found bool
		for _, s := range rs.Scan([]byte(tc.content)) {
			if s.Class == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("Scan(%q) did not report %s", tc.content, tc.want)
		}
	}
}

// The half that decides whether anyone keeps the feature switched on.
// A hold costs somebody ten seconds; a hold on every ordinary sentence
// costs the customer their patience, and the rule gets turned off before it
// ever sees a real attack.
func TestOrdinaryCorrespondenceIsNotBEC(t *testing.T) {
	rs := Default()
	for _, content := range []string{
		"Please find our bank details attached for your records.",
		"Our account details are below.",
		"I do not use that system any more.",
		"The new account manager will contact you next week.",
		"Please send the signed copy to the following address.",
		"Payment received, thank you.",
		"Your account number is shown on page two.",
		"We have updated our privacy policy.",
		"The details have changed on the title report.",
	} {
		for _, s := range rs.Scan([]byte(content)) {
			if HasClassPrefix(s.Class, "bec") {
				t.Errorf("Scan(%q) reported %s on ordinary correspondence", content, s.Class)
			}
		}
	}
}

// The scenario end to end: a closing email that carries both the
// announcement and the new destination, alongside the account number
// itself. All three must be reported, because the receipt has to show what
// was in the message, not merely that something was.
func TestAClosingWireFraudMessageReportsEverything(t *testing.T) {
	const content = "Further to the closing on Thursday: our banking details have changed. " +
		"Do not use the account on the earlier statement. " +
		"Please wire to routing number 021000021, account 50100123456789."

	want := map[Class]bool{
		ClassBECBankChange:    false,
		ClassBECPayeeRedirect: false,
		ClassUSRouting:        false,
		ClassBankAccount:      false,
	}
	for _, s := range Default().Scan([]byte(content)) {
		if _, ok := want[s.Class]; ok {
			want[s.Class] = true
		}
	}
	for class, found := range want {
		if !found {
			t.Errorf("the closing message did not report %s", class)
		}
	}
}

// The two classes overlap by design, and overlap resolution picks one.
//
// "transfer into the updated bank account" is both an announcement that the
// details changed and an instruction to pay elsewhere. Both rules match the
// same span, they share a priority, and the higher-confidence class wins —
// so the message is reported once, as the stronger claim, rather than
// twice. Written down because the first version of the test above expected
// the redirect class here and the engine was right, not the test.
func TestWhenBothBECShapesMatchTheStrongerClassIsReported(t *testing.T) {
	const content = "Kindly transfer into the updated bank account."
	var classes []Class
	for _, s := range Default().Scan([]byte(content)) {
		if HasClassPrefix(s.Class, "bec") {
			classes = append(classes, s.Class)
		}
	}
	if len(classes) != 1 {
		t.Fatalf("got %v, want exactly one bec class", classes)
	}
	if classes[0] != ClassBECBankChange {
		t.Errorf("got %s, want %s — the higher-confidence class should win the overlap",
			classes[0], ClassBECBankChange)
	}
}

// Every class a person can see needs a name, or the console shows a raw
// dotted identifier next to the ones that have been given words.
func TestBECClassesHaveHumanLabels(t *testing.T) {
	for _, c := range []Class{ClassBECBankChange, ClassBECPayeeRedirect} {
		got := Label(c)
		if got == string(c) {
			t.Errorf("Label(%s) fell through to the identifier", c)
		}
		if got == "Business email compromise" {
			t.Errorf("Label(%s) fell back to the family; it needs its own name", c)
		}
	}
}
