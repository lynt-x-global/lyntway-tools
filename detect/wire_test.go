package detect

import "testing"

// Wire instructions pasted into an assistant.
//
// Probed on production before a demo for a title and escrow company: a line
// carrying a routing number and an account number came back with nothing
// found. Fraudulent wire instructions are the largest single loss in
// real-estate closings, and "check these details for me" is exactly how
// the genuine ones reach a model.
func TestWireInstructionsAreFound(t *testing.T) {
	rs := Default()
	for _, tc := range []struct {
		content string
		want    Class
		span    string
	}{
		{"Wire to Chase, routing 021000021, account 123456789012.", ClassUSRouting, "021000021"},
		{"Wire to Chase, routing 021000021, account 123456789012.", ClassBankAccount, "123456789012"},
		{"ABA: 026009593 for Bank of America", ClassUSRouting, "026009593"},
		{"Routing number 121000248", ClassUSRouting, "121000248"},
		{"RTN #011000138", ClassUSRouting, "011000138"},
		{"Routing/ABA 021000021", ClassUSRouting, "021000021"},
		{"Acct # 0045812377", ClassBankAccount, "0045812377"},
		{"Account No. 998877665544", ClassBankAccount, "998877665544"},
		// The Indian passbook form, which was reported as a card before.
		{"a/c no 50100123456789 HDFC", ClassBankAccount, "50100123456789"},
		// The sentence, which is how a supplier chasing a payment writes
		// it and which went through untouched until 7 Oct 2026. The rule
		// read the forms above and missed the commonest phrasing there is.
		{"Is invoice 8841 paid? My account is 50100123456789.", ClassBankAccount, "50100123456789"},
		{"Our account number is 998877665544, please remit there.", ClassBankAccount, "998877665544"},
		{"The new account is now 0045812377.", ClassBankAccount, "0045812377"},
		{"Account details: 123456789012", ClassBankAccount, "123456789012"},
		{"a/c no. : 50100123456789", ClassBankAccount, "50100123456789"},
		{"Routing number is 121000248 and we bank with Chase.", ClassUSRouting, "121000248"},
		{"The ABA is 026009593.", ClassUSRouting, "026009593"},
	} {
		var got []string
		for _, s := range rs.Scan([]byte(tc.content)) {
			if s.Class == tc.want {
				got = append(got, tc.content[s.Start:s.End])
			}
		}
		if len(got) != 1 || got[0] != tc.span {
			t.Errorf("Scan(%q) found %s %q, want exactly [%q]", tc.content, tc.want, got, tc.span)
		}
	}
}

// The negative half. Nine digits pass the ABA checksum one time in ten, so
// the word in front of them is what carries the rule.
func TestWireLookalikesAreNotReported(t *testing.T) {
	rs := Default()
	for _, tc := range []struct {
		content string
		never   Class
	}{
		{"order 021000021 shipped", ClassUSRouting},             // right checksum, no context
		{"routing 021000022 on file", ClassUSRouting},           // context, wrong checksum
		{"routing 991000021 on file", ClassUSRouting},           // prefix no Reserve district uses
		{"routing table has 123456789 entries", ClassUSRouting}, // "routing" in another sense, bad checksum
		{"account 2024 renewal", ClassBankAccount},              // a year, too short
		{"order 123456789012 shipped", ClassBankAccount},        // no context
		// The words the gap steps over are a closed list on purpose.
		// Widening it to "any few words" would make every number after
		// the word "account" an account number, and these are the ones
		// that would have gone wrong first: a balance is not an account,
		// a holder is a person, and a statement is a document.
		{"account balance 123456789", ClassBankAccount},
		{"account balance is 123456789", ClassBankAccount},
		{"account holder 998877665544", ClassBankAccount},
		{"account statement 123456789012 attached", ClassBankAccount},
		{"account manager called about 123456789", ClassBankAccount},
		{"account is not 123456789 any more", ClassBankAccount},
		// And a whole clause between the two is not a match either, which
		// is what bounds the gap rather than leaving it open.
		{"account with the Dubai branch of HDFC Bank 50100123456789", ClassBankAccount},
		{"routing table has 123456789 entries now", ClassUSRouting},
	} {
		for _, s := range rs.Scan([]byte(tc.content)) {
			if s.Class == tc.never {
				t.Errorf("Scan(%q) reported %s %q", tc.content, tc.never, tc.content[s.Start:s.End])
			}
		}
	}

	// A card number written after "account" is still reported as the card.
	// Contiguous on purpose: the account rule matches only unbroken digits,
	// so a spaced card never competes with it and would prove nothing about
	// which rule wins the overlap.
	c := "account 4111111111111111"
	var classes []Class
	for _, s := range rs.Scan([]byte(c)) {
		classes = append(classes, s.Class)
	}
	if len(classes) != 1 || classes[0] != ClassCreditCard {
		t.Errorf("Scan(%q) = %v; want one card finding", c, classes)
	}
}

func TestTheABAChecksum(t *testing.T) {
	for s, want := range map[string]bool{
		"021000021": true,  // JPMorgan Chase
		"026009593": true,  // Bank of America
		"121000248": true,  // Wells Fargo
		"011000138": true,  // Bank of America, Massachusetts
		"021000022": false, // one digit off
		"991000021": false, // no such prefix
		"02100002":  false, // eight digits
	} {
		if got := validABARouting(s); got != want {
			t.Errorf("validABARouting(%q) = %v, want %v", s, got, want)
		}
	}
}
