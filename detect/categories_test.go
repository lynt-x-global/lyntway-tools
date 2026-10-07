package detect

import "testing"

// Every class a rule can produce must belong to a category.
//
// This is the test the whole file exists for. The console offers categories
// as the thing an administrator enforces on, so a class with no category is a
// value no policy can name — and the failure is silent, because detection
// still finds it and nothing on screen says it was never selectable.
//
// Adding a rule with an uncategorised class fails here, which is the point:
// the list cannot drift from the ruleset because it is not a list.
func TestEveryDetectableClassHasACategory(t *testing.T) {
	rs := Default()
	for _, r := range rs.Rules() {
		if Category(r.Class) == "" {
			t.Errorf("rule %q produces class %q, which is in no category. "+
				"Place it in classCategories (or give its family a prefix in "+
				"familyCategories) — until then no policy can select it and "+
				"the console cannot offer it.", r.ID, r.Class)
		}
	}
}

// And no category may exist without something behind it.
//
// Three of the console's fourteen — password, passport, biometric — named
// nothing this ruleset detects. Ticking one promised a protection that did
// not exist, which is the receipt rule pointed at a settings screen.
func TestEveryCategoryHasAtLeastOneRule(t *testing.T) {
	rs := Default()
	for _, c := range rs.Categories() {
		if len(rs.ClassesIn(c)) == 0 {
			t.Errorf("category %q is offered but no rule produces a class in it", c)
		}
	}
}

// The categories this ruleset actually offers. Pinned as a literal, because
// the console renders them and a silent change to the set is a silent change
// to what an administrator is asked.
func TestTheOfferedCategoriesAreTheOnesWithRules(t *testing.T) {
	want := []string{"aadhaar", "address", "card", "email", "financial", "iban", "id",
		"injection", "ip", "key", "medical", "phone", "ssn"}
	got := Default().Categories()
	if len(got) != len(want) {
		t.Fatalf("categories = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("categories = %v, want %v", got, want)
		}
	}
}

// An empty selection means everything, which is what the console says it
// means. A policy that arrived without the field must not narrow enforcement
// to nothing.
func TestAnEmptySelectionSelectsEverything(t *testing.T) {
	for _, c := range []Class{ClassEmail, ClassCreditCard, ClassINHealthID} {
		if !InCategories(c, nil) {
			t.Errorf("InCategories(%q, nil) = false; an unset policy field must "+
				"not switch enforcement off", c)
		}
	}
}

func TestASelectionNarrowsToWhatWasChosen(t *testing.T) {
	sel := []string{"email", "key"}
	for _, c := range []Class{ClassEmail, ClassAWSAccessKey, ClassOpenAIKey} {
		if !InCategories(c, sel) {
			t.Errorf("InCategories(%q, %v) = false, want true", c, sel)
		}
	}
	for _, c := range []Class{ClassCreditCard, ClassPhone, ClassINAadhaar} {
		if InCategories(c, sel) {
			t.Errorf("InCategories(%q, %v) = true, want false", c, sel)
		}
	}
}

// A class nobody has categorised is acted on, not exempted. The opposite
// would mean a new rule is silently outside every policy that names
// categories — a hole that opens without anybody doing anything.
func TestAnUncategorisedClassIsStillActedOn(t *testing.T) {
	if !InCategories(Class("pii.something_new"), []string{"email"}) {
		t.Error("an uncategorised class was exempted by a category selection; " +
			"it must be acted on, or adding a rule quietly disables it")
	}
}

// Whole families are categorised by prefix, so a new secret rule is covered
// the moment it lands.
func TestANewSecretIsCategorisedWithoutBeingListed(t *testing.T) {
	if got := Category(Class("secret.some_new_vendor_token")); got != "key" {
		t.Errorf("Category(secret.some_new_vendor_token) = %q, want \"key\": "+
			"the families that grow are categorised by prefix so nobody has to "+
			"remember", got)
	}
}
