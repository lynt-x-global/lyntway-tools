package detect

import "strings"

// What to call a class when a person is reading.
//
// The classes are dotted identifiers because they are a taxonomy: stable,
// sortable, and safe to key on. That makes them right in a receipt and
// wrong on a screen. Somebody in a compliance team reading
// "pci.card_number" has to translate it, and "injection.instruction_override"
// means nothing at all to a reader who is not an engineer.
//
// So there is a name for each, and it lives here rather than in the console
// because four things display these — the console, the compliance pack, the
// alert emails and lyntway-verify — and four copies of a naming table drift
// apart within a month.
//
// The identifier is never replaced, only accompanied. A reader
// cross-referencing a screen against the receipt it came from needs to find
// the same string in both, and a screen that has helpfully renamed
// everything makes that impossible.

// classLabels names each class the way somebody would say it aloud.
var classLabels = map[Class]string{
	ClassEmail:      "Email address",
	ClassPhone:      "Phone number",
	ClassIPv4:       "IP address",
	ClassCreditCard: "Payment card number",
	ClassIBAN:       "Bank account number (IBAN)",
	ClassUSSSN:      "US Social Security number",
	ClassINPAN:      "Indian PAN",
	ClassINAadhaar:  "Aadhaar number",
	ClassUKNINO:     "UK National Insurance number",

	ClassAWSAccessKey: "AWS access key",
	ClassGitHubToken:  "GitHub token",
	ClassSlackToken:   "Slack token",
	ClassStripeKey:    "Stripe key",
	ClassOpenAIKey:    "OpenAI key",
	ClassAnthropicKey: "Anthropic key",
	ClassPrivateKey:   "Private key",
	ClassJWT:          "Session token (JWT)",

	ClassInstructionOverride: "Attempt to override instructions",
	ClassPromptExtraction:    "Attempt to extract the prompt",
	ClassPersonaOverride:     "Attempt to change the assistant's role",
	ClassContextEscape:       "Attempt to escape the surrounding context",
}

// familyLabels name the groups, for a class we have no specific name for.
//
// A model can report a class this build has never heard of — the analyzer
// ships its own taxonomy and moves faster than this table. Falling back to
// the family keeps the screen readable instead of showing a raw identifier
// the moment detection improves.
var familyLabels = map[string]string{
	"pii":       "Personal data",
	"pci":       "Payment data",
	"phi":       "Health data",
	"secret":    "Credential",
	"injection": "Prompt injection",
	"financial": "Financial data",
}

// Label returns the human name for a class.
//
// Falls back to the family, then to the identifier itself. It never returns
// empty: a blank cell where a finding should be reads as nothing found,
// which is the most expensive misreading available on these screens.
func Label(class Class) string {
	if name, ok := classLabels[class]; ok {
		return name
	}

	family, rest, found := strings.Cut(string(class), ".")
	if !found {
		return string(class)
	}
	if name, ok := familyLabels[family]; ok {
		// Named family, unknown member: say both, so the reader learns
		// what kind of thing it is without being told it is something we
		// can describe precisely.
		return name + " (" + strings.ReplaceAll(rest, "_", " ") + ")"
	}
	return string(class)
}

// Labels returns the full naming table.
//
// Handed to the console so one table serves every screen, rather than the
// browser carrying a second copy that drifts.
func Labels() map[string]string {
	out := make(map[string]string, len(classLabels)+len(familyLabels))
	for class, name := range classLabels {
		out[string(class)] = name
	}
	for family, name := range familyLabels {
		out[family] = name
	}
	return out
}
