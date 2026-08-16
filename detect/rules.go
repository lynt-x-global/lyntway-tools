package detect

import (
	"regexp"
	"strings"
)

// RulesetVersion is the version recorded in every receipt this ruleset
// contributes to.
//
// Bump it on ANY change to rule content. The digest will change regardless
// and would expose an unbumped edit, but a stale version string makes a
// receipt harder to interpret for anyone reading it later.
const RulesetVersion = "core-2026.08.15"

// Classes detected by the default ruleset.
const (
	ClassEmail      Class = "pii.email"
	ClassPhone      Class = "pii.phone"
	ClassIPv4       Class = "pii.ip_address"
	ClassCreditCard Class = "pci.card_number"
	ClassIBAN       Class = "pci.iban"
	ClassUSSSN      Class = "pii.us_ssn"
	ClassINPAN      Class = "pii.in_pan"
	ClassINAadhaar  Class = "pii.in_aadhaar"

	ClassAWSAccessKey Class = "secret.aws_access_key"
	ClassGitHubToken  Class = "secret.github_token"
	ClassSlackToken   Class = "secret.slack_token"
	ClassStripeKey    Class = "secret.stripe_key"
	ClassOpenAIKey    Class = "secret.openai_key"
	ClassAnthropicKey Class = "secret.anthropic_key"
	ClassPrivateKey   Class = "secret.private_key"
	ClassJWT          Class = "secret.jwt"
	ClassAzureConnStr Class = "secret.azure_connection_string"

	// Prompt injection. Four shapes, kept separate because they are not
	// equally alarming and a policy should be able to treat them
	// differently.
	ClassInstructionOverride Class = "injection.instruction_override"
	ClassPromptExtraction    Class = "injection.prompt_extraction"
	ClassPersonaOverride     Class = "injection.persona_override"
	ClassContextEscape       Class = "injection.context_escape"
)

// Default returns the built-in deterministic ruleset.
//
// Ordering within this slice is irrelevant — NewRuleset sorts by ID before
// computing the digest.
func Default() *Ruleset {
	return NewRuleset(RulesetVersion, defaultRules())
}

func defaultRules() []Rule {
	return []Rule{
		// --- Credentials -------------------------------------------------
		//
		// Vendor-prefixed credentials are the highest-value detections
		// available: the prefixes are unambiguous, so these can be blocked
		// automatically without meaningful false-positive risk. They carry
		// the highest priority so a generic entropy heuristic never claims
		// them first.
		{
			ID:         "aws-access-key",
			Class:      ClassAWSAccessKey,
			Pattern:    regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b`),
			Confidence: ConfidenceExact,
			Prefilter:  []string{"AKIA", "ASIA", "ABIA", "ACCA"},
			Priority:   100,
		},
		{
			ID: "github-token",
			// GitHub's own documented prefixes. gho_ and ghp_ are the
			// common ones; the rest are included so a refresh or app token
			// is not silently missed.
			Class:      ClassGitHubToken,
			Pattern:    regexp.MustCompile(`\b(gh[posru]_[A-Za-z0-9]{36,255})\b`),
			Confidence: ConfidenceExact,
			Prefilter:  []string{"ghp_", "gho_", "ghs_", "ghr_", "ghu_"},
			Priority:   100,
		},
		{
			ID:         "slack-token",
			Class:      ClassSlackToken,
			Pattern:    regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z-]{10,})\b`),
			Confidence: ConfidenceExact,
			Prefilter:  []string{"xox"},
			Priority:   100,
		},
		{
			ID:         "stripe-key",
			Class:      ClassStripeKey,
			Pattern:    regexp.MustCompile(`\b((?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,})\b`),
			Confidence: ConfidenceExact,
			Prefilter:  []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_"},
			Priority:   100,
		},
		{
			ID:         "openai-key",
			Class:      ClassOpenAIKey,
			Pattern:    regexp.MustCompile(`\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b`),
			Confidence: ConfidenceHigh,
			Prefilter:  []string{"sk-"},
			Priority:   95,
		},
		{
			ID:         "anthropic-key",
			Class:      ClassAnthropicKey,
			Pattern:    regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_-]{20,})\b`),
			Confidence: ConfidenceExact,
			Prefilter:  []string{"sk-ant-"},
			Priority:   100,
		},
		{
			ID: "private-key-block",
			// The whole PEM block is the secret, so the span deliberately
			// covers everything between the delimiters.
			Class:      ClassPrivateKey,
			Pattern:    regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
			Confidence: ConfidenceExact,
			Prefilter:  []string{"PRIVATE KEY"},
			Priority:   110,
		},
		{
			ID:         "azure-connection-string",
			Class:      ClassAzureConnStr,
			Pattern:    regexp.MustCompile(`(?i)\b(AccountKey=[A-Za-z0-9+/]{60,}={0,2})`),
			Confidence: ConfidenceExact,
			Priority:   100,
		},
		{
			ID: "jwt",
			// Requires a JWT-shaped header segment rather than any three
			// base64 runs joined by dots, which would match far too much.
			Class:      ClassJWT,
			Pattern:    regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`),
			Confidence: ConfidenceHigh,
			Prefilter:  []string{"eyJ"},
			Priority:   90,
		},

		// --- Financial ---------------------------------------------------
		//
		// Both of these carry checksums, so they are validated structurally
		// rather than matched on shape alone. A card-number regex without a
		// Luhn check flags order numbers and timestamps constantly.
		{
			ID:         "credit-card",
			Class:      ClassCreditCard,
			Pattern:    regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
			Confidence: ConfidenceExact,
			Validate:   validLuhn,
			Priority:   80,
		},
		{
			ID:         "iban",
			Class:      ClassIBAN,
			Pattern:    regexp.MustCompile(`\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b`),
			Confidence: ConfidenceExact,
			Validate:   validIBAN,
			Priority:   80,
		},

		// --- Government identifiers --------------------------------------
		{
			ID:    "us-ssn",
			Class: ClassUSSSN,
			// Structural exclusions live in the validator, not the pattern.
			// Go's regexp is RE2, which has no lookahead — and a validator
			// is easier to read and test than a wall of negative
			// assertions would have been anyway.
			Pattern:    regexp.MustCompile(`\b(\d{3}-\d{2}-\d{4})\b`),
			Confidence: ConfidenceHigh,
			Validate:   validUSSSN,
			Prefilter:  []string{"-"},
			Priority:   70,
		},
		{
			ID:         "india-pan",
			Class:      ClassINPAN,
			Pattern:    regexp.MustCompile(`\b([A-Z]{5}\d{4}[A-Z])\b`),
			Confidence: ConfidenceModerate,
			Priority:   70,
		},
		{
			ID:    "india-aadhaar",
			Class: ClassINAadhaar,
			// Aadhaar never begins 0 or 1, and carries a Verhoeff check
			// digit — without which this pattern would match any grouped
			// 12-digit number.
			//
			// The leading "+" is excluded because an Indian mobile in E.164
			// is twelve digits beginning 91 — exactly this shape — and
			// roughly one in ten passes Verhoeff by chance. Reporting one
			// as an Aadhaar number is a false claim about what was found,
			// and a far more alarming one than the truth. An Aadhaar number
			// is never written with a leading "+"; a country code always
			// is, so that single character separates them cleanly.
			Pattern:    regexp.MustCompile(`(?:^|[^\w+])(?P<target>[2-9]\d{3}\s?\d{4}\s?\d{4})\b`),
			Confidence: ConfidenceExact,
			Validate:   validVerhoeff,
			Priority:   75,
		},

		// --- Prompt injection ---------------------------------------------
		//
		// Everything above this point matches a thing: a card number is a
		// card number wherever it appears. These match an *intent*, and
		// intent has no checksum. The same sentence is an attack in a
		// retrieved document and a paragraph in a security training deck.
		//
		// Two consequences run through every rule here.
		//
		// None of them is exact, and none pretends to be. The highest
		// confidence offered is moderate, which the default policy turns
		// into log_only rather than enforcement. A governance layer that
		// silently blocked a customer's article about prompt injection
		// would be a worse outcome than the attack it prevented, and the
		// customer would be right to remove it.
		//
		// Where it matters is not the user's own prompt — somebody talking
		// to their own model may say anything — but content coming back
		// from a document, a web page or a tool, where an instruction
		// addressed to an AI has no business being. The class names the
		// shape; the receipt's surface and direction say where it was
		// found, and that is what makes it actionable.
		{
			ID: "injection-instruction-override",
			// The canonical opener. Anchored on a verb of dismissal
			// followed by a reference to prior instruction, because either
			// half alone is ordinary English.
			Class: ClassInstructionOverride,
			Pattern: regexp.MustCompile(
				`(?i)\b(ignore|disregard|forget|override|discard)\b[^.!?\n]{0,40}?\b(previous|prior|earlier|above|preceding|all)\b[^.!?\n]{0,20}?\b(instruction|instructions|prompt|prompts|rule|rules|direction|directions|context)\b`),
			Confidence: ConfidenceModerate,
			Prefilter:  []string{"ignore", "Ignore", "IGNORE", "disregard", "Disregard", "forget", "Forget", "override", "Override", "discard", "Discard"},
			Priority:   40,
		},
		{
			ID: "injection-prompt-extraction",
			// Asking a model to recite its own configuration. Harmless
			// curiosity from a developer, and the first move of an
			// attacker mapping a target.
			Class: ClassPromptExtraction,
			Pattern: regexp.MustCompile(
				`(?i)\b(reveal|repeat|print|show|output|display|tell me|what (?:is|are))\b[^.!?\n]{0,30}?\b(your |the )?(system prompt|initial instructions|original instructions|system message|developer message|prompt above)\b`),
			Confidence: ConfidenceModerate,
			Prefilter:  []string{"system prompt", "System prompt", "System Prompt", "initial instructions", "original instructions", "system message", "developer message", "prompt above"},
			Priority:   40,
		},
		{
			ID: "injection-persona-override",
			// Jailbreak personas. Named ones date quickly, so this matches
			// the grammar they share rather than the names themselves.
			Class: ClassPersonaOverride,
			Pattern: regexp.MustCompile(
				`(?i)\b(you are now|from now on,? you|act as if you|pretend (?:that )?you|you must now)\b[^.!?\n]{0,60}?\b(no (?:longer )?(?:have|has)|without|free from|unrestricted|unfiltered|no restrictions|no rules|do anything|jailbr|developer mode|dan mode)\b`),
			Confidence: ConfidenceModerate,
			Prefilter:  []string{"you are now", "You are now", "from now on", "From now on", "act as if", "Act as if", "pretend you", "Pretend you", "you must now", "You must now"},
			Priority:   40,
		},
		{
			ID: "injection-context-escape",
			// Chat-template delimiters appearing inside content. A user
			// message containing a system turn marker is either an attack
			// or a bug, and both are worth surfacing — legitimate prose
			// does not contain these tokens.
			Class: ClassContextEscape,
			Pattern: regexp.MustCompile(
				`(?i)(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|endoftext\|>|\[/?INST\]|<<SYS>>|###\s*(?:system|assistant)\s*:)`),
			Confidence: ConfidenceHigh,
			Prefilter:  []string{"<|im_start|>", "<|im_end|>", "<|system|>", "<|endoftext|>", "[INST]", "[/INST]", "<<SYS>>", "### system", "### System", "### assistant", "### Assistant"},
			Priority:   45,
		},

		// --- Contact details ---------------------------------------------
		{
			ID:         "email",
			Class:      ClassEmail,
			Pattern:    regexp.MustCompile(`\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b`),
			Confidence: ConfidenceExact,
			Prefilter:  []string{"@"},
			Priority:   60,
		},
		{
			ID: "phone-international",
			// A leading "+" is required, and it is the whole of the
			// discipline here. Loose national formats — bare runs of ten
			// digits — genuinely do produce false positives against
			// ordinary numeric text, and belong in the ML tier where
			// context is available. But requiring E.164 with no separators
			// over-corrected: almost nobody writes an international number
			// that way. "+91 98840 12345" is how the number appears in a
			// support ticket, and it was passing through untouched.
			//
			// So: still require the "+", now allow the separators people
			// write between the groups. validInternationalPhone enforces
			// the rest — 8 to 15 digits, per E.164, and a group structure a
			// real number has.
			//
			// The leading character is required context but must not be
			// part of the span, so it is excluded via the "target" capture
			// group. Without that the span swallows the preceding
			// character and tokenisation deletes it from the output.
			Class:      ClassPhone,
			Pattern:    regexp.MustCompile(`(?:^|[^\w+])(?P<target>\+[1-9][\d()\-. ]{6,18}\d)`),
			Confidence: ConfidenceHigh,
			Validate:   validInternationalPhone,
			Prefilter:  []string{"+"},
			Priority:   55,
		},
		{
			ID:    "ipv4",
			Class: ClassIPv4,
			// Reported at low confidence: an IP address is only personal
			// data in context, and this pattern matches plenty of
			// non-personal infrastructure addresses. Never enforce on this
			// alone.
			Pattern:    regexp.MustCompile(`\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b`),
			Confidence: ConfidenceLow,
			Priority:   30,
		},
	}
}

// validUSSSN rejects structurally impossible Social Security numbers.
//
// The SSA never issues area 000, 666, or 900-999, nor group 00, nor serial
// 0000. Excluding them removes a large share of false positives from
// ordinary formatted numbers without needing any context.
func validUSSSN(s string) bool {
	if len(s) != 11 || s[3] != '-' || s[6] != '-' {
		return false
	}
	area, group, serial := s[0:3], s[4:6], s[7:11]
	for _, part := range []string{area, group, serial} {
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	return group != "00" && serial != "0000"
}

// validLuhn reports whether s passes the Luhn checksum.
//
// This is what separates a card number from any other run of digits. A
// card-number rule without it is a false-positive generator, not a detector.
func validLuhn(s string) bool {
	var digits []int
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits = append(digits, int(r-'0'))
		case r == ' ' || r == '-':
			// Separators are permitted inside a card number.
		default:
			return false
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// validIBAN reports whether s passes the ISO 13616 mod-97 check.
func validIBAN(s string) bool {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(s))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9') && !(r >= 'A' && r <= 'Z') {
			return false
		}
	}

	// Move the first four characters to the end, then interpret letters as
	// their position in the alphabet plus nine.
	rearranged := s[4:] + s[:4]

	// Reduce incrementally: the full value overflows any fixed-width
	// integer for a 34-character IBAN.
	remainder := 0
	for _, r := range rearranged {
		var chunk int
		switch {
		case r >= '0' && r <= '9':
			chunk = int(r - '0')
			remainder = (remainder*10 + chunk) % 97
		default:
			chunk = int(r-'A') + 10
			remainder = (remainder*100 + chunk) % 97
		}
	}
	return remainder == 1
}

// verhoeffD is the dihedral group D5 multiplication table.
var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

// verhoeffP is the permutation table.
var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// validVerhoeff reports whether s passes the Verhoeff checksum used by
// Aadhaar numbers.
func validVerhoeff(s string) bool {
	var digits []int
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits = append(digits, int(r-'0'))
		case r == ' ' || r == '-':
		default:
			return false
		}
	}
	if len(digits) != 12 {
		return false
	}

	c := 0
	for i := len(digits) - 1; i >= 0; i-- {
		pos := (len(digits) - 1 - i) % 8
		c = verhoeffD[c][verhoeffP[pos][digits[i]]]
	}
	return c == 0
}

// validInternationalPhone checks a candidate has the shape of a real number.
//
// E.164 allows at most fifteen digits including the country code, and no
// assignable number has fewer than eight. Between those bounds the pattern
// is permissive about separators, so the group structure is checked here
// instead: a number written for a human has a handful of groups, none of
// them long, and no run of punctuation between them.
//
// The deliberate limitation: a number followed immediately by a bare
// numeric word — "+91 98840 12345 42" — can be captured whole. Tokenisation
// is format-preserving, so the released text still reads as a phone number
// and nothing is deleted, and that is a far smaller cost than the alternative
// this replaces, which missed every separated number written anywhere.
func validInternationalPhone(s string) bool {
	digits, groups, spacers := 0, 1, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
			if spacers > 0 {
				groups++
			}
			spacers = 0
		case r == '(' || r == ')':
			// Brackets group rather than separate, so they do not count
			// towards the run. "+1 (415) 555-0132" is one space, one
			// bracket pair and one hyphen — ordinary formatting, not
			// punctuation that happens to sit between two numbers.
		default:
			spacers++
			// Two spaces or dashes in a row is punctuation, not formatting.
			if spacers > 1 {
				return false
			}
		}
	}
	// A trailing separator cannot occur: the pattern ends on a digit.
	return digits >= 8 && digits <= 15 && groups <= 6
}
