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
const RulesetVersion = "core-2026.10.07a"

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
	ClassINHealthID Class = "pii.in_health_id"
	ClassINUPI      Class = "pii.in_upi"

	// Wire instructions: the routing number that says which bank, and the
	// account number that says whose money. Real-estate closings lose more
	// to fraudulent wire instructions than to anything else, and pasting a
	// closing's instructions into an assistant to "check the details" is
	// exactly how they leave.
	ClassUSRouting   Class = "pci.us_routing_number"
	ClassBankAccount Class = "pii.bank_account_number"
	ClassUKNINO      Class = "pii.uk_nino"
	// Classes only the model tier produces. They have no rule and so no
	// place in Categories(); they are named here so a receipt, a panel and
	// the agent all spell them the same way, and so detect.Label can say
	// what they are instead of "Personal data (entity)".
	ClassPersonName     Class = "pii.person_name"
	ClassLocation       Class = "pii.location"
	ClassDateOfBirth    Class = "pii.date_of_birth"
	ClassPassportNumber Class = "pii.passport_number"
	ClassEntity         Class = "pii.entity"
	// ClassINPIN is an Indian postal code, found only beside its label.
	ClassINPIN Class = "pii.in_pin"
	// ClassUserMarked is a region a person boxed out by hand, in the
	// comparison view, because the detectors missed it or because they
	// simply did not want it to leave. It is its own class so a receipt
	// says plainly which protections were automatic and which were
	// judgement; folding it into a model's count would be the receipt
	// claiming a capability the model does not have.
	ClassUserMarked Class = "pii.user_marked"

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

	// Business email compromise. A separate family from injection because
	// the target is different: injection aims at the model, these aim at
	// the process the model is running.
	ClassBECBankChange    Class = "bec.bank_detail_change"
	ClassBECPayeeRedirect Class = "bec.payee_redirect"
)

// cueGap is what a rule will step over between the word that names a
// number and the number itself.
//
// Two rules here are gated on a cue word — "routing", "account" — because
// the digits alone are an order number as often as they are wire
// instructions. Both required the number to follow the cue almost
// immediately, which caught "account no. 50100123456789" and the
// passbook forms and missed the single commonest phrasing in real mail:
// "my account is 50100123456789". A supplier chasing a payment writes a
// sentence, not a form.
//
// The gap is a closed list of connectives rather than "any few words",
// and that is the whole care in it. "account balance 123456789" is a
// balance and "account holder 998877" is somebody's name badge, so the
// words that mean nothing — is, number, our, the, new, now — are stepped
// over and every other word still ends the match. Four of them at most,
// which covers "account number is" and "a/c no. :" and stops short of a
// clause.
const cueGap = `(?:\s*(?:no|nos|number|num|is|are|was|were|the|our|my|your|their|new|now|to|as|of|details?|same|reads|shows|below|follows)\b|\s*[:#.,=-]+){0,4}`

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
			ID: "private-key-truncated",
			// A key whose END line never arrived.
			//
			// The rule above needs both delimiters, which is right for the
			// common case and right about the bare header: "-----BEGIN RSA
			// PRIVATE KEY-----" on its own appears in documentation, in code
			// comments and in this file, and flagging it would fire on people
			// writing about keys rather than pasting one.
			//
			// But the delimiter is not the secret — the body is. A key cut off
			// by a field length limit, a half-selected copy, or a log that
			// truncated the line is still a key, and it was going through
			// unnoticed. So this matches the header followed by enough base64
			// to be a key and no closing line.
			//
			// "Enough" is two full-width PEM lines. A 2048-bit RSA key is
			// twenty-five of them, so this still catches a badly truncated one;
			// a documentation example showing a header and an ellipsis does not
			// reach it. The span stops at the body rather than running to the
			// end of the input, because everything after it is not the key.
			Class:      ClassPrivateKey,
			Pattern:    regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\r\n]+(?:[A-Za-z0-9+/=]{40,}[\r\n]+){2,}`),
			Confidence: ConfidenceExact,
			Prefilter:  []string{"PRIVATE KEY"},
			// Below the complete block as a statement of intent. It is not
			// what prevents a complete key being counted twice — both rules
			// match it, and overlap resolution keeps the longer span, which is
			// the whole block either way. Checked by raising this to 110 and
			// confirming the count stays at one.
			Priority: 109,
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
			ID:    "credit-card",
			Class: ClassCreditCard,
			// A number that follows an IBAN's country and check digits is
			// the rest of an IBAN — one that failed its own checksum, which
			// is exactly when it must not turn into a card finding instead.
			Pattern:    regexp.MustCompile(`(?P<reject>\b[A-Z]{2}\d{2}[ -])?\b(?P<target>(?:\d[ -]*?){13,19})\b`),
			Confidence: ConfidenceExact,
			Validate:   validCard,
			Priority:   80,
		},
		{
			ID:    "iban",
			Class: ClassIBAN,
			// Separators are allowed because the spaced form is the
			// printed standard: every invoice and bank letter groups an
			// IBAN in fours. Matching only the unspaced form meant missing
			// it in exactly the documents it appears in.
			//
			// The separated form must be groups of four with a short final
			// group, which is the actual printed convention. Allowing a
			// separator between any two characters instead let a run of
			// unrelated capitals after a genuine IBAN be swallowed into
			// the match, where it failed the checksum and turned a
			// detection into a silent miss — the worse of the two
			// failures, and one a test now holds shut.
			// Case-insensitive since 22 September 2026. The pattern required
			// capitals while validIBAN already uppercased before checking,
			// so "gb82 west 1234 5698 7654 32" — an IBAN as somebody types
			// it into a chat message or a ticket, which is exactly the
			// content this service reads — never reached the checksum. The
			// third form of the same defect in this one rule.
			//
			// Safe to loosen because the mod-97 check is doing the real
			// work: two letters, two digits and a run of alphanumerics is
			// a weak pattern, and essentially nothing that is not an IBAN
			// survives ISO 13616.
			Pattern: regexp.MustCompile(
				`(?i)\b([A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?:[ -][A-Z0-9]{4})*(?:[ -][A-Z0-9]{1,4})?))\b`),
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
			//
			// The separator was a hyphen and only a hyphen until
			// 22 September 2026. "078 05 1120" and "078.05.1120" both went
			// through untouched, which an evaluator found by pasting the
			// four forms a US system might emit and watching three of them
			// reach the model. The same shape as the IBAN that matched
			// unspaced and was missed in the spaced form printed on every
			// invoice, and as the phone number that needed a leading "+".
			//
			// Nine bare digits are still not matched here, deliberately:
			// that is any nine-digit identifier, and it belongs to the
			// model tier where context is available. A number written with
			// separators is a different proposition.
			//
			// No Prefilter: the separators are "-", " " and ".", and a set
			// containing a space filters nothing.
			Pattern:    regexp.MustCompile(`\b(\d{3}[ .-]\d{2}[ .-]\d{4})\b`),
			Confidence: ConfidenceHigh,
			Validate:   validUSSSN,
			Priority:   70,
		},
		{
			ID: "india-health-id",
			// India's fourteen-digit health identifiers: the ABHA number every
			// patient is issued, and the HPR ID every registered practitioner
			// is. Both come from the National Health Authority and both are
			// written in the same 2-4-4-4 grouping.
			//
			// Added because one went to an AI service inside an uploaded
			// registration PDF while every other identifier on the page was
			// known. Aadhaar and PAN were covered; the health identifier that
			// sits beside them on the same forms was not, which is the gap a
			// rule list acquires by growing one leak at a time.
			//
			// # Why the grouping is required
			//
			// There is no published check digit for these, unlike Aadhaar's
			// Verhoeff, so the shape is all there is. Fourteen bare digits are
			// far too common to claim — a timestamp, an order line, a phone
			// number with a country code and an extension. Requiring the
			// separators makes it the written form rather than any run of
			// digits, and that written form is what appears on a certificate,
			// in a form field and in the text somebody pastes.
			//
			// The cost is admitted rather than hidden: an identifier typed
			// without its separators is not matched. Moderate confidence says
			// so, and this is deliberately not ConfidenceExact — nothing was
			// verified, only recognised.
			Class:      ClassINHealthID,
			Pattern:    regexp.MustCompile(`\b(\d{2}[- ]\d{4}[- ]\d{4}[- ]\d{4})\b`),
			Confidence: ConfidenceModerate,
			Priority:   70,
		},
		{
			ID:    "india-pan",
			Class: ClassINPAN,
			// Case-insensitive since 22 September 2026. A PAN is printed in
			// capitals and typed however the person typing it likes, and a
			// line pasted from a chat — "my pan is abcpe1234f" — reached the
			// model untouched. Five letters, four digits and a letter
			// standing as one word is rare enough in either case that the
			// pattern carries the rule on its own.
			//
			// High, not moderate, since 2 October 2026, and with a validator.
			// The default policy substitutes personal data only at high
			// confidence, so a PAN on the hosted gateway was found, counted
			// and sent as it was — visible as the one value left standing in
			// a demo where everything beside it had been replaced. The fourth
			// character of a PAN is the holder type and takes one of ten
			// letters; checking it rejects the product codes a bare
			// five-letters-four-digits-letter pattern would otherwise call a
			// PAN, which is what earns the higher confidence. "ABCDE1234F",
			// the placeholder half the internet uses, has a D there and is
			// not a PAN.
			Pattern:    regexp.MustCompile(`(?i)\b([A-Z]{5}\d{4}[A-Z])\b`),
			Confidence: ConfidenceHigh,
			Validate:   validINPAN,
			Priority:   70,
		},
		{
			ID:    "uk-nino",
			Class: ClassUKNINO,
			// Two letters, six digits, one letter, written either unbroken
			// or in the spaced groups printed on the card and on every
			// HMRC letter. The demo text on the playground carried the
			// spaced form and nothing detected it.
			//
			// No checksum exists for these, so the structural rules HMRC
			// publishes do the work instead and live in the validator:
			// which letters may open the number, which prefixes were never
			// allocated, and that the suffix is one of A to D. A number
			// printed without its suffix — a form some old payslips use —
			// is two letters and six digits, which is also a product code,
			// and is deliberately not matched: the rule that caught it
			// would flag half of every parts catalogue.
			Pattern:    regexp.MustCompile(`\b([A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D])\b`),
			Confidence: ConfidenceHigh,
			Validate:   validUKNINO,
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
			//
			// A hyphen before it is excluded as well (the tail of an
			// identifier such as a UUID), and a further group of digits after
			// it rejects the match: the first twelve digits of a grouped
			// sixteen-digit number passed Verhoeff one time in ten, and a
			// card number that failed Luhn was then reported as an Aadhaar
			// number. The detection benchmark found both.
			//
			// Hyphenated groups are matched too: "2345-6789-0124" is how the
			// number comes out of plenty of Indian forms and spreadsheets,
			// and it went through untouched while the spaced form was
			// caught. The guards above still hold — a hyphen before the
			// number, or another group after it, rejects the match.
			Pattern:    regexp.MustCompile(`(?:^|[^\w+\-])(?P<target>[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4})(?P<reject>[ -]\d+)?\b`),
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
				`(?i)\b(ignore|disregard|forget|override|discard)\b[^.!?\n]{0,40}?\b(previous|prior|earlier|above|preceding|all)\b[^.!?\n]{0,20}?\b(instruction|instructions|prompt|prompts|rule|rules|direction|directions|context|information|guidance|guidelines|constraints|directives|programming|configuration)\b`),
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

		// The rules below were written against the tune split of
		// analyzer/eval, where they close gaps the classifier leaves: it
		// scored "Forget everything before that." at 0.0006 and every
		// non-English attack as benign. They stay at moderate confidence
		// for the same reason as the four above. Their prefilters are the
		// case-folded kind: a case-sensitive list in front of a (?i)
		// pattern is how a rule silently stops matching "FoRgEt
		// EvErYtHiNg BeFoRe", and with no prefilter at all they tripled the
		// cost of scanning ordinary prose. Each literal is one the pattern
		// cannot match without, in every branch; none spans whitespace,
		// because the patterns allow any run of it.
		{
			ID: "injection-prior-dismissal",
			// Dismissing the whole of what came before, rather than naming
			// the instructions. The temporal word is required: "forget
			// everything" alone is a figure of speech, "forget everything
			// before this" is a reset.
			Class: ClassInstructionOverride,
			Pattern: regexp.MustCompile(
				`(?i)\b(?:ignore|disregard|forget|discard)\s+(?:about\s+)?(?:everything|all|anything)(?:\s+(?:that|which))?(?:\s+(?:we|you)\s+(?:have\s+|had\s+)?(?:discussed|said|told\s+you|were\s+told|have\s+been\s+told|talked\s+about|covered|received|learned|learnt))?\s*,?\s*(?:before(?:hand)?|above|previously|earlier|so\s+far|until\s+now|up\s+to\s+now|prior)\b`),
			Confidence:    ConfidenceModerate,
			PrefilterFold: []string{"ignore", "disregard", "forget", "discard"},
			Priority:      40,
		},
		{
			ID: "injection-guidance-revoked",
			// Telling the model its own guidance has lapsed. Anchored on
			// "your", or on "the ... you were given", because "the old rules
			// no longer apply" is an ordinary sentence about a policy change.
			Class: ClassInstructionOverride,
			Pattern: regexp.MustCompile(
				`(?i)(?:\byour\s+(?:(?:previous|prior|earlier|original|initial)\s+)?(?:instructions|rules|guidance|guidelines|constraints|restrictions|directives|programming|configuration)|\bthe\s+(?:(?:previous|prior|earlier|original|initial)\s+)?(?:instructions|rules|guidance|guidelines|constraints|restrictions|directives|configuration)\s+(?:that\s+|which\s+)?you\s+(?:were\s+given|received|got|have\s+been\s+given|were\s+configured\s+with|started\s+with))(?:\s+(?:earlier|before|previously))?\s+(?:no\s+longer\s+appl(?:y|ies)|(?:have|has)\s+been\s+(?:revoked|lifted|removed|suspended|cancell?ed|disabled|replaced)|(?:are|is)\s+(?:now\s+)?(?:void|revoked|suspended|lifted|cancell?ed|disabled))\b`),
			Confidence:    ConfidenceModerate,
			PrefilterFold: []string{"longer", "revoked", "lifted", "removed", "suspended", "cancel", "disabled", "replaced", "void"},
			Priority:      40,
		},
		{
			ID: "injection-safety-disabled",
			// Announcing that the model's safeguards are off — usually
			// dressed as a system notice. Limited to safeguards a model has;
			// "safety training is suspended" is about a workplace.
			Class: ClassInstructionOverride,
			Pattern: regexp.MustCompile(
				`(?i)\b(?:safety|content|ethical|moral)\s+(?:filters?|guardrails|guidelines|restrictions)\s+(?:(?:are|is|have\s+been|has\s+been|now|been)\s+)*(?:disabled|removed|lifted|switched\s+off|turned\s+off|deactivated|bypassed)\b`),
			Confidence:    ConfidenceModerate,
			PrefilterFold: []string{"filter", "guardrails", "guidelines", "restrictions"},
			Priority:      40,
		},
		{
			ID: "injection-task-hijack",
			// Replacing the task rather than the rules: the praise-then-pivot
			// ("well done, now further tasks follow") and the instruction
			// buried in a question ("do not answer this, just output X").
			// English and German, because that is what the public data
			// carries and what the classifier misses.
			Class: ClassInstructionOverride,
			Pattern: regexp.MustCompile(
				`(?i)(?:\bdo\s+not\s+(?:answer|look\s+at|look\s+in|read|use|follow)\b[^.!?\n]{0,60}?\b(?:just|only|instead)\s+(?:output|say|print|write|reply\s+with|respond\s+with)\b|\b(?:now|nun|jetzt)\b[^.!?\n]{0,25}?\b(?:new|further|additional|weitere|neue)\s+(?:tasks?|aufgaben|instructions|anweisungen)\s+(?:follow|are\s+followed|folgen)\b|\bstart\s+(?:over|again|afresh|from\s+(?:the\s+)?(?:front|scratch|beginning))\b[^.!?\n]{0,30}?\bnew\s+task\b|\bleave\s+all\s+(?:the\s+)?previous\s+(?:information|instructions)\s+behind\b|\blassen\s+sie\s+alle\s+vorherigen\s+informationen\s+hinter\s+sich\b)`),
			Confidence:    ConfidenceModerate,
			PrefilterFold: []string{"not", "follow", "folgen", "task", "behind", "hinter"},
			Priority:      40,
		},
		{
			ID: "injection-prompt-extraction-hidden",
			// Asking for the configuration without naming it "system
			// prompt": the hidden setup, the secret rules. Limited to
			// adjectives that only make sense about something withheld,
			// because "show me your full setup" is a question about a
			// home lab.
			Class: ClassPromptExtraction,
			Pattern: regexp.MustCompile(
				`(?i)\b(?:paste|repeat|print|show|reveal|output|share|display|tell\s+me|give\s+me|spell\s+out|translate|summari[sz]e|list|encode|recite|dump|leak)\b[^.!?\n]{0,40}?(?:\byour\s+(?:hidden|secret|confidential)\s+(?:setup|instructions|rules|guidelines|prompt|configuration|directives)\b|\b(?:hidden|secret|confidential)\s+(?:setup|system)\s+(?:text|prompt|instructions|message)\b|\beverything\s+(?:that\s+)?(?:appears|comes|came|was\s+written)\s+before\s+my\s+first\s+message\b)`),
			Confidence:    ConfidenceModerate,
			PrefilterFold: []string{"hidden", "secret", "confidential", "everything"},
			Priority:      40,
		},
		{
			ID: "injection-unrestricted-persona",
			// The persona is defined by what it lacks. The subject must be
			// the model — "an assistant that answers anything" — so that
			// "you are free from travel restrictions" is left alone.
			Class: ClassPersonaOverride,
			Pattern: regexp.MustCompile(
				`(?i)(?:\b(?:dan|god|jailbreak|jailbroken|unrestricted|unfiltered|uncensored|evil)\s+mode\b|\ban?\s+(?:ai|assistant|model|chatbot|bot|version\s+of\s+yourself)\b[^.!?\n]{0,40}?(?:\b(?:that|who|which)\s+(?:answers|does|says|will\s+answer|will\s+do|can\s+do|responds\s+to)\s+anything\b|\bnever\s+refuses?\b|\b(?:has|have|with)\s+no\s+(?:filters|restrictions|guidelines|censorship|rules|content\s+policy)\b|\bfreed?\s+from\b[^.!?\n]{0,30}?\b(?:restrictions|rules|guidelines|filters|polic(?:y|ies))\b|\b(?:filters|restrictions|guidelines)\s+(?:have\s+been\s+|are\s+)?(?:switched|turned)\s+off\b))`),
			Confidence:    ConfidenceModerate,
			PrefilterFold: []string{"mode", "anything", "refuse", "filters", "restrictions", "guidelines", "censorship", "rules", "polic", "free", "switched", "turned"},
			Priority:      40,
		},
		{
			ID: "injection-instruction-override-translated",
			// "Ignore the previous instructions" in the languages the
			// classifier was never trained on. It is English-only, so
			// without this every one of these reached a receipt as clean.
			// Go's \b is ASCII-only, so words are bounded by a non-letter
			// instead.
			Class: ClassInstructionOverride,
			Pattern: regexp.MustCompile(
				`(?i)(?:^|[^\p{L}])(?:(?:ignorier\p{L}*|vergiss|vergessen\s+sie|missachte\p{L}*)\s+(?:\p{L}+\s+){0,3}?(?:vorherigen?|bisherigen?|obigen?|vorigen?|früheren?)\s+(?:anweisungen|instruktionen|regeln|anordnungen|informationen|befehle)|vergiss\s+alles\s*,?\s*(?:davor|vorher|zuvor|bisher|was\s+(?:wir|du)\b)|(?:ignore[rz]?|oublie[rz]?)\s+(?:\p{L}+\s+){0,3}?(?:instructions|consignes|règles|directives)\s+(?:précédentes|antérieures|ci-dessus)|(?:ignora|ignore|olvida|olvide)\p{L}*\s+(?:\p{L}+\s+){0,3}?(?:instrucciones|reglas|indicaciones|directrices)\s+(?:anteriores|previas)|(?:ignor[ae]\p{L}*|esque[çc]a)\s+(?:\p{L}+\s+){0,3}?(?:instruções|instrucoes|regras|diretrizes)\s+(?:anteriores|prévias|previas)|(?:ignora|dimentica)\p{L}*\s+(?:\p{L}+\s+){0,3}?(?:istruzioni|regole)\s+precedenti|(?:игнорируй|игнорируйте|забудь|забудьте)\s+(?:\p{L}+\s+){0,3}?(?:предыдущие|прошлые|прежние)\s+(?:инструкции|указания|правила)|(?:忽略|无视|忘记|忘掉)(?:之前|以上|前面|先前|上面|此前)的?(?:所有|全部|一切)?的?(?:指令|指示|说明|规则|提示))`),
			Confidence:    ConfidenceModerate,
			PrefilterFold: []string{"anweisungen", "instruktionen", "regeln", "anordnungen", "informationen", "befehle", "vergiss", "instructions", "consignes", "règles", "directives", "instrucciones", "reglas", "indicaciones", "directrices", "instruções", "instrucoes", "regras", "diretrizes", "istruzioni", "regole", "инструкции", "указания", "правила", "忽略", "无视", "忘记", "忘掉"},
			Priority:      40,
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
			ID: "phone-nanp",
			// A North American number written the way people write one.
			//
			// The rule above requires a leading "+", and its reasoning —
			// that bare runs of ten digits produce false positives against
			// ordinary numeric text — is correct and still stands. But it
			// was applied as a rule about national formats when it is
			// really a rule about UNSEPARATED digits. "512-555-0148" and
			// "(512) 555-0148" are not ten loose digits; they are a
			// punctuation pattern almost nothing else wears, and they are
			// the two forms every US clinical, billing and CRM system
			// emits.
			//
			// Found on 22 September 2026 by a healthcare evaluator who fed
			// the detector a realistic patient line and watched the phone
			// number reach the model while the receipt read mode "full".
			// Exactly the shape of the IBAN defect: matched unspaced, and
			// missed in the spaced form printed on every invoice. The rule
			// was right about the value and wrong about how it is written.
			//
			// A separator or bracketed area code is required throughout, so
			// "5125550148" still does not match here. That was a real
			// judgement, not an oversight, and it is left alone.
			//
			// Priority 54 puts it below phone-international deliberately:
			// "+1 512 555 0148" matches both, the spans overlap, and the
			// international rule must claim it so one number is one
			// finding.
			//
			// No Prefilter: its separators are "-", ".", " " and "(", and a
			// set containing a space filters nothing. An always-scanning
			// RE2 pattern is the honest cost of covering this class.
			Class: ClassPhone,
			Pattern: regexp.MustCompile(
				`(?:^|[^\d+])(?P<target>(?:1[ .\-])?(?:\([2-9]\d{2}\)[ ]?|[2-9]\d{2}[ .\-])[2-9]\d{2}[ .\-]\d{4})`),
			Confidence: ConfidenceHigh,
			Validate:   validNANPPhone,
			Priority:   54,
		},
		{
			ID: "india-mobile-labelled",
			// An Indian mobile number, only where the text says it is one.
			//
			// phone-international is right that a bare run of ten digits is
			// too common to claim, and phone-nanp is right that the fix is a
			// written form nothing else wears. Neither covers India, where
			// the written form is ten bare digits with no separators at all:
			// "9951310751" is how a mobile appears on a registration
			// certificate, a KYC form and an invoice, and "+91" is the
			// exception rather than the rule.
			//
			// So the distinguishing mark cannot be punctuation, and it is
			// taken from us-routing-number instead: the label in front of
			// it. Every form that prints one of these prints "Mobile No"
			// beside it. The label is required context and stays out of the
			// span, so substitution leaves the field heading readable.
			//
			// The first digit must be 6-9, which is the whole of India's
			// mobile range and excludes a ten-digit order number starting
			// with 0-5. There is no check digit to lean on.
			//
			// The run between the label and the number allows "*", "#", "."
			// and ":" as well as spaces, because the form that prompted this
			// prints "Mobile No*:" — the asterisk is the required-field
			// marker every Indian government form puts there, and a
			// separator class of whitespace alone missed the real document
			// while matching the one written out in a test. It is bounded so
			// a label cannot claim a number further down the page.
			//
			// Found on 1 October 2026: a practitioner's registration PDF
			// reached a model with the mobile number intact while the
			// receipt read mode "full", because every other identifier on
			// the page was covered and this one was not. The same shape as
			// the IBAN and NANP defects before it — the value was known,
			// the form it is actually written in was not.
			//
			// What this deliberately does not do is match an unlabelled run
			// of ten digits. That judgement belongs to phone-international
			// and it is not reopened here; an unlabelled number is still
			// the model tier's to find.
			Class: ClassPhone,
			Pattern: regexp.MustCompile(
				`(?i)\b(?:mobile|mob|telephone|phone|tel|contact|cell|whatsapp)\b[\s*.:#\-]{0,40}` +
					`(?:no|number|num)?[\s*.:#\-]{0,40}(?P<target>[6-9]\d{9})(?:[^\d]|$)`),
			Confidence: ConfidenceHigh,
			// Folded, because the pattern is (?i): a case-sensitive list is
			// how such a rule quietly stops matching. Each literal is one
			// the pattern cannot match without — the longer alternatives
			// contain the shorter ones ("mobile" carries "mob").
			PrefilterFold: []string{"mob", "tel", "phone", "contact", "cell", "whatsapp"},
			Priority:      53,
		},
		{
			ID: "india-pin-labelled",
			// An Indian postal code, only where the text says it is one.
			//
			// Six digits are everywhere. Beside "Postal code", "PIN code" or
			// "Pincode" they are an address, and an address was the one
			// thing still readable in a registration certificate after the
			// rest of it had been boxed. The label is context and stays out
			// of the span. The first digit is 1-9: Indian PINs do not start
			// with zero, and that alone excludes a run of six that is a
			// time, a count or the tail of something longer.
			Class: ClassINPIN,
			Pattern: regexp.MustCompile(
				`(?i)\b(?:pin\s*code|pincode|postal\s*code|post\s*code|zip)\b[\s*.:#\-]{0,40}(?P<target>[1-9]\d{5})(?:[^\d]|$)`),
			Confidence:    ConfidenceHigh,
			PrefilterFold: []string{"pin", "postal", "post", "zip"},
			Priority:      52,
		},
		{
			ID: "us-routing-number",
			// An ABA routing number, only where the text says it is one.
			//
			// Nine digits with the ABA 3-7-1 checksum is not enough on its
			// own: one nine-digit run in ten passes it, and nine digits are
			// also an SSN written without separators, a ZIP+4, an order
			// number. The word in front of it — routing, ABA, RTN, transit —
			// is what wire instructions always carry, so the rule requires
			// it and the checksum both. The word is context and stays out of
			// the span, so substitution leaves it readable.
			//
			// The first two digits must be a Federal Reserve district or
			// thrift range (00-12, 21-32), a government range (61-72) or
			// 80 for traveller's cheques; the checksum does the rest.
			//
			// cueGap is what lets "routing number is 021000021" through.
			// The checksum carries most of the weight here, so stepping
			// over a connective costs little and the sentence form is how
			// the number usually arrives.
			Class: ClassUSRouting,
			Pattern: regexp.MustCompile(`(?i)\b(?:routing|aba|rtn|transit)(?:\s*/\s*aba)?` +
				cueGap + `\s*(?P<target>\d{9})\b`),
			Confidence: ConfidenceExact,
			Validate:   validABARouting,
			Priority:   75,
		},
		{
			ID: "bank-account-number",
			// A bank account number, only where the text names it as one.
			//
			// There is no checksum and no shared format — six to seventeen
			// digits covers US and Indian banks — so a bare run of digits is
			// never matched. "Account", "acct" or "a/c" in front of it is
			// what makes it one, and is what every set of wire instructions
			// and every Indian passbook line carries.
			//
			// It used to require the number almost immediately after the
			// cue, which read the forms and missed the sentence: "my
			// account is 50100123456789" went through untouched, and that
			// is how a supplier chasing a payment writes it. cueGap steps
			// over the connectives and nothing else, so a balance and an
			// account holder are still not account numbers.
			//
			// Family pii rather than pci: under GLBA an account number is
			// nonpublic personal information, and the default policy
			// tokenises pii at this confidence. Priority 50, below the card
			// rule, so a Luhn-valid card number written after "account" is
			// still reported as the card it is.
			Class: ClassBankAccount,
			Pattern: regexp.MustCompile(`(?i)\b(?:account|acct|acc|a/c)` +
				cueGap + `\s*(?P<target>\d{6,17})\b`),
			Confidence: ConfidenceHigh,
			Priority:   50,
		},
		{
			ID: "phone-india",
			// An Indian mobile written the way Indians write one: five
			// digits, a space or hyphen, five digits, beginning 6 to 9,
			// sometimes with a trunk 0 in front. "98840 12345" went through
			// untouched while "+91 98840 12345" was caught by the rule
			// above, and the first is how the number appears in almost every
			// form, invoice and chat message in India.
			//
			// The same judgement as phone-nanp: a separator is required, so
			// "9884012345" as ten bare digits is still not matched here — it
			// is also an order number, and belongs to the model tier. And the
			// same priority, below phone-international, so "+91 98840 12345"
			// stays one finding.
			Class:      ClassPhone,
			Pattern:    regexp.MustCompile(`(?:^|[^\d+])(?P<target>0?[6-9]\d{4}[ -]\d{5})(?P<reject>[ -]?\d+)?\b`),
			Confidence: ConfidenceHigh,
			Priority:   54,
		},
		{
			ID: "india-upi",
			// A UPI ID: name@handle, where the handle is one of the payment
			// apps' own. It is the address money is sent to in India, and it
			// was missed entirely — it has no dot after the "@", so the
			// email rule never saw it.
			//
			// Only known handles, deliberately. "anything@anything" is a
			// social handle, a git remote, a mention. The list is the handles
			// the large PSP apps issue; a UPI ID on a smaller bank's handle
			// is missed, which is the trade against flagging every "@word"
			// in a chat. Priority 55, below email, so "x@ybl.com" — an email
			// address at a domain that happens to share a handle's name —
			// stays an email.
			Class: ClassINUPI,
			Pattern: regexp.MustCompile(`(?i)(?:^|[^\w.@-])(?P<target>[a-z0-9][a-z0-9._-]{1,63}@` +
				`(?:okhdfcbank|okicici|oksbi|okaxis|ybl|ibl|axl|paytm|ptyes|ptaxis|pthdfc|ptsbi|apl|yapl|` +
				`upi|axisbank|axisb|icici|hdfcbank|sbi|kotak|pnb|boi|barodampay|idfcbank|indus|rbl|yesbank|` +
				`airtel|jio|fbl|ikwik|freecharge|waaxis|wahdfcbank|wasbi|abfspay|jupiteraxis|naviaxis|` +
				`superyes|timecosmos|slc|tapicici|pingpay))(?:$|[^\w.@-]|\.(?:$|\s))`),
			Confidence: ConfidenceHigh,
			Prefilter:  []string{"@"},
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

		// Business email compromise. Not injection, and the difference is
		// the whole point: an injection attacks the model's instruction
		// following, while this attacks the business process. There is
		// nothing hidden, nothing encoded, and nothing a prompt filter can
		// see — it is an ordinary, well-written message asking for a
		// harmful thing, and an agent processing invoices will comply
		// because complying is its job.
		//
		// These classes exist to feed a gate, not a filter. The control is
		// that anything moving money waits for a person, so a perfect
		// attack still fails because the agent was never able to act on it.
		// That makes the cost of a false positive ten seconds of somebody's
		// attention and the cost of a false negative a wire transfer, which
		// is why these are deliberately generous and why nothing here
		// should ever be wired to block.
		{
			ID: "bec-bank-detail-change",
			// The announcement, in both word orders. A change verb is
			// required next to the payment noun: "please find our bank
			// details below" is ordinary business correspondence, and only
			// the claim that they have *changed* is the fraud signal.
			Class: ClassBECBankChange,
			Pattern: regexp.MustCompile(
				`(?i)\b(?:(?:new|updated|changed|amended|revised|different)\s+(?:our\s+|the\s+|my\s+|their\s+)?` +
					`(?:bank(?:ing)?|account|wire|payment|remittance|beneficiary|payee)\s+` +
					`(?:details|instructions|information|number|account)` +
					`|(?:bank(?:ing)?|account|wire|payment|remittance|beneficiary|payee)\s+` +
					`(?:details|instructions|information|number)\s+` +
					`(?:have|has|had)?\s*(?:now\s+)?(?:been\s+)?(?:changed|updated|amended|revised))\b`),
			Confidence: ConfidenceHigh,
			// Every alternation in the pattern contains one of these
			// nouns, so the prefilter is a safe superset. A narrower list
			// reads better and silently suppresses matches: "updated bank
			// account" was missed by a prefilter of "updated account",
			// which is the failure a prefilter is most likely to cause and
			// the hardest to notice, because nothing errors.
			PrefilterFold: []string{
				"bank", "account", "wire", "payment", "remittance", "beneficiary", "payee",
			},
			Priority: 45,
		},
		{
			ID: "bec-payee-redirect",
			// The instruction that follows the announcement: stop using
			// the account you have, use this one. "No longer" and "instead
			// of" next to a payment noun is the shape, and it is the half
			// that survives when the sender never says the word "changed".
			Class: ClassBECPayeeRedirect,
			Pattern: regexp.MustCompile(
				`(?i)\b(?:(?:do\s+not|don't|no\s+longer|cease\s+to)\s+(?:use|send|remit|wire|pay|transfer)` +
					`[^.!?\n]{0,50}?\b(?:account|bank|iban|routing|sort\s*code|wire|details)` +
					`|(?:use|to|into)\s+(?:the\s+)?(?:new|updated|following|below|revised)\s+` +
					`(?:bank\s+)?(?:account|details|iban|wire\s+instructions))\b`),
			Confidence: ConfidenceModerate,
			// Same rule as above: the payment noun is present in both
			// alternations, the adjectives are not.
			PrefilterFold: []string{
				"account", "bank", "iban", "routing", "sort code", "wire", "details",
			},
			Priority: 45,
		},
	}
}

// validUSSSN rejects structurally impossible Social Security numbers.
//
// The SSA never issues area 000, 666, or 900-999, nor group 00, nor serial
// 0000. Excluding them removes a large share of false positives from
// ordinary formatted numbers without needing any context.
func validUSSSN(s string) bool {
	if len(s) != 11 {
		return false
	}
	// One separator, used consistently. RE2 has no backreference, so the
	// pattern cannot require the two to match and this has to. "078-05
	// 1120" is not a Social Security number anybody writes; it is two
	// unrelated numbers that happen to be adjacent.
	switch s[3] {
	case '-', ' ', '.':
	default:
		return false
	}
	if s[6] != s[3] {
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

// validUKNINO applies the allocation rules HMRC publishes for National
// Insurance numbers.
//
// The first letter is never D, F, I, Q, U or V; the second is never D, F,
// I, O, Q, U or V; and the prefixes BG, GB, KN, NK, NT, TN and ZZ have
// never been allocated. The suffix, when the number carries one, is A to D.
// The pattern already insists on the suffix, so this checks the prefix.
// validINPAN checks the holder-type letter: P individual, C company, H HUF,
// A association, B body of individuals, G government, J artificial juridical
// person, L local authority, F firm, T trust. Nothing else is issued.
func validINPAN(s string) bool {
	if len(s) != 10 {
		return false
	}
	return strings.IndexByte("PCHABGJLFT", strings.ToUpper(s)[3]) >= 0
}

func validUKNINO(s string) bool {
	if len(s) < 2 {
		return false
	}
	first, second := s[0], s[1]
	if strings.IndexByte("DFIQUV", first) >= 0 || strings.IndexByte("DFIOQUV", second) >= 0 {
		return false
	}
	switch s[:2] {
	case "BG", "GB", "KN", "NK", "NT", "TN", "ZZ":
		return false
	}
	return true
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

// validCard reports whether s is a payment card number: Luhn, and a length
// the network that owns its leading digits actually issues.
//
// Luhn alone passes one run of digits in ten, so every sixteen-digit order
// number, tracking reference and account id had a one-in-ten chance of
// being reported as a card; the detection benchmark measured it. Real card
// numbers start with a network's identifier, and most digit runs do not.
// Private-label and fleet cards outside these ranges are missed, which is
// the trade: they are rare in the traffic this sees, and a false card
// finding is substituted on its way out.
func validCard(s string) bool {
	if !validLuhn(s) {
		return false
	}
	d := strings.NewReplacer(" ", "", "-", "").Replace(s)
	n := len(d)
	prefix := func(p string) bool { return strings.HasPrefix(d, p) }
	between := func(width int, lo, hi int) bool {
		if len(d) < width {
			return false
		}
		v := 0
		for _, c := range d[:width] {
			v = v*10 + int(c-'0')
		}
		return v >= lo && v <= hi
	}
	switch {
	case prefix("4"): // Visa
		return n == 13 || n == 16 || n == 19
	case between(2, 51, 55), between(4, 2221, 2720): // Mastercard
		return n == 16
	case prefix("34"), prefix("37"): // American Express
		return n == 15
	case prefix("6011"), between(3, 644, 649), prefix("65"), prefix("62"): // Discover, UnionPay
		return n >= 16 && n <= 19
	case between(4, 3528, 3589): // JCB
		return n >= 16 && n <= 19
	case prefix("36"), prefix("38"), prefix("39"), between(3, 300, 305), prefix("3095"): // Diners Club
		return n >= 14 && n <= 19
	case between(4, 2200, 2204): // Mir
		return n >= 16 && n <= 19
	case prefix("5018"), prefix("5020"), prefix("5038"), between(2, 56, 69): // Maestro and other debit ranges
		// Not every number beginning "50". That was the rule until
		// 22 September 2026, and HDFC Bank's savings accounts are fourteen
		// digits beginning 50100 — one in ten passes Luhn, and each of those
		// was reported as a payment card. A receipt saying a card crossed
		// the wire when an account number did is a false claim, and a card
		// finding is substituted on its way out. The real card ranges in
		// the fifties are Maestro's 5018, 5020 and 5038, and RuPay's 508.
		return n >= 12 && n <= 19
	case prefix("508"), prefix("81"), prefix("82"): // RuPay
		// India's domestic network. 81 and 82 were missed entirely before:
		// they matched no case and fell through to "no network".
		return n == 16
	case prefix("1"): // UATP
		return n == 15
	case prefix("9999"):
		// The reserved range card tokens are drawn from. No issuer uses it,
		// and a substitute has to be found by the rule its original was:
		// the streaming paths count findings by re-scanning what they
		// released, which is already substituted.
		return n >= 13 && n <= 19
	}
	return false
}

// validABARouting reports whether s is a structurally valid ABA routing
// number: nine digits, a prefix the Federal Reserve assigns, and the 3-7-1
// checksum.
func validABARouting(s string) bool {
	if len(s) != 9 {
		return false
	}
	d := make([]int, 9)
	for i := 0; i < 9; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		d[i] = int(s[i] - '0')
	}
	prefix := d[0]*10 + d[1]
	switch {
	case prefix <= 12, prefix >= 21 && prefix <= 32, prefix >= 61 && prefix <= 72, prefix == 80:
	default:
		return false
	}
	sum := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2] + d[5] + d[8])
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
// VerhoeffCheckDigit is the digit that makes body plus the digit pass the
// Verhoeff check — exported for the tokeniser, so a substitute Aadhaar
// number validates on a form the way the real one did. ok is false when
// body is not all digits.
func VerhoeffCheckDigit(body string) (digit int, ok bool) {
	c := 0
	n := len(body)
	for i := n - 1; i >= 0; i-- {
		if body[i] < '0' || body[i] > '9' {
			return 0, false
		}
		// The check digit will sit at position 0; the body's positions
		// start at 1.
		pos := (n - i) % 8
		c = verhoeffD[c][verhoeffP[pos][int(body[i]-'0')]]
	}
	return verhoeffInverse[c], true
}

// verhoeffInverse is the multiplicative inverse in the dihedral group D5.
var verhoeffInverse = [10]int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}

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
// validNANPPhone rejects the North American codes that cannot begin a real
// subscriber number.
//
// N11 — 211, 311, 411, 611, 911 — is reserved for services and is never an
// area code or an exchange. Without this check a date range, a version
// triple or a document reference written with the right punctuation reads
// as somebody's phone number, and a false finding on a receipt is as
// damaging as a missed one: it is a claim that something was in the traffic
// that was not.
func validNANPPhone(s string) bool {
	digits := make([]byte, 0, 11)
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			digits = append(digits, s[i])
		}
	}
	// The pattern allows an optional leading country code of 1.
	if len(digits) == 11 && digits[0] == '1' {
		digits = digits[1:]
	}
	if len(digits) != 10 {
		return false
	}
	for _, code := range [][]byte{digits[0:3], digits[3:6]} {
		if code[1] == '1' && code[2] == '1' {
			return false
		}
	}
	return true
}

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
