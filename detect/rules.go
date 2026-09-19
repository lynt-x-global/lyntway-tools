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
const RulesetVersion = "core-2026.09.19"

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
	ClassUKNINO     Class = "pii.uk_nino"

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
			Pattern: regexp.MustCompile(
				`\b([A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?:[ -][A-Z0-9]{4})*(?:[ -][A-Z0-9]{1,4})?))\b`),
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
			Pattern:    regexp.MustCompile(`(?:^|[^\w+\-])(?P<target>[2-9]\d{3}\s?\d{4}\s?\d{4})(?P<reject>[ -]\d+)?\b`),
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

// validUKNINO applies the allocation rules HMRC publishes for National
// Insurance numbers.
//
// The first letter is never D, F, I, Q, U or V; the second is never D, F,
// I, O, Q, U or V; and the prefixes BG, GB, KN, NK, NT, TN and ZZ have
// never been allocated. The suffix, when the number carries one, is A to D.
// The pattern already insists on the suffix, so this checks the prefix.
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
	case prefix("50"), between(2, 56, 69): // Maestro and other debit ranges
		return n >= 12 && n <= 19
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
