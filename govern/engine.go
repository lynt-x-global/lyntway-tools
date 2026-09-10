package govern

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
	"github.com/lynt-x-global/lyntway-tools/tokenize"
)

// EngineName identifies the detection stack in receipts.
const EngineName = "lyntway-core"

// EngineVersion is the build of the governance engine.
//
// Recorded in every receipt. Bump it whenever the behaviour of Govern
// changes in a way that could alter a decision, or receipts will claim
// reproducibility they cannot deliver.
const EngineVersion = "0.1.0"

// Component is one detection subsystem the engine is configured to use.
//
// Declaring components explicitly is what makes the receipt's mode field
// meaningful. A deployment running only the deterministic tier reports full
// strength *for that configuration*, and the receipt lists exactly which
// components ran — so a reader can see there was no ML tier rather than
// having to trust the word "full".
type Component struct {
	// Name identifies the subsystem in receipts.
	Name string

	// Health reports the subsystem's current state. Called once per
	// governed action, so it must be cheap and must not block: a health
	// probe that hangs converts a governance layer into an outage.
	Health func() receipt.Health
}

// Engine governs content and issues receipts.
//
// Safe for concurrent use.
type Engine struct {
	ruleset    *detect.Ruleset
	policy     *Policy
	signer     receipt.Signer
	components []Component
	analyzers  []Analyzer
	issuer     string
	chainStore ChainStore

	mu     sync.Mutex
	chains map[string]*receipt.ChainBuilder
	// chainKeys records which key each chain is signed by, so a chain
	// cannot change hands.
	chainKeys map[string]string
}

// Config configures an Engine.
type Config struct {
	// Ruleset is the detection ruleset. Defaults to detect.Default().
	Ruleset *detect.Ruleset

	// Policy decides what to do with findings. Defaults to DefaultPolicy().
	Policy *Policy

	// Signer signs receipts. Required.
	Signer receipt.Signer

	// Analyzers are probabilistic detectors that run alongside the rules.
	//
	// Each is registered as a health component automatically, so an
	// analyzer that is down makes the receipt's mode degraded without
	// anybody having to remember to wire that up separately. Forgetting
	// would produce receipts claiming a full scan that never happened.
	Analyzers []Analyzer

	// Components are the detection subsystems this deployment is
	// configured to run. Defaults to the deterministic tier alone.
	Components []Component

	// Issuer names the party issuing receipts. Defaults to the hosted
	// service's name. A local tool signing with a key lyntway.com never
	// published must set this to say so — a receipt naming an issuer whose
	// key directory does not hold the signing key sends a verifier to the
	// wrong place and reads as forged.
	Issuer string

	// ChainStore persists each chain's position across restarts. Optional,
	// but without it every restart forks every chain at seq 0, and a
	// verifier walking the chain sees a discontinuity indistinguishable
	// from deletion — the accusation the chain exists to refute.
	ChainStore ChainStore
}

// ChainStore remembers where each chain is between processes.
type ChainStore interface {
	// LoadChain returns the next sequence number and current head for a
	// chain, or found=false if the chain has never been seen.
	LoadChain(chainID string) (nextSeq uint64, head string, found bool, err error)
	// SaveChain records the position after a receipt is issued.
	SaveChain(chainID string, nextSeq uint64, head string) error
}

// ChainPersistError reports that a receipt was issued but its chain
// position could not be saved.
//
// The receipt is valid and has been returned; what is at risk is the next
// restart, which will not know this receipt exists. Callers should surface
// the warning rather than discard a signed receipt over it.
type ChainPersistError struct {
	ChainID string
	Err     error
}

func (e *ChainPersistError) Error() string {
	return fmt.Sprintf("govern: receipt issued but chain %q position not saved: %v", e.ChainID, e.Err)
}

func (e *ChainPersistError) Unwrap() error { return e.Err }

// New creates an Engine.
func New(cfg Config) (*Engine, error) {
	if cfg.Signer == nil {
		return nil, errors.New("govern: a signer is required")
	}
	if cfg.Ruleset == nil {
		cfg.Ruleset = detect.Default()
	}
	if cfg.Policy == nil {
		cfg.Policy = DefaultPolicy()
	}
	if err := cfg.Policy.Validate(); err != nil {
		return nil, err
	}
	if len(cfg.Components) == 0 {
		cfg.Components = []Component{{
			Name:   "deterministic",
			Health: func() receipt.Health { return receipt.HealthHealthy },
		}}
	}
	for i, c := range cfg.Components {
		if c.Name == "" {
			return nil, fmt.Errorf("govern: component %d has no name", i)
		}
		if c.Health == nil {
			return nil, fmt.Errorf("govern: component %q has no health probe", c.Name)
		}
	}

	issuer := cfg.Issuer
	if issuer == "" {
		issuer = issuerName
	}

	return &Engine{
		ruleset:    cfg.Ruleset,
		policy:     cfg.Policy,
		analyzers:  cfg.Analyzers,
		signer:     cfg.Signer,
		components: withAnalyzerHealth(cfg.Components, cfg.Analyzers),
		issuer:     issuer,
		chainStore: cfg.ChainStore,
		chains:     make(map[string]*receipt.ChainBuilder),
		chainKeys:  make(map[string]string),
	}, nil
}

// Request is one action to govern.
type Request struct {
	// ChainID scopes the receipt chain. One chain per workspace, session,
	// or agent — whatever boundary completeness must be provable over.
	ChainID string

	// ReceiptID uniquely identifies the receipt. Supplied by the caller so
	// it can correlate with its own records.
	ReceiptID string

	// Content is the payload to govern. Not retained: only its digest
	// reaches the receipt.
	Content []byte

	// Action describes the operation. Chain position and content digests
	// are filled in by Govern.
	Action receipt.Action

	// Actor describes who performed it.
	Actor receipt.Actor

	// Signer overrides the engine's key for this request.
	//
	// Used to sign each customer's receipts with that customer's own key.
	// A single key across all customers means none of them can show a
	// receipt is theirs rather than someone else's, and one compromise
	// forges receipts for everybody.
	//
	// Optional; the engine's own key signs when this is nil.
	Signer receipt.Signer

	// KeyAttestation is the deployment's signed statement that Signer may
	// issue for this chain. It travels inside the receipt so a verifier
	// needs only the deployment's published key.
	//
	// Required whenever Signer is set: a per-customer key that nothing
	// vouches for is a key a verifier has no reason to trust, and issuing
	// receipts under one would produce evidence nobody can check.
	KeyAttestation *receipt.KeyAttestation

	// Evidence records how this action became known — whether the caller
	// handled the bytes, was told about them, or is describing its own
	// behaviour. Absent means asserted, which is the weakest reading and
	// the right default for a library call.
	Evidence *receipt.Evidence

	// Ruleset overrides the engine's own for this request.
	//
	// Used where a customer has added rules of their own: the same engine
	// serves everybody, and a tenant's ruleset is theirs alone. Nil means
	// the engine's, which is the common case.
	//
	// The receipt records whichever ruleset actually ran, by version and
	// digest, so a decision stays reproducible by whoever holds the
	// receipt — including after the customer edits their rules, which is
	// the moment it would otherwise stop being.
	Ruleset *detect.Ruleset

	// Policy overrides the engine's own for this request.
	//
	// Paired with Ruleset: a tenant's rules are only half of what they
	// configured — the other half is what should happen when one matches.
	// Supplying rules without the policy that acts on them produces
	// findings that appear in a receipt and change nothing, which looks
	// exactly like working software.
	Policy *Policy

	// Subject states what the content digests actually cover.
	//
	// Empty means the payload, which is what every governing path produces
	// and what the schema assumes. A caller building a receipt from a
	// report rather than from data sets telemetry, because the digest
	// covers the report — and the schema then refuses the combinations
	// that would overstate it, such as claiming a transform nothing
	// performed.
	Subject receipt.ContentSubject

	// SelfDescribed marks Content as a record this service composed from a
	// caller's fields, rather than bytes a caller sent. It is digested,
	// because the digest is what proves the report was not altered, but it
	// is not scanned: a destination of 127.0.0.1 in our own bookkeeping
	// would otherwise be reported as an address found in the traffic, and
	// the receipt would carry findings about text nobody sent anywhere.
	// The tool's own findings travel in Evidence.Reported.
	SelfDescribed bool

	// Irrevocable means the content has already left: a streamed response
	// whose bytes the caller holds. A block or hold decided now cannot be
	// enforced, so it is recorded as log_only rather than claimed.
	Irrevocable bool

	// Truncated means Content is the prefix of a stream that was cut;
	// the remainder was withheld. Recorded on the receipt so a cut stream
	// never reads as a complete one.
	Truncated bool

	// Components are detection capabilities the caller knows about this
	// request and the engine cannot probe: a database gateway that could
	// read the text parameters of a Bind but not the binary ones, a shim
	// that saw half a payload. Anything listed impaired makes the receipt
	// degraded. The engine's own components are always included; these are
	// added beside them, so the receipt lists every capability that bore on
	// this decision and how each fared.
	Components []receipt.Component

	// Refusal, when set, blocks the action for a reason that is not a
	// finding — the caller refused it on its own account and forwarded
	// nothing. Recorded on the receipt so the block is explained.
	Refusal string

	// Approval resolves a hold. The caller governed this content once,
	// was told require_approval, parked it, and a person has now decided;
	// this is the same content governed again with that decision in hand.
	//
	// Approved: the decision stays require_approval — that is what policy
	// said, and the receipt must not read as though policy allowed it —
	// but the content is released, with every other class in the payload
	// still substituted as policy asks. Denied or expired: the caller sets
	// Refusal too, and the action is blocked with the refusal and this
	// record both on the receipt. Nil for every ordinary call.
	Approval *receipt.Approval

	// PriorFindings were established over bytes this request does not
	// carry — an in-flight governor that watched a whole stream, of which
	// Content is only the delivered part. Merged into the receipt so the
	// class that caused a cut is on the record even though it was never
	// delivered.
	PriorFindings []receipt.Finding

	// Inspect runs detection and enforcement without transforming content.
	//
	// For the direction where content is returning to the party that owns
	// it. Tokenising there would hand an application substitutes for its
	// own values and break it, so the useful questions inbound are what was
	// present and whether releasing it is permitted at all — not how to
	// disguise it from its owner.
	//
	// Blocking still applies: a policy that refuses to release something
	// refuses in both directions. Everything short of blocking becomes
	// log_only, which is precisely what "findings recorded, content
	// unaltered" means, so the receipt keeps describing what actually
	// happened.
	Inspect bool

	// Scope provides reversible tokenisation. Required when the policy may
	// tokenise; without it, a tokenise decision has nowhere to record the
	// mapping and the transformation would be silently irreversible.
	Scope *tokenize.Scope

	// KeyID scopes per-key rules. When set, only rules whose KeyIDs list
	// includes this value — or rules with no KeyIDs at all — apply. Empty
	// means no key restriction: every rule matches as before.
	KeyID string

	// Hold requires a person for a reason that is not a finding, exactly
	// as Refusal blocks for a reason that is not a finding.
	//
	// The case it exists for: a write to a payment route. Nothing in the
	// content decides it — the same body sent to a reporting API needs
	// nobody — so no rule over findings can express it, and the policy
	// machinery has nothing to match on when the payload is clean. Without
	// this the caller would have to park the request itself and issue a
	// receipt saying "allow" for content that went nowhere.
	//
	// Deliberately a bool and not a reason string: a reason here would
	// read as though it were recorded, and it is not. The receipt says
	// require_approval and no more; why lives in the approval record and
	// the audit entry, which are the things a person actually reads. A
	// held action that nobody releases carries no output digest, so this
	// can never make a receipt claim more than happened.
	Hold bool
}

// Result is the outcome of governing one action.
type Result struct {
	// Content is the governed payload. Nil when the action was blocked or
	// held for approval — nothing was released, so there is nothing to
	// return.
	Content []byte

	// Receipt is the signed record of what happened.
	Receipt *receipt.Receipt

	// Decision is the strongest enforcement action taken.
	Decision receipt.Decision

	// Findings summarises detections by class. Counts only; the detected
	// values never leave the engine.
	Findings []receipt.Finding

	// Warning is set when the receipt is valid but something around it
	// did not complete — today, only a chain position that could not be
	// persisted. Empty on a clean issue.
	Warning string
}

// Govern runs detection, applies policy, transforms content, and issues a
// signed receipt.
//
// A receipt is issued for every call, including calls where nothing was
// found and calls that were blocked. Issuing selectively would leave holes
// in the chain, and a hole is indistinguishable from a deleted record.
func (e *Engine) Govern(req Request) (*Result, error) {
	if req.ChainID == "" {
		return nil, errors.New("govern: chain ID is required")
	}
	if req.ReceiptID == "" {
		return nil, errors.New("govern: receipt ID is required")
	}

	// Health is sampled before detection so the receipt describes the
	// conditions the decision was actually made under.
	components, health := e.sampleHealth()

	// A payload can be perfectly healthy to scan and still contain
	// something no scanner can read — a base64 image on a vision request,
	// a document uploaded the same way. Finding nothing in it is honest;
	// letting the receipt read as though it had been examined is not.
	if carriesUnreadableContent(req.Content) {
		components, health = withUnreadableContent(components, health)
	}
	if len(req.Components) > 0 {
		components, health = withCallerComponents(components, health, req.Components)
	}
	mode := modeFor(health)

	ruleset := e.ruleset
	if req.Ruleset != nil {
		ruleset = req.Ruleset
	}

	// A metadata subject means the bytes are a note about traffic this
	// process never read. Scanning the note would find things in the
	// note — a host name that looks like an address — and the receipt
	// would then carry findings about traffic nothing examined.
	var spans []detect.Span
	if mode != receipt.ModeBypassed && req.Subject != receipt.SubjectMetadata && !req.SelfDescribed {
		spans = ruleset.Scan(req.Content)

		// The probabilistic tier runs alongside, and its findings are kept
		// distinguishable rather than merged into the same claim. Where
		// the two overlap the rules win: a checksum-validated finding is
		// not improved by a model agreeing with it.
		modelSpans, failed := e.runAnalyzers(req.Content)
		spans = mergeSpans(spans, modelSpans)

		// The health sampled above described the conditions going in. An
		// analyzer that failed during this very request changes them, and
		// the receipt must describe what ran, not what was expected to.
		if len(failed) > 0 {
			components, health = withFailedAnalyzers(components, failed)
			mode = modeFor(health)
		}
	}

	policy := e.policy
	if req.Policy != nil {
		policy = req.Policy
	}

	// Decided for the destination the action names. On the gateway that is
	// the upstream actually dialled; on the primitive it is the caller's
	// word, and a rule scoped to it is only as good as that word.
	// Prior findings were established over the whole stream by a governor
	// that read every byte as it passed, restored values and fresh ones
	// alike. The delivered text this request carries is what that governor
	// let through: the same values, and tokens where it substituted. A
	// deterministic scan of it therefore finds nothing that was not
	// already counted, and a token it finds is not a card number. Only the
	// model tier can add something here, because the in-flight governor
	// has no model tier; and even it must not count a substitute.
	if len(req.PriorFindings) > 0 {
		spans = spansNewSincePrior(spans, req.Content)
	}
	findings, decision := findingDecisions(policy, req.Action.Target, req.KeyID, spans)
	if len(req.PriorFindings) > 0 {
		findings, decision = mergeFindings(findings, decision, req.PriorFindings)
	}

	// A bypassed run examined nothing, so it cannot honestly report
	// findings or enforcement.
	if mode == receipt.ModeBypassed {
		findings, decision = nil, receipt.DecisionAllow
	}

	// A hold the caller placed for a reason of its own. Applied after the
	// bypassed reset, because the reason is not something detection found:
	// a run that examined nothing still knows the request was a write to a
	// payment route, and holding it is the honest answer rather than
	// letting it through because inspection was unavailable.
	//
	// Placed before the inspect and irrevocable adjustments below so it is
	// held to the same truths they enforce: witness mode keeps a hold,
	// because a hold alters nothing; content already delivered downgrades
	// it to log_only, because there is no longer anything to hold.
	if req.Hold {
		decision = strongest(decision, receipt.DecisionRequireApproval)
	}

	// Inspection keeps every finding and every refusal, and drops only the
	// transformation. The decision is rewritten so the receipt cannot claim
	// content was tokenised when it was returned untouched.
	if req.Inspect && decision != receipt.DecisionBlock && decision != receipt.DecisionRequireApproval {
		if len(findings) > 0 {
			decision = receipt.DecisionLogOnly
		} else {
			decision = receipt.DecisionAllow
		}
	}

	// Enforcement needs something left to enforce on. Once bytes have
	// been delivered, a refusal can only be recorded; claiming a block
	// would describe work nothing performed. A truncated stream is the
	// one case where a block genuinely happened — the remainder was
	// withheld — so it keeps the word.
	if req.Irrevocable && !req.Truncated &&
		(decision == receipt.DecisionBlock || decision == receipt.DecisionRequireApproval) {
		decision = receipt.DecisionLogOnly
	}

	// A refusal the caller made for its own reasons is still a block:
	// nothing was forwarded. It overrides inspect and irrevocable alike,
	// because both of those describe content that went somewhere, and
	// this content did not.
	if req.Refusal != "" {
		decision = receipt.DecisionBlock
	}

	// An approval that no longer has a hold to resolve — the policy
	// changed between the park and the decision — is not carried onto
	// the receipt. The content left under whatever policy now says, and
	// a record claiming a person released it would give that release a
	// weight it did not have. The denied and expired outcomes always
	// stand, because the caller blocked on them regardless.
	if req.Approval != nil && req.Approval.Outcome == receipt.ApprovalApproved &&
		decision != receipt.DecisionRequireApproval {
		req.Approval = nil
	}

	inputDigest := receipt.DigestContent(req.Content)

	out, outputDigest, err := e.transform(req, spans, decision, policy)
	if err != nil {
		return nil, err
	}

	// A block releases nothing, so the transform reports no output. A cut
	// stream is different: the prefix had already left, and the receipt
	// must digest what was delivered rather than pretend nothing was.
	if req.Truncated && outputDigest == "" {
		outputDigest = inputDigest
	}

	// A one-way scope substitutes but retains nothing, so the values are
	// gone for good. The schema defines tokenisation as reversible
	// substitution and redaction as irreversible removal, which makes
	// "redact" the true description of what just happened — the
	// substitute's format-preserving shape is a property of how the value
	// was removed, not a promise that it can be recovered.
	//
	// Rewritten after the transform rather than before it, because the
	// transform must still run the tokenising path: that is what preserves
	// the format. Only the claim changes.
	if decision == receipt.DecisionTokenize && req.Scope != nil && !req.Scope.Reversible() {
		decision = receipt.DecisionRedact
		findings = asIrreversible(findings)
	}

	signer := e.signerFor(req)

	r := &receipt.Receipt{
		ID:       req.ReceiptID,
		IssuedAt: receipt.Now(),
		Issuer: receipt.Issuer{
			KeyID: signer.KeyID(),
			// Named with an address, because the person most likely to read
			// this has never heard of us. A receipt reaches an auditor, an
			// underwriter or opposing counsel long after it leaves the
			// customer, and a bare word gives them nowhere to go to find out
			// what it is or how to check it themselves.
			//
			// Advisory only, and the field's own documentation says so: a
			// verifier selects a key by KeyID and checks the signature.
			// Anyone can write any name here, which is exactly why nothing
			// depends on it.
			Name:           e.issuer,
			KeyAttestation: req.KeyAttestation,
		},
		Action:   req.Action,
		Actor:    req.Actor,
		Evidence: req.Evidence,
		Content: receipt.Content{
			Algorithm:    receipt.DigestSHA256,
			InputDigest:  inputDigest,
			OutputDigest: outputDigest,
			Bytes:        int64(len(req.Content)),
			Subject:      req.Subject,
			Truncated:    req.Truncated,
		},
		Governance: receipt.Governance{
			Mode:     mode,
			Decision: decision,
			Findings: findings,
			Detector: receipt.Detector{
				Engine:         EngineName,
				EngineVersion:  EngineVersion,
				RulesetVersion: ruleset.Version(),
				Health:         health,
				Components:     components,
			},
			// The policy that decided, not the engine's default. A tenant
			// override produces its own version, and a reader re-running
			// the version named here must reach the same decision.
			Policy: receipt.Policy{
				ID:           policy.ID,
				Version:      policy.Version,
				BundleDigest: ruleset.Digest(),
			},
			Refusal:  req.Refusal,
			Approval: req.Approval,
		},
	}

	var warning string
	if err := e.issue(req.ChainID, signer, r); err != nil {
		// A persist failure happens after the receipt is signed. Throwing
		// the receipt away would punch a hole in the chain to report that
		// the chain might get a hole later.
		var persist *ChainPersistError
		if !errors.As(err, &persist) {
			return nil, err
		}
		warning = err.Error()
	}

	return &Result{
		Content:  out,
		Receipt:  r,
		Decision: decision,
		Findings: findings,
		Warning:  warning,
	}, nil
}

// transform applies the decision to the content.
func (e *Engine) transform(req Request, spans []detect.Span, decision receipt.Decision, policy *Policy) (out []byte, outputDigest string, err error) {
	// A hold a person has released is transformed like any released
	// content: the class that was held passes as they approved it, and
	// everything else in the payload gets whatever policy asks. In witness
	// mode nothing is substituted, as on every other path.
	approved := decision == receipt.DecisionRequireApproval &&
		req.Approval != nil && req.Approval.Outcome == receipt.ApprovalApproved
	if approved && req.Inspect {
		decision = receipt.DecisionLogOnly
	} else if approved {
		decision = receipt.DecisionTokenize
	}

	switch decision {
	case receipt.DecisionBlock, receipt.DecisionRequireApproval:
		// Nothing was released, so there is no output to digest. The
		// receipt schema enforces this: an output digest here would be a
		// claim about content that never existed.
		return nil, "", nil

	case receipt.DecisionAllow, receipt.DecisionLogOnly:
		// Content passes through unchanged, so the digests must match. The
		// receipt schema checks this for the allow case.
		out = make([]byte, len(req.Content))
		copy(out, req.Content)
		return out, receipt.DigestContent(out), nil

	case receipt.DecisionTokenize, receipt.DecisionRedact:
		// Both, in one pass, because a payload can contain findings of each
		// kind and the receipt-level decision names only the strongest.
		//
		// Handling one kind per branch left the other untouched: an email
		// marked for tokenisation was released in the clear because
		// something else in the same payload was marked for redaction. The
		// receipt said "redact" and was telling the truth about the
		// strongest action taken, which is exactly why the gap was
		// invisible from the outside.
		out, err = alter(req, spans, policy)
		if err != nil {
			return nil, "", err
		}
		return out, receipt.DigestContent(out), nil

	default:
		return nil, "", fmt.Errorf("govern: unrecognised decision %q", decision)
	}
}

// redact irreversibly removes spans the policy marked for redaction.
//
// Replacement walks forwards but rebuilds the output rather than editing in
// place, so span offsets stay valid throughout.
func alter(req Request, spans []detect.Span, p *Policy) ([]byte, error) {
	content := req.Content
	out := make([]byte, 0, len(content))
	prev := 0

	// Computed once, and nil for anything that is not JSON.
	keys := jsonObjectKeys(content)

	for _, s := range spans {
		// The same question findingDecisions asked, with the same target
		// and key. Asking it without one would let the receipt record a
		// substitution for this destination that the bytes never had.
		decision := p.DecideFor(req.Action.Target, req.KeyID, s.Class, s.Confidence)
		if decision != receipt.DecisionRedact && decision != receipt.DecisionTokenize {
			// Logged, allowed, or otherwise left alone. A finding the
			// policy merely records must not be rewritten because another
			// class in the same payload triggered a transform.
			continue
		}
		if withinKey(s.Start, s.End, keys) {
			// The name of a field, not the data under it. Detection reads
			// raw bytes and cannot tell the two apart, so "jsonrpc" was
			// reported as a person and the key was rewritten — leaving
			// valid JSON that was no longer a JSON-RPC message, and an MCP
			// server that answered "Parse error" to every request.
			//
			// Still counted as a finding. Nobody has ever asked for the
			// name of a field to be protected.
			continue
		}
		if s.Start < prev {
			return nil, fmt.Errorf("govern: spans overlap at offset %d", s.Start)
		}
		if s.End > len(content) {
			return nil, errors.New("govern: span extends past the end of content")
		}

		out = append(out, content[prev:s.Start]...)

		if decision == receipt.DecisionTokenize {
			if req.Scope == nil {
				return nil, fmt.Errorf("govern: policy decided to tokenise but no scope was supplied: %w",
					tokenize.ErrScopeRequired)
			}
			token, err := req.Scope.Tokenize(s.Class, s.Value)
			if err != nil {
				// A tokenisation failure must not degrade into releasing
				// the original content. If the reverse mapping could not
				// be recorded, the caller would receive a token they
				// believe is reversible and is not.
				return nil, fmt.Errorf("govern: tokenising: %w", err)
			}
			out = append(out, token...)
		} else {
			out = append(out, "[REDACTED:"...)
			out = append(out, s.Class...)
			out = append(out, ']')
		}
		prev = s.End
	}
	return append(out, content[prev:]...), nil
}

// sampleHealth probes every configured component once and aggregates the
// results.
//
// The aggregation has three outcomes, and the distinction between the last
// two matters:
//
//	healthy      every component ran normally
//	degraded     at least one component ran, at least one did not
//	unavailable  no component ran at all
//
// A single component being down is NOT a total outage. Reporting it as one
// would mark the action bypassed, which claims nothing examined the content
// — while the deterministic tier may have run perfectly and caught
// everything it was going to catch. Understating governance that actually
// happened is less dangerous than overstating it, but it is still a false
// statement in a signed receipt.
// Components reports what is currently examining content, and how well.
//
// Exported so a customer's own console can show it. A model tier that is
// down is a coverage gap in the present tense: names, addresses and
// non-English personal data are going undetected right now, every receipt
// issued in the meantime says degraded, and the person who would want to
// know that is looking at a dashboard rather than reading receipts.
func (e *Engine) Components() []receipt.Component {
	if e == nil {
		return nil
	}
	components, _ := e.sampleHealth()
	return components
}

// AnalyzerNames reports which components are the probabilistic tier.
//
// Exported because a caller describing these to a person needs to say
// different things about them — a model being down costs names and
// addresses, a ruleset being down costs card numbers — and the alternative
// was matching on the component's name, which is a guess that was already
// wrong once.
func (e *Engine) AnalyzerNames() []string {
	if e == nil {
		return nil
	}
	names := make([]string, 0, len(e.analyzers))
	for _, a := range e.analyzers {
		names = append(names, a.Name())
	}
	return names
}

func (e *Engine) sampleHealth() ([]receipt.Component, receipt.Health) {
	components := make([]receipt.Component, 0, len(e.components))
	unavailable, impaired := 0, 0

	for _, c := range e.components {
		h := c.Health()
		components = append(components, receipt.Component{Name: c.Name, Health: h})
		switch h {
		case receipt.HealthUnavailable:
			unavailable++
			impaired++
		case receipt.HealthDegraded:
			impaired++
		}
	}

	switch {
	case unavailable == len(e.components):
		// Nothing examined the content.
		return components, receipt.HealthUnavailable
	case impaired > 0:
		// Something ran, something did not.
		return components, receipt.HealthDegraded
	default:
		return components, receipt.HealthHealthy
	}
}

// mergeFindings folds findings established elsewhere into this request's.
//
// The streaming path is the caller: its in-flight governor saw the whole
// response, including anything it withheld, while the content governed
// here is only the prefix that was delivered. Counts add, the stronger
// decision per class wins, and a class either tier attributed to a model
// stays attributed to it — the weaker claim, as everywhere else.
// spansNewSincePrior keeps the spans a scan of delivered text can add to
// findings already established in flight: model-tier spans, and none that
// are token-shaped. See the call site for why deterministic spans are
// dropped wholesale rather than de-duplicated by class.
func spansNewSincePrior(spans []detect.Span, content []byte) []detect.Span {
	var kept []detect.Span
	for _, sp := range spans {
		if sp.Detector == "" {
			continue
		}
		if sp.Start >= 0 && sp.End <= len(content) && sp.Start < sp.End &&
			tokenize.IsToken(string(content[sp.Start:sp.End])) {
			continue
		}
		kept = append(kept, sp)
	}
	return kept
}

func mergeFindings(mine []receipt.Finding, decision receipt.Decision, prior []receipt.Finding) ([]receipt.Finding, receipt.Decision) {
	byClass := make(map[string]*receipt.Finding, len(mine)+len(prior))
	for i := range mine {
		f := mine[i]
		byClass[f.Class] = &f
	}
	for _, p := range prior {
		if f, ok := byClass[p.Class]; ok {
			f.Count += p.Count
			f.Decision = strongest(f.Decision, p.Decision)
			if f.Detector == "" {
				f.Detector = p.Detector
			}
		} else {
			f := p
			byClass[p.Class] = &f
		}
		decision = strongest(decision, p.Decision)
	}
	out := make([]receipt.Finding, 0, len(byClass))
	for _, f := range byClass {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Class < out[j].Class })
	return out, decision
}

// withCallerComponents adds capabilities the caller reports for this request.
//
// An impaired caller component degrades the receipt but never bypasses it:
// the caller is describing something it could not fully read, and the
// engine's own tiers still ran over what it could.
func withCallerComponents(components []receipt.Component, health receipt.Health, extra []receipt.Component) ([]receipt.Component, receipt.Health) {
	out := append([]receipt.Component{}, components...)
	for _, c := range extra {
		if c.Name == "" {
			continue
		}
		out = append(out, c)
		if c.Health != receipt.HealthHealthy && health == receipt.HealthHealthy {
			health = receipt.HealthDegraded
		}
	}
	return out, health
}

// withFailedAnalyzers downgrades the components for analyzers that were
// called during this request and did not answer.
//
// The result is never worse than degraded. The deterministic tier had
// already run by the time an analyzer failed, so "nothing examined the
// content" would be its own overclaim in the other direction.
func withFailedAnalyzers(components []receipt.Component, failed map[string]string) ([]receipt.Component, receipt.Health) {
	out := append([]receipt.Component{}, components...)
	for i := range out {
		if reason, ok := failed[out[i].Name]; ok {
			out[i].Health = receipt.HealthUnavailable
			out[i].Detail = reason
		}
	}
	return out, receipt.HealthDegraded
}

// modeFor maps aggregate detector health to a governance mode.
func modeFor(h receipt.Health) receipt.Mode {
	switch h {
	case receipt.HealthHealthy:
		return receipt.ModeFull
	case receipt.HealthUnavailable:
		return receipt.ModeBypassed
	default:
		return receipt.ModeDegraded
	}
}

// issue signs the receipt into its chain, creating the chain on first use.
func (e *Engine) issue(chainID string, signer receipt.Signer, r *receipt.Receipt) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	b, ok := e.chains[chainID]
	if !ok {
		var err error
		b, err = e.openChain(chainID, signer)
		if err != nil {
			return err
		}
		e.chains[chainID] = b
		e.chainKeys[chainID] = signer.KeyID()
		return e.issueOn(b, r)
	}

	// A chain belongs to one customer, so it is signed by one key for its
	// whole life. Two keys on one chain would mean either that two
	// customers are writing to it, or that a rotation happened without
	// starting a new chain — and a verifier walking the chain would see a
	// key change mid-sequence with nothing to say which side is authentic.
	if existing := e.chainKeys[chainID]; existing != signer.KeyID() {
		return fmt.Errorf("govern: chain %q is signed by key %q; refusing to issue under %q",
			chainID, existing, signer.KeyID())
	}
	return e.issueOn(b, r)
}

// openChain builds a chain the process has not seen yet, resuming from the
// store when one is configured.
//
// A store error refuses to issue rather than starting fresh. Starting
// fresh would be a fork, and a fork is exactly what a verifier cannot
// tell apart from tampering; refusing is loud and recoverable.
func (e *Engine) openChain(chainID string, signer receipt.Signer) (*receipt.ChainBuilder, error) {
	if e.chainStore == nil {
		return receipt.NewChainBuilder(chainID, signer)
	}
	nextSeq, head, found, err := e.chainStore.LoadChain(chainID)
	if err != nil {
		return nil, fmt.Errorf("govern: loading chain %q position: %w", chainID, err)
	}
	if !found {
		return receipt.NewChainBuilder(chainID, signer)
	}
	return receipt.ResumeChainBuilder(chainID, signer, nextSeq, head)
}

// issueOn signs r into the chain and records the new position.
func (e *Engine) issueOn(b *receipt.ChainBuilder, r *receipt.Receipt) error {
	if err := b.Issue(r); err != nil {
		return err
	}
	if e.chainStore == nil {
		return nil
	}
	if err := e.chainStore.SaveChain(b.ChainID(), b.NextSeq(), b.Head()); err != nil {
		return &ChainPersistError{ChainID: b.ChainID(), Err: err}
	}
	return nil
}

// signerFor picks the key for a request.
func (e *Engine) signerFor(req Request) receipt.Signer {
	if req.Signer != nil {
		return req.Signer
	}
	return e.signer
}

// ChainHead returns the current sequence and head digest for a chain, which
// together are the entire state needed to resume it after a restart.
//
// Persist these. Losing them means starting a new chain rather than
// continuing this one, and a verifier will report the discontinuity.
func (e *Engine) ChainHead(chainID string) (seq uint64, head string, known bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	b, ok := e.chains[chainID]
	if !ok {
		return 0, "", false
	}
	return b.NextSeq(), b.Head(), true
}

// ResumeChain restores a chain's position after a restart.
func (e *Engine) ResumeChain(chainID string, nextSeq uint64, head string) error {
	b, err := receipt.ResumeChainBuilder(chainID, e.signer, nextSeq, head)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.chains[chainID] = b
	e.chainKeys[chainID] = e.signer.KeyID()
	e.mu.Unlock()
	return nil
}

// RootSigner returns the engine's own key.
//
// Exposed so a deployment can use it to attest per-tenant keys: the key
// verifiers already trust is exactly the one that must vouch for the
// others, and introducing a second root would mean publishing a second key.
func (e *Engine) RootSigner() receipt.Signer { return e.signer }

// PublicKey returns the signer's public key, for publishing a verification
// endpoint.
func (e *Engine) PublicKey() (keyID string, alg receipt.Algorithm, pub any) {
	return e.signer.KeyID(), e.signer.Algorithm(), e.signer.Public()
}

// asIrreversible restates tokenisation findings as redaction.
//
// Per-finding as well as receipt-level, because a reader checking whether
// one class was recoverable looks at that class's own decision. Leaving it
// as "tokenize" would answer yes for a value that no longer exists.
func asIrreversible(findings []receipt.Finding) []receipt.Finding {
	out := make([]receipt.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if out[i].Decision == receipt.DecisionTokenize {
			out[i].Decision = receipt.DecisionRedact
		}
	}
	return out
}

// withAnalyzerHealth registers every analyzer as a health component.
//
// Done here rather than left to the caller, because the failure of
// forgetting is silent and severe: an analyzer would go down, the rules
// would carry on alone, and every receipt would keep claiming a full scan.
// Wiring it automatically means "this deployment runs a model" and "the
// receipt knows when the model is down" cannot come apart.
func withAnalyzerHealth(components []Component, analyzers []Analyzer) []Component {
	out := append([]Component{}, components...)
	for _, a := range analyzers {
		out = append(out, Component{Name: a.Name(), Health: a.Health})
	}
	return out
}

// issuerName labels receipts for whoever reads one.
//
// A constant rather than configuration. The name is not a security
// property — a verifier trusts the key, never the label — so making it
// settable would only invite a deployment to write somebody else's name on
// its own statements.
const issuerName = "Lyntway (lyntway.com)"
