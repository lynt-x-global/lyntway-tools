package govern

import (
	"errors"
	"fmt"
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
}

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

	return &Engine{
		ruleset:    cfg.Ruleset,
		policy:     cfg.Policy,
		analyzers:  cfg.Analyzers,
		signer:     cfg.Signer,
		components: withAnalyzerHealth(cfg.Components, cfg.Analyzers),
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
	mode := modeFor(health)

	ruleset := e.ruleset
	if req.Ruleset != nil {
		ruleset = req.Ruleset
	}

	var spans []detect.Span
	if mode != receipt.ModeBypassed {
		spans = ruleset.Scan(req.Content)

		// The probabilistic tier runs alongside, and its findings are kept
		// distinguishable rather than merged into the same claim. Where
		// the two overlap the rules win: a checksum-validated finding is
		// not improved by a model agreeing with it.
		spans = mergeSpans(spans, e.runAnalyzers(req.Content))
	}

	policy := e.policy
	if req.Policy != nil {
		policy = req.Policy
	}

	findings, decision := findingDecisions(policy, spans)

	// A bypassed run examined nothing, so it cannot honestly report
	// findings or enforcement.
	if mode == receipt.ModeBypassed {
		findings, decision = nil, receipt.DecisionAllow
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

	inputDigest := receipt.DigestContent(req.Content)

	out, outputDigest, err := e.transform(req, spans, decision, policy)
	if err != nil {
		return nil, err
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
			KeyID:          signer.KeyID(),
			Name:           "Lyntway",
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
			Policy: receipt.Policy{
				ID:           e.policy.ID,
				Version:      e.policy.Version,
				BundleDigest: ruleset.Digest(),
			},
		},
	}

	if err := e.issue(req.ChainID, signer, r); err != nil {
		return nil, err
	}

	return &Result{
		Content:  out,
		Receipt:  r,
		Decision: decision,
		Findings: findings,
	}, nil
}

// transform applies the decision to the content.
func (e *Engine) transform(req Request, spans []detect.Span, decision receipt.Decision, policy *Policy) (out []byte, outputDigest string, err error) {
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

	for _, s := range spans {
		decision := p.Decide(s.Class, s.Confidence)
		if decision != receipt.DecisionRedact && decision != receipt.DecisionTokenize {
			// Logged, allowed, or otherwise left alone. A finding the
			// policy merely records must not be rewritten because another
			// class in the same payload triggered a transform.
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
		b, err = receipt.NewChainBuilder(chainID, signer)
		if err != nil {
			return err
		}
		e.chains[chainID] = b
		e.chainKeys[chainID] = signer.KeyID()
		return b.Issue(r)
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
	return b.Issue(r)
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
