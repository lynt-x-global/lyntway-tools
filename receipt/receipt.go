// Package receipt implements Lyntway's signed action receipt: an
// offline-verifiable record of one governed action.
//
// A receipt answers four questions for a third party who has never heard of
// Lyntway and cannot reach the network:
//
//  1. What action was taken, by whom, on whose behalf?
//  2. What did the governance engine do to the data?
//  3. Was the engine actually healthy when it decided that?
//  4. Has any of the above been altered since it was signed?
//
// Question 3 is the one most implementations get wrong. A governance layer
// that fails open and still issues a full-strength receipt is asserting
// something untrue at exactly the moment it matters. Mode and DetectorInfo
// are therefore required fields, and Validate rejects receipts that omit
// them or that claim health inconsistent with their component reports.
//
// Content is never carried in a receipt — only digests. A receipt is safe to
// publish; the data it describes is not.
//
// # Design constraints
//
// The core carries zero external dependencies. This package is the root of
// trust for every claim the product makes, so its supply chain is stdlib only
// and auditable in an afternoon.
//
// The schema deliberately contains no floating-point numbers. Canonical JSON
// (RFC 8785) requires ECMAScript number formatting, which is the single
// largest source of cross-implementation signature mismatches. Integers and
// strings sidestep it entirely; see canonical.go.
package receipt

import (
	"strings"
	"time"
)

// SchemaVersion identifies the receipt envelope shape. It is included in the
// signed payload, so a verifier can reject a receipt whose schema it does not
// understand rather than silently misreading fields.
const SchemaVersion = "lyntway-receipt/1"

// Receipt is a signed record of one governed action.
//
// Field order in this struct is irrelevant to the signature: the canonical
// form sorts keys. It is ordered here for human legibility.
type Receipt struct {
	// Version is the receipt schema version. Always SchemaVersion for
	// receipts this package issues.
	Version string `json:"version"`

	// ID uniquely identifies this receipt. Callers supply it; the package
	// does not impose a format beyond non-empty, so ULIDs, UUIDs, or an
	// existing internal identifier all work.
	ID string `json:"id"`

	// IssuedAt is when the receipt was signed, RFC 3339 in UTC with second
	// precision. String rather than time.Time so the canonical form is
	// exactly what was signed, with no reformatting on the round trip.
	IssuedAt string `json:"issued_at"`

	// Issuer identifies the signing key. A verifier resolves the public key
	// from KeyID out of band — a JWKS endpoint, a pinned key, or a key
	// distributed with the receipt bundle.
	Issuer Issuer `json:"issuer"`

	// Chain positions this receipt in an append-only sequence. Without it a
	// receipt proves only that an action happened, not that no action was
	// deleted from the record.
	Chain Chain `json:"chain"`

	// Action describes what was done.
	Action Action `json:"action"`

	// Actor describes who did it, and on whose behalf.
	Actor Actor `json:"actor"`

	// Content carries digests of the governed payload. Never the payload.
	Content Content `json:"content"`

	// Governance records what the engine decided and whether it was healthy
	// enough for that decision to mean anything.
	Governance Governance `json:"governance"`

	// Evidence records how the issuer came to know what this receipt
	// describes — whether it handled the bytes, was told about them, or was
	// simply given a description.
	//
	// Optional so that receipts issued before the field existed remain
	// valid. Absent is read as the weakest possibility rather than the
	// strongest; see EffectiveProvenance.
	Evidence *Evidence `json:"evidence,omitempty"`

	// Anchors are external timestamp proofs. Empty at issuance; populated
	// asynchronously once an anchor returns. Anchors are excluded from the
	// signature precisely because they arrive later — see SigningInput.
	Anchors []Anchor `json:"anchors,omitempty"`

	// Signature covers every field above except Anchors and Signature
	// itself.
	Signature *Signature `json:"signature,omitempty"`
}

// Issuer identifies the party that signed a receipt.
type Issuer struct {
	// KeyID is the stable identifier of the signing key, used by a verifier
	// to select the right public key. Rotating a key means issuing under a
	// new KeyID, never reusing one.
	KeyID string `json:"key_id"`

	// Name is a human-readable issuer label. Advisory only — never trust it
	// for key selection.
	Name string `json:"name,omitempty"`

	// KeyAttestation carries the deployment's signed statement that KeyID
	// is authorised to sign for this receipt's chain.
	//
	// Present when the receipt was signed by a per-customer key rather than
	// the deployment key itself. It travels with the receipt so that a
	// verifier needs only the deployment's published key — no directory
	// lookup, and no disclosure of which other customers exist.
	//
	// It is inside the signed portion of the receipt deliberately: the
	// signature covers the attestation, so an attestation cannot be swapped
	// for another after issuance.
	KeyAttestation *KeyAttestation `json:"key_attestation,omitempty"`
}

// Chain positions a receipt within an append-only sequence.
//
// Standalone receipts prove individual actions. A chain additionally proves
// completeness: because each receipt commits to its predecessor's digest,
// removing one breaks every receipt after it.
type Chain struct {
	// ID scopes the sequence. One chain per workspace, per session, or per
	// agent, depending on what completeness needs to be provable over.
	ID string `json:"id"`

	// Seq is the position in the chain, starting at 0 for the genesis
	// receipt.
	Seq uint64 `json:"seq"`

	// PrevHash is the hex-encoded digest of the previous receipt's signing
	// input. Empty only when Seq is 0.
	PrevHash string `json:"prev_hash"`
}

// Surface names the data plane an action crossed.
type Surface string

const (
	// SurfaceModel is traffic to a model inference endpoint.
	SurfaceModel Surface = "model"
	// SurfaceMCP is a Model Context Protocol tool call or result.
	SurfaceMCP Surface = "mcp"
	// SurfaceDatabase is database wire protocol traffic.
	SurfaceDatabase Surface = "database"
	// SurfacePrimitive is a direct call to the govern API, where the caller
	// hands us content rather than us intercepting it.
	SurfacePrimitive Surface = "primitive"
)

func (s Surface) valid() bool {
	switch s {
	case SurfaceModel, SurfaceMCP, SurfaceDatabase, SurfacePrimitive:
		return true
	}
	return false
}

// Direction distinguishes the leg of a round trip an action occurred on.
//
// This matters more than it looks. Sensitive data leaks on both legs, but
// indirect prompt injection arrives almost entirely on the response leg —
// in tool results, retrieved documents, and database rows. A receipt that
// cannot say which leg it covers cannot support that distinction.
type Direction string

const (
	// DirectionRequest is content travelling from the actor outward.
	DirectionRequest Direction = "request"
	// DirectionResponse is content returning toward the actor.
	DirectionResponse Direction = "response"
)

func (d Direction) valid() bool {
	return d == DirectionRequest || d == DirectionResponse
}

// Action describes the governed operation.
type Action struct {
	// Surface is the data plane crossed.
	Surface Surface `json:"surface"`

	// Direction is which leg of the round trip this receipt covers.
	Direction Direction `json:"direction"`

	// Method is the surface-native operation: an HTTP method and path for
	// model traffic, an MCP method such as "tools/call", or a SQL verb.
	Method string `json:"method"`

	// Target is what was acted upon: a model identifier, an MCP tool name,
	// or a database and relation. Free-form because the surfaces have
	// genuinely incompatible naming.
	Target string `json:"target,omitempty"`

	// Destination is where governed content was permitted to travel. This
	// is the field no single-plane tool can populate honestly, and the one
	// an auditor cares most about.
	Destination string `json:"destination,omitempty"`
}

// ActorType distinguishes classes of principal.
type ActorType string

const (
	// ActorAgent is an autonomous or semi-autonomous software agent.
	ActorAgent ActorType = "agent"
	// ActorHuman is a person acting directly.
	ActorHuman ActorType = "human"
	// ActorService is a non-interactive workload.
	ActorService ActorType = "service"
)

func (a ActorType) valid() bool {
	switch a {
	case ActorAgent, ActorHuman, ActorService:
		return true
	}
	return false
}

// IdentitySource names where an actor's identity claim came from.
//
// Lyntway does not issue agent identity — that layer belongs to Entra, Okta,
// Web Bot Auth, and the DID ecosystem. It consumes those claims and records
// which one it verified, so a receipt inherits their assurance rather than
// asserting its own.
type IdentitySource string

const (
	// IdentityNone means no external identity claim was presented.
	IdentityNone IdentitySource = "none"
	// IdentityWebBotAuth is an RFC 9421 HTTP message signature verified
	// against a published key directory.
	IdentityWebBotAuth IdentitySource = "web_bot_auth"
	// IdentityEntraAgent is a Microsoft Entra Agent ID.
	IdentityEntraAgent IdentitySource = "entra_agent_id"
	// IdentityOkta is an Okta agent identity.
	IdentityOkta IdentitySource = "okta"
	// IdentityOIDC is a generic OIDC subject from a validated token.
	IdentityOIDC IdentitySource = "oidc"
	// IdentityDID is a W3C Decentralized Identifier.
	IdentityDID IdentitySource = "did"
	// IdentityLyntwayKey is a Lyntway-issued virtual key. Weakest of the
	// sources: it authenticates the caller to us, but attests nothing about
	// the agent to anyone else.
	IdentityLyntwayKey IdentitySource = "lyntway_key"
)

func (i IdentitySource) valid() bool {
	switch i {
	case IdentityNone, IdentityWebBotAuth, IdentityEntraAgent,
		IdentityOkta, IdentityOIDC, IdentityDID, IdentityLyntwayKey:
		return true
	}
	return false
}

// Actor identifies who performed an action and under whose authority.
type Actor struct {
	// Type is the class of principal.
	Type ActorType `json:"type"`

	// ID identifies the actor within Source's namespace.
	ID string `json:"id"`

	// Source names where the identity claim originated.
	Source IdentitySource `json:"source"`

	// Verified records whether Lyntway cryptographically verified the
	// claim, as opposed to accepting an asserted value. A receipt with
	// Verified false is still useful; it just carries less weight, and it
	// must not be presented as attested identity.
	Verified bool `json:"verified"`

	// Delegation is the chain of principals from the ultimate human
	// authority down to the acting agent, outermost first. Empty means the
	// actor acted on its own authority.
	Delegation []DelegationHop `json:"delegation,omitempty"`
}

// DelegationHop is one step in an on-behalf-of chain.
//
// Populating this is what separates "an agent read customer records" from
// "an agent read customer records on behalf of a named employee". The second
// is accountable; the first is not.
type DelegationHop struct {
	// Type is the class of principal at this hop.
	Type ActorType `json:"type"`
	// ID identifies the principal within Source's namespace.
	ID string `json:"id"`
	// Source names where this hop's identity claim originated.
	Source IdentitySource `json:"source"`
}

// DigestAlgorithm names a content hash function.
type DigestAlgorithm string

// DigestSHA256 is SHA-256, hex encoded lowercase.
const DigestSHA256 DigestAlgorithm = "sha-256"

// Content carries digests of the governed payload.
//
// Deliberately not the payload. Receipts are designed to be shared with
// auditors, customers, and underwriters; carrying content would make every
// receipt a data breach waiting for a mailing list. The cost is that a
// receipt proves what happened, not what the data said — which is the right
// trade, and one this package will not let a caller reverse.
type Content struct {
	// Algorithm is the digest function used for both digests below.
	Algorithm DigestAlgorithm `json:"algorithm"`

	// InputDigest is the digest of the content as received, before any
	// governance transformation.
	InputDigest string `json:"input_digest"`

	// OutputDigest is the digest of the content as released, after
	// transformation. Equal to InputDigest when the decision was Allow;
	// empty when the action was blocked and nothing was released.
	OutputDigest string `json:"output_digest,omitempty"`

	// Bytes is the size of the input content in bytes. Useful for
	// anomaly and exfiltration analysis without revealing content.
	Bytes int64 `json:"bytes"`

	// Subject states what the digests above actually cover.
	//
	// Absent means the payload, which is what every receipt meant before
	// this field existed and what the governing paths still produce.
	//
	// It exists because a receipt can be built from a telemetry record
	// rather than from the data itself. Those records usually carry no
	// content — capturing prompts is off by default, for good reason — so
	// there is nothing of the payload to digest. Digesting the telemetry
	// instead is honest and useful, and presenting that digest without
	// saying so would let a reader believe the prompt had been hashed.
	Subject ContentSubject `json:"subject,omitempty"`
}

// ContentSubject names what a receipt's digests are taken over.
type ContentSubject string

const (
	// SubjectPayload means the digests cover the governed data itself.
	// The default, and the only form that can support a claim about what
	// the data contained.
	SubjectPayload ContentSubject = "payload"

	// SubjectTelemetry means the digests cover a telemetry record
	// describing the action, not the data involved in it.
	//
	// Such a receipt proves an action was reported and that the report has
	// not been altered. It proves nothing about what the action carried.
	SubjectTelemetry ContentSubject = "telemetry"

	// SubjectMetadata means the digests cover facts about the action that
	// the issuer observed directly, without seeing its contents.
	//
	// A tunnelled connection is the case this exists for: the issuer
	// carried the bytes and can state where they went, when, and how many
	// there were, while the payload inside was encrypted end to end.
	//
	// Distinct from telemetry, and the difference is who is speaking. A
	// telemetry receipt repeats what another system reported. This one
	// reports what the issuer handled — first-hand about the connection,
	// silent about the content.
	SubjectMetadata ContentSubject = "metadata"
)

// EffectiveSubject reports what a receipt's digests cover, treating an
// absent value as the payload — which is what every receipt issued before
// this field existed meant.
func (r *Receipt) EffectiveSubject() ContentSubject {
	if r == nil || r.Content.Subject == "" {
		return SubjectPayload
	}
	return r.Content.Subject
}

// Mode records how much governance was actually applied.
//
// This is the honesty field. Any inline governance layer must decide what to
// do when its detectors are unavailable: fail closed and break the caller's
// application, or fail open and let traffic through. Both are defensible.
// What is not defensible is failing open while issuing a receipt that reads
// identically to a healthy one.
type Mode string

const (
	// ModeFull means every configured detector ran and reported healthy.
	ModeFull Mode = "full"

	// ModeDegraded means governance was applied with reduced capability —
	// typically the deterministic floor ran while an ML detector was
	// unavailable. The receipt remains valid and useful; it simply must not
	// be read as a full-strength assertion.
	ModeDegraded Mode = "degraded"

	// ModeBypassed means no governance was applied and content passed
	// unexamined. Issuing a receipt for a bypassed action is a deliberate
	// choice: silence would leave a hole in the chain, and a hole is worse
	// than an honest admission.
	ModeBypassed Mode = "bypassed"
)

func (m Mode) valid() bool {
	switch m {
	case ModeFull, ModeDegraded, ModeBypassed:
		return true
	}
	return false
}

// Decision is the enforcement action taken on content.
type Decision string

const (
	// DecisionAllow passed content through unchanged.
	DecisionAllow Decision = "allow"
	// DecisionLogOnly recorded findings without altering content. The
	// correct default for detectors whose precision does not support
	// automated blocking.
	DecisionLogOnly Decision = "log_only"
	// DecisionTokenize substituted values reversibly, preserving format so
	// downstream workflows continue to function.
	DecisionTokenize Decision = "tokenize"
	// DecisionRedact removed values irreversibly.
	DecisionRedact Decision = "redact"
	// DecisionRequireApproval held the action pending a human decision.
	DecisionRequireApproval Decision = "require_approval"
	// DecisionBlock refused the action and released nothing.
	DecisionBlock Decision = "block"
)

func (d Decision) valid() bool {
	switch d {
	case DecisionAllow, DecisionLogOnly, DecisionTokenize,
		DecisionRedact, DecisionRequireApproval, DecisionBlock:
		return true
	}
	return false
}

// Health is a detector component's operational state.
type Health string

const (
	// HealthHealthy means the component ran normally.
	HealthHealthy Health = "healthy"
	// HealthDegraded means the component ran with reduced capability.
	HealthDegraded Health = "degraded"
	// HealthUnavailable means the component did not run.
	HealthUnavailable Health = "unavailable"
)

func (h Health) valid() bool {
	switch h {
	case HealthHealthy, HealthDegraded, HealthUnavailable:
		return true
	}
	return false
}

// Governance records the engine's decision and the conditions under which it
// was reached.
type Governance struct {
	// Mode is how much governance was actually applied.
	Mode Mode `json:"mode"`

	// Decision is the enforcement action taken.
	Decision Decision `json:"decision"`

	// Findings summarises what was detected, by class and count. Never the
	// detected values themselves.
	Findings []Finding `json:"findings,omitempty"`

	// Detector identifies the engine that produced those findings, at the
	// version that produced them.
	Detector Detector `json:"detector"`

	// Policy identifies the ruleset that turned findings into a decision.
	Policy Policy `json:"policy"`
}

// Finding is one class of detection and how it was handled.
type Finding struct {
	// Class is the taxonomy identifier, dotted and hierarchical:
	// "pii.email", "secret.aws_access_key", "injection.indirect".
	Class string `json:"class"`

	// Count is how many spans of this class were found.
	Count int `json:"count"`

	// Decision is what was done about this specific class, which may differ
	// from the receipt-level decision when a policy applies different
	// actions to different classes.
	Decision Decision `json:"decision"`

	// Detector names what found this, when it was not the deterministic
	// ruleset.
	//
	// Absent means the rules, which are reproducible: the ruleset digest
	// above pins them, so anyone can re-run the same patterns over the same
	// content and get the same answer. A named detector is probabilistic,
	// and re-running it is not guaranteed to agree — better recall, weaker
	// reproducibility.
	//
	// Both are real findings. They are not the same kind of evidence, and a
	// receipt that presented them identically would be overstating one of
	// them.
	Detector string `json:"detector,omitempty"`
}

// Detector identifies the detection engine and its exact version.
//
// Version pinning is what makes a receipt reproducible. A self-improving
// engine that retrains is desirable; an engine whose past decisions cannot be
// reconstructed is not auditable. Recording engine and ruleset versions makes
// both possible at once: retrain freely, and remain able to answer "why was
// this span not redacted in March" in September.
type Detector struct {
	// Engine names the detection stack.
	Engine string `json:"engine"`

	// EngineVersion is the exact build that ran. Required.
	EngineVersion string `json:"engine_version"`

	// RulesetVersion is the version of the deterministic rule bundle that
	// ran. Required.
	RulesetVersion string `json:"ruleset_version"`

	// Health is the aggregate state of the engine for this action.
	Health Health `json:"health"`

	// Components reports per-component health. Populated whenever Health is
	// not healthy, so a reader can tell which capability was missing rather
	// than guessing.
	Components []Component `json:"components,omitempty"`
}

// Component is one detector subsystem's health for a single action.
type Component struct {
	// Name identifies the subsystem, e.g. "regex", "onnx-pii",
	// "injection-classifier".
	Name string `json:"name"`
	// Health is the subsystem's state.
	Health Health `json:"health"`
	// Detail is an optional human-readable reason. Advisory only.
	Detail string `json:"detail,omitempty"`
}

// Policy identifies the ruleset that produced a decision.
type Policy struct {
	// ID is the stable policy identifier.
	ID string `json:"id"`
	// Version is the policy version that evaluated this action. Required
	// for the same reason as detector versions: reproducibility.
	Version string `json:"version"`
	// BundleDigest is the hex digest of the exact signed policy bundle,
	// pinning the decision to bytes rather than a mutable version label.
	BundleDigest string `json:"bundle_digest,omitempty"`
}

// AnchorType names an external timestamping mechanism.
type AnchorType string

const (
	// AnchorRFC3161 is an RFC 3161 timestamp token from a trusted
	// authority. The answer enterprise auditors already accept.
	AnchorRFC3161 AnchorType = "rfc3161"
	// AnchorOpenTimestamps is an OpenTimestamps proof, which requires no
	// trusted party. Weaker latency, stronger independence.
	AnchorOpenTimestamps AnchorType = "opentimestamps"
)

// Anchor is external evidence that a receipt existed at a point in time.
//
// Anchors are excluded from the signature because they necessarily arrive
// after signing: an anchor commits to the signed receipt, not the reverse.
// Anchoring both would be circular.
type Anchor struct {
	// Type names the anchoring mechanism.
	Type AnchorType `json:"type"`
	// Value is the base64-encoded proof token.
	Value string `json:"value"`
	// AnchoredAt is when the anchor was obtained, RFC 3339 UTC.
	AnchoredAt string `json:"anchored_at"`
}

// Signature carries the cryptographic proof over a receipt's signing input.
type Signature struct {
	// Algorithm names the signature scheme. Present so that adding a
	// post-quantum scheme later is a registry entry rather than a schema
	// break — and so a verifier can reject an algorithm it does not accept
	// instead of being talked into a weaker one.
	Algorithm Algorithm `json:"algorithm"`

	// KeyID identifies the key that produced Value. Duplicated from Issuer
	// so a detached signature remains self-describing.
	KeyID string `json:"key_id"`

	// Canonicalization names the byte-serialization the signature covers.
	// Explicit so a verifier never has to infer it.
	Canonicalization string `json:"canonicalization"`

	// Value is the base64 (standard, padded) signature.
	Value string `json:"value"`
}

// CanonicalizationJCS is RFC 8785 JSON Canonicalization Scheme.
const CanonicalizationJCS = "jcs"

// Now returns the current time formatted for the IssuedAt field.
func Now() string { return FormatTime(time.Now()) }

// FormatTime renders t in the form receipts use: RFC 3339, UTC, second
// precision. Second precision is deliberate — sub-second timestamps leak
// timing information about the governed workload without improving the
// evidentiary value of the receipt.
func FormatTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// ParseTime parses a receipt timestamp.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, &FieldError{Field: "issued_at", Reason: "not a valid RFC 3339 timestamp"}
	}
	return t, nil
}

// Validate reports whether r is structurally sound and internally consistent.
//
// It enforces the schema's non-negotiables: a receipt must state how much
// governance ran, which engine version ran it, and which policy version
// decided. It also enforces consistency between claims — a receipt cannot
// report full-mode governance while admitting an unavailable component, and
// cannot report a healthy engine while listing a degraded one.
//
// Validate does not check the signature; see Verify.
func (r *Receipt) Validate() error {
	var errs FieldErrors

	if r.Version != SchemaVersion {
		errs.add("version", "must be "+SchemaVersion)
	}
	if strings.TrimSpace(r.ID) == "" {
		errs.add("id", "must not be empty")
	}
	if r.IssuedAt == "" {
		errs.add("issued_at", "must not be empty")
	} else if _, err := ParseTime(r.IssuedAt); err != nil {
		errs.add("issued_at", "not a valid RFC 3339 timestamp")
	}
	if strings.TrimSpace(r.Issuer.KeyID) == "" {
		errs.add("issuer.key_id", "must not be empty")
	}

	if r.Evidence != nil {
		r.Evidence.validateInto(&errs)
	}

	switch r.Content.Subject {
	case "", SubjectPayload:
	case SubjectMetadata:
		// The issuer carried the bytes but never read them, so it cannot
		// have transformed them.
		switch r.Governance.Decision {
		case DecisionTokenize, DecisionRedact:
			errs.add("governance.decision",
				"cannot be "+string(r.Governance.Decision)+" when the digests cover metadata rather than the payload; the content was never read")
		}
		// Findings require having looked at something. Metadata-only
		// observation cannot produce them.
		if len(r.Governance.Findings) > 0 {
			errs.add("governance.findings",
				"must be empty when the digests cover metadata rather than the payload; nothing examined the content")
		}
	case SubjectTelemetry:
		// A receipt built from a telemetry record never held the data, so
		// it cannot have transformed it. Claiming a decision that alters
		// content would describe work nothing performed.
		switch r.Governance.Decision {
		case DecisionTokenize, DecisionRedact:
			errs.add("governance.decision",
				"cannot be "+string(r.Governance.Decision)+" when the digests cover telemetry rather than the payload; nothing held the content to transform it")
		}
		// Observation is a claim about handling bytes. A record derived
		// from someone else's telemetry did not handle them.
		if r.Evidence != nil && r.Evidence.Provenance == ProvenanceObserved {
			errs.add("evidence.provenance",
				"cannot be observed when the digests cover telemetry rather than the payload")
		}
	default:
		errs.add("content.subject", "unrecognised value")
	}

	// Chain. Seq 0 is genesis and must not claim a predecessor; every other
	// position must, or deletion of the first receipt would be invisible.
	if strings.TrimSpace(r.Chain.ID) == "" {
		errs.add("chain.id", "must not be empty")
	}
	switch {
	case r.Chain.Seq == 0 && r.Chain.PrevHash != "":
		errs.add("chain.prev_hash", "must be empty for the genesis receipt (seq 0)")
	case r.Chain.Seq > 0 && r.Chain.PrevHash == "":
		errs.add("chain.prev_hash", "must be set for any receipt after genesis")
	case r.Chain.Seq > 0 && !isHexDigest(r.Chain.PrevHash):
		errs.add("chain.prev_hash", "must be a lowercase hex SHA-256 digest")
	}

	// Action.
	if !r.Action.Surface.valid() {
		errs.add("action.surface", "must be one of: model, mcp, database, primitive")
	}
	if !r.Action.Direction.valid() {
		errs.add("action.direction", "must be one of: request, response")
	}
	if strings.TrimSpace(r.Action.Method) == "" {
		errs.add("action.method", "must not be empty")
	}

	// Actor.
	if !r.Actor.Type.valid() {
		errs.add("actor.type", "must be one of: agent, human, service")
	}
	if strings.TrimSpace(r.Actor.ID) == "" {
		errs.add("actor.id", "must not be empty")
	}
	if !r.Actor.Source.valid() {
		errs.add("actor.source", "unrecognised identity source")
	}
	// An unverified claim cannot come from a source whose entire purpose is
	// cryptographic verification; that combination means a bug upstream.
	if !r.Actor.Verified && r.Actor.Source == IdentityWebBotAuth {
		errs.add("actor.verified", "web_bot_auth identities are only recorded when signature verification succeeded")
	}
	if r.Actor.Source == IdentityNone && r.Actor.Verified {
		errs.add("actor.verified", "cannot be true when no identity source was presented")
	}
	for i, hop := range r.Actor.Delegation {
		p := "actor.delegation[" + itoa(i) + "]"
		if !hop.Type.valid() {
			errs.add(p+".type", "must be one of: agent, human, service")
		}
		if strings.TrimSpace(hop.ID) == "" {
			errs.add(p+".id", "must not be empty")
		}
		if !hop.Source.valid() {
			errs.add(p+".source", "unrecognised identity source")
		}
	}

	// Content.
	if r.Content.Algorithm != DigestSHA256 {
		errs.add("content.algorithm", "must be sha-256")
	}
	if !isHexDigest(r.Content.InputDigest) {
		errs.add("content.input_digest", "must be a lowercase hex SHA-256 digest")
	}
	if r.Content.Bytes < 0 {
		errs.add("content.bytes", "must not be negative")
	}
	// A blocked action releases nothing, so an output digest would be a
	// claim about content that never existed.
	if r.Governance.Decision == DecisionBlock && r.Content.OutputDigest != "" {
		errs.add("content.output_digest", "must be empty when the decision was block")
	}
	if r.Content.OutputDigest != "" && !isHexDigest(r.Content.OutputDigest) {
		errs.add("content.output_digest", "must be a lowercase hex SHA-256 digest")
	}
	// Anything short of a block released something, so its digest is
	// required — otherwise the receipt cannot show what actually left.
	if r.Governance.Decision != DecisionBlock &&
		r.Governance.Decision != DecisionRequireApproval &&
		r.Content.OutputDigest == "" {
		errs.add("content.output_digest", "required unless the action was blocked or held for approval")
	}
	// Passing content through unchanged means the digests must match. A
	// mismatch here means the pipeline mutated content it claimed not to.
	if r.Governance.Decision == DecisionAllow && r.Content.OutputDigest != "" &&
		r.Content.OutputDigest != r.Content.InputDigest {
		errs.add("content.output_digest", "must equal input_digest when the decision was allow")
	}

	errs.merge(r.Governance.validate())

	for i, a := range r.Anchors {
		p := "anchors[" + itoa(i) + "]"
		if a.Type != AnchorRFC3161 && a.Type != AnchorOpenTimestamps {
			errs.add(p+".type", "must be one of: rfc3161, opentimestamps")
		}
		if strings.TrimSpace(a.Value) == "" {
			errs.add(p+".value", "must not be empty")
		}
		if _, err := ParseTime(a.AnchoredAt); err != nil {
			errs.add(p+".anchored_at", "not a valid RFC 3339 timestamp")
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errs
}

// validate checks the governance block's internal consistency.
func (g *Governance) validate() FieldErrors {
	var errs FieldErrors

	if !g.Mode.valid() {
		errs.add("governance.mode", "must be one of: full, degraded, bypassed")
	}
	if !g.Decision.valid() {
		errs.add("governance.decision", "unrecognised decision")
	}
	if strings.TrimSpace(g.Detector.Engine) == "" {
		errs.add("governance.detector.engine", "must not be empty")
	}
	// Both version fields are load-bearing for reproducibility. A receipt
	// without them cannot be re-derived once the engine moves on, which
	// makes it unverifiable at exactly the moment someone disputes it.
	if strings.TrimSpace(g.Detector.EngineVersion) == "" {
		errs.add("governance.detector.engine_version", "required: a receipt must be reproducible against the exact engine build that issued it")
	}
	if strings.TrimSpace(g.Detector.RulesetVersion) == "" {
		errs.add("governance.detector.ruleset_version", "required: a receipt must be reproducible against the exact ruleset that issued it")
	}
	if !g.Detector.Health.valid() {
		errs.add("governance.detector.health", "must be one of: healthy, degraded, unavailable")
	}
	if strings.TrimSpace(g.Policy.ID) == "" {
		errs.add("governance.policy.id", "must not be empty")
	}
	if strings.TrimSpace(g.Policy.Version) == "" {
		errs.add("governance.policy.version", "required: a decision must be attributable to an exact policy version")
	}
	if g.Policy.BundleDigest != "" && !isHexDigest(g.Policy.BundleDigest) {
		errs.add("governance.policy.bundle_digest", "must be a lowercase hex SHA-256 digest")
	}

	for i, c := range g.Detector.Components {
		p := "governance.detector.components[" + itoa(i) + "]"
		if strings.TrimSpace(c.Name) == "" {
			errs.add(p+".name", "must not be empty")
		}
		if !c.Health.valid() {
			errs.add(p+".health", "must be one of: healthy, degraded, unavailable")
		}
	}

	for i, f := range g.Findings {
		f.validateInto(&errs, "governance.findings", i)
	}

	// Consistency between the mode, the aggregate health, and the component
	// reports. These are the checks that stop a fail-open window from being
	// dressed up as a healthy one.
	worst := g.Detector.worstComponentHealth()

	if g.Detector.Health == HealthHealthy && worst != HealthHealthy {
		errs.add("governance.detector.health",
			"claims healthy while a component reports "+string(worst))
	}
	if g.Mode == ModeFull && g.Detector.Health != HealthHealthy {
		errs.add("governance.mode",
			"cannot be full when the detector reports "+string(g.Detector.Health))
	}
	if g.Mode == ModeDegraded && g.Detector.Health == HealthHealthy {
		errs.add("governance.mode",
			"claims degraded but the detector reports healthy; state the actual reason in detector.components")
	}
	// Nothing ran, so nothing can have been found or enforced. A bypassed
	// receipt asserting findings would be describing work it did not do.
	if g.Mode == ModeBypassed {
		if len(g.Findings) > 0 {
			errs.add("governance.findings", "must be empty when governance was bypassed")
		}
		if g.Decision != DecisionAllow {
			errs.add("governance.decision", "must be allow when governance was bypassed: no enforcement occurred")
		}
	}
	// A degraded run must name what was missing, or a reader cannot judge
	// how much weight the receipt deserves.
	if g.Mode == ModeDegraded && len(g.Detector.Components) == 0 {
		errs.add("governance.detector.components",
			"required when mode is degraded: name which components were unavailable")
	}

	return errs
}

// worstComponentHealth returns the least healthy component state reported,
// or HealthHealthy when no components were reported.
func (d *Detector) worstComponentHealth() Health {
	worst := HealthHealthy
	for _, c := range d.Components {
		switch c.Health {
		case HealthUnavailable:
			return HealthUnavailable
		case HealthDegraded:
			worst = HealthDegraded
		}
	}
	return worst
}

// IsFullStrength reports whether a receipt asserts complete governance.
//
// Verifiers and user interfaces should call this rather than testing Mode
// directly, so that a future mode is not silently treated as full strength
// by code written before it existed.
func (r *Receipt) IsFullStrength() bool {
	return r.Governance.Mode == ModeFull &&
		r.Governance.Detector.Health == HealthHealthy
}

// isHexDigest reports whether s is a lowercase hex-encoded SHA-256 digest.
func isHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// itoa formats small non-negative ints without pulling in strconv at every
// call site. Index positions in error paths only.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// validateInto checks one finding, wherever it appears.
//
// Shared because a finding reported by another system has to meet the same
// bar as one this engine produced: a class, a positive count, and a
// recognised decision. Two copies of this check would drift, and the copy
// that drifted would be the one guarding somebody else's data.
func (f Finding) validateInto(errs *FieldErrors, field string, index int) {
	p := field + "[" + itoa(index) + "]"
	if strings.TrimSpace(f.Class) == "" {
		errs.add(p+".class", "must not be empty")
	}
	if f.Count <= 0 {
		errs.add(p+".count", "must be greater than zero")
	}
	if !f.Decision.valid() {
		errs.add(p+".decision", "unrecognised decision")
	}
}
