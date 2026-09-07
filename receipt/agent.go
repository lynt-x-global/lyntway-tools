package receipt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// # Agents, and what a receipt can honestly say about one
//
// An agent identity is a claim. Whoever issues it — this deployment, a
// SPIFFE trust domain, a certificate authority — is vouching for who the
// agent is, and a verifier weighs that as far as they trust the issuer. It
// is never observed: nothing about watching the bytes tells you which
// agent sent them. So the identity sits on the actor, beside the existing
// Source and Verified fields, and the honesty of the receipt still rests on
// the receipt's own provenance.
//
// What makes the identity worth carrying is the manifest. At registration
// an agent declares what it is — its models, its tools, what it may reach.
// The deployment countersigns that declaration so the agent cannot later
// deny having made it, and every receipt the agent produces names the
// manifest by digest. The declaration is the agent's claim; the receipts
// are what it did; the difference between them is a finding no inventory
// of declarations alone can produce.

// AgentIdentity binds a receipt to a registered agent.
type AgentIdentity struct {
	// ID identifies the agent within Issuer's namespace: a registration
	// id here, a SPIFFE ID, a certificate subject.
	ID string `json:"id"`

	// Issuer names who vouches for the identity. "lyntway" when the agent
	// was registered with this deployment; otherwise the trust domain or
	// authority that issued it. Required, because an identity with no
	// issuer is an identity nobody stands behind.
	Issuer string `json:"issuer"`

	// KeyID names the key that signed the manifest this identity refers
	// to, so a verifier can check the manifest with the same published
	// keys that check the receipt. Optional for external issuers.
	KeyID string `json:"key_id,omitempty"`

	// Manifest is the hex SHA-256 digest of the signed manifest the agent
	// registered: the exact declaration this receipt should be judged
	// against. By digest, never by name, for the reason recorded above
	// the Chain type — a name can be repointed; a digest names the bytes.
	Manifest string `json:"manifest,omitempty"`
}

func (a *AgentIdentity) validateInto(errs *FieldErrors) {
	if strings.TrimSpace(a.ID) == "" {
		errs.add("actor.agent.id", "must not be empty")
	}
	if strings.TrimSpace(a.Issuer) == "" {
		errs.add("actor.agent.issuer", "must name who vouches for the identity")
	}
	if a.Manifest != "" && !isHexDigest(a.Manifest) {
		errs.add("actor.agent.manifest", "must be a lowercase hex SHA-256 digest")
	}
}

// AgentManifestVersion identifies the manifest schema.
const AgentManifestVersion = "lyntway-agent-manifest/1"

// agentManifestDomain separates manifest signatures from every other
// signature the same root key makes. See keyAttestationDomain.
const agentManifestDomain = "lyntway-agent-manifest-v1\x00"

// AgentManifest is an agent's declaration of what it is, countersigned by
// the deployment.
//
// Everything in it is the agent's claim. The signature does not make the
// claim true; it makes it non-repudiable, and it fixes the exact bytes a
// receipt's AgentIdentity.Manifest refers to.
type AgentManifest struct {
	// Version is the manifest schema version.
	Version string `json:"version"`

	// AgentID is the identifier the deployment assigned at registration.
	AgentID string `json:"agent_id"`

	// Name is what the operator calls the agent. Advisory.
	Name string `json:"name"`

	// Owner is the tenant the agent belongs to.
	Owner string `json:"owner"`

	// Models, Tools and Reach are what the agent declares it uses. Reach
	// entries are "<surface>:<destination>" — model:api.openai.com,
	// mcp:filesystem, database:customers — the destinations it says it may
	// touch. A receipt whose action falls outside Reach is drift.
	Models []string `json:"models,omitempty"`
	Tools  []string `json:"tools,omitempty"`
	Reach  []string `json:"reach,omitempty"`

	// PromptDigest is the hex SHA-256 of the agent's system prompt. The
	// prompt itself is never carried: the manifest is published-safe, and
	// a digest is enough to prove a later prompt is not the declared one.
	PromptDigest string `json:"prompt_digest,omitempty"`

	// Revision distinguishes successive manifests for the same agent. A
	// manifest is never edited; a change is a new manifest.
	Revision string `json:"revision,omitempty"`

	// RegisteredAt is when the deployment countersigned, RFC 3339 UTC.
	RegisteredAt string `json:"registered_at"`

	// PublicKey and Algorithm describe the agent's own key, when it holds
	// one, base64 standard encoding of the raw form. Optional: an agent
	// that only calls through the gateway has no key of its own.
	PublicKey string    `json:"public_key,omitempty"`
	Algorithm Algorithm `json:"algorithm,omitempty"`

	// RootKeyID and RootAlgorithm identify the deployment key that
	// countersigned. A verifier resolves it from the published keys.
	RootKeyID     string    `json:"root_key_id"`
	RootAlgorithm Algorithm `json:"root_algorithm"`

	// Signature is the root key's signature over the manifest, base64.
	// omitempty for the reason given on KeyAttestation.Signature.
	Signature string `json:"signature,omitempty"`
}

// Validate checks a manifest is well-formed. It does not check the
// signature; see VerifyAgentManifest.
func (m *AgentManifest) Validate() error {
	var errs FieldErrors
	if m.Version != AgentManifestVersion {
		errs.add("version", fmt.Sprintf("must be %q", AgentManifestVersion))
	}
	if strings.TrimSpace(m.AgentID) == "" {
		errs.add("agent_id", "must not be empty")
	}
	if strings.TrimSpace(m.Owner) == "" {
		errs.add("owner", "must not be empty")
	}
	if m.PromptDigest != "" && !isHexDigest(m.PromptDigest) {
		errs.add("prompt_digest", "must be a lowercase hex SHA-256 digest")
	}
	if _, err := time.Parse(time.RFC3339, m.RegisteredAt); err != nil {
		errs.add("registered_at", "must be RFC 3339")
	}
	for i, r := range m.Reach {
		surface, dest, ok := strings.Cut(r, ":")
		if !ok || strings.TrimSpace(dest) == "" || !Surface(surface).valid() {
			errs.add(fmt.Sprintf("reach[%d]", i), "must be <surface>:<destination> with a known surface")
		}
	}
	if (m.PublicKey == "") != (m.Algorithm == "") {
		errs.add("public_key", "public_key and algorithm go together")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// signingInput returns the exact bytes the countersignature covers.
func (m *AgentManifest) signingInput() ([]byte, error) {
	unsigned := *m
	unsigned.Signature = ""
	body, err := Canonicalize(&unsigned)
	if err != nil {
		return nil, fmt.Errorf("receipt: canonicalizing agent manifest: %w", err)
	}
	return append([]byte(agentManifestDomain), body...), nil
}

// AgentManifestDigest is the digest a receipt names the manifest by.
//
// Over the signing input rather than the signed document, for the same
// reason receipts are: the signature is a property of the copy, the
// declaration is the thing.
func AgentManifestDigest(m *AgentManifest) (string, error) {
	input, err := m.signingInput()
	if err != nil {
		return "", err
	}
	return DigestContent(input), nil
}

// SignAgentManifest countersigns a manifest with the deployment's key.
func SignAgentManifest(m *AgentManifest, root Signer) error {
	if root == nil {
		return errors.New("receipt: a root signer is required to sign a manifest")
	}
	if m.Version == "" {
		m.Version = AgentManifestVersion
	}
	m.RootKeyID = root.KeyID()
	m.RootAlgorithm = root.Algorithm()
	m.Signature = ""
	if err := m.Validate(); err != nil {
		return err
	}
	input, err := m.signingInput()
	if err != nil {
		return err
	}
	sig, err := root.Sign(input)
	if err != nil {
		return fmt.Errorf("receipt: signing agent manifest: %w", err)
	}
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// ErrManifestInvalid means the manifest's countersignature does not check
// out, so nothing it declares can be attributed to the deployment.
var ErrManifestInvalid = errors.New("receipt: agent manifest is not valid")

// VerifyAgentManifest checks the countersignature against the deployment's
// published keys.
func VerifyAgentManifest(m *AgentManifest, roots KeyResolver) error {
	if m == nil {
		return errors.New("receipt: nil agent manifest")
	}
	if roots == nil {
		return errors.New("receipt: nil key resolver")
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrManifestInvalid, err)
	}
	if m.Signature == "" {
		return fmt.Errorf("%w: unsigned", ErrManifestInvalid)
	}
	rootKey, err := roots.ResolveKey(m.RootKeyID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrManifestInvalid, err)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not valid base64", ErrManifestInvalid)
	}
	input, err := m.signingInput()
	if err != nil {
		return err
	}
	if !VerifyRaw(m.RootAlgorithm, rootKey, input, sig) {
		return fmt.Errorf("%w: the deployment key did not sign this manifest", ErrManifestInvalid)
	}
	return nil
}
