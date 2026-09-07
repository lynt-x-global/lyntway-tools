package receipt

import (
	"strings"
	"testing"
)

func manifest() *AgentManifest {
	return &AgentManifest{
		AgentID: "agt_0123456789abcdef01234567", Name: "support-bot", Owner: "t_acme",
		Models: []string{"gpt-4o"}, Tools: []string{"supabase.query"},
		Reach:        []string{"model:api.openai.com", "database:customers"},
		PromptDigest: strings.Repeat("ab", 32), Revision: "3",
		RegisteredAt: "2026-09-04T10:00:00Z",
	}
}

// The signature makes the declaration non-repudiable and fixes the bytes a
// receipt refers to. It must survive a round trip and nothing else.
func TestAManifestSignsVerifiesAndNamesItsBytes(t *testing.T) {
	root, err := GenerateEd25519Signer("root-1")
	if err != nil {
		t.Fatal(err)
	}
	m := manifest()
	if err := SignAgentManifest(m, root); err != nil {
		t.Fatal(err)
	}
	keys := StaticKeyResolver{root.KeyID(): root.Public()}
	if err := VerifyAgentManifest(m, keys); err != nil {
		t.Fatalf("a freshly signed manifest does not verify: %v", err)
	}
	digest, err := AgentManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	if !isHexDigest(digest) {
		t.Errorf("digest %q is not hex SHA-256", digest)
	}

	// The digest names the declaration, not the copy: it is the same with
	// or without the signature attached.
	unsigned := *m
	unsigned.Signature = ""
	again, _ := AgentManifestDigest(&unsigned)
	if again != digest {
		t.Error("the digest changes with the signature, so a receipt could not name the declaration")
	}

	// Change one declared destination and the deployment's signature no
	// longer covers what is claimed.
	tampered := *m
	tampered.Reach = append([]string{}, m.Reach...)
	tampered.Reach[1] = "database:everything"
	if err := VerifyAgentManifest(&tampered, keys); err == nil {
		t.Error("an altered declaration still verified")
	}
	other, _ := GenerateEd25519Signer("root-2")
	if err := VerifyAgentManifest(m, StaticKeyResolver{other.KeyID(): other.Public()}); err == nil {
		t.Error("verified against a key that did not sign it")
	}
}

func TestAManifestRefusesTheMalformed(t *testing.T) {
	root, _ := GenerateEd25519Signer("root-1")
	for name, mutate := range map[string]func(*AgentManifest){
		"bad reach":       func(m *AgentManifest) { m.Reach = []string{"api.openai.com"} },
		"unknown surface": func(m *AgentManifest) { m.Reach = []string{"cloud:api.openai.com"} },
		"bad prompt":      func(m *AgentManifest) { m.PromptDigest = "notahash" },
		"no owner":        func(m *AgentManifest) { m.Owner = "" },
		"key without alg": func(m *AgentManifest) { m.PublicKey = "AAAA" },
	} {
		m := manifest()
		mutate(m)
		if err := SignAgentManifest(m, root); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

// An identity on a receipt is a claim about who, never about what was
// seen, and it must at least say who is making it.
func TestAnAgentIdentityMustNameItsIssuer(t *testing.T) {
	var errs FieldErrors
	(&AgentIdentity{ID: "agt_x"}).validateInto(&errs)
	if len(errs) == 0 {
		t.Error("an identity nobody vouches for was accepted")
	}
	errs = nil
	(&AgentIdentity{ID: "agt_x", Issuer: "lyntway", Manifest: "zz"}).validateInto(&errs)
	if len(errs) == 0 {
		t.Error("a non-hex manifest digest was accepted")
	}
	errs = nil
	(&AgentIdentity{ID: "spiffe://acme/agent/support", Issuer: "spiffe"}).validateInto(&errs)
	if len(errs) != 0 {
		t.Errorf("a well-formed external identity was refused: %v", errs)
	}
}
