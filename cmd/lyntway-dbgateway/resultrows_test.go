package main

import (
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// The Postgres proxy governs every DataRow it relays. MySQL and MongoDB
// copy the server's reply straight through with io.CopyBuffer — their
// relays do not even take a governor — because neither result-set framing
// is parsed here. The query is examined on all three, so all three wrote a
// receipt, and nothing on it told them apart: a SELECT returning ten
// thousand card numbers left the same record as one returning none, under
// evidence.provenance: observed and governance.mode: full.
func TestAProtocolThatDoesNotReadItsRepliesSaysSoOnTheReceipt(t *testing.T) {
	g := testGovernor(t)

	for _, proto := range []string{"MySQL", "MongoDB"} {
		t.Run(proto, func(t *testing.T) {
			res, err := g.governQueryUninspectedReplies("neon", auditQuery, "SELECT", proto)
			if err != nil {
				t.Fatal(err)
			}
			rec := res.Receipt

			var found *receipt.Component
			for i := range rec.Governance.Detector.Components {
				if rec.Governance.Detector.Components[i].Name == componentResultRows {
					found = &rec.Governance.Detector.Components[i]
				}
			}
			if found == nil {
				t.Fatalf("no %q component: the receipt says nothing about rows nobody read", componentResultRows)
			}
			if found.Health != receipt.HealthUnavailable {
				t.Errorf("the rows component reports %q; nothing read them", found.Health)
			}
			if found.Detail == "" {
				t.Error("unavailable with no detail: a reader cannot tell what went unexamined")
			}

			// The mode is the field a verifier reads first, and it must not
			// say every component ran.
			if rec.Governance.Mode == receipt.ModeFull {
				t.Errorf("governance.mode is %q while the replies went unread", rec.Governance.Mode)
			}
			if rec.Governance.Detector.Health == receipt.HealthHealthy {
				t.Errorf("detector.health is %q while a component is unavailable", rec.Governance.Detector.Health)
			}

			// And it must still be a receipt anyone can verify: the
			// validator refuses a mode that disagrees with its components,
			// so this is also the check that the two stay consistent.
			if err := rec.Validate(); err != nil {
				t.Errorf("the receipt does not validate: %v", err)
			}
		})
	}
}

// Postgres reads its rows, so claiming otherwise on its receipts would be
// the same fault in the opposite direction.
func TestPostgresDoesNotReportItsRowsAsUnread(t *testing.T) {
	g := testGovernor(t)

	res, err := g.governQuery("neon", auditQuery, "SELECT")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Receipt.Governance.Detector.Components {
		if c.Name == componentResultRows {
			t.Fatalf("a Postgres query receipt carries %q, but pgRelayServerToClient governs every DataRow", componentResultRows)
		}
	}
	if res.Receipt.Governance.Mode != receipt.ModeFull {
		t.Errorf("governance.mode is %q on a path where everything ran", res.Receipt.Governance.Mode)
	}
}
