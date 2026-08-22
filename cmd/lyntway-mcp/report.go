package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Telling the account what this machine handled, without telling it what
// the content was.
//
// # The problem this fixes
//
// The shim governed tool traffic correctly and wrote receipts to a file on
// the laptop, where nobody ever looked. Somebody ran `lyntway init`, saw
// the shim working, opened their dashboard and found it empty — which
// reads as a broken product rather than as a deliberate boundary.
//
// # The distinction that was conflated
//
// Content must stay on the machine. Findings need not.
//
// A tool result carrying a customer record is the disclosure this exists to
// prevent, so it is inspected here and never sent anywhere. But "this
// laptop's tools handled three email addresses and a card number" is not
// the customer's data — it is a count, and it is exactly what somebody
// needs to see to know the thing is working and where their exposure is.
//
// So classes and counts go to /v1/attest and nothing else does. Not the
// content, not a digest of it, not the values, not the tool's arguments.
//
// # What the receipt is allowed to claim
//
// Attested, never observed. The shim watched this, we did not, and the
// account holder is the one who installed the shim — so the honest reading
// is "a tool you run reported this", which is what /v1/attest is for and
// what it records.
//
// # Failure policy
//
// This sits inside somebody's agent. A reporter that can block a tool call
// or crash an editor is a reporter they uninstall, so every failure here
// ends in a dropped report and a line on stderr. The local receipt file is
// written either way, so nothing is lost that was not already kept.

// reporter sends finding summaries to an account, best effort.
type reporter struct {
	origin string
	key    string
	client *http.Client

	// queue is bounded and lossy on purpose. A burst of tool calls while
	// the network is slow must not grow memory inside somebody's editor,
	// and a dropped summary costs a row in a dashboard rather than a
	// receipt — the receipts are on disk regardless.
	queue chan attestation

	wg   sync.WaitGroup
	once sync.Once
}

// attestation is one governed message, reduced to what may leave.
type attestation struct {
	Server   string
	Chain    string
	Decision string
	Findings map[string]int
	Bytes    int64
}

// localConfig is what `lyntway login` wrote.
type localConfig struct {
	Origin string `json:"origin"`
	Key    string `json:"key"`
}

// newReporter returns a reporter, or nil when this machine is not signed in.
//
// Not signed in is an ordinary state, not an error: the shim is useful on
// its own and the local receipts are written either way. Returning nil
// rather than an error keeps that path silent.
func newReporter() *reporter {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	body, err := os.ReadFile(filepath.Join(home, ".lyntway", "config.json"))
	if err != nil {
		return nil
	}
	var c localConfig
	if err := json.Unmarshal(body, &c); err != nil || c.Origin == "" || c.Key == "" {
		return nil
	}

	r := &reporter{
		origin: c.Origin,
		key:    c.Key,
		// Short. This runs beside an agent waiting on a tool call, and a
		// slow reporter is worse than a missing row.
		client: &http.Client{Timeout: 5 * time.Second},
		queue:  make(chan attestation, 256),
	}
	r.wg.Add(1)
	go r.run()
	return r
}

// report queues a summary. Never blocks, never fails.
func (r *reporter) report(a attestation) {
	if r == nil {
		return
	}
	select {
	case r.queue <- a:
	default:
		// Full. Dropped deliberately rather than blocking the agent.
	}
}

func (r *reporter) run() {
	defer r.wg.Done()
	for a := range r.queue {
		if err := r.send(a); err != nil {
			fmt.Fprintf(os.Stderr, "lyntway-mcp: a summary was not reported: %v\n", err)
		}
	}
}

// send posts one summary.
func (r *reporter) send(a attestation) error {
	findings := make([]map[string]any, 0, len(a.Findings))
	for class, count := range a.Findings {
		findings = append(findings, map[string]any{"class": class, "count": count})
	}

	body, err := json.Marshal(map[string]any{
		"chain_id": a.Chain,
		"tool":     "lyntway-mcp",
		"action": map[string]any{
			"surface":   "mcp",
			"direction": "response",
			"method":    "tools/call",
			// Where the data came from, named as the person would name it.
			// An auditor asking what handled their data wants the server,
			// not the shim that watched it.
			"destination": a.Server,
		},
		"actor": map[string]any{
			"type": "agent",
			"id":   "lyntway-mcp",
		},
		"decision": a.Decision,
		"findings": findings,
		"bytes":    a.Bytes,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, r.origin+"/v1/attest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.key)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("the service answered %d", resp.StatusCode)
	}
	return nil
}

// close drains what is queued and stops.
//
// Bounded, because a shim that hangs on exit is a shim that hangs the
// editor that spawned it. Whatever has not gone by then stays in the local
// receipt file, which is the copy that matters.
func (r *reporter) close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		close(r.queue)
		done := make(chan struct{})
		go func() { r.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	})
}
