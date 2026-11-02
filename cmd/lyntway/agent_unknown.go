package main

import (
	"fmt"
	"io"
	"time"
)

// What is reaching an AI service from this machine right now, including
// the things nobody has a name for.
//
// # Why this exists next to the inventory
//
// The inventory answers "which of the AI tools we know about are here",
// from a catalogue of twenty-four products. It is the right answer to the
// question a security team asks first and the wrong answer to the one that
// actually worries them: a script somebody wrote, a vendor's agent nobody
// announced, a binary with an innocent name — none of those is in any
// catalogue, and a list built only from a catalogue reports a clean
// machine.
//
// The connection table answers it instead. A process holding a socket to
// api.openai.com is reaching OpenAI whether or not we have heard of it,
// and appForProcess already says which of the two it is.
//
// # Why this is a snapshot and the device agent samples
//
// One look sees the connections that are open at that instant. The agent
// samples on an interval for exactly that reason, and over a day it sees
// far more. So the honest reading of an empty result here is "nothing was
// connected in the moment we looked", never "nothing connects" — which is
// why emptiness is reported with that sentence rather than as a clean
// bill.
//
// # Why there is a budget
//
// Attributing an address to a host means resolving the known AI hosts
// through this machine's own resolver. On a warm cache that is fast; on a
// cold one, behind a captive portal, or offline, forty-five lookups can
// take longer than the whole scan is allowed. So the look is bounded and a
// budget that runs out is reported as a look that did not finish. A scan
// that silently skipped this and printed nothing would read as a machine
// with no AI traffic on it, which is the failure this whole file exists to
// prevent.

// agentSighting is one thing reaching one AI destination.
type agentSighting struct {
	// App is the application the catalogue named, or the process's own
	// name when the catalogue did not.
	App string

	// Host is the destination, or "localhost:<port>" for a local model
	// server.
	Host string

	Connections int

	// Unrecognised says the catalogue has no entry for whatever is holding
	// this connection.
	Unrecognised bool
}

// agentDiscovery is the result of one look at the connection table.
type agentDiscovery struct {
	Sightings []agentSighting

	// Looked says the connection table was read and attributed. When
	// false, Why says what stopped it and the sightings are whatever was
	// gathered before that — never presented as the whole picture.
	Looked bool
	Why    string
}

// Unrecognised returns only the sightings the catalogue could not name.
func (d agentDiscovery) Unrecognised() []agentSighting {
	var out []agentSighting
	for _, s := range d.Sightings {
		if s.Unrecognised {
			out = append(out, s)
		}
	}
	return out
}

// discoverAgents takes one look at what is reaching an AI service.
//
// budget bounds the whole operation including name resolution. The
// aggregator and resolver are the device agent's own, so there is one
// implementation of "which application does this connection belong to"
// and the free scan and the enrolled agent cannot come to disagree about
// it — the mistake that shipped two browser extensions.
func discoverAgents(goos string, budget time.Duration) agentDiscovery {
	conns, err := sampleConnections(goos)
	if err != nil {
		return agentDiscovery{Why: "this machine's connection table could not be read: " + err.Error()}
	}
	if len(conns) == 0 {
		return agentDiscovery{Looked: true}
	}

	procs, _ := listProcesses(goos)
	byPID := make(map[int]procInfo, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}

	// Resolution is the only slow part, so it is the part under the
	// budget. done closes either way; a timeout leaves the resolver
	// holding whatever it managed, which is still correct for the
	// addresses it did resolve.
	r := newHostResolver()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.refresh()
	}()
	select {
	case <-done:
	case <-time.After(budget):
		return agentDiscovery{
			Why: "the AI service addresses could not be looked up inside " +
				budget.String() + ", so nothing here is attributed",
		}
	}

	a := newDestAggregator()
	a.add(conns, byPID, goos, r)

	rows := a.rows()
	out := agentDiscovery{Looked: true, Sightings: make([]agentSighting, 0, len(rows))}
	for _, d := range rows {
		out.Sightings = append(out.Sightings, agentSighting{
			App: d.App, Host: d.Host, Connections: d.Connections, Unrecognised: d.Unrecognised,
		})
	}
	return out
}

// writeAgentSightings prints what was reaching an AI service.
//
// The unrecognised ones lead, because they are the only part of this a
// person could not have told you themselves.
//
// Three outcomes and three different sentences, because they are three
// different facts: the look failed, the look found nothing open at that
// instant, or the look found things. The middle one is the dangerous one —
// printed as "no AI traffic" it would read as a clean machine, when all it
// means is that nothing was mid-request while we looked.
func writeAgentSightings(w io.Writer, d agentDiscovery) {
	if !d.Looked {
		fmt.Fprintf(w, "\nWhat is reaching an AI service\n"+
			"  Not established: %s\n", d.Why)
		return
	}
	if len(d.Sightings) == 0 {
		fmt.Fprint(w, "\nWhat is reaching an AI service\n"+
			"  Nothing was connected in the moment this looked. One look sees only\n"+
			"  what is open at that instant, so this is not the same as nothing\n"+
			"  ever connecting.\n")
		return
	}

	if un := d.Unrecognised(); len(un) > 0 {
		fmt.Fprintf(w, "\nReaching an AI service, and not recognised (%d)\n", len(un))
		for _, s := range un {
			fmt.Fprintf(w, "  %-28s → %-34s %d %s\n", s.App, s.Host, s.Connections,
				plural(s.Connections, "connection", "connections"))
		}
		fmt.Fprint(w, "\n  Nothing here says these are a problem. It says no list in this tool\n"+
			"  has a name for them, which is worth one look from somebody who knows\n"+
			"  what should be running.\n")
	}

	var named []agentSighting
	for _, s := range d.Sightings {
		if !s.Unrecognised {
			named = append(named, s)
		}
	}
	if len(named) > 0 {
		fmt.Fprintf(w, "\nReaching an AI service (%d)\n", len(named))
		for _, s := range named {
			fmt.Fprintf(w, "  %-28s → %-34s %d %s\n", s.App, s.Host, s.Connections,
				plural(s.Connections, "connection", "connections"))
		}
	}
}
