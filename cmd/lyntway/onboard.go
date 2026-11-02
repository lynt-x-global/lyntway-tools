package main

import (
	"fmt"
	"strings"
)

// The parts of setup that are about the person rather than the machine.
//
// Everything else in setup answers "what is here and how do I route it".
// These three answer "who is this for, who else needs it, and is it
// actually covered" — and they were missing, so somebody finished setup
// with their own tools routed, nobody else invited, two whole surfaces
// uncovered and no sentence saying any of that.
//
// # Why the audience question is asked at all
//
// It changes what is offered and never what is enforced. One person
// working alone does not want to be asked about invitations or a fleet
// agent, and a team that is not asked never finds them — the console has
// both, three clicks apart, and nobody goes looking for a page they do
// not know exists. Asking once and remembering the answer costs one line
// and removes the two worst outcomes.

const (
	audienceOrganisation = "organisation"
	audiencePersonal     = "personal"
)

// askAudience asks who this machine is being set up for, once ever.
func askAudience(c config, yes bool) (config, bool) {
	if c.Audience != "" {
		return c, false
	}
	if yes {
		// --yes means "do not ask me things", not "assume I have a
		// team". The quieter answer is the one that offers less.
		c.Audience = audiencePersonal
		return c, false
	}

	fmt.Fprintln(stdout, "\n2. Who is this for")
	fmt.Fprintln(stdout, "   An organisation — colleagues will use this too")
	fmt.Fprintln(stdout, "   Just me — one person, one machine")
	switch askLine("\n   [O]rganisation or just [m]e? [O/m] ") {
	case "m", "me", "j", "just me", "personal", "individual", "freelancer":
		c.Audience = audiencePersonal
		fmt.Fprintln(stdout, "   Just you. Nothing here will ask about a team again.")
	default:
		c.Audience = audienceOrganisation
		fmt.Fprintln(stdout, "   An organisation. The account this machine signed in to is yours to administer.")
	}
	return c, true
}

// offerTeam points an organisation at the page that invites people.
//
// The browser rather than the terminal, deliberately. Inviting somebody
// is a console action behind a session, and the alternative would be an
// API-key endpoint that can add a member to an organisation — so a
// gateway key leaked from a .env file could make an attacker an owner.
// A key that governs traffic must not be able to grant access, and the
// browser used to sign in a moment ago is already holding a session that
// can.
//
// No addresses are collected here and none are put in the URL. A query
// string lands in browser history and in every log between here and the
// page; the invite form asks for them where they belong.
func offerTeam(c config, yes bool) {
	if c.Audience != audienceOrganisation || yes || c.Origin == "" {
		return
	}
	fmt.Fprintln(stdout, "\n6. Your team")
	fmt.Fprintln(stdout, "   Colleagues need their own sign-in — a shared key is a key nobody can revoke")
	fmt.Fprintln(stdout, "   without locking everybody out.")
	switch askLine("\n   Open the page to invite them? [Y/n] ") {
	case "", "y", "yes":
		url := c.Origin + "/settings?tab=team"
		fmt.Fprintf(stdout, "   Opening %s\n", url)
		openBrowser(url)
	default:
		fmt.Fprintf(stdout, "   Skipped. It is at %s/settings?tab=team when you want it.\n", c.Origin)
	}
}

// coverageGap is a surface setup cannot cover by itself.
type coverageGap struct {
	What    string
	Why     string
	Command string
}

// remainingCoverage names what setup did not cover.
//
// setup routes this machine's command-line tools, and that is all it can
// do: a browser tab has its own network stack and a server is not this
// machine. Both were already reported as uncovered in the device report
// it sends — "Setup does not install the browser extension" — and said
// nowhere a person would see it. A gap the product knows about and does
// not mention reads, to the person who finished setup, as covered.
func remainingCoverage(c config) []coverageGap {
	gaps := []coverageGap{
		{
			What:    "Browser tabs",
			Why:     "chatgpt.com, claude.ai and Copilot are pasted into, not called through a key",
			Command: "the extension, from " + c.Origin + "/on-device",
		},
		{
			What:    "Local models",
			Why:     "Ollama and LM Studio are reached on this machine and never cross the network",
			Command: "lyntway proxy",
		},
	}
	if c.Audience == audienceOrganisation {
		gaps = append(gaps, coverageGap{
			What:    "Other machines",
			Why:     "this set up the one you are on; a colleague's laptop is not covered by it",
			Command: "lyntway device, from an enrolment key at " + c.Origin + "/on-device",
		})
	}
	return gaps
}

// welcome is the last thing setup prints.
//
// It used to be one line — "Lyntway is ready" — after a summary of what
// had been changed. That is a true sentence and the wrong last word: it
// reads as "you are covered" to somebody whose browser, local models and
// colleagues' machines are not. The close now says what is governed, what
// is not and what to run next, in that order, because the gap is the part
// they cannot find out any other way.
func welcome(c config, gaps []coverageGap, routed, migrated bool) {
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, strings.Repeat("─", 50))
	fmt.Fprintln(stdout, "Welcome to Lyntway.")
	fmt.Fprintln(stdout)

	switch {
	case routed && migrated:
		fmt.Fprintln(stdout, "   This machine's AI tools now go through the gateway, your provider")
		fmt.Fprintln(stdout, "   keys are held there instead of in .env, and every call leaves a")
		fmt.Fprintln(stdout, "   signed receipt.")
	case routed:
		fmt.Fprintln(stdout, "   This machine's AI tools now go through the gateway, and every call")
		fmt.Fprintln(stdout, "   they make leaves a signed receipt.")
	case migrated:
		fmt.Fprintln(stdout, "   Your provider keys are held by the gateway instead of sitting in")
		fmt.Fprintln(stdout, "   .env. Route this machine's tools with `lyntway init` to have their")
		fmt.Fprintln(stdout, "   calls receipted too.")
	default:
		// Nothing was changed, and saying otherwise here would be the
		// one claim this product exists to refuse, made in the last
		// sentence somebody reads.
		fmt.Fprintln(stdout, "   Nothing on this machine was changed — every step was skipped.")
		fmt.Fprintln(stdout, "   Run `lyntway setup` again, or `lyntway init` to route its tools.")
	}

	if len(gaps) > 0 {
		fmt.Fprintln(stdout, "\n   Not yet covered:")
		for _, g := range gaps {
			fmt.Fprintf(stdout, "     %-15s %s\n", g.What, g.Why)
			fmt.Fprintf(stdout, "     %-15s → %s\n", "", g.Command)
		}
	}

	fmt.Fprintln(stdout, "\n   lyntway status        what is covered, and what is not")
	fmt.Fprintln(stdout, "   lyntway secure        what your AI tools have already seen")
	if c.Origin != "" {
		fmt.Fprintf(stdout, "   %s — your receipts\n", c.Origin+"/overview")
	}
	fmt.Fprintln(stdout, "\n   Undo all of it with `lyntway undo`.")
}
