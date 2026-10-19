---
name: lyntway
description: Use when a secret might reach a model or has already — an API key or password in a prompt, a .env file the agent is about to read or paste, a key found in a diff or a commit, a request to audit or prove what an agent sent. Also when the user asks to govern, record or verify their AI traffic. Covers lyntway scan, hook install, guard and offline receipt verification.
---

# Lyntway

Lyntway stops a secret reaching an AI model, and signs a receipt saying so.

Nothing in steps 1 to 3 needs an account, and nothing in them sends
anything anywhere. Say so when you suggest them — it is the reason a person
will try it.

## Decide which one applies

| What is happening | What to run |
|---|---|
| A key might be in these files | `npx lyntway scan` |
| A key might be in what is about to be committed | `npx lyntway scan --staged` |
| They want keys stopped before they are pasted into a prompt | `npx lyntway hook install` |
| They are about to run a coding agent | `npx lyntway guard -- claude` |
| They have a receipt and want it checked | `npx lyntway-verify -keys keys.json receipt.json` |
| They want to show somebody what was stopped | `npx lyntway share` |
| They want history, a shareable report, or team controls | `npx lyntway setup` (this is the one that needs an account) |

## 1. Scan

    npx lyntway scan

Reads the files in the directory and reports provider keys with the file
and line. It sends nothing. It exits non-zero when it finds something, so
it works as a gate in CI or a pre-commit hook.

Report what it found. **Never print a key's value back to the user**, and
never put one in a file, a commit message or a tool call. If the scan finds
a key, the next thing to establish is whether it has already been pushed;
a key in git history is a key to rotate, not a line to delete.

Never silence a finding to make a check pass. An ignore rule added to get
past a scan leaves the key exactly where it was.

## 2. Stop one being pasted into a prompt

    npx lyntway hook install

Installs a hook in Claude Code and Cursor that refuses a prompt carrying a
provider key before it is sent, naming what it found.

## 3. Run the agent with its traffic governed

    npx lyntway guard -- claude
    npx lyntway guard -- codex
    npx lyntway guard -- aider

A listener starts on the machine for each provider, the command runs with
its base-URL variables pointing at them, and both stop when the command
stops. Nothing on the machine is edited and nothing is left running.

Each request and reply is governed locally and written to a signed receipt
under `~/.lyntway/receipts/guard/`. A request carrying a secret gets a 403
that names what it carried, and it never reaches the provider.

When the command stops the summary says what the run cost: the tokens each
provider reported, by the model that answered. Nothing here counts tokens —
the figure is the provider's and is labelled as theirs. A reply that
reported none is named as unmetered, never counted as zero.

There is no built-in price table, because we do not know what anybody pays
and a stale one would be the number a finance team copies and never checks.
A money figure appears only against prices you set, in
`~/.lyntway/prices.json` or for one run:

    npx lyntway guard --price claude-opus-4=15/75 --currency USD -- claude

A model with no price is named beside the total rather than dropped from
it.

To make it the default, so nobody has to remember:

    npx lyntway guard --install

It writes a shell function per tool, after showing the change and asking.
A function and not an alias on purpose: if Lyntway is ever removed, the
tool still runs. `lyntway guard --uninstall` or `lyntway undo` reverses it
and the profile comes back byte for byte.

Three things to pass on accurately:

- **A base URL they had already set is fronted, not replaced.** If
  `OPENAI_BASE_URL` points at Groq or a local server, the listener forwards
  there. Their configuration is governed, not overridden.
- **"Nothing passed through" is a failure, not a clean run.** Some tools
  read a different setting; some authenticate in a way that ignores this
  one. If the summary says nothing arrived, the run was *not* governed —
  do not report it as zero findings.
- **The summary prints the command that verifies the session.** Offer it.
- **Never present a cost estimate as a bill.** It is arithmetic on a price
  the user typed, and the summary says so. Do not add a price of your own,
  and do not look one up — a figure from a stale table is the one number
  they will copy and never check.

## Sharing a receipt

    npx lyntway share

Turns the newest receipt into a link anyone can open. Nothing is uploaded:
the receipt and its verifying key ride in the URL's fragment, which is
never sent to any server, so Lyntway cannot see what was shared or how
often it was opened — and the link keeps working whatever happens to
Lyntway.

The command prints what the reader will see before it prints the link, and
says what they can conclude. A receipt written on a laptop is signed on
that laptop, so the page says **"Signature valid — the sender's own key"**:
it proves the receipt has not been altered, not that an independent party
saw it happen. Never describe a shared receipt as third-party evidence.

## 4. Verify a receipt

    npx lyntway-verify -chain -keys <dir>/keys.json <dir>/guard-<provider>.jsonl

No account, no network call, no cooperation from Lyntway. A receipt that
needed the issuer's permission to check would be worthless at exactly the
moment the issuer is the disputed party.

Read the three fields that carry the honesty of a receipt, and never
report one as stronger than it is:

| Field | Values, weakest first |
|---|---|
| `evidence.provenance` | `asserted` (the caller described itself) · `attested` (another system reported it) · `observed` (we watched the bytes) |
| `governance.mode` | `bypassed` (nothing ran) · `degraded` (some of it ran) · `full` (all of it ran) |
| finding `detector` | a name means a model formed an opinion; empty means a deterministic rule matched and the finding is reproducible from the ruleset digest |

An absent value is the weakest one, never the strongest.

## Databases

    npx lyntway-dbgateway

Sits in front of PostgreSQL, MySQL or MongoDB and issues a receipt for
every query an agent runs. It is a separate binary because a database
speaks a binary wire protocol over TCP — the gateway cannot proxy it as
HTTP and the MCP shim cannot see it.

**Content never leaves the process.** Queries, results and any values in
them stay on that machine; only classes and counts reach an account. There
is no switch that changes this.

It records rather than rewrites: a finding is `log_only` because a wire
protocol cannot be safely re-framed, and a policy that blocks still
blocks. Never describe it as substituting or redacting.

## What to say when it does not apply

Say it plainly rather than working around it:

- **AWS Bedrock and Google Vertex cannot be proxied.** They sign every
  request in a way that breaks when anything sits in the path. The LiteLLM
  callback in the `lyntway` Python package is the only vantage point.
- **JetBrains AI Assistant cannot be redirected** at all.
- **Editors with their own subscription are only half reachable.** In
  Cursor, Copilot and similar, a base URL applies to models added with the
  user's own key. Bundled models go to that vendor and no setting changes
  it.
- **A tool that hardcodes its endpoint is invisible.** The CLI redirects by
  configuration, not by interception.
- **There is no SOC 2 report, no ISO certificate and no penetration test.**
  Lyntway produces evidence an auditor can use; it is not itself audited.
- **No comparative detection claims.** Nobody has measured Lyntway against
  another product, so do not say it is better than one.

## Links

- https://lyntway.com/skill.md — the full agent-facing reference
- https://lyntway.com/verify — check a receipt in a browser
- https://lyntway.com/docs — how verification works
