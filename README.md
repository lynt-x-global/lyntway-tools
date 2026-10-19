# Lyntway tools

Four command-line tools, and the packages behind them. No third-party
dependencies — the whole module is standard library, so what goes into the
tool that checks receipts can be read in an afternoon.

| Tool | What it does | Needs an account |
|---|---|---|
| `lyntway-verify` | Checks a receipt. No network calls, ever. | No |
| `lyntway-mcp` | Runs between an agent and an MCP server, and governs tool results on the machine they land on. | No |
| `lyntway` | Reports what AI software is on a machine, and can point it at a Lyntway service. | Only to record |
| `lyntway-dbgateway` | Sits in front of PostgreSQL, MySQL or MongoDB and receipts every query. Content never leaves the process. | Yes, to know which databases |

## Install

```bash
brew install lynt-x-global/lyntway/lyntway
```

Or download a build for your platform from
[releases](https://github.com/lynt-x-global/lyntway-tools/releases) and put
the three binaries on your `PATH`.

## Start here

```bash
lyntway
```

No account, no sign-up, no network call. It reads this machine's own
configuration files and process list and tells you what is there:

```
lyntway — what is on this machine

  mb-air.local · macos 26.5 · someone

AI tools (9)
  Claude                                   running    2.37337.1
  Claude Code                              running    2.1.300
  Cline in VS Code                         running    4.1.25
  Codex in VS Code                         running    26.1007.21434
  llama.cpp server                         installed  version unknown

MCP servers your agents are configured to reach (3)
  Claude Code            heyreach                 mcp.heyreach.io
  Claude Code            atlassian                api.atlassian.com        credential in config
  Claude Code            internal-crm             local process            credential in config

  2 of these have a credential written into the config file beside
  them. Anything that can read that file can read the credential.

Provider keys in this directory (1)
  server/.env:12	OpenAI key	…4f9a

Nothing left this machine. Everything above was read from this
computer's own configuration files and its process list: no traffic was
watched, no value was copied out of any file, and no account was needed.

Nothing here is being recorded yet.
```

That last line is the honest one. This screen is a list of what is
**configured** — not of what anything did. It is read from files on disk,
so an agent that was installed somewhere this does not look is not in it,
and `lyntway agent --explain` says exactly where it looks and what it never
collects.

Recording what those tools actually send is a different job, and that is
what the rest of this is for.

## Running a coding agent with its traffic governed

```bash
lyntway guard -- claude
```

A listener starts on this machine for each provider, the command runs with
its base-URL variables pointing at them, and both stop when the command
stops. Nothing on the machine is edited and nothing is left running.

Every request and reply is governed here and written to a signed receipt
under `~/.lyntway/receipts/guard/`. A request carrying a secret is answered
with a 403 naming what it carried, and never reaches the provider:

```
✗ lyntway stopped this request — Supabase secret key (secret.supabase_key) ×1 · receipt rcpt_c6d934df…
```

Three things worth knowing before you rely on it:

- **A base URL you had already set is fronted, not replaced.** If
  `OPENAI_BASE_URL` points at Groq or at a local server, the listener
  forwards there. Your configuration is governed, not overridden.
- **"Nothing passed through" is reported as a failure, not a clean run.**
  Pointing a tool at an address is a request, not a guarantee: some read a
  different setting, some authenticate in a way that ignores this one. A
  summary saying "0 findings" would describe an inspection that never
  happened, so it says the run was not governed and names the addresses
  that went unused.
- **Each session verifies on its own**, with the command the summary
  prints. A session writes its own chain, so two guards running at once
  cannot interleave into what would read afterwards as a deleted receipt.

`lyntway proxy` is the other half of this: use `guard` for a command you
are launching, and `proxy` for a model server other applications are
already talking to.

### Running it every time, without remembering

```bash
lyntway guard --install
```

Writes a shell function per tool, after showing you exactly what it will
add and asking. Afterwards `claude` *is* governed — no new habit, no extra
word to type.

**It is a function, not an alias, and that matters.** An alias would break
your tool completely the day Lyntway is removed, moved, or missing from a
shell with a different PATH, leaving you with a command that does not
start and no reason why. The function checks for us first and falls
through to the real command when we are not there:

```sh
claude() {
  if command -v lyntway >/dev/null 2>&1; then
    lyntway guard -- claude "$@"
  else
    command claude "$@"
  fi
}
```

The worst case is that governance quietly stops, which `lyntway status`
reports — never that the tool dies.

`lyntway guard --uninstall` takes it out, and so does `lyntway undo`. The
profile comes back byte for byte, and a backup is written beside it first.

### What the session cost

When the command stops, the summary says what the run cost — the part
somebody reads on a day when nothing was withheld:

```
  tokens    184,320 in, 31,004 out, as the provider reported them
            claude-sonnet-4-5-20250929           184,320 in    31,004 out
  cost      USD 1.0177 — estimate at the price you entered per million tokens
```

**The token counts are the provider's own figure**, read out of its
response and labelled as theirs. Nothing here counts tokens — the
tokenizer is the provider's, and a count made on this side would be a
guess dressed as a measurement. A reply that reported no figure is named
as unmetered rather than counted as zero, because zero reads as free.

**There is no built-in price table.** Providers change list prices without
notice, negotiated rates differ, and a figure from a stale table would be
the one number a finance team copies into a spreadsheet and never checks.
Prices are yours, from `~/.lyntway/prices.json` or for one run:

```bash
lyntway guard --price claude-opus-4=15/75 --currency USD -- claude
```

A model with no price is named beside the total rather than dropped from
it — a total that silently left one out would read as the whole bill.

### Sharing one

```bash
lyntway share
```

Turns the newest receipt into a link anyone can open. **Nothing is
uploaded.** The receipt and its verifying key ride in the URL's fragment,
and a fragment is never sent to any server — so we cannot see what was
shared, how often it was opened, or by whom, and the link keeps working
whatever happens to us. A link that stops working when its issuer does is
not proof.

What it prints before the link is the point of it:

```
This link carries one receipt. A reader will see:

  receipt   rcpt_c0ee4bdc6a7544033d94509e
  action    POST /v1/messages → api.anthropic.com
  decision  block, governance full
  found     Supabase secret key (secret.supabase_key) ×1
  signed by local-1abb9d47d1f87e70

  No content. A receipt records classes, counts and digests; the text
  that was governed is not in it and never was.

  The key travels with the link, because it is a key on this machine
  and nobody else publishes it. So the reader can prove this receipt
  has not been altered since you made it — not that an independent
  party saw it happen. The page says the same.
```

That last paragraph is not a disclaimer, it is the design. A receipt
written on a laptop is signed on that laptop, and the page the link opens
says **"Signature valid — the sender's own key"** rather than "Verified",
because a reader who concluded a third party had vouched for it would have
been misled by us and not by the sender. Evidence somebody else weighs is
signed by a deployment's published key instead.

Change one character of the receipt in the link and the page says
**Invalid**. That is the whole demonstration, and the reader can run it
themselves in ten seconds.

### Databases

```bash
lyntway-dbgateway
```

The only vantage point a database has. The gateway cannot proxy a binary
wire protocol as HTTP, and the MCP shim cannot see it because it is not
JSON-RPC over stdio — so this is a separate listener that understands
PostgreSQL, MySQL and MongoDB framing, proxies to the real database, and
issues a receipt for every query.

**Content never leaves the process.** The queries, the results and any
values found in them stay on that machine; only classes and counts are
reported to an account. There is no switch that changes this.

It records rather than rewrites: a wire protocol cannot be re-framed
safely, so a finding is `log_only` and a policy that blocks still blocks.
It does not substitute, and it does not claim to.

## In Claude Code

```
/plugin marketplace add lynt-x-global/lyntway-tools
/plugin install lyntway@lyntway
```

Adds a skill the agent reads when a secret is in play, and a
`/lyntway-scan` command. See [plugin/](plugin/).

## Connecting what it found

```bash
lyntway connect
```

The same discovery, with one question at the end. It names the keys using
the 385-entry provider catalog in [`catalog/`](catalog/) — the same table
the console's picker uses — so a Stripe key in a .env is called a Stripe
key rather than counted. Naming is not moving: only the seven providers
`keys migrate` can hold are offered to be moved, and the rest are listed
and labelled as not moved from here.

Every change it makes is `lyntway keys migrate` or `lyntway init`, so
`lyntway undo` reverses all of it.

## Checking a receipt

This is the part that matters, and it works without us:

```bash
lyntway-verify -keys keys.json receipt.json
```

Fetch the keys once from `/.well-known/lyntway-keys.json` on whichever
Lyntway issued the receipt, and the check runs offline for good. No
account, no network, no cooperation from the issuer — which is the point.
Evidence that needs the issuer's permission to verify fails exactly when
the issuer is the party in dispute.

Any RFC 8785 and RFC 9052 implementation will do the same job. This one is
here so that nobody has to write it.

## Governing MCP tool results locally

```bash
lyntway-mcp --sink receipts.jsonl -- npx -y @modelcontextprotocol/server-github
```

Detection runs on that machine. Nothing is sent anywhere to be inspected,
because a tool result carrying a customer record is the disclosure this
exists to prevent — shipping it somewhere to be checked would be the
problem, not the fix.

**What these receipts are worth.** Run on its own, `lyntway-mcp` signs with
a key it generates at startup and throws away. That is genuinely useful for
seeing what your tools handle, and it is worth nothing as evidence to
anybody else: the key belongs to the person being audited. Receipts that
carry weight with a third party need a key that was not minted on the
laptop under examination, which is what the hosted service and the
self-hosted deployment provide.

## Keeping keys out of pull requests

```yaml
- uses: actions/checkout@v4
- uses: lynt-x-global/lyntway-tools/action@main
```

Runs `lyntway scan` on the lines a pull request adds and fails the job
when one of them is a provider key, with the fix in the job summary. The
scan runs on the runner and sends nothing anywhere; the key's value is
never printed. Details in [action/README.md](action/README.md).

## Reporting what AI is on a machine

```bash
lyntway agent --explain   # what it collects, and what it never does
lyntway agent --dry-run   # the exact report it would send, sent nowhere
```

`lyntway agent` lists the AI apps, editor extensions, local models and MCP
servers on a laptop or server, and which AI hosts it is connected to, and
reports that to the account with a line per surface saying how much is
actually covered. No content, no credential values, no browser history.
Fleet installs for RMM tools are in [scripts/agent](scripts/agent/).

## Python: the SDK and the LiteLLM callback

```bash
pip install "lyntway @ git+https://github.com/lynt-x-global/lyntway-tools#subdirectory=python"
```

The SDK verifies receipts in Python, and carries the LiteLLM callback:

```yaml
litellm_settings:
  callbacks: [lyntway.litellm.handler]

environment_variables:
  LYNTWAY_URL: https://your-lyntway
  LYNTWAY_KEY: sk-...
```

This is the only way to record **AWS Bedrock and Google Vertex**. Both sign
every request in a way that a proxy in the path breaks, so they cannot be
gatewayed at all — but LiteLLM signs them itself, and a callback running
inside LiteLLM sees them. The receipt says LiteLLM told us rather than that
we watched, because it did.

The callback never blocks and never raises: LiteLLM's success hook runs
after the response is back, so there is nothing left to change, and a
recorder that can fail somebody's traffic is a recorder they remove.

## Where the rest of it lives

The gateway, the console, the transparency log and the compliance pack are
not in this repository. <https://lyntway.com>

## Licence

Apache-2.0. Generated from the Lyntway source tree; issues and pull
requests are welcome here and are applied upstream.
