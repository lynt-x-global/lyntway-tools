# Lyntway tools

Three command-line tools, and the packages behind them. No third-party
dependencies — the whole module is standard library, so what goes into the
tool that checks receipts can be read in an afternoon.

| Tool | What it does | Needs an account |
|---|---|---|
| `lyntway-verify` | Checks a receipt. No network calls, ever. | No |
| `lyntway-mcp` | Runs between an agent and an MCP server, and governs tool results on the machine they land on. | No |
| `lyntway` | Reports what AI software is on a machine, and can point it at a Lyntway service. | Only to record |

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
