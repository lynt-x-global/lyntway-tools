# Lyntway tools

Three command-line tools, and the packages behind them. No third-party
dependencies — the whole module is standard library, so what goes into the
tool that checks receipts can be read in an afternoon.

| Tool | What it does | Needs an account |
|---|---|---|
| `lyntway-verify` | Checks a receipt. No network calls, ever. | No |
| `lyntway-mcp` | Runs between an agent and an MCP server, and governs tool results on the machine they land on. | No |
| `lyntway` | Points a machine's AI tools at a Lyntway service. | Yes |

## Install

```bash
brew install lynt-x-global/lyntway/lyntway
```

Or download a build for your platform from
[releases](https://github.com/lynt-x-global/lyntway-tools/releases) and put
the three binaries on your `PATH`.

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

## Where the rest of it lives

The gateway, the console, the transparency log and the compliance pack are
not in this repository. <https://lyntway.com>

## Licence

Apache-2.0. Generated from the Lyntway source tree; issues and pull
requests are welcome here and are applied upstream.
