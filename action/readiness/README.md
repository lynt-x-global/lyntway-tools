# Lyntway readiness, on a schedule

Checks the endpoints your AI actually reached and the packages your project
installs, and **says nothing when nothing moved**.

```yaml
name: Readiness
on:
  schedule: [{ cron: '17 3 * * *' }]   # nightly, at an odd minute
  workflow_dispatch:

jobs:
  readiness:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      # Without this the runner starts empty every night, every run is a
      # first run, and "what changed" never says anything.
      - uses: actions/cache@v4
        with:
          path: .lyntway-readiness-state.json
          key: lyntway-readiness-${{ github.repository }}-${{ github.run_id }}
          restore-keys: lyntway-readiness-${{ github.repository }}-

      - uses: lynt-x-global/lyntway-tools/action/readiness@v0.3.1
        with:
          api-key: ${{ secrets.LYNTWAY_KEY }}
          scope: api.acme.com,api.internal.acme.com
          sign: true
```

## What a run does

**Dependencies** — reads `package-lock.json`, `package.json` and
`requirements.txt`, and asks the public vulnerability database about the
packages pinned to an exact version. Names and versions are the only thing
that leaves the runner; `offline: true` skips even that. Needs no account.

**Endpoints** — with an `api-key`, reads the endpoints your AI traffic
actually reached, and asks each one what it answers with no credential
attached. Only `GET`, `HEAD` and `OPTIONS` are ever sent, only to hosts
named in `scope`, and never to a templated path.

**The difference** — both are compared with the last run. A summary is
written only when something differs, and the job fails only when something
is worse. An endpoint that *started* asking for a credential is a good
morning, not a failed build.

## Scope is required for the endpoint half

There is no discovery mode. A host that is not named in `scope` is never
sent anything, however plainly it appears in your own traffic — because a
host in our records is not the same as a host you are authorised to send
requests to. Without `scope` the run lists what it saw and checks
dependencies only.

## What this is not

A check of authentication and of published advisories. **It is not a
penetration test and does not replace one.** It is what an assessor would
otherwise spend their first day finding, so that the days you pay them for
go on the work only they can do.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `api-key` | — | Reads the observed endpoints, and signs the report |
| `scope` | — | Hosts you are authorised to check. Required for the endpoint half |
| `sign` | `false` | Registers the report's digest so a third party can verify it |
| `fail-on-new` | `true` | Fail the job when something got worse |
| `state` | `.lyntway-readiness-state.json` | Where the last run is remembered |
| `report` | `lyntway-readiness.json` | Where the report is written |
| `offline` | `false` | Skip the vulnerability database entirely |
| `no-deps` | `false` | Skip the dependency half |
| `http` | `false` | Reach scoped hosts over http, for an internal API not on TLS |
| `api-url` | `https://lyntway.com` | If you self-host |

## Outputs

`changed` — `"true"` when anything differed · `worse` — how many of those
were for the worse · `report` — path to the report · `version` — the
lyntway build that ran.

## Keeping the signed report

With `sign: true` the run writes `lyntway-readiness.json` and
`lyntway-readiness.receipt.json`. Upload both — the pair is what somebody
verifies:

```yaml
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: readiness
          path: lyntway-readiness*.json
```

Anyone can then check it without an account, and without asking us:

```bash
curl -O https://lyntway.com/.well-known/lyntway-keys.json
lyntway-verify -keys lyntway-keys.json \
  -file lyntway-readiness.json lyntway-readiness.receipt.json
```

The signature settles that the report has not been altered since it was
issued. It says nothing about whether the findings are correct, which
belongs to whoever signs the assessment.
