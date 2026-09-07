# Lyntway scan — GitHub Action

Fails a pull request that adds a provider API key.

```yaml
name: Keys stay out of the code
on:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: lynt-x-global/lyntway-tools/action@main
```

Each key found is annotated on the line that adds it, and the job summary
says what to do: remove it, rotate it, and store it with
`lyntway keys migrate` so the application holds a Lyntway key instead.

## What it does, exactly

`lyntway scan --diff=<base> --format=github`, run on the runner.

- **Only the lines the change adds are read.** The base is the pull
  request's base commit, or the commit before a push. On a push to a new
  branch there is nothing to diff against, so the whole tree is scanned
  and the log says so.
- **Nothing leaves the runner.** The detectors are the same deterministic
  rules the Lyntway gateway applies — OpenAI, Anthropic, AWS, GitHub, Slack
  and Stripe prefixes, and the names a `.env` file gives them. No account,
  no token, no call to lyntway.com.
- **The value is never printed.** The annotation carries the file, the line,
  the provider and the last four characters, so the person reading it can
  tell which key without the log becoming another copy of it.
- **A scan that could not run fails differently from one that found a key.**
  Exit 1 from `lyntway scan` is a finding; any other failure is reported as
  "nothing was checked", because a check that silently did not happen is
  worse than no check.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `version` | `latest` | Release of the tools to install, e.g. `0.2.0`. |
| `sha256` | — | Expected SHA-256 of the tarball for the runner's platform. Set it to pin the install to bytes you have seen. |
| `base` | the event's base | Commit to diff against. |
| `working-directory` | `.` | Directory of the checkout to scan. |

Output `version` is the tools version that ran.

## How the tools are installed

`install.sh` downloads `lyntway_<version>_<os>_<arch>.tar.gz` from
[the releases](https://github.com/lynt-x-global/lyntway-tools/releases),
checks it against the `SHA256SUMS` of the same release, unpacks it into the
runner's temporary directory and adds that to `PATH`. Linux and macOS
runners, x64 and ARM64.

The checksum proves the download is what the release listed; it does not
prove the release is ours, because the sums sit beside the tarball. For
that, pin `sha256`. The Homebrew formula in
[homebrew-lyntway](https://github.com/lynt-x-global/homebrew-lyntway)
records one per platform from a published release, taken separately.

A release that ships no `SHA256SUMS` is refused, not installed unchecked.

## Where this sits

This catches a key on its way into the code. It does not see one that is
already in an environment variable, a CI secret, or a running process —
those are what `lyntway keys migrate` and the gateway are for. And it runs
on what a pull request changes, so a key committed before the action was
added is found by running `lyntway scan .` once, by hand.
