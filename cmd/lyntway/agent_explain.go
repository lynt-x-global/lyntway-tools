package main

// agentExplanation is `lyntway agent --explain`, and the README's section
// on the agent carries the same text; agent_test.go fails if they drift.
//
// Written for the person whose machine this runs on, not for the buyer.
// Each claim in it is one the code keeps: the report struct has no field
// for anything under "Never collected", and the tests plant a credential
// in every file the agent reads and check it is absent from the output.
const agentExplanation = `What lyntway agent collects, and what it never does

The agent tells your organisation which AI tools are on this machine and
which of them anything is covering. It is not a monitor of what you do.

Collected, every report
  - This device: a random id made on first run, its hostname, operating
    system and version, the agent's version, and your OS username.
  - AI apps: which known AI applications, editor extensions and command-line
    tools are installed, whether each is running, and its version when the
    app's own folder says. Read from application folders, extension folders
    and the list of running process names.
  - MCP servers: for each server your AI clients are configured to use, the
    client, the server's name, whether it runs locally or over HTTP, the
    host it reaches, and whether a credential is written into the config
    beside it (yes or no).
  - AI destinations: which known AI services this machine held connections
    to, from which app, and how many connections, over the reporting
    window. Taken from the operating system's list of open connections
    every 30 seconds.
  - Coverage: for each of the above, one sentence saying how much is
    actually seen, including what is not.

Collected in server mode, or with --scan
  - For each file holding an AI provider key: the file's path and the kind
    of key, counted. Sent as a finding to /v1/attest.
  - Which AI SDKs a project declares, and the exact settings change that
    would route each through the gateway. Printed here, not sent.

Never collected
  - Prompts, replies, or any content sent to or from an AI service.
  - The value of any key, token or password, or any part or digest of one.
  - Commands, arguments, environment variables or headers from MCP
    configurations; only the facts above are kept of them.
  - Browser history, page titles, window titles, screenshots, keystrokes,
    clipboard or file contents.
  - Network packets. No traffic is captured, decrypted or redirected.
  - Anything about processes other than their names and program paths.

Where it goes
  To the Lyntway address this agent is configured with, over HTTPS, signed
  with this machine's key when it has one. The last report sent is kept at
  last-report.json in the agent's state directory, so you can read exactly
  what left: ~/.lyntway/agent on a personal install, /var/lib/lyntway on a
  Linux server, /Library/Application Support/Lyntway or
  C:\ProgramData\Lyntway when installed for the whole machine.

See it for yourself
  lyntway agent --dry-run   prints the exact report and sends nothing
  lyntway agent --explain   prints this

What it cannot see
  An AI website in a browser shows only as connections from the browser,
  and only when the site's address is one this machine resolves for a
  known AI host. Connections through a VPN or proxy, connections shorter
  than 30 seconds, and apps it does not know are missed. Without
  administrator rights on macOS it sees only your own processes. Local
  models count as covered only while lyntway proxy runs in front of them.
`
