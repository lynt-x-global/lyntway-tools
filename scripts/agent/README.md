# Installing the Lyntway agent from an RMM

`install.sh` (macOS, Linux) and `install.ps1` (Windows) download the
`lyntway` binary from a lyntway-tools release, check it against that
release's `SHA256SUMS`, and run `lyntway agent install`. Run by an RMM as
root or SYSTEM, they install for the whole machine; run by a person, for
that person.

The key is always an environment variable, never an argument. Arguments
are visible to every user in the process list; the scripts refuse any, and
the binary refuses `--key`.

```bash
# macOS / Linux, as root from the RMM's script runner
export LYNTWAY_API_KEY='<from the RMM secret store>'
export LYNTWAY_AGENT_MODE=laptop   # or server
bash install.sh
```

```powershell
# Windows, as SYSTEM from the RMM's script runner
$env:LYNTWAY_API_KEY = '<from the RMM secret store>'
powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
```

Pin `LYNTWAY_VERSION` and `LYNTWAY_SHA256` in a fleet rollout, so every
machine installs bytes somebody has looked at rather than whatever
`latest` is on the day.

What the agent collects, and what it never does: `lyntway agent --explain`,
also in the repository README. `lyntway agent --dry-run` prints the exact
report without sending it; the last report actually sent is kept as
`last-report.json` in the agent's state directory.

## Where things go

| | Per user | Whole machine |
|---|---|---|
| macOS service | `~/Library/LaunchAgents/com.lyntway.agent.plist` | `/Library/LaunchDaemons/com.lyntway.agent.plist` |
| Linux service | `~/.config/systemd/user/lyntway-agent.service` | `/etc/systemd/system/lyntway-agent.service` |
| Windows | scheduled task "Lyntway Agent", at logon | scheduled task "Lyntway Agent", at boot as SYSTEM |
| State and key | `~/.lyntway/agent` | `/Library/Application Support/Lyntway`, `/var/lib/lyntway`, `C:\ProgramData\Lyntway` |

The key file (`agent.json`) is readable by root or SYSTEM only. The device
id is not a secret and is left readable by the person at the machine
(`~/.lyntway/device_id` for a per-user install; `device_id` in the state
directory, which is traversable but not listable, for a machine-wide one),
so the browser extension can later say it is the same device.

`lyntway agent uninstall` removes the service and keeps the state, so a
reinstall is the same device; `--purge` removes that too.

## What needs elevation

Nothing, for the basics. A per-user install inventories that user's apps,
MCP configuration and connections. Run as root, the agent reads the
console user's configuration and sees every process's connections, which
on macOS a normal user cannot (`lsof` shows only their own). On Linux the
connection table is readable by anyone but the owning process is only
known for the caller's own processes without root. Server mode reads
`/srv`, `/opt`, `/var/www`, `/app`, `/home`, `/root` and
`/etc/systemd/system`, and sees only what the user it runs as may read.

## Code signing, still to do

The binaries are not code-signed. A fleet rollout needs:

- **macOS: an Apple Developer ID Application certificate, and
  notarization.** Sign `lyntway` with the hardened runtime
  (`codesign --options runtime --timestamp`), submit it with
  `xcrun notarytool`, and ship it inside a signed `.pkg` (Developer ID
  Installer certificate) with the ticket stapled. Without that, Gatekeeper
  blocks a binary that arrived through a browser, and MDMs (Jamf, Kandji,
  Intune) cannot allow-list it by Team ID. A binary fetched by `curl` from
  a script carries no quarantine flag and runs unsigned, which is why the
  script works today and why that is not a reason to skip signing.
- **Windows: an Authenticode code-signing certificate**, ideally EV so
  SmartScreen reputation is immediate. Sign `lyntway.exe` with
  `signtool sign /tr <RFC 3161 timestamp URL> /td sha256 /fd sha256`.
  Unsigned, SmartScreen warns and many EDR products quarantine or flag it.
- **Linux:** no platform signing; the release's `SHA256SUMS` (ideally
  itself signed, e.g. with cosign or minisign) is the check.

Both certificates belong to the company, not a person, and the private
keys should live in an HSM or a cloud signing service rather than on a
build machine.
