# Install the Lyntway agent on Windows, from an RMM tool or by hand.
#
#   $env:LYNTWAY_API_KEY = '...'; powershell -ExecutionPolicy Bypass -File install.ps1
#
# Run as SYSTEM or an administrator (what an RMM does) and it installs for
# the whole machine: a scheduled task that starts at boot as SYSTEM, with
# its state in C:\ProgramData\Lyntway restricted to SYSTEM and
# Administrators. Run as a person and it installs for them: a task at their
# logon, state in %USERPROFILE%\.lyntway\agent.
#
# Why the key is an environment variable: a command-line argument is visible
# to every user through the process list for as long as the process runs.
# This script takes no key argument, and the binary refuses one.
#
# The zip is checked against the SHA256SUMS the same release published, or
# against LYNTWAY_SHA256 when set. The binary is not yet Authenticode-signed;
# see README.md beside this file.
#
# Environment:
#   LYNTWAY_API_KEY     required
#   LYNTWAY_URL         optional: a self-hosted Lyntway
#   LYNTWAY_AGENT_MODE  optional: laptop (default) or server
#   LYNTWAY_VERSION     optional: latest (default) or e.g. 0.3.0
#   LYNTWAY_SHA256      optional: expected checksum of the zip

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Fail($msg) { Write-Error "lyntway install: $msg"; exit 1 }

if ($args.Count -gt 0) { Fail 'this script takes no arguments; the key goes in LYNTWAY_API_KEY, where the process list cannot show it' }
if (-not $env:LYNTWAY_API_KEY) { Fail 'set LYNTWAY_API_KEY to the account''s API key' }

$mode = if ($env:LYNTWAY_AGENT_MODE) { $env:LYNTWAY_AGENT_MODE } else { 'laptop' }
if ($mode -ne 'laptop' -and $mode -ne 'server') { Fail "LYNTWAY_AGENT_MODE is laptop or server, not '$mode'" }
if (-not [Environment]::Is64BitOperatingSystem) { Fail 'lyntway is built for 64-bit Windows only' }

$repo = 'https://github.com/lynt-x-global/lyntway-tools/releases'
$version = if ($env:LYNTWAY_VERSION) { $env:LYNTWAY_VERSION } else { 'latest' }
if ($version -eq 'latest') {
  # The redirect GitHub serves for /releases/latest names the tag.
  $req = [Net.WebRequest]::Create("$repo/latest")
  $req.AllowAutoRedirect = $false
  $resp = $req.GetResponse()
  $location = $resp.Headers['Location']
  $resp.Close()
  if (-not $location -or $location -notmatch '/tag/v?(.+)$') { Fail "could not find the latest release at $repo/latest" }
  $version = $Matches[1]
}
$version = $version.TrimStart('v')
if ($version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') { Fail "'$version' is not a release version" }

$asset = "lyntway_${version}_windows_amd64.zip"
$base = "$repo/download/v$version"
$work = Join-Path ([IO.Path]::GetTempPath()) ("lyntway-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
  Write-Host "downloading $asset"
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile "$work\$asset"
  if ($env:LYNTWAY_SHA256) {
    $expected = $env:LYNTWAY_SHA256.ToLower()
  } else {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile "$work\SHA256SUMS"
    $line = Get-Content "$work\SHA256SUMS" | Where-Object { ($_ -split '\s+')[1] -eq $asset } | Select-Object -First 1
    if (-not $line) { Fail "SHA256SUMS does not list $asset" }
    $expected = ($line -split '\s+')[0].ToLower()
  }
  $actual = (Get-FileHash -Algorithm SHA256 "$work\$asset").Hash.ToLower()
  if ($actual -ne $expected) { Fail "$asset does not match its checksum; not installing it" }

  $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $dest = if ($admin) { Join-Path $env:ProgramFiles 'Lyntway' } else { Join-Path $env:LOCALAPPDATA 'Programs\Lyntway' }
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Expand-Archive -Force -Path "$work\$asset" -DestinationPath $work
  Copy-Item -Force "$work\lyntway.exe" "$dest\lyntway.exe"
} finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

$exe = Join-Path $dest 'lyntway.exe'
$built = & $exe version
if ($LASTEXITCODE -ne 0) { Fail 'the downloaded lyntway does not run here' }
Write-Host "installed lyntway $built to $dest"

# The key reaches the agent through the environment, and the agent writes it
# to a file whose ACL admits SYSTEM and Administrators only.
$installArgs = @('agent', 'install')
if ($mode -eq 'server') { $installArgs += '--server' }
& $exe @installArgs
if ($LASTEXITCODE -ne 0) { Fail 'the agent service could not be installed' }

Write-Host ''
Write-Host "What the agent collects: & '$exe' agent --explain"
