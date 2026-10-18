# Install a Lyntway agent on Windows.
#
# Two modes, chosen by how the script is invoked:
#
# 1. CLI agent (telemetry, receipts):
#      $env:LYNTWAY_API_KEY = '...'; powershell -ExecutionPolicy Bypass -File install-agent.ps1
#
# 2. On-device agent (HTTPS proxy, PII redaction, governance):
#      powershell -ExecutionPolicy Bypass -File install-agent.ps1 -Token TOKEN -ApiBase https://lyntway.com
#
# # CLI agent
#
# Run as SYSTEM or an administrator (what an RMM does) and it installs for
# the whole machine: a scheduled task that starts at boot as SYSTEM, with
# its state in C:\ProgramData\Lyntway restricted to SYSTEM and
# Administrators. Run as a person and it installs for them: a task at their
# logon, state in %USERPROFILE%\.lyntway\agent.
#
# Why the key is an environment variable: a command-line argument is visible
# to every user through the process list for as long as the process runs.
#
# The zip is checked against the SHA256SUMS the same release published, or
# against LYNTWAY_SHA256 when set. Whether the binaries carry an
# Authenticode signature is read from signing.json beside them and printed,
# rather than asserted here where it would go stale the day one is bought.
#
# Environment (CLI mode):
#   LYNTWAY_API_KEY     required
#   LYNTWAY_URL         optional: a self-hosted Lyntway
#   LYNTWAY_AGENT_MODE  optional: laptop (default) or server
#   LYNTWAY_VERSION     optional: latest (default) or e.g. 0.3.0
#   LYNTWAY_SHA256      optional: expected checksum of the zip
#
# # On-device agent
#
# Requires administrator. The enrollment token is single-use and expires in
# one hour; generate it from the console at /on-device.
#
# Parameters:
#   -Token TOKEN        required: the enrollment token from the console
#   -ApiBase URL        required: the Lyntway server (e.g. https://lyntway.com)
#   -NoProxy            optional: skip system proxy configuration
#   -NoSidecar          optional: skip AI sidecar model download

param(
  [string]$Token,
  [string]$ApiBase,
  [switch]$NoProxy,
  [switch]$NoSidecar
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Fail($msg) { Write-Error "lyntway install: $msg"; exit 1 }

$TotalSteps = 8
function Step($n, $msg) { Write-Host "`nStep $n of $TotalSteps - $msg" -ForegroundColor White }
function Info($msg) { Write-Host "  [info]  $msg" -ForegroundColor Cyan }
function Ok($msg) { Write-Host "    [ok]  $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "  [warn]  $msg" -ForegroundColor Yellow }

if (-not [Environment]::Is64BitOperatingSystem) { Fail 'lyntway is built for 64-bit Windows only' }

# Which Windows this is. Until 18 October 2026 both of this script's modes
# assumed amd64, so on a Copilot+ PC the x64 binary was fetched and run
# under emulation, and the machine then reported amd64 to the console —
# a fleet inventory that disagreed with the hardware it was describing.
#
# PROCESSOR_ARCHITECTURE describes *this process*, so a 32-bit PowerShell on
# 64-bit Windows answers x86 and puts the truth in PROCESSOR_ARCHITEW6432.
# OSArchitecture asks the operating system and is the one to believe when
# the runtime is new enough to have it.
function Get-LyntwayArch {
  try {
    switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
      'X64'   { return 'amd64' }
      'Arm64' { return 'arm64' }
    }
  } catch { }
  $raw = $env:PROCESSOR_ARCHITEW6432
  if (-not $raw) { $raw = $env:PROCESSOR_ARCHITECTURE }
  switch ($raw) {
    'AMD64' { return 'amd64' }
    'ARM64' { return 'arm64' }
  }
  Fail "no lyntway build for $raw"
}
$arch = Get-LyntwayArch

# ── On-device agent mode ─────────────────────────────────────────────

if ($Token) {
  if (-not $ApiBase) { Fail '-ApiBase is required with -Token' }

  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { Fail 'the on-device agent must be installed as administrator' }

  $ApiBase = $ApiBase.TrimEnd('/')

  # Detect RAM for sidecar profile decision.
  $ramGB = [math]::Floor((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
  Info "detected $ramGB GB RAM on windows/$arch"

  $work = Join-Path ([IO.Path]::GetTempPath()) ("lyntway-od-" + [Guid]::NewGuid())
  New-Item -ItemType Directory -Path $work | Out-Null

  try {
    # Step 1: Download the on-device agent binary.

    Step 1 "Download the on-device agent"

    $dlBase = "$ApiBase/dl/on-device"
    $binaryName = "lyntway-agent_windows_$arch.exe"
    Invoke-WebRequest -UseBasicParsing -Uri "$dlBase/$binaryName" -OutFile "$work\lyntway-agent.exe"
    Ok "downloaded lyntway-agent for windows/$arch"

    # Integrity, before anything reaches Program Files.
    #
    # Same history as the Unix installer: this is the download that puts a
    # certificate authority in the machine's trust store, and it was fetched
    # and run unverified while the CLI path at the bottom of this same file
    # checked a checksum. Refusing costs an install; at this point nothing
    # has been copied, no certificate added and no proxy pointed anywhere.
    try {
      Invoke-WebRequest -UseBasicParsing -Uri "$dlBase/SHA256SUMS" -OutFile "$work\SHA256SUMS"
    } catch {
      Fail "$ApiBase published no SHA256SUMS beside $binaryName; refusing to install an agent we cannot verify"
    }
    $want = $null
    foreach ($line in Get-Content "$work\SHA256SUMS") {
      $parts = $line.Trim() -split '\s+'
      # sha256sum writes a leading asterisk for an entry read in binary mode.
      if ($parts.Count -ge 2 -and $parts[1].TrimStart('*') -eq $binaryName) { $want = $parts[0]; break }
    }
    if (-not $want) { Fail "SHA256SUMS names no entry for $binaryName; refusing to install" }
    $actual = (Get-FileHash -Algorithm SHA256 "$work\lyntway-agent.exe").Hash
    if ($want.ToLower() -ne $actual.ToLower()) {
      Fail "checksum mismatch for $binaryName`n     published: $want`n    downloaded: $actual`n  Nothing has been changed on this machine."
    }
    Ok "checksum matches what $ApiBase published"

    # What the signature says, said exactly. signing.json is published
    # beside the binaries, so it describes this download rather than a
    # claim made elsewhere — and where it says the set is unsigned, that is
    # printed. An installer silent about signing reads as signed, which is
    # the strongest reading of an absent value and so the wrong one.
    $signed = $false
    $signReason = ''
    try {
      Invoke-WebRequest -UseBasicParsing -Uri "$dlBase/signing.json" -OutFile "$work\signing.json"
      $manifest = Get-Content -Raw "$work\signing.json" | ConvertFrom-Json
      $signed = [bool]$manifest.signed
      $signReason = [string]$manifest.reason
    } catch { }
    if ($signed) {
      $sig = Get-AuthenticodeSignature "$work\lyntway-agent.exe"
      if ($sig.Status -ne 'Valid') {
        Fail "$ApiBase says this agent is signed and Windows reports its signature as $($sig.Status); refusing to install"
      }
      Ok "Authenticode signature verified: $($sig.SignerCertificate.Subject)"
    } else {
      if ($signReason) { Warn "this agent is NOT Authenticode-signed - $signReason" }
      else { Warn 'this agent is NOT Authenticode-signed' }
      Warn "the checksum above is the only thing that ties it to $ApiBase"
    }

    # Step 2: Install to Program Files.

    Step 2 "Install binary"

    $dest = Join-Path $env:ProgramFiles 'Lyntway'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item -Force "$work\lyntway-agent.exe" "$dest\lyntway-agent.exe"

    # Remove the Mark-of-the-Web.
    #
    # This is what stops SmartScreen prompting on a file fetched over the
    # network, and it is a workaround for the binary being unsigned rather
    # than a fix: an Authenticode signature with reputation is the actual
    # answer, and the manifest check above says which of the two is in play.
    $exe = Join-Path $dest 'lyntway-agent.exe'
    Remove-Item -Stream Zone.Identifier -Path $exe -ErrorAction SilentlyContinue

    # Add to PATH if not already there.
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($machinePath -notlike "*$dest*") {
      [Environment]::SetEnvironmentVariable('Path', "$machinePath;$dest", 'Machine')
    }
    Ok "installed to $dest\lyntway-agent.exe"

    # Step 3: Activate with enrollment token.

    Step 3 "Activate with enrollment token"

    $hostname = $env:COMPUTERNAME
    $body = @{
      token    = $Token
      hostname = $hostname
      os       = 'windows'
      arch     = $arch
    } | ConvertTo-Json

    try {
      $resp = Invoke-RestMethod -Method Post -Uri "$ApiBase/v1/on-device/activate" `
        -ContentType 'application/json' -Body $body
    } catch {
      Fail "activation failed - the token may have expired or already been used: $_"
    }

    $apiKey = $resp.api_key
    $machineId = $resp.machine_id
    if (-not $apiKey) { Fail 'activation succeeded but no API key was returned' }

    # Write credentials to a SYSTEM-only directory.
    $stateDir = Join-Path $env:ProgramData 'Lyntway\Agent'
    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
    $acl = Get-Acl $stateDir
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object Security.AccessControl.FileSystemAccessRule(
      'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $systemRule = New-Object Security.AccessControl.FileSystemAccessRule(
      'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl $stateDir $acl

    @"
LYNTWAY_API_KEY=$apiKey
LYNTWAY_API_BASE=$ApiBase
LYNTWAY_MACHINE_ID=$machineId
"@ | Set-Content "$stateDir\agent.env" -Force
    Ok "activated as $machineId"

    # Step 4: Install CA certificate.

    Step 4 "Install MITM CA certificate"

    # A native command does not throw on failure, so the old try/catch
    # printed "installed" over every failure. The exit code is the truth,
    # and the agent itself checks the store before it ever enables the
    # proxy, so a CA this machine does not trust leaves HTTPS alone.
    & $exe --install-ca 2>&1 | Out-Null
    $caOk = ($LASTEXITCODE -eq 0)
    if ($caOk) {
      Ok "CA certificate installed to the machine's Root store"
    } else {
      Warn "the CA was not installed - the system proxy will stay OFF until it is trusted,"
      Warn "so HTTPS keeps working on this machine but is not inspected"
      Warn "to retry as administrator: `"$exe`" --install-ca"
    }

    # Step 5: System proxy.
    #
    # Not set here. The agent points the machine at itself only once its
    # listener is bound AND the OS trusts its CA, and it clears the same keys
    # when it stops. This script used to write the machine-wide policy keys
    # directly; the agent cleared only the per-user ones, so a service that
    # died left a machine pointed at a port nothing served, with nothing able
    # to undo it. Stale keys from that version are cleared below.

    Step 5 "System proxy"
    foreach ($v in 'ProxyEnable','ProxyServer','ProxyOverride','ProxySettingsPerUser') {
      Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Name $v -ErrorAction SilentlyContinue
    }
    & netsh winhttp reset proxy 2>$null | Out-Null
    Remove-NetFirewallRule -DisplayName 'Lyntway - Block QUIC (UDP 443)' -ErrorAction SilentlyContinue
    if ($NoProxy) {
      Info "the agent will run without pointing this machine at it (-NoProxy)"
    } elseif ($caOk) {
      Info "the agent enables the system proxy itself once it is listening and the CA is trusted"
    } else {
      Info "the system proxy stays OFF until this machine trusts the CA"
    }


    # Step 6: Register Windows service.

    Step 6 "Register autostart"

    $svcName = 'LyntwayAgent'
    # Stop and remove any existing service.
    if (Get-Service $svcName -ErrorAction SilentlyContinue) {
      Stop-Service $svcName -Force -ErrorAction SilentlyContinue
      & sc.exe delete $svcName 2>$null | Out-Null
      Start-Sleep -Seconds 1
    }

    # Create service (sc.exe because New-Service doesn't support all options).
    $daemonArgs = '--daemon'
    if ($NoProxy) { $daemonArgs = '--daemon --no-system-proxy' }
    & sc.exe create $svcName binPath= "`"$exe`" $daemonArgs" `
      start= auto DisplayName= "Lyntway On-Device Agent" | Out-Null
    & sc.exe description $svcName "Intercepts and governs AI traffic on this machine" | Out-Null
    & sc.exe failure $svcName reset= 60 actions= restart/5000/restart/10000/restart/30000 | Out-Null

    # Set environment variables for the service via the registry.
    $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
    $envMulti = @(
      "LYNTWAY_API_KEY=$apiKey",
      "LYNTWAY_API_BASE=$ApiBase",
      "LYNTWAY_MACHINE_ID=$machineId"
    )
    Set-ItemProperty -Path $svcRegPath -Name Environment -Value $envMulti -Type MultiString

    Start-Service $svcName
    Ok "registered and started Windows service"

    # Step 7: AI sidecar (on-device ML).
    #
    # RAM < 12 GB: skip (ONNX-only mode via the agent binary)
    # RAM 12-16 GB: "lean" profile (~4 GB resident)
    # RAM >= 16 GB: "full" profile (all models)
    #
    # The sidecar is a Python FastAPI service that downloads its ML models
    # from HuggingFace/spaCy on first startup. We install the code, create
    # a venv, and register it as a scheduled task on 127.0.0.1:8092.

    if (-not $NoSidecar -and $ramGB -ge 12) {
      Step 7 "AI sidecar (on-device ML)"

      $profile = if ($ramGB -ge 16) { 'full' } else { 'lean' }
      Info "RAM profile: $profile ($ramGB GB)"

      $sidecarDir = Join-Path $stateDir 'sidecar'
      New-Item -ItemType Directory -Force -Path $sidecarDir | Out-Null

      Info "downloading sidecar package..."
      try {
        Invoke-WebRequest -UseBasicParsing -Uri "$dlBase/sidecar/sidecar.tar.gz" `
          -OutFile "$env:TEMP\lw-sidecar.tar.gz"
      } catch {
        Warn "could not download sidecar package - skipping"
        $sidecarDir = $null
      }

      if ($sidecarDir) {
        tar xzf "$env:TEMP\lw-sidecar.tar.gz" -C $sidecarDir
        Remove-Item "$env:TEMP\lw-sidecar.tar.gz" -Force -ErrorAction SilentlyContinue
        Ok "sidecar package extracted"

        # Check for Python, and for a new enough one.
        #
        # The first interpreter on PATH was used, and gliner, transformers and
        # onnxruntime need 3.10 or newer — so on a machine with an older Python
        # the venv was built on an interpreter that cannot install the
        # requirements, pip failed quietly behind --quiet, and the install
        # reported success with no model tier on the machine.
        # The window is 3.10 to 3.12: below 3.10 gliner, transformers and
        # onnxruntime will not install, and 3.13 upward is where the model tier
        # has not been installed and measured. Choosing the newest interpreter
        # therefore picks the one version nothing here has been proven on.
        $pythonExe = $null
        foreach ($cand in @('python3.12','python3.11','python3.10','python','python3')) {
          $c = Get-Command $cand -ErrorAction SilentlyContinue
          if (-not $c) { continue }
          & $c.Source -c 'import sys; sys.exit(0 if (3,10) <= sys.version_info < (3,13) else 1)' 2>$null
          if ($LASTEXITCODE -eq 0) { $pythonExe = $c; break }
        }

        if ($pythonExe) {
          $pyVer = (& $pythonExe.Source --version 2>&1)
          Info "creating Python environment with $pyVer — this may take a few minutes..."
          & $pythonExe.Source -m venv "$sidecarDir\venv"
          # Not quiet, and not forgiven: a model tier that failed to install is
          # the difference between detecting a name and not.
          & "$sidecarDir\venv\Scripts\pip" install -r "$sidecarDir\requirements.txt"
          if ($LASTEXITCODE -ne 0) {
            Warn "the model tier did not install"
            Warn "the agent still runs: deterministic rules only, and every event will say degraded"
            Warn "to retry: $sidecarDir\venv\Scripts\pip install -r $sidecarDir\requirements.txt"
          }

          # Write a profile marker so the sidecar knows which tier to load.
          Set-Content -Path "$sidecarDir\.profile" -Value $profile -NoNewline

          # Register as Windows Scheduled Task (runs at logon, restarts on failure).
          $taskName = 'LyntwaySidecar'
          Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

          $action = New-ScheduledTaskAction `
            -Execute "$sidecarDir\venv\Scripts\uvicorn.exe" `
            -Argument "app:app --host 127.0.0.1 --port 8092" `
            -WorkingDirectory $sidecarDir
          $triggerStartup = New-ScheduledTaskTrigger -AtStartup
          $triggerLogon = New-ScheduledTaskTrigger -AtLogOn
          $settings = New-ScheduledTaskSettingsSet -RestartCount 999 `
            -RestartInterval (New-TimeSpan -Seconds 30) -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries
          Register-ScheduledTask -TaskName $taskName -Action $action `
            -Trigger @($triggerStartup, $triggerLogon) `
            -Settings $settings -Description "Lyntway AI Sidecar ($profile profile)" `
            -Force | Out-Null

          # Set environment variable for profile.
          [Environment]::SetEnvironmentVariable('LYNTWAY_SIDECAR_PROFILE', $profile, 'Machine')

          # Start immediately.
          Start-ScheduledTask -TaskName $taskName

          # Wait for health — models download on first startup, so 15 s may
          # not be enough. Report status either way.
          $sidecarOk = $false
          for ($i = 0; $i -lt 5; $i++) {
            Start-Sleep -Seconds 3
            try {
              $h = Invoke-RestMethod http://127.0.0.1:8092/health -ErrorAction Stop
              if ($h.status -eq 'ok') { $sidecarOk = $true; break }
            } catch {}
          }
          if ($sidecarOk) {
            Ok "sidecar running (profile: $($h.profile))"
          } else {
            Warn "sidecar not yet healthy - models downloading in background"
          }
        } else {
          # Named precisely: "not found" sent people looking for a missing
          # interpreter when the usual problem is that theirs is too old.
          Warn "no Python between 3.10 and 3.12 found - the model tier is not installed"
          Warn "the agent still runs: deterministic rules only, and every event will say degraded"
          Warn "install one and re-run this script to add it"
          Warn "3.13 and newer are outside the window the model tier has been installed and measured on"
        }

        # Tesseract reads the pixels: scanned pages, and the painted copies the
        # redactor writes and reads back to prove the values are gone. A system
        # package, installed here with winget (UB Mannheim's build, the standard
        # Windows one). Not fatal when it cannot be: the sidecar names the
        # missing engine in /health and records scans as unread, never clean.
        $tess = Get-Command tesseract -ErrorAction SilentlyContinue
        if (-not $tess -and -not (Test-Path "$env:ProgramFiles\Tesseract-OCR\tesseract.exe")) {
          if (Get-Command winget -ErrorAction SilentlyContinue) {
            Info "installing Tesseract OCR with winget..."
            & winget install --id UB-Mannheim.TesseractOCR -e --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
            if (Test-Path "$env:ProgramFiles\Tesseract-OCR\tesseract.exe") {
              Ok "tesseract installed"
            } else {
              Warn "tesseract did not install - scanned pages and painted copies cannot be read on this machine"
              Warn "to add it: winget install UB-Mannheim.TesseractOCR"
            }
          } else {
            Warn "winget not found, so tesseract was not installed - scanned pages and painted copies cannot be read"
            Warn "to add it: https://github.com/UB-Mannheim/tesseract/wiki"
          }
        } else {
          Ok "tesseract present"
        }
      }
    } elseif ($NoSidecar) {
      Info "skipping sidecar (-NoSidecar)"
    } else {
      Info "skipping sidecar ($ramGB GB RAM < 12 GB minimum)"
    }

    # Step 8: Health check.

    Step 8 "Verify"

    Start-Sleep -Seconds 2
    $healthy = $false
    for ($i = 0; $i -lt 5; $i++) {
      try {
        $null = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:9090/health' -TimeoutSec 2
        $healthy = $true
        break
      } catch {
        Start-Sleep -Seconds 1
      }
    }

    if ($healthy) {
      Ok "on-device agent is running on 127.0.0.1:9090"
    } else {
      Warn "agent may still be starting - check: curl http://127.0.0.1:9090/health"
    }

    $summary = if ($caOk) { "  LYNTWAY agent installed and active               " } else { "  LYNTWAY agent installed; CA NOT trusted, proxy OFF  " }
    $colour = if ($caOk) { 'Green' } else { 'Yellow' }
    Write-Host ""
    Write-Host "  +-------------------------------------------------------+" -ForegroundColor $colour
    Write-Host "  |   " -ForegroundColor $colour -NoNewline
    Write-Host $(if ($caOk) { 'OK' } else { '!!' }) -ForegroundColor $colour -NoNewline
    Write-Host $summary -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |   Manage:    $ApiBase/on-device" -ForegroundColor Green -NoNewline
    Write-Host "$(' ' * [Math]::Max(0, 34 - $ApiBase.Length))" -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |   Status:    lyntway-agent --status                   |" -ForegroundColor Green
    Write-Host "  +-------------------------------------------------------+" -ForegroundColor Green
    Write-Host ""

  } finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
  }

  exit 0
}

# ── CLI agent mode ────────────────────────────────────────────────────

if (-not $env:LYNTWAY_API_KEY) { Fail 'set LYNTWAY_API_KEY to the account''s API key, or use -Token TOKEN -ApiBase URL for the on-device agent' }

$mode = if ($env:LYNTWAY_AGENT_MODE) { $env:LYNTWAY_AGENT_MODE } else { 'laptop' }
if ($mode -ne 'laptop' -and $mode -ne 'server') { Fail "LYNTWAY_AGENT_MODE is laptop or server, not '$mode'" }

$repo = 'https://github.com/lynt-x-global/lyntway-tools/releases'
$version = if ($env:LYNTWAY_VERSION) { $env:LYNTWAY_VERSION } else { 'latest' }
if ($version -eq 'latest') {
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

# Windows on ARM runs x64 under emulation, and releases up to v0.7.0
# published no arm64 archive. Fall back rather than refuse a machine that can
# run the tool — but say which binary was taken, because somebody debugging
# slow behaviour on a Copilot+ PC needs to know it is a translated one.
$assetArch = $arch
if ($arch -ne 'amd64') {
  $probe = "$base/lyntway_${version}_windows_${arch}.zip"
  $native = $false
  try {
    $null = Invoke-WebRequest -UseBasicParsing -Method Head -Uri $probe -TimeoutSec 20
    $native = $true
  } catch { }
  if (-not $native) {
    Warn "v$version publishes no windows/$arch archive; taking the x64 build, which runs under emulation"
    $assetArch = 'amd64'
  }
}
$asset = "lyntway_${version}_windows_${assetArch}.zip"
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

$installArgs = @('agent', 'install')
if ($mode -eq 'server') { $installArgs += '--server' }
& $exe @installArgs
if ($LASTEXITCODE -ne 0) { Fail 'the agent service could not be installed' }

Write-Host ''
Write-Host "What the agent collects: & '$exe' agent --explain"
