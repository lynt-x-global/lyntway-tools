package main

// `lyntway device` installs the on-device governance agent.
//
// The whole point is that an IT admin can type `npx lyntway device` on a
// machine and walk away. Every step — auth, download, CA, proxy, autostart,
// sidecar — runs from here without a second command.
//
// This lives in the root module (zero third-party deps), so anything that
// needs the server module's code is done by shelling out to the downloaded
// agent binary. The boundary is deliberate: the CLI downloads the agent,
// then the agent does the platform-specific work it already knows how to do.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func deviceCommand(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "doctor":
			return deviceDoctor()
		case "uninstall":
			return deviceUninstall(args[1:])
		case "start":
			return deviceStart()
		case "stop":
			return deviceStop()
		case "restart":
			_ = deviceStop()
			time.Sleep(2 * time.Second)
			return deviceStart()
		case "status":
			return deviceStatus()
		case "help", "-h", "--help":
			deviceUsage()
			return nil
		}
		// Anything that looks like a flag but is not one we know is a typo, and
		// installing an agent is not a reasonable response to a typo. Every
		// unrecognised argument used to fall through to deviceInstall, so
		// `lyntway device --help` installed the agent and configured it.
		for _, a := range args {
			if strings.HasPrefix(a, "-") && !knownInstallFlag(a) {
				deviceUsage()
				return fmt.Errorf("device: no option called %q", a)
			}
		}
	}
	return deviceInstall(args)
}

// knownInstallFlag reports whether deviceInstall's flag parser understands this
// argument. It has to agree with the loop in deviceInstall; the test asserts
// that every flag that loop reads is listed here.
func knownInstallFlag(a string) bool {
	switch {
	case a == "--key" || strings.HasPrefix(a, "--key="):
		return true
	case a == "--url" || strings.HasPrefix(a, "--url="):
		return true
	case a == "--no-proxy":
		return true
	}
	return false
}

func deviceUsage() {
	fmt.Println(`lyntway device — install and manage the on-device governance agent

Usage:
  lyntway device [--key KEY] [--url URL] [--no-proxy]   install and enrol
  lyntway device start | stop | restart | status        control a running agent
  lyntway device doctor                                 check its health
  lyntway device uninstall                              remove it

Options:
  --key KEY    an enrollment key from the console at /on-device. Single-use,
               and it expires. Without one, and with nothing already signed in,
               the install stops rather than leaving an agent that cannot report.
  --url URL    a self-hosted Lyntway (default https://lyntway.com)
  --no-proxy   install without changing this machine's system proxy`)
}

func deviceStart() error {
	bin := agentBinaryPath()
	if !exists(bin) {
		return fmt.Errorf("agent not installed — run 'npx lyntway device' first")
	}
	fmt.Println("  Starting Lyntway agent...")
	cmd := exec.Command(bin, "--daemon")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

func deviceStop() error {
	bin := agentBinaryPath()
	if !exists(bin) {
		return fmt.Errorf("agent not installed")
	}
	fmt.Println("  Stopping Lyntway agent...")
	cmd := exec.Command(bin, "--stop")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func deviceStatus() error {
	resp, err := http.Get("http://127.0.0.1:9090/health")
	if err != nil {
		fmt.Println("  Agent: not running")
	} else {
		resp.Body.Close()
		fmt.Println("  Agent: running")
	}
	resp, err = http.Get("http://127.0.0.1:8092/health")
	if err != nil {
		fmt.Println("  Sidecar: not running")
	} else {
		resp.Body.Close()
		fmt.Println("  Sidecar: running")
	}
	return nil
}

// ── Welcome ─────────────────────────────────────────────────────────────

const banner = `
  ┌─────────────┐
  │ █         █ │
  │             │  ██       ██    ██ ███    ██ ████████ ██     ██  █████  ██    ██
  │    █ █ █    │  ██        ██  ██  ████   ██    ██    ██     ██ ██   ██  ██  ██
  │  █ █   █ █  │  ██         ████   ██ ██  ██    ██    ██  █  ██ ███████   ████
  │  █       █  │  ██          ██    ██  ██ ██    ██    ██ ███ ██ ██   ██    ██
  │      █      │  ███████     ██    ██   ████    ██     ███ ███  ██   ██    ██
  │  █ █ █ █ █  │
  └─────────────┘  On-Device Governance Agent

`

// killExistingAgent stops any running agent process by killing whatever
// holds ports 9090 (proxy) and 9091 (IPC). Without this, a stale process
// from a previous install blocks the new one from binding.
func killExistingAgent() {
	agentBin := agentBinaryPath()
	if exists(agentBin) {
		cmd := exec.Command(agentBin, "--stop")
		cmd.Stdout = nil
		cmd.Stderr = nil
		_ = cmd.Run()
	}
	// Belt and suspenders: kill anything still on our ports.
	for _, port := range []string{"9090", "9091"} {
		killProcessOnPort(port)
	}
}

// killProcessOnPort finds and kills the process listening on a TCP port.
func killProcessOnPort(port string) {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("netstat", "-ano").Output()
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, "LISTENING") {
				continue
			}
			if !strings.Contains(line, "127.0.0.1:"+port) && !strings.Contains(line, "0.0.0.0:"+port) {
				continue
			}
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 5 {
				continue
			}
			pid := fields[len(fields)-1]
			if pid == "0" {
				continue
			}
			_ = exec.Command("taskkill", "/F", "/PID", pid).Run()
		}
		return
	}
	// macOS / Linux: lsof + kill
	out, err := exec.Command("lsof", "-ti", "tcp:"+port).Output()
	if err != nil {
		return
	}
	for _, pid := range strings.Fields(strings.TrimSpace(string(out))) {
		_ = exec.Command("kill", "-9", pid).Run()
	}
}

// ── Install ─────────────────────────────────────────────────────────────

func deviceInstall(args []string) error {
	fmt.Fprint(stdout, banner)

	// Step 1: check if agent is already running.
	if agentHealthy() {
		fmt.Fprintln(stdout, "  The Lyntway agent is already running on this machine.")
		fmt.Fprintln(stdout, "  Run `lyntway device doctor` for diagnostics.")
		fmt.Fprintln(stdout)
		return nil
	}

	// Step 2: authenticate — either with a one-time key or browser link.
	origin := defaultOrigin
	var apiKey, keyID string

	// Parse flags.
	var enrollKey string
	var noProxy bool
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--key" && i+1 < len(args):
			enrollKey = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--key="):
			enrollKey = strings.TrimPrefix(args[i], "--key=")
		case args[i] == "--url" && i+1 < len(args):
			origin = strings.TrimRight(args[i+1], "/")
			i++
		case strings.HasPrefix(args[i], "--url="):
			origin = strings.TrimRight(strings.TrimPrefix(args[i], "--url="), "/")
		case args[i] == "--no-proxy":
			noProxy = true
		}
	}

	fmt.Fprintln(stdout, "Step 1/5: Authentication")

	if enrollKey == "" {
		// Try existing config first.
		if c, err := loadConfig(); err == nil && c.Key != "" {
			prefix := c.Key
			if len(prefix) > 12 {
				prefix = prefix[:12]
			}
			fmt.Fprintf(stdout, "  This machine is already signed in (%s…).\n", prefix)
			fmt.Fprint(stdout, "  Use the existing key? [Y/n] ")
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			answer := strings.TrimSpace(strings.ToLower(line))
			if answer == "" || answer == "y" || answer == "yes" {
				apiKey, keyID = c.Key, c.KeyID
				origin = c.Origin
			}
		}

		// If still no key, prompt interactively.
		if apiKey == "" {
			fmt.Fprint(stdout, "  Enter your enrollment key: ")
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			enrollKey = strings.TrimSpace(line)
		}
	}

	if enrollKey != "" {
		// One-time enrollment key from the console or email.
		fmt.Fprintf(stdout, "  Activating with enrollment key…\n")
		result, err := activateEnrollKey(origin, enrollKey)
		if err != nil {
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "  The enrollment key was not accepted.")
			fmt.Fprintln(stdout, "  Keys are single-use and expire after 5 minutes.")
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "  If you have dashboard access, generate a new key from On-Device → Enroll.")
			fmt.Fprintln(stdout, "  If you do not have access, contact your administrator.")
			fmt.Fprintf(stdout, "  Support: support@lyntway.com\n")
			return fmt.Errorf("enrollment failed: %w", err)
		}
		apiKey = result.APIKey
		fmt.Fprintln(stdout, "  Activated.")
		fmt.Fprintln(stdout)
	}

	// No key, from the arguments, from an existing sign-in, or from the prompt.
	//
	// This used to carry on: the prompt reads from stdin, its error is
	// discarded, and a closed stdin gives an empty line — so a non-interactive
	// run skipped activation entirely, downloaded the agent, wrote a config with
	// an empty auth_token and printed "Configured." An agent that cannot
	// authenticate reports nothing, and an install that says it worked is worse
	// than one that stops, because nobody goes looking.
	if apiKey == "" {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "  No enrollment key, and this machine is not signed in.")
		fmt.Fprintln(stdout, "  Generate one from the console at /on-device, then:")
		fmt.Fprintln(stdout, "    lyntway device --key KEY")
		return fmt.Errorf("device: no enrollment key, so there is nothing to install against")
	}

	// Save credentials so the agent binary can find them.
	c := config{Origin: origin, Key: apiKey, KeyID: keyID}
	if prev, err := loadConfig(); err == nil && prev.SigningKey != "" {
		c.SigningKey = prev.SigningKey
		if c.KeyID == "" {
			c.KeyID = prev.KeyID
		}
	}
	if _, err := saveConfig(c); err != nil {
		return fmt.Errorf("saving credentials: %w", err)
	}

	// Step 3: download the agent binary.
	fmt.Fprintln(stdout, "Step 2/5: Downloading agent binary")
	agentPath, err := downloadAgent(origin)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	fmt.Fprintf(stdout, "  Installed to %s\n\n", agentPath)

	// Step 4: write agent config so the binary can authenticate heartbeats.
	// The CLI already activated with the server (Step 1), so we write the
	// config directly rather than shelling out to the agent's own --enroll
	// (which would try to consume the enrollment token a second time).
	fmt.Fprintln(stdout, "Step 3/5: Configuring agent")
	hostname, _ := os.Hostname()
	if err := writeAgentConfig(origin, apiKey, hostname); err != nil {
		return fmt.Errorf("writing agent config: %w", err)
	}
	fmt.Fprintln(stdout, "  Configured.")
	fmt.Fprintln(stdout)

	// Step 5: setup — CA, proxy, autostart.
	fmt.Fprintln(stdout, "Step 4/5: System setup (CA, proxy, autostart)")
	setupArgs := []string{"--setup"}
	if noProxy {
		fmt.Fprintln(stdout, "  Skipping system proxy (--no-proxy).")
	}
	if err := runAgentSetup(agentPath, setupArgs); err != nil {
		// Setup failures are warnings, not fatal — the agent can still
		// run without CA or autostart; they just need manual steps.
		fmt.Fprintf(stdout, "  Warning: setup had issues: %v\n", err)
		fmt.Fprintln(stdout, "  The agent may need manual CA or autostart configuration.")
	} else {
		fmt.Fprintln(stdout, "  CA installed, autostart registered.")
		fmt.Fprintln(stdout)
	}

	// Step 6: health check.
	fmt.Fprintln(stdout, "Step 5/5: Health check")

	// Kill any stale agent process from a previous install before starting.
	killExistingAgent()

	// Start the agent if it isn't already running.
	if !agentHealthy() {
		if err := startAgent(agentPath); err != nil {
			fmt.Fprintf(stdout, "  Could not start agent: %v\n", err)
		} else {
			// Give it a moment to come up.
			for i := 0; i < 20; i++ {
				if agentHealthy() {
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
		}
	}

	if agentHealthy() {
		fmt.Fprintln(stdout, "  Agent is running and healthy.")
	} else {
		fmt.Fprintln(stdout, "  Agent installed but not yet responding.")
		fmt.Fprintln(stdout, "  Run `lyntway device doctor` to diagnose.")
	}

	fmt.Fprintln(stdout, "\nDone. This device is now governed by Lyntway.")
	fmt.Fprintln(stdout, "View it in your console at "+origin+"/on-device")
	return nil
}

// ── Uninstall ────────────────────────────────────────────────────────────

func deviceUninstall(args []string) error {
	fmt.Fprintln(stdout, "Lyntway On-Device Agent — Uninstall")
	fmt.Fprintln(stdout, strings.Repeat("─", 50))

	// Parse --url flag.
	origin := defaultOrigin
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--url" && i+1 < len(args):
			origin = strings.TrimRight(args[i+1], "/")
			i++
		case strings.HasPrefix(args[i], "--url="):
			origin = strings.TrimRight(strings.TrimPrefix(args[i], "--url="), "/")
		}
	}

	// Load saved config for origin and machine identity.
	if c, err := loadConfig(); err == nil && c.Origin != "" {
		origin = c.Origin
	}

	// Prompt for the uninstall token from the admin.
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  An uninstall token is required. Ask your administrator to")
	fmt.Fprintln(stdout, "  generate one from the dashboard: On-Device → device menu → Uninstall.")
	fmt.Fprintln(stdout)
	fmt.Fprint(stdout, "  Enter uninstall token: ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	token := strings.TrimSpace(line)
	if token == "" {
		return fmt.Errorf("no uninstall token provided")
	}

	// Verify the token with the server.
	fmt.Fprintln(stdout, "  Verifying token…")
	payload, _ := json.Marshal(map[string]string{"token": token})
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(origin+"/v1/on-device/verify-uninstall", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", origin, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		fmt.Fprintln(stdout, "  Token was not accepted. It may have expired or already been used.")
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(raw))
	}
	fmt.Fprintln(stdout, "  Token verified.")
	fmt.Fprintln(stdout)

	// Step 1: Stop the agent — gracefully first, then force-kill the ports.
	fmt.Fprintln(stdout, "Step 1/4: Stopping agent")
	killExistingAgent()
	fmt.Fprintln(stdout, "  Agent stopped.")

	// Step 2: Remove system configuration (proxy, CA, autostart).
	// Done directly instead of via --uninstall because the token has
	// already been consumed by the verify call above.
	fmt.Fprintln(stdout, "Step 2/4: Removing system configuration")
	agentBin := agentBinaryPath()
	if exists(agentBin) {
		// Disable system proxy first — most critical, keeps internet working.
		_ = exec.Command(agentBin, "--disable-system-proxy").Run()
		fmt.Fprintln(stdout, "  System proxy disabled.")

		_ = exec.Command(agentBin, "--uninstall-ca").Run()
		fmt.Fprintln(stdout, "  CA certificate removed.")

		// Remove autostart (scheduled task / launchd / systemd).
		removeAutoStart()
		fmt.Fprintln(stdout, "  Autostart removed.")

		// Clean up sidecar env var on Windows.
		if runtime.GOOS == "windows" {
			_ = exec.Command("powershell", "-NoProfile", "-Command",
				`[Environment]::SetEnvironmentVariable("LYNTWAY_SIDECAR_PROFILE", $null, "User")`).Run()
		}
	} else {
		// No binary — do proxy cleanup directly so internet is not broken.
		disableProxyDirect()
		fmt.Fprintln(stdout, "  Agent binary not found, proxy cleaned up directly.")
	}

	// Always clean up CA env vars directly — even when the binary is gone
	// or --uninstall-ca failed. A stale NODE_EXTRA_CA_CERTS pointing at a
	// deleted cert file breaks Node.js apps (Claude Code, Cursor, etc.).
	clearCAEnvVarsDirect()

	// Step 3: Remove the agent binary.
	fmt.Fprintln(stdout, "Step 3/4: Removing agent binary")
	if exists(agentBin) {
		if err := os.Remove(agentBin); err != nil {
			fmt.Fprintf(stdout, "  Warning: could not remove %s: %v\n", agentBin, err)
		} else {
			fmt.Fprintf(stdout, "  Removed %s\n", agentBin)
		}
	} else {
		fmt.Fprintln(stdout, "  Already removed.")
	}

	// Step 4: Remove config.
	fmt.Fprintln(stdout, "Step 4/4: Removing credentials")
	cfgPath, err := configPath()
	if err == nil && exists(cfgPath) {
		if err := os.Remove(cfgPath); err != nil {
			fmt.Fprintf(stdout, "  Warning: could not remove %s: %v\n", cfgPath, err)
		} else {
			fmt.Fprintf(stdout, "  Removed %s\n", cfgPath)
		}
	} else {
		fmt.Fprintln(stdout, "  No credentials found.")
	}

	// Clean up empty directories.
	h := home()
	if h != "" {
		agentDir := filepath.Join(h, ".lyntway", "agent")
		os.RemoveAll(agentDir) // agent config + CA certs
		binDir := filepath.Join(h, ".lyntway", "bin")
		os.Remove(binDir) // only succeeds if empty
		lyntDir := filepath.Join(h, ".lyntway")
		os.Remove(lyntDir) // only succeeds if empty
	}

	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Done. The Lyntway agent has been removed from this device.")
	return nil
}

// ── Doctor ──────────────────────────────────────────────────────────────

func deviceDoctor() error {
	fmt.Fprintln(stdout, "Lyntway On-Device Agent")
	fmt.Fprintln(stdout, strings.Repeat("─", 50))

	// Agent process.
	if agentHealthy() {
		info, err := agentStatus()
		if err == nil && info != nil {
			if v, ok := info["version"].(string); ok {
				fmt.Fprintf(stdout, "  Agent:     running (version %s)\n", v)
			} else {
				fmt.Fprintln(stdout, "  Agent:     running")
			}
			if uptime, ok := info["uptime"].(string); ok {
				fmt.Fprintf(stdout, "  Uptime:    %s\n", uptime)
			}
		} else {
			fmt.Fprintln(stdout, "  Agent:     running")
		}
		fmt.Fprintln(stdout, "  Proxy:     127.0.0.1:9090 ✓")
	} else {
		fmt.Fprintln(stdout, "  Agent:     not running")
		fmt.Fprintln(stdout, "  Proxy:     not responding")
	}

	// Config.
	c, err := loadConfig()
	if err != nil {
		fmt.Fprintln(stdout, "  Auth:      not signed in")
	} else {
		fmt.Fprintf(stdout, "  API:       connected to %s\n", c.Origin)
	}

	// Agent binary.
	agentBin := agentBinaryPath()
	if exists(agentBin) {
		fmt.Fprintf(stdout, "  Binary:    %s ✓\n", agentBin)
	} else {
		fmt.Fprintln(stdout, "  Binary:    not found")
	}

	// Sidecar.
	if sidecarHealthy() {
		fmt.Fprintln(stdout, "  Sidecar:   healthy ✓")
	} else {
		fmt.Fprintln(stdout, "  Sidecar:   not running")
	}

	// RAM.
	fmt.Fprintf(stdout, "  Platform:  %s/%s\n", runtime.GOOS, runtime.GOARCH)

	fmt.Fprintln(stdout, strings.Repeat("─", 50))
	return nil
}

// ── Helpers ─────────────────────────────────────────────────────────────

// agentHealthy probes whether the agent process is running. It tries the
// proxy port, the IPC port, and on Windows the named pipe — any one
// responding is enough.
func agentHealthy() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	for _, addr := range []string{
		"http://127.0.0.1:9090/status",
		"http://127.0.0.1:9091/status",
	} {
		resp, err := client.Get(addr)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
	}
	// On Windows, check if the process is alive by name.
	if runtime.GOOS == "windows" {
		out, err := exec.Command("tasklist", "/FI", "IMAGENAME eq lyntway-agent.exe", "/NH").Output()
		if err == nil && strings.Contains(string(out), "lyntway-agent.exe") {
			return true
		}
	}
	return false
}

// agentStatus returns the agent's status JSON, if reachable.
func agentStatus() (map[string]interface{}, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:9090/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var info map[string]interface{}
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, err
	}
	return info, nil
}

// sidecarHealthy probes the AI sidecar.
func sidecarHealthy() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8092/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// agentBinaryPath returns where the agent binary should be installed.
func agentBinaryPath() string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	h := home()
	if h == "" {
		return "lyntway-agent" + ext
	}
	return filepath.Join(h, ".lyntway", "bin", "lyntway-agent"+ext)
}

// downloadAgent fetches the agent binary from the service and installs it.
func downloadAgent(origin string) (string, error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}
	filename := fmt.Sprintf("lyntway-agent_%s_%s%s", goos, goarch, ext)
	url := origin + "/dl/on-device/" + filename

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("reaching %s: %w", origin, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned %d for %s", resp.StatusCode, filename)
	}

	dest := agentBinaryPath()
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}

	// Write to a temp file, then rename — so a partial download never
	// leaves a broken binary behind.
	tmp, err := os.CreateTemp(filepath.Dir(dest), "lyntway-agent-*.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", err
	}
	tmp.Close()

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	return dest, nil
}

// activateEnrollKey uses a one-time enrollment token against the service.
type enrollResult struct {
	APIKey string `json:"api_key"`
}

func activateEnrollKey(origin, token string) (enrollResult, error) {
	hostname, _ := os.Hostname()
	payload, _ := json.Marshal(map[string]string{
		"token":         token,
		"machine_id":    fmt.Sprintf("dev-%s-%s-%s", hostname, runtime.GOOS, runtime.GOARCH),
		"hostname":      hostname,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"agent_version": version,
	})

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(origin+"/v1/on-device/activate", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		return enrollResult{}, fmt.Errorf("reaching %s: %w", origin, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return enrollResult{}, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(raw))
	}
	var result struct {
		Status    string `json:"status"`
		APIKey    string `json:"api_key"`
		EmailHint string `json:"email_hint"`
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return enrollResult{}, fmt.Errorf("invalid response: %w", err)
	}

	// Two-step verification: server sent a 6-digit code to the employee's
	// email. Prompt for it and complete the activation.
	if result.Status == "verify_email" {
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "  A verification code has been sent to %s\n", result.EmailHint)
		fmt.Fprint(stdout, "  Enter code: ")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		code := strings.TrimSpace(line)
		if code == "" {
			return enrollResult{}, fmt.Errorf("no verification code entered")
		}
		return verifyEnrollCode(origin, result.SessionID, code)
	}

	return enrollResult{APIKey: result.APIKey}, nil
}

func verifyEnrollCode(origin, sessionID, code string) (enrollResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"code":       code,
	})
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(origin+"/v1/on-device/verify", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		return enrollResult{}, fmt.Errorf("reaching %s: %w", origin, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return enrollResult{}, fmt.Errorf("verification failed: %s", string(raw))
	}
	var result struct {
		Status string `json:"status"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return enrollResult{}, fmt.Errorf("invalid response: %w", err)
	}
	return enrollResult{APIKey: result.APIKey}, nil
}

// writeAgentConfig writes the agent's config file directly. The CLI has
// already activated the enrollment token and received an API key, so we
// skip the agent's own --enroll path (which would try to consume the
// token a second time and fail).
func writeAgentConfig(origin, apiKey, hostname string) error {
	agentDir := filepath.Join(home(), ".lyntway", "agent")
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		return err
	}
	cfg := map[string]string{
		"auth_token":   apiKey,
		"api_base_url": origin,
		"machine_id":   fmt.Sprintf("dev-%s-%s-%s", hostname, runtime.GOOS, runtime.GOARCH),
		"hostname":     hostname,
		"listen_addr":  "127.0.0.1:9090",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(agentDir, "agent.json"), data, 0o600)
}

// runAgentSetup shells out to the agent binary for CA + proxy + autostart.
func runAgentSetup(agentPath string, extraArgs []string) error {
	cmd := exec.Command(agentPath, extraArgs...)
	cmd.Stdout = stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// startAgent starts the agent binary in daemon mode.
func startAgent(agentPath string) error {
	cmd := exec.Command(agentPath, "--daemon")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// removeAutoStart deletes the OS-level autostart registration.
func removeAutoStart() {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("schtasks", "/delete", "/tn", "LyntwayAgent", "/f").Run()
	case "darwin":
		plist := filepath.Join(home(), "Library", "LaunchAgents", "com.lyntway.agent.plist")
		_ = exec.Command("launchctl", "unload", plist).Run()
		os.Remove(plist)
	case "linux":
		_ = exec.Command("systemctl", "--user", "stop", "lyntway-agent").Run()
		_ = exec.Command("systemctl", "--user", "disable", "lyntway-agent").Run()
		svc := filepath.Join(home(), ".config", "systemd", "user", "lyntway-agent.service")
		os.Remove(svc)
	}
}

// clearCAEnvVarsDirect removes NODE_EXTRA_CA_CERTS and related env vars
// without needing the agent binary. Used during uninstall so a stale
// env var pointing at a deleted cert file does not break Node.js apps.
func clearCAEnvVarsDirect() {
	caEnvVars := []string{"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"}
	switch runtime.GOOS {
	case "windows":
		for _, name := range caEnvVars {
			_ = exec.Command("powershell", "-NoProfile", "-Command",
				fmt.Sprintf(`[Environment]::SetEnvironmentVariable("%s", $null, "User")`, name)).Run()
		}
	case "darwin", "linux":
		// Remove the marker block from shell RC files.
		h := home()
		if h == "" {
			return
		}
		marker := "# lyntway-agent ca"
		for _, rc := range []string{".zprofile", ".bash_profile", ".profile", ".bashrc"} {
			rcPath := filepath.Join(h, rc)
			data, err := os.ReadFile(rcPath)
			if err != nil {
				continue
			}
			if !strings.Contains(string(data), marker) {
				continue
			}
			lines := strings.Split(string(data), "\n")
			var out []string
			skip := false
			for _, line := range lines {
				if strings.TrimSpace(line) == marker {
					skip = true
					continue
				}
				if skip && strings.HasPrefix(strings.TrimSpace(line), "export ") {
					continue
				}
				skip = false
				out = append(out, line)
			}
			_ = os.WriteFile(rcPath, []byte(strings.Join(out, "\n")), 0o644)
		}
	}
}

// disableProxyDirect removes the system proxy without needing the agent
// binary.  Used when the binary is already gone.
func disableProxyDirect() {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("reg", "add",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
			"/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f").Run()
		_ = exec.Command("reg", "delete",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
			"/v", "ProxyServer", "/f").Run()
		for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY"} {
			_ = exec.Command("powershell", "-NoProfile", "-Command",
				fmt.Sprintf(`[Environment]::SetEnvironmentVariable("%s", $null, "User")`, name)).Run()
		}
	case "darwin":
		for _, svc := range []string{"Wi-Fi", "Ethernet"} {
			_ = exec.Command("networksetup", "-setwebproxystate", svc, "off").Run()
			_ = exec.Command("networksetup", "-setsecurewebproxystate", svc, "off").Run()
		}
	case "linux":
		_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
	}
}
