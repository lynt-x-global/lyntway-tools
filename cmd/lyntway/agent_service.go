package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"
)

// Running the agent as a service.
//
// # Two shapes, chosen by who runs the install
//
// A person installing it for themselves gets a per-user service: a launchd
// agent, a systemd user unit, or a scheduled task at their logon. It reads
// their own AI configuration, and needs no administrator.
//
// An RMM tool installing it for a fleet runs as root or SYSTEM, and gets a
// machine service: a launchd daemon, a systemd system unit, or a SYSTEM
// scheduled task at startup. It reads the configuration of whoever is at
// the console, and keeps its state where only an administrator can read
// it, because that state holds the account's key.
//
// # Why a scheduled task rather than a Windows service
//
// A Windows service has to answer the Service Control Manager's protocol,
// which the standard library does not speak and the root module takes no
// dependency to learn. A task that starts at boot, restarts on failure and
// has no time limit is the same thing to everybody but the SCM.
//
// # Signing, which this does not do
//
// The binaries are not yet code-signed. macOS Gatekeeper refuses an
// unsigned binary that arrived through a browser, and an MDM will not
// allow-list one without a Team ID; Windows SmartScreen and most EDR
// products warn on one. Shipping to fleets needs an Apple Developer ID
// Application certificate with notarization (and a stapled ticket on the
// installer package), and a Windows Authenticode certificate — EV, if
// SmartScreen reputation is to be immediate. See scripts/agent/README.md.

const (
	agentLabel    = "com.lyntway.agent"
	agentUnitName = "lyntway-agent.service"
	agentTaskName = "Lyntway Agent"
)

// serviceSpec is everything a service definition is built from.
type serviceSpec struct {
	GOOS     string
	System   bool // root/SYSTEM, machine-wide
	Exe      string
	Args     []string
	StateDir string
	LogPath  string
	User     string // the Windows account a per-user task runs as
}

func agentServiceArgs(stateDir string, server, proxy bool, scan []string) []string {
	args := []string{"agent", "--state-dir", stateDir}
	if server {
		args = append(args, "--server")
	}
	if proxy {
		args = append(args, "--proxy")
	}
	for _, s := range scan {
		args = append(args, "--scan", s)
	}
	return args
}

func agentInstall(args []string) error {
	fs := flag.NewFlagSet("agent install", flag.ExitOnError)
	server := fs.Bool("server", false, "install in server mode")
	proxy := fs.Bool("proxy", false, "keep lyntway proxy in front of a local model server (per-user installs only)")
	stateDir := fs.String("state-dir", "", "where the agent keeps its state")
	printOnly := fs.Bool("print", false, "print the service definition and the commands, and change nothing")
	var scan stringList
	fs.Var(&scan, "scan", "a directory to scan for provider keys (repeatable)")
	_ = fs.Parse(flagsFirst(fs, args))

	goos := runtime.GOOS
	system := elevated()
	if *stateDir == "" {
		*stateDir = defaultStateDir(goos, *server, system, home())
	}
	if *proxy && system {
		return fmt.Errorf("--proxy is for a per-user install: the proxy signs with the person's key and writes receipts to their home, which a root service should not hold. Install without it, or as the user")
	}

	exe := selfPath()
	if abs, err := filepath.Abs(exe); err == nil {
		exe = abs
	}
	spec := serviceSpec{
		GOOS: goos, System: system, Exe: exe, StateDir: *stateDir,
		Args: agentServiceArgs(*stateDir, *server, *proxy, scan),
	}
	spec.LogPath = filepath.Join(*stateDir, "agent.log")
	if goos == "darwin" && system {
		spec.LogPath = "/Library/Logs/Lyntway/agent.log"
	}
	if u, err := user.Current(); err == nil {
		spec.User = u.Username
	}

	path, body, cmds := serviceDefinition(spec)
	if *printOnly {
		shown := string(body)
		if goos == "windows" {
			shown = taskXML(spec)
		}
		fmt.Fprintf(stdout, "# %s\n%s\n# then:\n", path, shown)
		for _, c := range cmds {
			fmt.Fprintf(stdout, "%s\n", strings.Join(c, " "))
		}
		return nil
	}

	if strings.Contains(exe, os.TempDir()) || strings.Contains(exe, "/go-build") {
		return fmt.Errorf("%s is in a temporary directory and will not survive a reboot; put lyntway somewhere permanent first (scripts/agent/install.sh does)", exe)
	}

	// The key: from the environment, written to the agent's own file; or,
	// for a per-user install, the one `lyntway login` already saved.
	c, have := agentConfig(*stateDir)
	if !have {
		return fmt.Errorf("no API key: set LYNTWAY_API_KEY (and LYNTWAY_URL if self-hosted) in the environment and run this again")
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return fmt.Errorf("cannot create %s: %w", *stateDir, err)
	}
	if os.Getenv("LYNTWAY_API_KEY") != "" || system {
		body := agentJSON(config{Origin: c.Origin, Key: c.Key})
		if err := os.WriteFile(filepath.Join(*stateDir, "agent.json"), body, 0o600); err != nil {
			return err
		}
	}
	if goos == "windows" && system {
		// 0600 means nothing to NTFS, and ProgramData is readable by every
		// user by default. The key lives here, so the ACL is replaced with
		// SYSTEM and Administrators only.
		if out, err := exec.Command("icacls", *stateDir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput(); err != nil {
			return fmt.Errorf("could not restrict %s to administrators: %v: %s", *stateDir, err, bytes.TrimSpace(out))
		}
	}
	id, _, err := loadDeviceID(*stateDir, true)
	if err != nil {
		return err
	}
	if err := publishDeviceID(*stateDir, id, system, home()); err != nil {
		return err
	}
	if goos == "windows" && system {
		// The id alone is readable by Users (see publishDeviceID); Windows
		// grants everyone traversal, so the path resolves without the
		// directory being listable.
		idFile := filepath.Join(*stateDir, "device_id")
		if out, err := exec.Command("icacls", idFile, "/grant", "*S-1-5-32-545:R").CombinedOutput(); err != nil {
			return fmt.Errorf("could not make %s readable: %v: %s", idFile, err, bytes.TrimSpace(out))
		}
	}
	if err := os.MkdirAll(filepath.Dir(spec.LogPath), 0o700); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	for _, cmd := range cmds {
		out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if err != nil && !ignorableServiceError(cmd, out) {
			return fmt.Errorf("%s: %v: %s", strings.Join(cmd, " "), err, bytes.TrimSpace(out))
		}
	}
	scope := "for this user"
	if system {
		scope = "for the whole machine"
	}
	fmt.Fprintf(stdout, "Installed %s: %s\nState: %s\nLog:   %s\n\nWhat it collects: `lyntway agent --explain`. The last report it sent: %s\n",
		scope, path, *stateDir, spec.LogPath, filepath.Join(*stateDir, "last-report.json"))
	return nil
}

// ignorableServiceError lets the install be run twice: unloading a service
// that is not loaded is the only failure that means nothing.
func ignorableServiceError(cmd []string, out []byte) bool {
	s := strings.ToLower(string(out))
	return len(cmd) > 1 && cmd[0] == "launchctl" && cmd[1] == "bootout" ||
		strings.Contains(s, "no such process") || strings.Contains(s, "not loaded")
}

func agentUninstall(args []string) error {
	fs := flag.NewFlagSet("agent uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "also delete the state directory: device id, key file and last report")
	stateDir := fs.String("state-dir", "", "the agent's state directory")
	server := fs.Bool("server", false, "it was installed in server mode")
	_ = fs.Parse(flagsFirst(fs, args))

	goos, system := runtime.GOOS, elevated()
	if *stateDir == "" {
		*stateDir = defaultStateDir(goos, *server, system, home())
	}
	spec := serviceSpec{GOOS: goos, System: system, StateDir: *stateDir}
	path, _, _ := serviceDefinition(spec)
	for _, cmd := range serviceRemoval(spec) {
		_ = exec.Command(cmd[0], cmd[1:]...).Run()
	}
	removed := false
	if goos != "windows" {
		if err := os.Remove(path); err == nil {
			removed = true
		}
		if goos == "linux" {
			_ = exec.Command("systemctl", systemctlScope(system, "daemon-reload")...).Run()
		}
	} else {
		removed = true
	}
	if *purge {
		if err := os.RemoveAll(*stateDir); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Removed %s.\n", *stateDir)
	} else {
		fmt.Fprintf(stdout, "The state in %s is kept, so a reinstall is the same device; --purge removes it.\n", *stateDir)
	}
	if removed {
		fmt.Fprintf(stdout, "Uninstalled the agent service (%s).\n", path)
	} else {
		fmt.Fprintf(stdout, "No agent service was installed at %s.\n", path)
	}
	return nil
}

// serviceDefinition returns where the definition goes, its bytes, and the
// commands that load it.
func serviceDefinition(s serviceSpec) (string, []byte, [][]string) {
	switch s.GOOS {
	case "darwin":
		path := filepath.Join(home(), "Library", "LaunchAgents", agentLabel+".plist")
		domain := fmt.Sprintf("gui/%d", os.Getuid())
		if s.System {
			path = filepath.Join("/Library", "LaunchDaemons", agentLabel+".plist")
			domain = "system"
		}
		return path, []byte(launchdPlist(s)), [][]string{
			{"launchctl", "bootout", domain + "/" + agentLabel},
			{"launchctl", "bootstrap", domain, path},
		}
	case "windows":
		path := filepath.Join(s.StateDir, "agent-task.xml")
		return path, utf16LE(taskXML(s)), [][]string{
			{"schtasks", "/Create", "/TN", agentTaskName, "/XML", path, "/F"},
			{"schtasks", "/Run", "/TN", agentTaskName},
		}
	default:
		path := filepath.Join("/etc/systemd/system", agentUnitName)
		if !s.System {
			path = filepath.Join(home(), ".config", "systemd", "user", agentUnitName)
		}
		return path, []byte(systemdUnit(s)), [][]string{
			append([]string{"systemctl"}, systemctlScope(s.System, "daemon-reload")...),
			append([]string{"systemctl"}, systemctlScope(s.System, "enable", "--now", agentUnitName)...),
		}
	}
}

func serviceRemoval(s serviceSpec) [][]string {
	switch s.GOOS {
	case "darwin":
		domain := fmt.Sprintf("gui/%d", os.Getuid())
		if s.System {
			domain = "system"
		}
		return [][]string{{"launchctl", "bootout", domain + "/" + agentLabel}}
	case "windows":
		return [][]string{{"schtasks", "/End", "/TN", agentTaskName}, {"schtasks", "/Delete", "/TN", agentTaskName, "/F"}}
	default:
		return [][]string{append([]string{"systemctl"}, systemctlScope(s.System, "disable", "--now", agentUnitName)...)}
	}
}

func systemctlScope(system bool, args ...string) []string {
	if system {
		return args
	}
	return append([]string{"--user"}, args...)
}

// launchdPlist is the launchd job. KeepAlive restarts it if it exits;
// ProcessType Background tells the scheduler it may be throttled.
func launchdPlist(s serviceSpec) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>` + agentLabel + `</string>
  <key>ProgramArguments</key>
  <array>
`)
	for _, a := range append([]string{s.Exe}, s.Args...) {
		b.WriteString("    <string>" + xmlEscape(a) + "</string>\n")
	}
	b.WriteString(`  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>60</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>` + xmlEscape(s.LogPath) + `</string>
  <key>StandardErrorPath</key>
  <string>` + xmlEscape(s.LogPath) + `</string>
</dict>
</plist>
`)
	return b.String()
}

func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// systemdUnit is the unit file. The system unit is sandboxed: it may read
// the filesystem (that is its job in server mode) and write only its own
// state directory.
func systemdUnit(s serviceSpec) string {
	quoted := make([]string, 0, len(s.Args)+1)
	for _, a := range append([]string{s.Exe}, s.Args...) {
		if strings.ContainsAny(a, " \t\"\\") {
			a = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(a) + `"`
		}
		quoted = append(quoted, a)
	}
	var b strings.Builder
	b.WriteString(`[Unit]
Description=Lyntway agent: reports which AI tools are on this machine
Documentation=https://lyntway.com/docs
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + strings.Join(quoted, " ") + `
Restart=on-failure
RestartSec=30
Nice=10
`)
	if s.System {
		b.WriteString(`StateDirectory=lyntway
StateDirectoryMode=0711
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=` + s.StateDir + `
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
`)
	}
	target := "default.target"
	if s.System {
		target = "multi-user.target"
	}
	b.WriteString("\n[Install]\nWantedBy=" + target + "\n")
	return b.String()
}

// taskXML is a Task Scheduler definition. ExecutionTimeLimit PT0S removes
// the default 72-hour limit, which would otherwise stop the agent three
// days after every boot.
func taskXML(s serviceSpec) string {
	args := make([]string, 0, len(s.Args))
	for _, a := range s.Args {
		if strings.ContainsAny(a, " \t") {
			a = `"` + a + `"`
		}
		args = append(args, a)
	}
	trigger := "<BootTrigger><Enabled>true</Enabled></BootTrigger>"
	principal := `<Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>`
	if !s.System {
		trigger = "<LogonTrigger><Enabled>true</Enabled><UserId>" + xmlEscape(s.User) + "</UserId></LogonTrigger>"
		principal = `<Principal id="Author"><UserId>` + xmlEscape(s.User) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal>`
	}
	doc := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Lyntway agent: reports which AI tools are on this machine. lyntway agent --explain says what it collects.</Description></RegistrationInfo>
  <Triggers>` + trigger + `</Triggers>
  <Principals>` + principal + `</Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlEscape(s.Exe) + `</Command>
      <Arguments>` + xmlEscape(strings.Join(args, " ")) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`
	return doc
}

// utf16LE encodes with a byte-order mark, which is what schtasks /XML
// reads reliably; UTF-8 is accepted by some Windows builds and not others.
func utf16LE(doc string) []byte {
	units := utf16.Encode([]rune(doc))
	out := make([]byte, 2+2*len(units))
	out[0], out[1] = 0xFF, 0xFE
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2+2*i:], u)
	}
	return out
}
