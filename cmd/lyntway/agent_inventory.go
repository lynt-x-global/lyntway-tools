package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// What AI software is on this machine, and which of it is running.
//
// # Methods, and why these
//
// Every fact here comes from one of three places: an application folder
// (a stat, and on macOS the version string in the bundle's Info.plist),
// an editor's extension folder (the directory names carry the version),
// and the process list (names and executable paths — never arguments,
// which is where people put keys). Nothing is executed that belongs to
// the software being inventoried: running `claude --version` to learn a
// version would be starting somebody's AI tool behind their back, and a
// version is not worth that.
//
// # What elevation changes
//
// Nothing, for the basics. Application folders are world-readable, and
// every OS lets a user see the names of their own processes. Run as root
// or SYSTEM the process list includes every user's, and the inventory is
// taken for the person at the console rather than for root, whose home
// has none of this in it.

// agentHost is the machine as the agent sees it: whose home to read, and
// where that OS keeps things. Tests build one pointing at a fixture tree,
// which is how every OS's paths are exercised on whichever OS runs them.
type agentHost struct {
	GOOS         string
	Home         string
	AppData      string // Windows %APPDATA%
	LocalAppData string // Windows %LOCALAPPDATA%
	ProgramFiles []string
	User         string
	Elevated     bool
	// Path is the directories searched for command-line tools, before the
	// usual install locations are added.
	Path []string
	// Root prefixes machine-wide paths such as /Applications and /opt.
	// The filesystem root on a real machine; a fixture tree in tests.
	Root string
}

func (h agentHost) join(parts ...string) string {
	if h.Home == "" {
		return ""
	}
	return filepath.Join(append([]string{h.Home}, parts...)...)
}

// appSupport is where desktop applications keep per-user settings.
func (h agentHost) appSupport(parts ...string) string {
	switch h.GOOS {
	case "darwin":
		return h.join(append([]string{"Library", "Application Support"}, parts...)...)
	case "windows":
		if h.AppData == "" {
			return ""
		}
		return filepath.Join(append([]string{h.AppData}, parts...)...)
	default:
		return h.join(append([]string{".config"}, parts...)...)
	}
}

func (h agentHost) zedSettings() string {
	if h.GOOS == "windows" {
		if h.AppData == "" {
			return ""
		}
		return filepath.Join(h.AppData, "Zed", "settings.json")
	}
	return h.join(".config", "zed", "settings.json")
}

// currentHost describes this machine. When running elevated for a laptop,
// it describes the person at the console instead of root.
func currentHost(server bool) agentHost {
	h := agentHost{GOOS: runtime.GOOS, Elevated: elevated(), Root: string(filepath.Separator)}
	h.Path = filepath.SplitList(os.Getenv("PATH"))
	h.ProgramFiles = nonEmpty(os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"))

	// $HOME first, as every other command here reads it; the account
	// database only when it is unset, as it is for some services.
	if hd, err := os.UserHomeDir(); err == nil {
		h.Home = hd
	}
	if u, err := user.Current(); err == nil {
		h.User = shortUser(u.Username)
		if h.Home == "" {
			h.Home = u.HomeDir
		}
	}
	h.AppData, h.LocalAppData = os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA")

	if h.Elevated && !server {
		if name, home := consoleUser(h.GOOS); home != "" {
			h.User, h.Home = name, home
			if h.GOOS == "windows" {
				h.AppData = filepath.Join(home, "AppData", "Roaming")
				h.LocalAppData = filepath.Join(home, "AppData", "Local")
			}
		}
	}
	return h
}

func shortUser(name string) string {
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		return name[i+1:]
	}
	return name
}

func nonEmpty(vs ...string) []string {
	var out []string
	for _, v := range vs {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// elevated reports root on Unix, and an administrator token on Windows —
// asked of `net session`, which only an administrator may run, because
// the standard library has no other way to ask.
func elevated() bool {
	if runtime.GOOS == "windows" {
		return exec.Command("net", "session").Run() == nil
	}
	return os.Geteuid() == 0
}

// consoleUser finds who is sitting at the machine.
func consoleUser(goos string) (name, home string) {
	lookup := func(uid string) (string, string) {
		u, err := user.LookupId(uid)
		if err != nil {
			return "", ""
		}
		return shortUser(u.Username), u.HomeDir
	}
	switch goos {
	case "darwin":
		// The owner of /dev/console is whoever is logged in at the screen;
		// root owns it at the login window, and then there is nobody.
		info, err := os.Stat("/dev/console")
		if err != nil {
			return "", ""
		}
		if uid, ok := fileOwnerUID(info); ok && uid != 0 {
			return lookup(strconv.Itoa(uid))
		}
	case "linux":
		// systemd-logind makes /run/user/<uid> for every logged-in user;
		// the lowest ordinary uid is the likeliest to be the person.
		entries, _ := os.ReadDir("/run/user")
		best := -1
		for _, e := range entries {
			if n, err := strconv.Atoi(e.Name()); err == nil && n >= 1000 && (best < 0 || n < best) {
				best = n
			}
		}
		if best >= 0 {
			return lookup(strconv.Itoa(best))
		}
	case "windows":
		// Whoever owns explorer.exe is the interactive user.
		out, err := exec.Command("tasklist", "/v", "/fo", "csv", "/nh", "/fi", "imagename eq explorer.exe").Output()
		if err != nil {
			return "", ""
		}
		for _, row := range parseCSVLines(string(out)) {
			if len(row) >= 7 && row[6] != "" && row[6] != "N/A" {
				n := shortUser(row[6])
				if u, err := user.Lookup(row[6]); err == nil {
					return n, u.HomeDir
				}
				return n, filepath.Join(os.Getenv("SystemDrive")+`\`, "Users", n)
			}
		}
	}
	return "", ""
}

// aiApp is one piece of AI software, as reported.
//
// Endpoints is where the machine's configuration says this application
// sends, and is filled in by agent_endpoints.go. Configuration, never
// traffic: there is no field here for what the application did, because
// this agent does not watch it do anything.
type aiApp struct {
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	Running   bool            `json:"running"`
	Version   string          `json:"version"`
	Endpoints []aiAppEndpoint `json:"endpoints,omitempty"`
}

// aiAppDef is how to recognise one application on each OS.
type aiAppDef struct {
	Name string
	Kind string // desktop, cli or local_model

	MacBundle   string   // "ChatGPT.app", under /Applications or ~/Applications
	WinPaths    []string // slash-separated, under %LOCALAPPDATA% or Program Files
	WinPackage  string   // a Microsoft Store package family prefix under %LOCALAPPDATA%\Packages
	LinuxPaths  []string // absolute, or relative to home when they start with "~/"
	Bins        []string // command-line names looked for on PATH
	Procs       []string // process names, without .exe
	PathHints   []string // substrings of an executable path that identify it
	ExcludeHint []string // substrings that mean the process is a different app

	// VersionDir, relative to home, holds one directory per installed
	// version; the newest name is the version.
	VersionDir string
}

// aiApps is the catalogue. Short on purpose: each entry is a product
// somebody's security team will ask about, with an install location that
// is documented and stable. A longer list is a list nobody keeps current.
var aiApps = []aiAppDef{
	{Name: "ChatGPT", Kind: "desktop", MacBundle: "ChatGPT.app", WinPackage: "OpenAI.ChatGPT-Desktop_", Procs: []string{"ChatGPT"}},
	{Name: "Claude", Kind: "desktop", MacBundle: "Claude.app", WinPaths: []string{`AnthropicClaude/claude.exe`}, WinPackage: "Claude_", PathHints: []string{"AnthropicClaude", "/Claude.app/"}, Procs: []string{"Claude"}},
	{Name: "Cursor", Kind: "desktop", MacBundle: "Cursor.app", WinPaths: []string{`Programs/cursor/Cursor.exe`}, LinuxPaths: []string{"/opt/Cursor", "/usr/share/cursor", "~/Applications/cursor.AppImage"}, Bins: []string{"cursor"}, Procs: []string{"Cursor", "cursor"}},
	{Name: "Windsurf", Kind: "desktop", MacBundle: "Windsurf.app", WinPaths: []string{`Programs/Windsurf/Windsurf.exe`}, LinuxPaths: []string{"/usr/share/windsurf", "/opt/windsurf"}, Bins: []string{"windsurf"}, Procs: []string{"Windsurf", "windsurf"}},
	{Name: "Zed", Kind: "desktop", MacBundle: "Zed.app", WinPaths: []string{`Programs/Zed/Zed.exe`}, LinuxPaths: []string{"~/.local/zed.app"}, Bins: []string{"zed", "zeditor"}, Procs: []string{"zed", "Zed", "zed-editor"}},
	{Name: "Perplexity", Kind: "desktop", MacBundle: "Perplexity.app", WinPaths: []string{`Programs/Perplexity/Perplexity.exe`}, Procs: []string{"Perplexity"}},
	{Name: "Microsoft Copilot", Kind: "desktop", WinPackage: "Microsoft.Copilot_", PathHints: []string{"Microsoft.Copilot_"}},
	{Name: "Ollama", Kind: "local_model", MacBundle: "Ollama.app", WinPaths: []string{`Programs/Ollama/ollama.exe`}, LinuxPaths: []string{"/usr/local/bin/ollama", "/usr/bin/ollama"}, Bins: []string{"ollama"}, Procs: []string{"ollama", "Ollama"}},
	{Name: "LM Studio", Kind: "local_model", MacBundle: "LM Studio.app", WinPaths: []string{`Programs/LM Studio/LM Studio.exe`, `Programs/LM-Studio/LM Studio.exe`}, LinuxPaths: []string{"~/.lmstudio/bin/lms"}, Bins: []string{"lms"}, Procs: []string{"LM Studio", "lm-studio"}},
	{Name: "Msty", Kind: "local_model", MacBundle: "Msty.app", WinPaths: []string{`Programs/Msty/Msty.exe`}, Procs: []string{"Msty"}},
	{Name: "Jan", Kind: "local_model", MacBundle: "Jan.app", WinPaths: []string{`Programs/jan/Jan.exe`}, Procs: []string{"Jan"}},
	{Name: "GPT4All", Kind: "local_model", MacBundle: "gpt4all.app", Procs: []string{"chat", "gpt4all"}, PathHints: []string{"/gpt4all"}},
	{Name: "llama.cpp server", Kind: "local_model", Bins: []string{"llama-server"}, Procs: []string{"llama-server"}},

	{Name: "Claude Code", Kind: "cli", Bins: []string{"claude"}, Procs: []string{"claude"}, PathHints: []string{"/claude/versions/", `\claude\versions\`}, ExcludeHint: []string{"AnthropicClaude", "/Claude.app/"}, VersionDir: ".local/share/claude/versions"},
	{Name: "Codex CLI", Kind: "cli", Bins: []string{"codex"}, Procs: []string{"codex"}},
	{Name: "Gemini CLI", Kind: "cli", Bins: []string{"gemini"}, Procs: []string{"gemini"}},
	{Name: "GitHub Copilot CLI", Kind: "cli", Bins: []string{"copilot"}, Procs: []string{"copilot"}},
	{Name: "Cursor Agent CLI", Kind: "cli", Bins: []string{"cursor-agent"}, Procs: []string{"cursor-agent"}},
	{Name: "Aider", Kind: "cli", Bins: []string{"aider"}, Procs: []string{"aider"}},
	{Name: "opencode", Kind: "cli", Bins: []string{"opencode"}, Procs: []string{"opencode"}},
	{Name: "Goose", Kind: "cli", Bins: []string{"goose"}, Procs: []string{"goose"}},
	{Name: "Amp", Kind: "cli", Bins: []string{"amp"}, Procs: []string{"amp"}},
}

// aiExtensions are editor extensions that send code or prompts to a model.
var aiExtensions = []struct{ ID, Name string }{
	{"github.copilot", "GitHub Copilot"},
	{"github.copilot-chat", "GitHub Copilot Chat"},
	{"continue.continue", "Continue"},
	{"saoudrizwan.claude-dev", "Cline"},
	{"rooveterinaryinc.roo-cline", "Roo Code"},
	{"kilocode.kilo-code", "Kilo Code"},
	{"anthropic.claude-code", "Claude Code"},
	{"openai.chatgpt", "Codex"},
	{"codeium.codeium", "Windsurf Plugin"},
	{"tabnine.tabnine-vscode", "Tabnine"},
	{"amazonwebservices.amazon-q-vscode", "Amazon Q"},
	{"google.geminicodeassist", "Gemini Code Assist"},
	{"sourcegraph.cody-ai", "Cody"},
	{"ms-windows-ai-studio.windows-ai-studio", "AI Toolkit"},
	{"teamsdevapp.vscode-ai-foundry", "Azure AI Foundry"},
	{"ms-azuretools.vscode-azure-github-copilot", "GitHub Copilot for Azure"},
}

// editors are where those extensions are installed, and how to tell the
// editor is running.
type editorDef struct {
	Name      string
	ExtDir    string // relative to home
	MacBundle string
	Procs     []string
}

var editors = []editorDef{
	{Name: "VS Code", ExtDir: ".vscode/extensions", MacBundle: "Visual Studio Code.app", Procs: []string{"Code", "code"}},
	{Name: "VS Code Insiders", ExtDir: ".vscode-insiders/extensions", MacBundle: "Visual Studio Code - Insiders.app", Procs: []string{"Code - Insiders", "code-insiders"}},
	{Name: "Cursor", ExtDir: ".cursor/extensions", MacBundle: "Cursor.app", Procs: []string{"Cursor", "cursor"}},
	{Name: "Windsurf", ExtDir: ".windsurf/extensions", MacBundle: "Windsurf.app", Procs: []string{"Windsurf", "windsurf"}},
}

// jetbrainsProcs are the IDE launchers; AI Assistant runs inside them.
var jetbrainsProcs = []string{"idea", "pycharm", "webstorm", "goland", "rider", "clion", "phpstorm", "rubymine", "datagrip", "rustrover", "idea64", "pycharm64", "webstorm64", "goland64", "rider64", "clion64", "phpstorm64"}

// procInfo is one running process: its id, its name, and its executable
// path when the OS will say.
type procInfo struct {
	PID  int
	Name string
	Path string
}

// procMatches reports whether a process is this application.
func (d aiAppDef) procMatches(goos string, p procInfo) bool {
	for _, x := range d.ExcludeHint {
		if strings.Contains(p.Path, x) {
			return false
		}
	}
	// Editor extensions ship their own copies of these tools — the Codex
	// extension runs a binary named codex, Claude Code's runs one named
	// claude — and the first run on a real machine reported "Codex CLI
	// running" on a machine with no Codex CLI installed. A binary inside
	// an editor's folders is that extension's, and is named as such.
	if d.Kind == "cli" && editorOwned(p.Path) {
		return false
	}
	hints := d.PathHints
	if d.MacBundle != "" && goos == "darwin" {
		hints = append(append([]string(nil), hints...), "/"+d.MacBundle+"/")
	}
	for _, x := range hints {
		if p.Path != "" && strings.Contains(p.Path, x) {
			return true
		}
	}
	return nameMatches(goos, p.Name, d.Procs)
}

// editorOwned reports a path inside an editor's extension or storage
// folders.
func editorOwned(path string) bool {
	p := filepath.ToSlash(path)
	if strings.Contains(p, "/globalStorage/") {
		return true
	}
	for _, ed := range editors {
		if strings.Contains(p, "/"+ed.ExtDir+"/") {
			return true
		}
	}
	return false
}

// extensionForPath names the AI extension a process path belongs to:
// "Codex in VS Code".
func extensionForPath(path string) (string, bool) {
	p := strings.ToLower(filepath.ToSlash(path))
	for _, ed := range editors {
		marker := "/" + strings.ToLower(ed.ExtDir) + "/"
		i := strings.Index(p, marker)
		if i < 0 {
			continue
		}
		segment, _, _ := strings.Cut(p[i+len(marker):], "/")
		for _, ext := range aiExtensions {
			if strings.HasPrefix(segment, ext.ID+"-") {
				return ext.Name + " in " + ed.Name, true
			}
		}
	}
	return "", false
}

// nameMatches compares process names the way the OS does: Windows folds
// case and carries .exe, everything else is exact. Exact matters — "claude"
// is Claude Code and "Claude" is the desktop app.
func nameMatches(goos, name string, want []string) bool {
	if goos == "windows" {
		name = strings.TrimSuffix(strings.ToLower(name), ".exe")
		for _, w := range want {
			if strings.ToLower(w) == name {
				return true
			}
		}
		return false
	}
	for _, w := range want {
		if w == name {
			return true
		}
	}
	return false
}

// inventory lists the AI software on this machine.
func inventory(h agentHost, procs []procInfo) []aiApp {
	var out []aiApp
	for _, d := range aiApps {
		installed, version := d.installed(h)
		running := false
		for _, p := range procs {
			if d.procMatches(h.GOOS, p) {
				running = true
				break
			}
		}
		if !installed && !running {
			continue
		}
		out = append(out, aiApp{Name: d.Name, Kind: d.Kind, Running: running, Version: version})
	}

	for _, ed := range editors {
		edRunning := false
		for _, p := range procs {
			if nameMatches(h.GOOS, p.Name, ed.Procs) || (h.GOOS == "darwin" && strings.Contains(p.Path, "/"+ed.MacBundle+"/")) {
				edRunning = true
				break
			}
		}
		for _, ext := range installedExtensions(h.join(filepath.FromSlash(ed.ExtDir))) {
			out = append(out, aiApp{Name: ext.Name + " in " + ed.Name, Kind: "desktop", Running: edRunning, Version: ext.Version})
		}
	}

	if dirs := jetbrainsAIPlugins(h); len(dirs) > 0 {
		running := false
		for _, p := range procs {
			if nameMatches(h.GOOS, p.Name, jetbrainsProcs) {
				running = true
				break
			}
		}
		out = append(out, aiApp{Name: "JetBrains AI Assistant", Kind: "desktop", Running: running})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// installed reports whether the application is on disk, and its version
// when that is readable without running it.
func (d aiAppDef) installed(h agentHost) (bool, string) {
	switch h.GOOS {
	case "darwin":
		if d.MacBundle != "" {
			for _, root := range []string{filepath.Join(h.Root, "Applications"), h.join("Applications")} {
				if root == "" {
					continue
				}
				bundle := filepath.Join(root, d.MacBundle)
				if info, err := os.Stat(bundle); err == nil && info.IsDir() {
					return true, bundleVersion(bundle)
				}
			}
		}
	case "windows":
		for _, rel := range d.WinPaths {
			for _, root := range append([]string{h.LocalAppData}, h.ProgramFiles...) {
				if root != "" && exists(filepath.Join(root, filepath.FromSlash(rel))) {
					return true, ""
				}
			}
		}
		if d.WinPackage != "" && h.LocalAppData != "" {
			if m, _ := filepath.Glob(filepath.Join(h.LocalAppData, "Packages", d.WinPackage+"*")); len(m) > 0 {
				return true, ""
			}
		}
	default:
		for _, p := range d.LinuxPaths {
			if strings.HasPrefix(p, "~/") {
				p = h.join(filepath.FromSlash(p[2:]))
			} else {
				p = filepath.Join(h.Root, filepath.FromSlash(p))
			}
			if p != "" && pathExists(p) {
				return true, ""
			}
		}
	}
	if len(d.Bins) > 0 && findBinary(h, d.Bins) != "" {
		return true, d.versionFromDir(h)
	}
	if d.VersionDir != "" {
		if v := d.versionFromDir(h); v != "" {
			return true, v
		}
	}
	return false, ""
}

func (d aiAppDef) versionFromDir(h agentHost) string {
	if d.VersionDir == "" {
		return ""
	}
	entries, err := os.ReadDir(h.join(filepath.FromSlash(d.VersionDir)))
	if err != nil {
		return ""
	}
	best := ""
	for _, e := range entries {
		if looksLikeVersion(e.Name()) && versionLess(best, e.Name()) {
			best = e.Name()
		}
	}
	return best
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// findBinary looks for a command on PATH and in the places installers put
// them. The service's PATH is minimal, so the usual per-user locations are
// searched too; nothing found is run.
func findBinary(h agentHost, names []string) string {
	dirs := append([]string(nil), h.Path...)
	for _, rel := range []string{".local/bin", "bin", ".npm-global/bin", ".bun/bin", ".cargo/bin", "go/bin", ".lmstudio/bin", ".opencode/bin", ".claude/local"} {
		if p := h.join(filepath.FromSlash(rel)); p != "" {
			dirs = append(dirs, p)
		}
	}
	if h.GOOS == "windows" {
		if h.AppData != "" {
			dirs = append(dirs, filepath.Join(h.AppData, "npm"))
		}
	} else {
		for _, d := range []string{"/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/snap/bin"} {
			dirs = append(dirs, filepath.Join(h.Root, d))
		}
	}
	for _, dir := range dirs {
		// An editor puts its extensions' launchers on the terminal's PATH
		// (Copilot Chat's copilot shim lives in globalStorage); those are
		// the extension's, already reported as the extension.
		if dir == "" || editorOwned(dir+"/") {
			continue
		}
		for _, n := range names {
			candidates := []string{n}
			if h.GOOS == "windows" {
				candidates = []string{n + ".exe", n + ".cmd"}
			}
			for _, c := range candidates {
				p := filepath.Join(dir, c)
				if info, err := os.Stat(p); err == nil && !info.IsDir() {
					return p
				}
			}
		}
	}
	return ""
}

var plistVersion = regexp.MustCompile(`<key>CFBundleShortVersionString</key>\s*<string>([^<]{1,64})</string>`)

// bundleVersion reads CFBundleShortVersionString from a bundle. Binary
// plists are converted by plutil, which ships with macOS and reads a file;
// it runs nothing of the application's.
func bundleVersion(bundle string) string {
	path := filepath.Join(bundle, "Contents", "Info.plist")
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if bytes.HasPrefix(body, []byte("bplist")) {
		out, err := exec.Command("plutil", "-convert", "xml1", "-o", "-", path).Output()
		if err != nil {
			return ""
		}
		body = out
	}
	if m := plistVersion.FindSubmatch(body); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

type extensionInfo struct{ Name, Version string }

// installedExtensions reads an editor's extension folder. Directory names
// are "<publisher>.<name>-<version>[-<platform>]"; the newest version of
// each wins, and a folder listed in .obsolete — uninstalled, awaiting
// deletion — is not counted as installed.
func installedExtensions(dir string) []extensionInfo {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	obsolete := map[string]bool{}
	if body, err := readLocal(filepath.Join(dir, ".obsolete"), 4<<20); err == nil {
		_ = json.Unmarshal(body, &obsolete)
	}
	best := map[string]string{}
	for _, e := range entries {
		if !e.IsDir() || obsolete[e.Name()] {
			continue
		}
		lower := strings.ToLower(e.Name())
		for _, ext := range aiExtensions {
			rest, ok := strings.CutPrefix(lower, ext.ID+"-")
			if !ok || rest == "" || rest[0] < '0' || rest[0] > '9' {
				continue
			}
			v := rest
			if i := strings.Index(v, "-"); i >= 0 {
				v = v[:i]
			}
			if cur, seen := best[ext.ID]; !seen || versionLess(cur, v) {
				best[ext.ID] = v
			}
		}
	}
	var out []extensionInfo
	for _, ext := range aiExtensions {
		if v, ok := best[ext.ID]; ok {
			out = append(out, extensionInfo{Name: ext.Name, Version: v})
		}
	}
	return out
}

func looksLikeVersion(s string) bool {
	return s != "" && s[0] >= '0' && s[0] <= '9' && strings.Contains(s, ".")
}

// versionLess compares dotted versions numerically, so 1.10 is newer than
// 1.9. The empty string is older than everything.
func versionLess(a, b string) bool {
	if a == "" {
		return b != ""
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// jetbrainsAIPlugins finds AI Assistant's plugin folder in any JetBrains
// IDE's configuration. Recent IDEs bundle it instead, so a missing folder
// does not prove it absent; the coverage line says so.
func jetbrainsAIPlugins(h agentHost) []string {
	var patterns []string
	switch h.GOOS {
	case "darwin":
		patterns = []string{h.appSupport("JetBrains", "*", "plugins", "ml-llm")}
	case "windows":
		patterns = []string{h.appSupport("JetBrains", "*", "plugins", "ml-llm")}
	default:
		patterns = []string{h.join(".local", "share", "JetBrains", "*", "ml-llm")}
	}
	var out []string
	for _, p := range patterns {
		if p == "" {
			continue
		}
		m, _ := filepath.Glob(p)
		out = append(out, m...)
	}
	return out
}

// listProcesses reads the process list: names and executable paths, never
// command lines.
func listProcesses(goos string) ([]procInfo, error) {
	switch goos {
	case "linux":
		return procProcesses("/proc")
	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-Process | ForEach-Object { \"$($_.Id)`t$($_.ProcessName)`t$($_.Path)\" }").Output()
		if err == nil {
			return parseTabProcs(string(out)), nil
		}
		out, err = exec.Command("tasklist", "/fo", "csv", "/nh").Output()
		if err != nil {
			return nil, err
		}
		return parseTasklist(string(out)), nil
	default:
		// comm is the executable path on macOS, not the arguments; -ww
		// stops it being cut at the terminal's width.
		out, err := exec.Command("ps", "-axww", "-o", "pid=,comm=").Output()
		if err != nil {
			return nil, err
		}
		return parsePS(string(out)), nil
	}
}

// parsePS reads `ps -o pid=,comm=`.
func parsePS(out string) []procInfo {
	var procs []procInfo
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		pidText, comm, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(pidText)
		if err != nil {
			continue
		}
		comm = strings.TrimSpace(comm)
		p := procInfo{PID: pid, Name: filepath.Base(comm)}
		if strings.HasPrefix(comm, "/") {
			p.Path = comm
		}
		procs = append(procs, p)
	}
	return procs
}

// parseTabProcs reads "<pid>\t<name>\t<path>" lines from PowerShell.
func parseTabProcs(out string) []procInfo {
	var procs []procInfo
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(parts) < 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			continue
		}
		p := procInfo{PID: pid, Name: strings.TrimSpace(parts[1])}
		if len(parts) > 2 {
			p.Path = strings.TrimSpace(parts[2])
		}
		procs = append(procs, p)
	}
	return procs
}

// parseTasklist reads `tasklist /fo csv /nh`: "name","pid",…
func parseTasklist(out string) []procInfo {
	var procs []procInfo
	for _, row := range parseCSVLines(out) {
		if len(row) < 2 {
			continue
		}
		pid, err := strconv.Atoi(row[1])
		if err != nil {
			continue
		}
		procs = append(procs, procInfo{PID: pid, Name: strings.TrimSuffix(row[0], ".exe")})
	}
	return procs
}

// parseCSVLines reads the quoted CSV Windows tools print. Fields are
// always quoted there, and never contain a quote.
func parseCSVLines(out string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		fields := strings.Split(strings.Trim(line, `"`), `","`)
		rows = append(rows, fields)
	}
	return rows
}

// procProcesses reads /proc. The executable link is readable only for a
// process of the same user, or by root; the name always is.
func procProcesses(root string) ([]procInfo, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var procs []procInfo
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(root, e.Name(), "comm"))
		if err != nil {
			continue
		}
		p := procInfo{PID: pid, Name: strings.TrimSpace(string(comm))}
		if exe, err := os.Readlink(filepath.Join(root, e.Name(), "exe")); err == nil {
			p.Path = exe
			// comm is cut at 15 bytes; the executable's name is not.
			if base := filepath.Base(exe); strings.HasPrefix(base, p.Name) {
				p.Name = base
			}
		}
		procs = append(procs, p)
	}
	return procs, nil
}

// osVersion is the operating system's own version string.
func osVersion(goos string) string {
	switch goos {
	case "darwin":
		out, err := exec.Command("sw_vers", "-productVersion").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	case "linux":
		if body, err := os.ReadFile("/etc/os-release"); err == nil {
			return parseOSRelease(string(body))
		}
	case "windows":
		out, err := exec.Command("cmd", "/c", "ver").Output()
		if err == nil {
			s := string(out)
			if i := strings.Index(s, "Version "); i >= 0 {
				return strings.TrimRight(strings.TrimSpace(s[i+len("Version "):]), "]")
			}
		}
	}
	return ""
}

// parseOSRelease returns "Ubuntu 24.04" from /etc/os-release.
func parseOSRelease(body string) string {
	fields := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			fields[k] = strings.Trim(v, `"'`)
		}
	}
	name, ver := fields["NAME"], fields["VERSION_ID"]
	switch {
	case name != "" && ver != "":
		return name + " " + ver
	case fields["PRETTY_NAME"] != "":
		return fields["PRETTY_NAME"]
	}
	return name
}

func reportOS(goos string) string {
	switch goos {
	case "darwin":
		return "macos"
	case "windows", "linux":
		return goos
	}
	return "other"
}
