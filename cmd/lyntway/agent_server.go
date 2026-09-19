package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Server mode: the keys sitting in files, the SDKs that will use them, and
// the one change that routes each through the gateway.
//
// # Why a server is different from a laptop
//
// A laptop's AI is mostly applications a person opens. A server's is code:
// an SDK reading OPENAI_API_KEY from a .env file or a systemd unit, calling
// the provider directly. The inventory that matters there is which keys
// are on disk, which code will use them, and which processes are already
// talking to a provider — and the useful output is not a dashboard but the
// exact lines to change.
//
// # What leaves the machine
//
// For each file holding a key: its path and the class of key, counted. Sent
// to /v1/attest, where it becomes an attested receipt — this agent reported
// it; the service did not see the file. Never the value, never its last
// four characters, never a digest of it: a digest of a short secret is the
// secret to anybody with a list of candidates.
//
// The path does leave, which the migration receipt deliberately does not
// send. The difference is who reads it: a migration receipt is written to
// be handed to a stranger, and this report is for the operator who has to
// go and rotate the key, for whom a finding without a path is a finding
// they cannot act on. Kolide's secret detection makes the same choice.

// serverScanLimits bound the walk. A server's /opt can hold millions of
// files, and an agent that pins a CPU for an hour is an agent somebody
// uninstalls; the coverage line says when a limit was hit.
type serverScanLimits struct {
	MaxFiles int
	MaxBytes int64
	MaxDepth int
}

var defaultServerLimits = serverScanLimits{MaxFiles: 50000, MaxBytes: 1 << 20, MaxDepth: 8}

// defaultServerRoots is where application code and its configuration live
// on a Linux server. /etc/systemd/system is included because a unit's
// Environment= line is where a key goes when somebody has been told not to
// put it in a .env file.
var defaultServerRoots = []string{"/srv", "/opt", "/var/www", "/app", "/home", "/root", "/etc/systemd/system", "/etc/environment"}

// skipDirs are never descended: dependencies and caches, whose keys (if
// any) are somebody else's fixtures, and the kernel's pseudo-filesystems.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"site-packages": true, "dist-packages": true, "__pycache__": true, ".cache": true,
	".npm": true, ".cargo": true, ".rustup": true, "target": true, ".gradle": true,
	".m2": true, ".tox": true, ".next": true, "proc": true, "sys": true, "dev": true,
	".lyntway": true,
}

var codeExts = map[string]bool{
	".py": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".jsx": true,
	".go": true, ".rb": true, ".java": true, ".kt": true, ".cs": true, ".php": true, ".rs": true,
	".yaml": true, ".yml": true, ".toml": true, ".json": true, ".ini": true, ".cfg": true,
	".conf": true, ".properties": true, ".sh": true, ".service": true, ".env": true, ".tf": true,
	".tfvars": true, ".ipynb": true,
}

// scannable reports whether a file is one this reads.
func scannable(name string) bool {
	lower := strings.ToLower(name)
	switch {
	case lower == ".env", strings.HasPrefix(lower, ".env."), lower == "environment",
		lower == "dockerfile", strings.HasPrefix(lower, "docker-compose"):
		return true
	}
	return codeExts[filepath.Ext(lower)]
}

// keyAtRest is one key found in a file. Value-free by construction.
type keyAtRest struct {
	File     string
	Line     int
	Class    string
	Label    string
	Upstream string
}

// sdkUse is an AI SDK a project declares.
type sdkUse struct {
	Name     string
	Upstream string
	Dir      string
}

// hostInCode is a provider's address written into source.
type hostInCode struct {
	Host string
	File string
}

type serverScan struct {
	Roots     []string
	Files     int
	NotLocal  int // in cloud storage, not downloaded, not read
	Truncated bool
	Keys      []keyAtRest
	SDKs      []sdkUse
	Hosts     []hostInCode
	// Modified is each file's modification time, which distinguishes one
	// version of a file's findings from the next.
	Modified map[string]time.Time
	// ScannedAt is when the findings were made.
	ScannedAt time.Time
}

// aiSDKs maps package names to the upstream they call.
var aiSDKs = map[string]string{
	"openai": "openai", "@openai/agents": "openai", "github.com/openai/openai-go": "openai",
	"github.com/sashabaranov/go-openai": "openai", "@ai-sdk/openai": "openai",
	"anthropic": "anthropic", "@anthropic-ai/sdk": "anthropic", "@anthropic-ai/claude-agent-sdk": "anthropic",
	"claude-agent-sdk": "anthropic", "github.com/anthropics/anthropic-sdk-go": "anthropic", "@ai-sdk/anthropic": "anthropic",
	"google-generativeai": "gemini", "google-genai": "gemini", "@google/generative-ai": "gemini",
	"@google/genai": "gemini", "@ai-sdk/google": "gemini",
	"mistralai": "mistral", "@mistralai/mistralai": "mistral",
	"xai-sdk": "xai", "@ai-sdk/xai": "xai",
	"cohere": "", "cohere-ai": "", "groq": "", "groq-sdk": "", "together": "", "replicate": "",
	"litellm": "", "langchain": "", "langchain-openai": "openai", "langchain-anthropic": "anthropic",
	"@langchain/openai": "openai", "@langchain/anthropic": "anthropic", "llama-index": "", "ollama": "",
}

// scanServerFiles walks roots for keys, SDK declarations and provider
// addresses in code.
func scanServerFiles(roots []string, lim serverScanLimits) serverScan {
	s := serverScan{Roots: roots, Modified: map[string]time.Time{}, ScannedAt: time.Now().UTC()}
	sdkSeen := map[string]bool{}
	hostSeen := map[string]bool{}
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		base := strings.Count(filepath.Clean(root), string(filepath.Separator))
		walk := func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// An unreadable directory is skipped, not fatal: a server
				// has plenty this user may not read, and the coverage line
				// already says the scan saw what it could.
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if s.Truncated {
				return filepath.SkipAll
			}
			if d.IsDir() {
				if path != root && (skipDirs[d.Name()] || strings.Count(path, string(filepath.Separator))-base > lim.MaxDepth) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			name := d.Name()
			if sdk := sdksIn(path, name); len(sdk) > 0 {
				for _, u := range sdk {
					k := u.Name + "\x00" + u.Dir
					if !sdkSeen[k] {
						sdkSeen[k] = true
						s.SDKs = append(s.SDKs, u)
					}
				}
			}
			if !scannable(name) {
				return nil
			}
			fi, err := d.Info()
			if err != nil || fi.Size() > lim.MaxBytes {
				return nil
			}
			if s.Files >= lim.MaxFiles {
				s.Truncated = true
				return filepath.SkipAll
			}
			body, err := readLocal(path, lim.MaxBytes)
			if errors.Is(err, errNotLocal) {
				s.NotLocal++
				return nil
			}
			if err != nil || isBinary(body) {
				return nil
			}
			s.Files++
			text := string(body)
			for _, h := range findKeys(text, 1) {
				s.Keys = append(s.Keys, keyAtRest{File: path, Line: h.Line, Class: h.Class, Label: h.Label, Upstream: h.Upstream})
				s.Modified[path] = fi.ModTime().UTC().Truncate(time.Second)
			}
			for _, d := range aiHosts {
				if d.Upstream == "" || d.Upstream == "lyntway" {
					continue
				}
				if strings.Contains(text, d.Host) && !hostSeen[d.Host+"\x00"+path] {
					hostSeen[d.Host+"\x00"+path] = true
					s.Hosts = append(s.Hosts, hostInCode{Host: d.Host, File: path})
				}
			}
			return nil
		}
		if !info.IsDir() {
			_ = walk(root, fs.FileInfoToDirEntry(info), nil)
			continue
		}
		_ = filepath.WalkDir(root, walk)
	}
	return s
}

// sdksIn reads a dependency manifest for AI SDKs. Names only: which
// version is installed is the dependency check's question, not this one.
func sdksIn(path, name string) []sdkUse {
	var names []string
	switch name {
	case "package.json":
		body, err := readLocal(path, 1<<20)
		if err != nil {
			return nil
		}
		var pkg struct {
			Deps    map[string]string `json:"dependencies"`
			DevDeps map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(body, &pkg) != nil {
			return nil
		}
		for n := range pkg.Deps {
			names = append(names, n)
		}
		for n := range pkg.DevDeps {
			names = append(names, n)
		}
	case "requirements.txt", "pyproject.toml", "go.mod", "Pipfile":
		body, err := readLocal(path, 1<<20)
		if err != nil || len(body) > 1<<20 {
			return nil
		}
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue
			}
			line = strings.Trim(strings.TrimPrefix(line, "require "), `"', `)
			end := strings.IndexAny(line, " =<>~!;[\t\"'")
			if end >= 0 {
				line = line[:end]
			}
			names = append(names, strings.ToLower(line))
		}
	default:
		return nil
	}
	var out []sdkUse
	dir := filepath.Dir(path)
	for _, n := range names {
		if up, ok := aiSDKs[n]; ok {
			out = append(out, sdkUse{Name: n, Upstream: up, Dir: dir})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// keyAttestation is what /v1/attest receives for one file. Built from
// classes and counts; there is no field here that could carry a value.
type keyAttestation struct {
	ChainID    string            `json:"chain_id"`
	Tool       string            `json:"tool"`
	Action     attestAction      `json:"action"`
	Actor      map[string]string `json:"actor"`
	Findings   []attestFinding   `json:"findings"`
	Reference  string            `json:"reference"`
	OccurredAt string            `json:"occurred_at"`
}

type attestAction struct {
	Surface     string `json:"surface"`
	Direction   string `json:"direction"`
	Method      string `json:"method"`
	Target      string `json:"target"`
	Destination string `json:"destination"`
}

type attestFinding struct {
	Class string `json:"class"`
	Count int    `json:"count"`
}

const agentTool = "lyntway-agent"

// keyAttestations groups a scan's keys by file.
//
// The destination names the file and the version of it that was read. It
// has to differ between versions: the service derives the receipt's id
// from the tool, destination, actor, decision and reference, and a file
// whose keys changed would otherwise be issued a second, different receipt
// under the first one's id.
func keyAttestations(s serverScan, deviceID, hostname string) []keyAttestation {
	byFile := map[string]map[string]int{}
	for _, k := range s.Keys {
		if byFile[k.File] == nil {
			byFile[k.File] = map[string]int{}
		}
		byFile[k.File][k.Class]++
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)

	var out []keyAttestation
	for _, f := range files {
		classes := make([]string, 0, len(byFile[f]))
		for c := range byFile[f] {
			classes = append(classes, c)
		}
		sort.Strings(classes)
		var findings []attestFinding
		for _, c := range classes {
			findings = append(findings, attestFinding{Class: c, Count: byFile[f][c]})
		}
		dest := "file://" + hostname + filepath.ToSlash(f)
		if m, ok := s.Modified[f]; ok {
			dest += "#modified=" + m.Format(time.RFC3339)
		}
		out = append(out, keyAttestation{
			ChainID: "device:" + deviceID,
			Tool:    agentTool,
			Action: attestAction{
				// primitive: content handed to the service rather than
				// intercepted, which is what a report is.
				Surface: "primitive", Direction: "request",
				Method: "key at rest", Target: filepath.ToSlash(f), Destination: dest,
			},
			Actor:     map[string]string{"type": "agent", "id": agentTool},
			Findings:  findings,
			Reference: deviceID,
			// When the finding was made. The service folds it into the
			// receipt id, so the same finding reported on two days is two
			// receipts rather than one id claimed twice.
			OccurredAt: s.ScannedAt.Format(time.RFC3339),
		})
	}
	return out
}

// fingerprint identifies an attestation's content, so an unchanged file is
// not reported again every fifteen minutes.
func (a keyAttestation) fingerprint() string {
	// Without the time: the same findings found again are not new.
	a.OccurredAt = ""
	body, _ := json.Marshal(a)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:8])
}

// sendKeyAttestations posts the attestations not already sent, and returns
// how many went. sent is updated in place.
func sendKeyAttestations(client *http.Client, c config, signer *requestSigner, atts []keyAttestation, sent map[string]string, log io.Writer) int {
	n := 0
	for _, a := range atts {
		fp := a.fingerprint()
		if sent[a.Action.Target] == fp {
			continue
		}
		status, raw, err := doAPI(client, c, signer, http.MethodPost, "/v1/attest", a)
		switch {
		case err != nil:
			fmt.Fprintf(log, "lyntway agent: the finding in %s was not reported: %v\n", a.Action.Target, err)
			continue
		case status != http.StatusOK && status != http.StatusCreated:
			fmt.Fprintf(log, "lyntway agent: the finding in %s was not reported: %s\n", a.Action.Target, apiMessage(status, raw))
			continue
		}
		sent[a.Action.Target] = fp
		n++
	}
	return n
}

// routingAdvice is the exact change that sends each provider's traffic
// through the gateway, for everything server mode found.
func routingAdvice(origin string, s serverScan, dests []destination) string {
	type evidence struct{ lines []string }
	byUp := map[string]*evidence{}
	note := func(up, line string) {
		if up == "" || up == "lyntway" {
			return
		}
		if byUp[up] == nil {
			byUp[up] = &evidence{}
		}
		if !contains(byUp[up].lines, line) {
			byUp[up].lines = append(byUp[up].lines, line)
		}
	}
	keyDirs := map[string][]string{}
	for _, k := range s.Keys {
		note(k.Upstream, fmt.Sprintf("%s in %s", upstreamLabel(k.Upstream), k.File))
		if k.Upstream != "" && isEnvFileName(filepath.Base(k.File)) && !contains(keyDirs[k.Upstream], filepath.Dir(k.File)) {
			keyDirs[k.Upstream] = append(keyDirs[k.Upstream], filepath.Dir(k.File))
		}
	}
	for _, u := range s.SDKs {
		note(u.Upstream, fmt.Sprintf("%s SDK declared in %s", u.Name, u.Dir))
	}
	for _, h := range s.Hosts {
		note(upstreamForHost(h.Host), fmt.Sprintf("%s written in %s", h.Host, h.File))
	}
	var unrouted, signed []string
	for _, d := range dests {
		line := fmt.Sprintf("%s (%d connection%s from %s)", d.Host, d.Connections, pluralS(d.Connections), d.App)
		switch routingFor(d.Host) {
		case routeBuiltIn:
			note(upstreamForHost(d.Host), fmt.Sprintf("%d connection%s to %s from %s", d.Connections, pluralS(d.Connections), d.Host, d.App))
		case routeAsUpstream:
			unrouted = append(unrouted, line)
		case routeSigned:
			signed = append(signed, line)
		}
		// routeNotFromCode: an editor's or a consumer service's backend.
		// No base URL on a server reaches it, so nothing is advised.
	}

	ups := make([]string, 0, len(byUp))
	for u := range byUp {
		ups = append(ups, u)
	}
	sort.Strings(ups)

	var b strings.Builder
	// The key is written as a placeholder, never as the configured key:
	// this output lands in RMM job logs, and a tenant key in a log is a
	// tenant key in whatever indexes that log.
	for _, up := range ups {
		provider := strings.TrimSuffix(upstreamLabel(up), " key")
		fmt.Fprintf(&b, "\n%s\n", provider)
		for _, l := range byUp[up].lines {
			fmt.Fprintf(&b, "  found: %s\n", l)
		}
		prefix := envPrefix(up)
		fmt.Fprintf(&b, "  change, in the environment of the process that calls it:\n")
		// The same lines `keys migrate` and `init` write, and no others:
		// advice for a pairing the gateway has not been exercised with
		// would be a guess printed as an instruction.
		switch up {
		case "anthropic":
			fmt.Fprintf(&b, "    ANTHROPIC_BASE_URL=%s\n", gatewayURL(origin, up))
			fmt.Fprintf(&b, "    ANTHROPIC_AUTH_TOKEN=<your Lyntway key>\n")
			fmt.Fprintf(&b, "    (ANTHROPIC_API_KEY stays your own; its SDK sends it in a header the gateway passes on)\n")
		case "openai":
			fmt.Fprintf(&b, "    OPENAI_BASE_URL=%s\n", gatewayURL(origin, up))
			fmt.Fprintf(&b, "    OPENAI_API_KEY=<your Lyntway key>~<your OpenAI key>\n")
			fmt.Fprintf(&b, "    (or OPENAI_API_KEY=<your Lyntway key> alone, once Lyntway holds the OpenAI key)\n")
		default:
			fmt.Fprintf(&b, "    %s_BASE_URL=%s\n", prefix, gatewayURL(origin, up))
			fmt.Fprintf(&b, "    %s_API_KEY=<your Lyntway key>, once Lyntway holds the %s key\n", prefix, provider)
		}
		for _, dir := range keyDirs[up] {
			fmt.Fprintf(&b, "  or let the CLI make that change to the .env files in %s:\n    lyntway keys migrate %s\n", dir, dir)
		}
	}
	if len(unrouted) > 0 {
		b.WriteString("\nNo built-in gateway route:\n")
		for _, u := range unrouted {
			fmt.Fprintf(&b, "  %s\n", u)
		}
		fmt.Fprintf(&b, "  Add it as an upstream in the console, then point its base URL at %s/gw/<name>.\n", origin)
	}
	if len(signed) > 0 {
		b.WriteString("\nCannot be routed through the gateway:\n")
		for _, s := range signed {
			fmt.Fprintf(&b, "  %s\n", s)
		}
		b.WriteString("  Bedrock and Vertex sign every request in a way that breaks with anything in the path.\n" +
			"  The LiteLLM callback in the lyntway Python package is the vantage point for them.\n")
	}
	if b.Len() == 0 {
		return ""
	}
	return "Route each through the gateway:\n" + b.String()
}

func envPrefix(upstream string) string {
	for _, p := range providerShapes {
		if p.Upstream == upstream && len(p.Vars) > 0 {
			return strings.TrimSuffix(p.Vars[0], "_API_KEY")
		}
	}
	return strings.ToUpper(upstream)
}

func isEnvFileName(name string) bool {
	return name == ".env" || strings.HasPrefix(name, ".env.")
}

// agentJSON marshals with a trailing newline, so what is printed and what
// is sent are the same bytes.
func agentJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return buf.Bytes()
}
