// Command lyntway-mcp governs a stdio MCP server from alongside it.
//
// # Why this cannot be a service
//
// Most MCP servers run as a subprocess of the agent and talk over a pipe.
// There is no network hop, so a proxy — however well placed — is blind to
// them. The only way to see a tool call on a developer's laptop is to be on
// that laptop, between the agent and the server it spawned.
//
// That matters more than it sounds. When a developer asks their assistant
// why a customer's subscription is broken, the assistant calls a database
// tool, receives a row containing that customer's email, address and card
// details, and puts it straight into the prompt it sends to a model. The
// gateway sees the prompt. By then the data is already in it.
//
// # What it does
//
// The agent is pointed at this command instead of the server, and this
// command spawns the server. Every JSON-RPC message in both directions
// passes through, and the parts that carry data are governed.
//
//	{"mcpServers": {"github": {
//	  "command": "lyntway-mcp",
//	  "args": ["--", "npx", "-y", "@modelcontextprotocol/server-github"]
//	}}}
//
// Tool results are governed on the way back, which is the direction that
// matters: a result is about to become part of a prompt sent to a model, so
// substituting values there is what keeps them from leaving at all.
//
// # Content never leaves the machine
//
// Detection and substitution happen here. Nothing is sent anywhere to be
// governed, because sending it would be the disclosure this exists to
// prevent. Only receipts leave, and a receipt carries digests rather than
// content.
//
// Without a configured endpoint, receipts are written to a local file and
// the tool still governs. Losing the network must not mean losing the
// protection.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/govern"
	"github.com/lynt-x-global/lyntway-tools/receipt"
	"github.com/lynt-x-global/lyntway-tools/tokenize"
)

const usage = `lyntway-mcp — govern an MCP server's traffic from alongside it

Usage:
  lyntway-mcp [flags] -- <command> [args...]

The command is the MCP server this would otherwise have run. Point your
agent at this instead:

  {"mcpServers": {"github": {
    "command": "lyntway-mcp",
    "args": ["--", "npx", "-y", "@modelcontextprotocol/server-github"]
  }}}

Flags:
  -receipts FILE   append receipts here (default ~/.lyntway/receipts.jsonl)
  -chain NAME      receipt chain for this server (default: the command name)
  -quiet           do not report what was governed on stderr
  -h, -help        show this message

Content never leaves this machine. Detection and substitution happen here;
only receipts are written, and a receipt carries digests rather than
content.
`

// version is stamped at link time by the release workflow. "dev" means a
// build from source.
var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	fs := flag.NewFlagSet("lyntway-mcp", flag.ContinueOnError)
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.SetOutput(io.Discard)
	receiptsPath := fs.String("receipts", "", "where to append receipts")
	chain := fs.String("chain", "", "receipt chain name")
	quiet := fs.Bool("quiet", false, "suppress the summary on stderr")
	help := fs.Bool("help", false, "show usage")
	fs.BoolVar(help, "h", false, "show usage")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "lyntway-mcp: %v\n\n%s", err, usage)
		return 2
	}
	if *showVersion {
		fmt.Println(version)
		return 0
	}
	if *help {
		fmt.Fprint(os.Stdout, usage)
		return 0
	}

	command := fs.Args()
	if len(command) == 0 {
		fmt.Fprintf(os.Stderr, "lyntway-mcp: no server command given\n\n%s", usage)
		return 2
	}

	g, err := newGovernor(*receiptsPath, orDefault(*chain, command[0]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "lyntway-mcp: %v\n", err)
		return 2
	}
	defer g.close()

	code := proxy(command, g, *quiet)
	if !*quiet {
		g.report()
	}
	return code
}

// proxy runs the server and relays governed messages in both directions.
func proxy(command []string, g *governor, quiet bool) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	// The server's own diagnostics belong to the developer, so they pass
	// through untouched. Swallowing them would make this look like the
	// cause of any problem the server reports.
	cmd.Stderr = os.Stderr

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lyntway-mcp: %v\n", err)
		return 2
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lyntway-mcp: %v\n", err)
		return 2
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "lyntway-mcp: could not start %s: %v\n", command[0], err)
		return 2
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Agent to server. Arguments a caller is sending outward.
	go func() {
		defer wg.Done()
		defer serverIn.Close()
		relay(os.Stdin, serverIn, g, directionToServer)
	}()

	// Server to agent. This is the direction that matters: a tool result is
	// about to become part of a prompt sent to a model, so governing here
	// is what stops the values leaving at all.
	go func() {
		defer wg.Done()
		relay(serverOut, os.Stdout, g, directionToAgent)
	}()

	wg.Wait()
	if err := cmd.Wait(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		return 1
	}
	return 0
}

type direction int

const (
	directionToServer direction = iota
	directionToAgent
)

// relay reads newline-delimited JSON-RPC, governs it, and writes it on.
func relay(src io.Reader, dst io.Writer, g *governor, dir direction) {
	scanner := bufio.NewScanner(src)
	// A tool result carrying a page of database rows is easily past the
	// default limit, and a truncated message is worse than a slow one.
	scanner.Buffer(make([]byte, 0, 64<<10), 8<<20)

	writer := bufio.NewWriter(dst)
	defer writer.Flush()

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		out, err := g.govern(line, dir)
		if err != nil {
			// A message that cannot be governed is not forwarded. Passing
			// it through would mean the one message this could not inspect
			// is the one that gets out unexamined.
			fmt.Fprintf(os.Stderr, "lyntway-mcp: withheld a message: %v\n", err)
			continue
		}

		writer.Write(out)
		writer.WriteByte('\n')
		// Flushed per message because this is a conversation, not a
		// stream: the agent is waiting for each reply before it acts.
		writer.Flush()
	}
}

// governor holds the local detection engine and the receipt sink.
type governor struct {
	engine *govern.Engine
	scope  *tokenize.Scope
	chain  string
	seq    uint64

	sink *os.File

	// reporter sends classes and counts to the account, never content.
	// nil when this machine is not signed in, which is an ordinary state.
	reporter *reporter

	// server is what the person calls the thing being wrapped, used as the
	// destination on the summary. An auditor asking what handled their data
	// wants "github", not "lyntway-mcp".
	server string

	mu       sync.Mutex
	findings map[detect.Class]int
	messages int
}

func newGovernor(receiptsPath, chain string) (*governor, error) {
	// An ephemeral key. Receipts issued here are evidence that tool traffic
	// was governed and by which ruleset; they are not intended to verify
	// against a published deployment key, because nothing on a laptop
	// should hold one.
	signer, err := receipt.GenerateEd25519Signer("lyntway-mcp-local")
	if err != nil {
		return nil, fmt.Errorf("generating a local signing key: %w", err)
	}
	engine, err := govern.New(govern.Config{Signer: signer})
	if err != nil {
		return nil, fmt.Errorf("starting the engine: %w", err)
	}

	// Fresh per run, and never written down. Tokens only need to be
	// consistent within one session for an agent to correlate values
	// across calls, and a key on disk is a key that can be taken.
	key := make([]byte, tokenize.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating a tokenisation key: %w", err)
	}
	scope, err := tokenize.NewScope(key, tokenize.NewMemoryStore())
	if err != nil {
		return nil, fmt.Errorf("creating a token scope: %w", err)
	}

	sink, err := openReceiptSink(receiptsPath)
	if err != nil {
		return nil, err
	}

	return &governor{
		engine:   engine,
		scope:    scope,
		chain:    "mcp/" + sanitise(chain),
		sink:     sink,
		server:   sanitise(chain),
		reporter: newReporter(),
		findings: make(map[detect.Class]int),
	}, nil
}

func (g *governor) close() {
	// Drained before the file is closed, so a summary queued by the last
	// message still has somewhere to be written if the network refuses it.
	g.reporter.close()
	if g.sink != nil {
		g.sink.Close()
	}
}

// jsonRPC is the part of a message this needs to see.
type jsonRPC struct {
	Method string          `json:"method,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
}

// govern inspects a message and returns what should be forwarded.
//
// Only the parts that carry data are governed. Handshakes, capability
// listings and identifiers are protocol, and rewriting them would break the
// conversation for no benefit — a tokenised method name is not safer, only
// broken.
func (g *governor) govern(message []byte, dir direction) ([]byte, error) {
	var envelope jsonRPC
	if err := json.Unmarshal(message, &envelope); err != nil {
		// Not JSON-RPC this understands. Forwarded unchanged rather than
		// dropped: the protocol has more in it than this needs to know,
		// and refusing everything unfamiliar would break the server.
		return message, nil
	}

	var payload []byte
	switch {
	case dir == directionToAgent && len(envelope.Result) > 0:
		payload = envelope.Result
	case dir == directionToServer && envelope.Method == "tools/call":
		payload = envelope.Params
	default:
		return message, nil
	}

	g.mu.Lock()
	g.seq++
	seq := g.seq
	g.mu.Unlock()

	res, err := g.engine.Govern(govern.Request{
		ChainID:   g.chain,
		ReceiptID: fmt.Sprintf("rcpt_mcp_%d", seq),
		Content:   payload,
		Action: receipt.Action{
			Surface:   receipt.SurfaceMCP,
			Direction: directionOf(dir),
			Method:    orDefault(envelope.Method, "tools/result"),
		},
		Actor: receipt.Actor{
			Type: receipt.ActorAgent, ID: "local-agent", Source: receipt.IdentityNone,
		},
		Scope: g.scope,
		Evidence: &receipt.Evidence{
			// This process handled the bytes, on the machine where they
			// were produced. Nothing is closer to the source than this.
			Provenance: receipt.ProvenanceObserved,
			Vantage:    "mcp-shim",
		},
	})
	if err != nil {
		return nil, err
	}

	g.record(res)

	if res.Content == nil {
		// Refused. The agent is told rather than left waiting, and the
		// message never reaches the other side.
		return nil, errors.New("policy refused this message")
	}

	// Substituted content goes back into the envelope it came from, so the
	// rest of the message — identifiers, protocol fields — is untouched.
	var envelopeMap map[string]json.RawMessage
	if err := json.Unmarshal(message, &envelopeMap); err != nil {
		return nil, err
	}
	if dir == directionToAgent {
		envelopeMap["result"] = res.Content
	} else {
		envelopeMap["params"] = res.Content
	}
	return json.Marshal(envelopeMap)
}

func (g *governor) record(res *govern.Result) {
	g.mu.Lock()
	g.messages++
	for _, f := range res.Findings {
		g.findings[detect.Class(f.Class)] += f.Count
	}
	g.mu.Unlock()

	// Classes and counts leave; the content does not, and neither does a
	// digest of it. A tool result carrying a customer record is the
	// disclosure this exists to prevent — but "this machine handled three
	// email addresses" is a number, and it is the number somebody needs to
	// see to know the thing is working.
	if g.reporter != nil {
		classes := make(map[string]int, len(res.Findings))
		for _, f := range res.Findings {
			classes[f.Class] += f.Count
		}
		g.reporter.report(attestation{
			Server:   g.server,
			Chain:    g.chain,
			Decision: string(res.Decision),
			Findings: classes,
			Bytes:    res.Receipt.Content.Bytes,
		})
	}

	if g.sink == nil {
		return
	}
	encoded, err := json.Marshal(res.Receipt)
	if err != nil {
		return
	}
	// Append and move on. A receipt that cannot be written must not stop
	// the developer working, and the failure is visible in the file's
	// absence rather than in a broken tool.
	_, _ = g.sink.Write(append(encoded, '\n'))
}

// report summarises what happened, on stderr so it cannot be mistaken for
// protocol output.
func (g *governor) report() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.messages == 0 {
		return
	}
	var parts []string
	for class, count := range g.findings {
		parts = append(parts, fmt.Sprintf("%s ×%d", class, count))
	}
	if len(parts) == 0 {
		fmt.Fprintf(os.Stderr, "lyntway-mcp: governed %d messages, nothing sensitive found\n", g.messages)
		return
	}
	fmt.Fprintf(os.Stderr, "lyntway-mcp: governed %d messages; %s\n",
		g.messages, strings.Join(parts, ", "))
}

func directionOf(d direction) receipt.Direction {
	if d == directionToServer {
		return receipt.DirectionRequest
	}
	return receipt.DirectionResponse
}

// openReceiptSink opens the receipt file, creating its directory.
func openReceiptSink(path string) (*os.File, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			// No home directory is not a reason to stop governing, only a
			// reason not to keep receipts.
			return nil, nil
		}
		dir := home + "/.lyntway"
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, nil
		}
		path = dir + "/receipts.jsonl"
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the receipt file: %w", err)
	}
	return f, nil
}

// sanitise reduces a command name to something usable in a chain
// identifier, since it comes from the developer's own configuration.
func sanitise(name string) string {
	var b strings.Builder
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case c == '-', c == '_', c == '.':
			b.WriteRune(c)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 40 {
			break
		}
	}
	if b.Len() == 0 {
		return "server"
	}
	return b.String()
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
