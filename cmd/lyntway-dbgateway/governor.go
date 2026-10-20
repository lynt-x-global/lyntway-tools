package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/govern"
	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// What a receipt from this gateway is allowed to say.
//
// The gateway reads every protocol message and forwards it unchanged. It
// does not rewrite a Query, a Parse or a DataRow, because a wire-protocol
// message with a substituted value is a message the database or the client
// will reject — and an audit found receipts saying "tokenize" for a card
// that had crossed the wire in the clear in both directions. So every
// request is governed in inspect mode: findings are kept, a block still
// blocks, and everything short of that is recorded as log_only, which is
// exactly what "findings recorded, content forwarded" means.
//
// The same audit found the gateway posting the SQL and the row values to
// the account while its own documentation promised they never left the
// machine. The documentation won. What leaves is the shape of what
// happened — classes, counts, decision, size — and nothing that was in it.

// governor holds the detection engine, the receipt sink, and the reporter
// that sends classes and counts (never content) to the account.
type governor struct {
	engine *govern.Engine
	sink   *os.File

	reporter *reporter

	mu       sync.Mutex
	findings map[detect.Class]int
	queries  int
}

// componentBindParameters names the part of detection that reads the
// parameter values of a Bind message. Binary-format parameters cannot be
// read as text, and a receipt that listed only the deterministic tier as
// healthy would read as a full examination of values nobody examined.
//
// Reported per request, on Bind receipts only. A Query or a row carries no
// parameters, so there is nothing for the component to say about them and
// listing it as healthy there would be a claim about an examination that
// had no subject.
const componentBindParameters = "bind-parameters"

// componentResultRows names the part of detection that reads the rows
// coming back from the database.
//
// The Postgres proxy governs every DataRow it relays. The MySQL and
// MongoDB proxies copy the server's reply straight through with
// io.CopyBuffer — their relays do not even take a governor — because
// neither result-set framing is parsed here. The query is examined on all
// three, so all three produced a receipt, and nothing on it distinguished
// them: a SELECT returning ten thousand card numbers left the same record
// as one returning none, under evidence.provenance: observed.
//
// Reported on the query receipt, because that is the only receipt those
// two protocols write. It is what makes the mode degraded, which is the
// honest reading: the gateway ran, and part of what it exists to inspect
// went past unread.
const componentResultRows = "result-rows"

// resultRowsNotInspected is what a protocol whose replies are forwarded
// unread says about them.
func resultRowsNotInspected(protocol string) receipt.Component {
	return receipt.Component{
		Name:   componentResultRows,
		Health: receipt.HealthUnavailable,
		Detail: "rows were forwarded without being read: this gateway does not parse " +
			protocol + " result framing, so only the query was examined",
	}
}

// governorConfig is everything a governor needs from its environment,
// gathered so a test can point every path at a temporary directory.
type governorConfig struct {
	// receipts is the JSONL file receipts are appended to. Empty keeps no
	// receipts, and with them no key directory and no chain positions —
	// there is nothing for a verifier to walk.
	receipts string

	// keyPath holds the signing seed, created on first use.
	keyPath string

	// origin and key identify the account to report to. Empty means
	// govern locally and report nothing.
	origin string
	key    string

	// policy overrides the engine's default. Nil means the default.
	policy *govern.Policy
}

func newGovernor(cfg governorConfig) (*governor, error) {
	signer, err := loadOrCreateSigner(cfg.keyPath)
	if err != nil {
		return nil, err
	}

	var store *fileChainStore
	if cfg.receipts != "" {
		if err := publishKey(keysPathFor(cfg.receipts), signer); err != nil {
			return nil, err
		}
		store = newFileChainStore(chainsPathFor(cfg.receipts))
	}

	engine, err := govern.New(govern.Config{
		Signer: signer,
		Policy: cfg.policy,
		// Truthful about who signed. The default names lyntway.com, whose
		// key directory has never held this key; a verifier sent there
		// would conclude the receipt was forged.
		Issuer:     localIssuer,
		ChainStore: chainStoreOrNil(store),
	})
	if err != nil {
		return nil, fmt.Errorf("starting the engine: %w", err)
	}

	sink, err := openSink(cfg.receipts)
	if err != nil {
		return nil, err
	}

	return &governor{
		engine:   engine,
		sink:     sink,
		reporter: newReporter(cfg.origin, cfg.key),
		findings: make(map[detect.Class]int),
	}, nil
}

// chainStoreOrNil keeps a nil *fileChainStore from becoming a non-nil
// interface, which the engine would then call.
func chainStoreOrNil(s *fileChainStore) govern.ChainStore {
	if s == nil {
		return nil
	}
	return s
}

func (g *governor) close() {
	// Drained before the file is closed, so a summary queued by the last
	// row still has somewhere to be written if the network refuses it.
	g.reporter.close()
	if g.sink != nil {
		g.sink.Close()
	}
}

// governOptions is what varies between one governed message and the next
// beyond its content and direction.
type governOptions struct {
	// refusal, when set, records that the gateway refused this message on
	// its own account and forwarded nothing. The receipt then reads as a
	// block with this reason, rather than as an allowed statement that
	// happens never to have reached the database.
	refusal string

	// components are capabilities the gateway reports for this message
	// that the engine cannot probe — for a Bind, whether its parameter
	// values could all be read. Listed beside the engine's own on the
	// receipt; any impaired one makes the mode degraded.
	components []receipt.Component
}

// governQuery runs the engine over a database query (request direction).
// Returns nil content when the policy blocks the query.
func (g *governor) governQuery(dbName, query, method string) (*govern.Result, error) {
	return g.govern(dbName, []byte(query), receipt.DirectionRequest, method, governOptions{})
}

// governQueryUninspectedReplies is governQuery for a protocol that forwards
// the server's reply without reading it. See componentResultRows.
func (g *governor) governQueryUninspectedReplies(dbName, query, method, protocol string) (*govern.Result, error) {
	return g.govern(dbName, []byte(query), receipt.DirectionRequest, method,
		governOptions{components: []receipt.Component{resultRowsNotInspected(protocol)}})
}

// governRefused receipts a query the gateway refused before the policy had
// a say — nothing was forwarded, and the reason is on the receipt.
func (g *governor) governRefused(dbName, query, method, reason string) (*govern.Result, error) {
	return g.govern(dbName, []byte(query), receipt.DirectionRequest, method, governOptions{refusal: reason})
}

// governBind runs the engine over the readable parameter values of a Bind,
// with the component that says how many of them were readable.
func (g *governor) governBind(dbName string, values []byte, readable receipt.Component, refusal string) (*govern.Result, error) {
	return g.govern(dbName, values, receipt.DirectionRequest, "BIND",
		governOptions{refusal: refusal, components: []receipt.Component{readable}})
}

// governResponse runs the engine over one row of a result.
func (g *governor) governResponse(dbName string, data []byte) (*govern.Result, error) {
	return g.govern(dbName, data, receipt.DirectionResponse, "RESULT", governOptions{})
}

func (g *governor) govern(dbName string, content []byte, dir receipt.Direction, method string, opts governOptions) (*govern.Result, error) {
	id, err := newReceiptID()
	if err != nil {
		return nil, err
	}
	res, err := g.engine.Govern(govern.Request{
		ChainID:   "db/" + dbName,
		ReceiptID: id,
		Content:   content,
		Action: receipt.Action{
			Surface:     receipt.SurfaceDatabase,
			Direction:   dir,
			Method:      method,
			Destination: dbName,
		},
		Actor: receipt.Actor{
			Type: receipt.ActorService, ID: "lyntway-dbgateway", Source: receipt.IdentityNone,
		},
		Evidence: &receipt.Evidence{
			Provenance: receipt.ProvenanceObserved,
			Vantage:    "db-gateway",
		},
		// See the note at the top of this file: the message is forwarded
		// as it arrived, so the receipt may not claim otherwise.
		Inspect:    true,
		Refusal:    opts.refusal,
		Components: opts.components,
	})
	if err != nil {
		return nil, err
	}
	if res.Warning != "" {
		// The receipt is signed and returned; what failed is remembering
		// where the chain now stands. Said once per occurrence, because the
		// next restart will fork the chain and somebody should know why.
		log.Printf("lyntway-dbgateway: %s", res.Warning)
	}
	g.record(res, dbName)
	return res, nil
}

// record counts, reports and keeps one governed message.
func (g *governor) record(res *govern.Result, dbName string) {
	g.mu.Lock()
	g.queries++
	for _, f := range res.Findings {
		g.findings[detect.Class(f.Class)] += f.Count
	}
	g.mu.Unlock()

	if g.reporter != nil {
		classes := make(map[string]int, len(res.Findings))
		for _, f := range res.Findings {
			classes[f.Class] += f.Count
		}
		g.reporter.report(attestation{
			Database:  dbName,
			Direction: string(res.Receipt.Action.Direction),
			Method:    res.Receipt.Action.Method,
			ReceiptID: res.Receipt.ID,
			Decision:  string(res.Decision),
			Findings:  classes,
			Bytes:     res.Receipt.Content.Bytes,
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
	// the application working, and the failure is visible in the file's
	// absence rather than in a broken connection.
	_, _ = g.sink.Write(append(encoded, '\n'))
}

// newReceiptID returns an identifier no other process can have issued.
//
// A per-process counter restarted at one on every launch, so a receipts
// file held several receipts with the same identifier — and the identifier
// is the only handle a person has on a receipt once it leaves the file.
func newReceiptID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating a receipt identifier: %w", err)
	}
	return "rcpt_" + hex.EncodeToString(b[:]), nil
}

// attestation is one governed message, reduced to what may leave.
type attestation struct {
	Database  string
	Direction string
	Method    string
	ReceiptID string
	Decision  string
	Findings  map[string]int
	Bytes     int64
}

// reporter sends finding summaries to an account, best effort.
//
// Mirrors lyntway-mcp's: classes and counts go to /v1/attest, so the
// service records them as what they are — a tool the customer runs
// reporting what it saw — and nothing else goes.
type reporter struct {
	origin string
	key    string
	client *http.Client

	// queue is bounded and lossy on purpose. A large result set is one
	// report per row, and a slow network must not grow memory inside the
	// path every query takes. A dropped summary costs a row in a dashboard
	// rather than a receipt: the receipts are on disk regardless.
	queue chan attestation

	wg   sync.WaitGroup
	once sync.Once
}

// newReporter returns a reporter, or nil when no account is configured.
func newReporter(origin, key string) *reporter {
	if origin == "" || key == "" {
		return nil
	}
	r := &reporter{
		origin: origin,
		key:    key,
		client: &http.Client{Timeout: 5 * time.Second},
		queue:  make(chan attestation, 256),
	}
	r.wg.Add(1)
	go r.run()
	return r
}

// report queues a summary. Never blocks, never fails.
func (r *reporter) report(a attestation) {
	if r == nil {
		return
	}
	select {
	case r.queue <- a:
	default:
	}
}

func (r *reporter) run() {
	defer r.wg.Done()
	for a := range r.queue {
		if err := r.send(a); err != nil {
			log.Printf("lyntway-dbgateway: a summary was not reported: %v", err)
		}
	}
}

// send posts one summary.
//
// The shape is the one /v1/attest accepts, and it is the whole of what the
// account learns about a message: which database, which way, which
// statement verb, what was found and how much of it, how many bytes, and
// the local receipt's identifier so the two records can be matched.
func (r *reporter) send(a attestation) error {
	findings := make([]map[string]any, 0, len(a.Findings))
	for class, count := range a.Findings {
		findings = append(findings, map[string]any{"class": class, "count": count})
	}

	body, err := json.Marshal(map[string]any{
		"chain_id":  "db/" + a.Database,
		"tool":      "lyntway-dbgateway",
		"reference": a.ReceiptID,
		"action": map[string]any{
			"surface":     "database",
			"direction":   a.Direction,
			"method":      a.Method,
			"destination": a.Database,
		},
		"actor": map[string]any{
			"type": "service",
			"id":   "lyntway-dbgateway",
		},
		"decision": a.Decision,
		"findings": findings,
		"bytes":    a.Bytes,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, r.origin+"/v1/attest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.key)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		answer, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("the service answered %d: %s", resp.StatusCode, bytes.TrimSpace(answer))
	}
	return nil
}

// close drains what is queued and stops, within a bound: a gateway that
// hangs on exit is one somebody kills, and whatever has not gone by then
// is in the receipt file anyway.
func (r *reporter) close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		close(r.queue)
		done := make(chan struct{})
		go func() { r.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	})
}

func openSink(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the receipt file: %w", err)
	}
	return f, nil
}
