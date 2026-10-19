package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

func TestSQLVerb(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"SELECT * FROM users", "SELECT"},
		{"  select * from users", "SELECT"},
		{"INSERT INTO orders VALUES (1)", "INSERT"},
		{"\n\tUPDATE users SET name='x'", "UPDATE"},
		{"DELETE FROM users", "DELETE"},
		{"CREATE TABLE t (id int)", "CREATE"},
		{"-- comment\nSELECT 1", "SELECT"},
		{"/* block */SELECT 1", "SELECT"},
		{"/* multi\nline */  SELECT 1", "SELECT"},
		{"", ""},
		{"   ", ""},
		{"-- only comment", ""},
	}
	for _, tt := range tests {
		got := sqlVerb(tt.input)
		if got != tt.want {
			t.Errorf("sqlVerb(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPGStartupParam(t *testing.T) {
	// Build a StartupMessage with database=testdb and user=testuser.
	var buf bytes.Buffer
	buf.Write(make([]byte, 4)) // placeholder for length
	binary.Write(&buf, binary.BigEndian, uint32(pgVersion))
	buf.WriteString("user")
	buf.WriteByte(0)
	buf.WriteString("testuser")
	buf.WriteByte(0)
	buf.WriteString("database")
	buf.WriteByte(0)
	buf.WriteString("testdb")
	buf.WriteByte(0)
	buf.WriteByte(0) // terminator

	msg := buf.Bytes()
	binary.BigEndian.PutUint32(msg[:4], uint32(len(msg)))

	got := pgStartupParam(msg, "database")
	if got != "testdb" {
		t.Errorf("pgStartupParam(database) = %q, want %q", got, "testdb")
	}

	got = pgStartupParam(msg, "user")
	if got != "testuser" {
		t.Errorf("pgStartupParam(user) = %q, want %q", got, "testuser")
	}

	got = pgStartupParam(msg, "missing")
	if got != "" {
		t.Errorf("pgStartupParam(missing) = %q, want %q", got, "")
	}
}

func TestPGReadStartup(t *testing.T) {
	// Build a minimal startup message.
	var buf bytes.Buffer
	payload := make([]byte, 8) // length + version
	binary.BigEndian.PutUint32(payload[:4], 8)
	binary.BigEndian.PutUint32(payload[4:8], pgVersion)
	buf.Write(payload)

	msg, err := pgReadStartup(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != 8 {
		t.Errorf("startup message length = %d, want 8", len(msg))
	}
	ver := binary.BigEndian.Uint32(msg[4:8])
	if ver != pgVersion {
		t.Errorf("version = %d, want %d", ver, pgVersion)
	}
}

func TestPGSSLRequest(t *testing.T) {
	// An SSL request is 8 bytes: length=8, code=80877103.
	var msg [8]byte
	binary.BigEndian.PutUint32(msg[:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], pgSSLRequest)

	// Verify detection.
	if binary.BigEndian.Uint32(msg[4:8]) != pgSSLRequest {
		t.Error("SSL request code not detected")
	}
}

func TestPGNullTermString(t *testing.T) {
	tests := []struct {
		input []byte
		want  string
	}{
		{[]byte("hello\x00"), "hello"},
		{[]byte("hello\x00world"), "hello"},
		{[]byte("hello"), "hello"},
		{nil, ""},
	}
	for _, tt := range tests {
		got := pgNullTermString(tt.input)
		if got != tt.want {
			t.Errorf("pgNullTermString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPGParseStatement(t *testing.T) {
	// Parse message payload: name\0 + query\0 + int16 param count.
	var payload bytes.Buffer
	payload.WriteString("stmt1")    // statement name
	payload.WriteByte(0)            // null terminator
	payload.WriteString("SELECT 1") // query
	payload.WriteByte(0)            // null terminator
	payload.Write([]byte{0, 0})     // 0 parameters

	got := pgParseStatement(payload.Bytes())
	if got != "SELECT 1" {
		t.Errorf("pgParseStatement = %q, want %q", got, "SELECT 1")
	}

	// Unnamed statement.
	var unnamed bytes.Buffer
	unnamed.WriteByte(0)                        // empty name
	unnamed.WriteString("INSERT INTO t VALUES") // query
	unnamed.WriteByte(0)
	unnamed.Write([]byte{0, 0})

	got = pgParseStatement(unnamed.Bytes())
	if got != "INSERT INTO t VALUES" {
		t.Errorf("pgParseStatement (unnamed) = %q, want %q", got, "INSERT INTO t VALUES")
	}
}

func TestPGMessageRoundTrip(t *testing.T) {
	payload := []byte("SELECT * FROM users\x00")
	var buf bytes.Buffer
	if err := pgWriteMessage(&buf, pgMsgQuery, payload); err != nil {
		t.Fatal(err)
	}

	msgType, gotPayload, err := pgReadMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != pgMsgQuery {
		t.Errorf("msgType = %c, want %c", msgType, pgMsgQuery)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestPGDataRowText(t *testing.T) {
	// Build a DataRow with 2 columns: "alice" and "bob@example.com".
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(2)) // 2 columns

	col1 := []byte("alice")
	binary.Write(&buf, binary.BigEndian, int32(len(col1)))
	buf.Write(col1)

	col2 := []byte("bob@example.com")
	binary.Write(&buf, binary.BigEndian, int32(len(col2)))
	buf.Write(col2)

	got := pgDataRowText(buf.Bytes())
	if string(got) != "alice\nbob@example.com" {
		t.Errorf("pgDataRowText = %q, want %q", got, "alice\nbob@example.com")
	}

	// NULL column.
	var buf2 bytes.Buffer
	binary.Write(&buf2, binary.BigEndian, uint16(2))
	binary.Write(&buf2, binary.BigEndian, int32(-1)) // NULL
	col3 := []byte("data")
	binary.Write(&buf2, binary.BigEndian, int32(len(col3)))
	buf2.Write(col3)

	got2 := pgDataRowText(buf2.Bytes())
	if string(got2) != "data" {
		t.Errorf("pgDataRowText with NULL = %q, want %q", got2, "data")
	}
}

func TestPGSendError(t *testing.T) {
	var buf bytes.Buffer
	pgSendError(&buf, "test error")

	msgType, payload, err := pgReadMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != pgMsgErrorResponse {
		t.Errorf("msgType = %c, want %c", msgType, pgMsgErrorResponse)
	}
	if !bytes.Contains(payload, []byte("test error")) {
		t.Error("error message not found in payload")
	}
}

func TestParseDBName(t *testing.T) {
	tests := []struct {
		rawURL string
		want   string
	}{
		{"postgresql://user:pass@host:5432/mydb", "mydb"},
		{"postgres://host/neondb", "neondb"},
		{"mysql://host:3306/shop", "shop"},
		{"mongodb://host:27017/analytics", "analytics"},
		{"mongodb+srv://user:pass@cluster.net/test", "test"},
		{"https://host:5432/postgres", "postgres"},
		{"https://host:5432", ""},
		{"host:5432", ""},
		{"postgresql://user:pass@host:5432/mydb?sslmode=require", "mydb"},
	}
	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			got := parseDBName(tt.rawURL)
			if got != tt.want {
				t.Errorf("parseDBName(%q) = %q, want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestPGResolveUpstream(t *testing.T) {
	neon := dbUpstream{Name: "neon", Host: "neon.tech", Database: "neondb"}
	supa := dbUpstream{Name: "supabase", Host: "supabase.co", Database: "postgres"}
	rds := dbUpstream{Name: "rds-pg", Host: "rds.amazonaws.com", Database: ""}

	both := []dbUpstream{neon, supa}

	// Single upstream — always returned regardless of dbName.
	got := pgResolveUpstream([]dbUpstream{neon}, "anything")
	if got.Name != "neon" {
		t.Errorf("single upstream: got %q, want neon", got.Name)
	}

	// Match by stored database name.
	got = pgResolveUpstream(both, "neondb")
	if got.Name != "neon" {
		t.Errorf("match by database: got %q, want neon", got.Name)
	}
	got = pgResolveUpstream(both, "postgres")
	if got.Name != "supabase" {
		t.Errorf("match by database: got %q, want supabase", got.Name)
	}

	// Match by upstream name.
	got = pgResolveUpstream([]dbUpstream{neon, rds}, "rds-pg")
	if got.Name != "rds-pg" {
		t.Errorf("match by name: got %q, want rds-pg", got.Name)
	}

	// No match — falls back to first.
	got = pgResolveUpstream(both, "unknown")
	if got.Name != "neon" {
		t.Errorf("fallback: got %q, want neon", got.Name)
	}

	// Empty dbName — falls back to first.
	got = pgResolveUpstream(both, "")
	if got.Name != "neon" {
		t.Errorf("empty dbName: got %q, want neon", got.Name)
	}
}

// pgFakeWire stands in for a client and a server on either side of the
// client-to-server relay.
type pgFakeWire struct {
	client net.Conn // the test writes queries here and reads answers
	server <-chan pgMsg
	sess   *pgSession
}

type pgMsg struct {
	typ     byte
	payload []byte
}

func newPGFakeWire(t *testing.T, g *governor) *pgFakeWire {
	t.Helper()
	clientEnd, proxyClient := net.Pipe()
	proxyServer, serverEnd := net.Pipe()
	t.Cleanup(func() { clientEnd.Close(); serverEnd.Close() })

	sess := newPGSession()
	go pgRelayClientToServer(proxyClient, proxyServer, g, "neon", sess)

	server := make(chan pgMsg, 16)
	go func() {
		for {
			typ, payload, err := pgReadMessage(serverEnd)
			if err != nil {
				return
			}
			server <- pgMsg{typ, payload}
		}
	}()
	return &pgFakeWire{client: clientEnd, server: server, sess: sess}
}

func (w *pgFakeWire) send(t *testing.T, typ byte, payload []byte) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- pgWriteMessage(w.client, typ, payload) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("writing %c: %v", typ, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("the relay never read the %c message", typ)
	}
}

func (w *pgFakeWire) query(t *testing.T, sql string) {
	t.Helper()
	w.send(t, pgMsgQuery, append([]byte(sql), 0))
}

// answer reads one message the relay sent back to the client.
func (w *pgFakeWire) answer(t *testing.T) pgMsg {
	t.Helper()
	w.client.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, payload, err := pgReadMessage(w.client)
	if err != nil {
		t.Fatalf("the client was left waiting: %v", err)
	}
	return pgMsg{typ, payload}
}

func (w *pgFakeWire) expectAnswers(t *testing.T, want ...byte) []pgMsg {
	t.Helper()
	var got []pgMsg
	for _, typ := range want {
		m := w.answer(t)
		if m.typ != typ {
			t.Fatalf("client received %c, want %c (after %d messages)", m.typ, typ, len(got))
		}
		got = append(got, m)
	}
	return got
}

func (w *pgFakeWire) serverReceived(t *testing.T) pgMsg {
	t.Helper()
	select {
	case m := <-w.server:
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("nothing reached the server")
		return pgMsg{}
	}
}

func (w *pgFakeWire) serverReceivedNothing(t *testing.T) {
	t.Helper()
	select {
	case m := <-w.server:
		t.Fatalf("the server received %c %q, which was refused", m.typ, m.payload)
	case <-time.After(200 * time.Millisecond):
	}
}

// The audit ran a blocked statement through psql and the second statement
// never ran: the client sat waiting for a ReadyForQuery that never came.
func TestRefusedQueryEndsWithReadyForQuery(t *testing.T) {
	g := testGovernorWith(t, governorConfig{policy: blockCards()})
	w := newPGFakeWire(t, g)

	w.query(t, "INSERT INTO cards VALUES ('4111111111111111')")
	msgs := w.expectAnswers(t, pgMsgErrorResponse, pgMsgReadyForQuery)
	if !bytes.Contains(msgs[0].payload, []byte("blocked by governance policy")) {
		t.Errorf("error does not say why: %q", msgs[0].payload)
	}
	if status := msgs[1].payload[0]; status != pgTxIdle {
		t.Errorf("ReadyForQuery status = %c, want %c outside a transaction", status, pgTxIdle)
	}
	w.serverReceivedNothing(t)

	// The next statement goes through as if nothing had happened.
	w.query(t, "SELECT 1")
	if m := w.serverReceived(t); m.typ != pgMsgQuery || string(m.payload) != "SELECT 1\x00" {
		t.Errorf("server received %c %q, want the SELECT", m.typ, m.payload)
	}
}

// Inside a transaction an error aborts it, and the client must be told
// so — and then held to it, because the server never saw the refusal.
func TestRefusedQueryInsideTransactionAbortsIt(t *testing.T) {
	g := testGovernorWith(t, governorConfig{policy: blockCards()})
	w := newPGFakeWire(t, g)
	w.sess.observe(pgTxOpen)

	w.query(t, "INSERT INTO cards VALUES ('4111111111111111')")
	msgs := w.expectAnswers(t, pgMsgErrorResponse, pgMsgReadyForQuery)
	if status := msgs[1].payload[0]; status != pgTxFailed {
		t.Errorf("ReadyForQuery status = %c, want %c inside a transaction", status, pgTxFailed)
	}
	w.serverReceivedNothing(t)

	// A statement sent into the failed transaction is refused the way the
	// server would refuse it, and does not reach a server that would run it.
	w.query(t, "INSERT INTO audit VALUES (1)")
	msgs = w.expectAnswers(t, pgMsgErrorResponse, pgMsgReadyForQuery)
	if !bytes.Contains(msgs[0].payload, []byte("current transaction is aborted")) {
		t.Errorf("error does not read as an aborted transaction: %q", msgs[0].payload)
	}
	if status := msgs[1].payload[0]; status != pgTxFailed {
		t.Errorf("ReadyForQuery status = %c, want %c", status, pgTxFailed)
	}
	w.serverReceivedNothing(t)

	// COMMIT in a failed transaction rolls back. Forwarding it would
	// commit whatever ran before the refusal.
	w.query(t, "COMMIT")
	if m := w.serverReceived(t); m.typ != pgMsgQuery || string(m.payload) != "ROLLBACK\x00" {
		t.Errorf("server received %c %q, want ROLLBACK", m.typ, m.payload)
	}
	if w.sess.isAborted() {
		t.Error("the session is still marked aborted after the block ended")
	}
}

// The extended protocol: the Bind, Execute and Sync that follow a refused
// Parse belong to it, carry its parameter values, and must not reach the
// server. ReadyForQuery comes after the Sync, as the server would send it.
func TestRefusedParseDiscardsThroughSync(t *testing.T) {
	g := testGovernorWith(t, governorConfig{policy: blockCards()})
	w := newPGFakeWire(t, g)

	var parse bytes.Buffer
	parse.WriteByte(0) // unnamed statement
	parse.WriteString("INSERT INTO cards VALUES ('4111111111111111', $1)")
	parse.WriteByte(0)
	parse.Write([]byte{0, 0})
	w.send(t, pgMsgParse, parse.Bytes())
	w.expectAnswers(t, pgMsgErrorResponse)

	w.send(t, 'B', []byte("\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0bsecret-value\x00\x00"))
	w.send(t, 'E', []byte("\x00\x00\x00\x00\x00"))
	w.send(t, pgMsgSync, nil)
	msgs := w.expectAnswers(t, pgMsgReadyForQuery)
	if status := msgs[0].payload[0]; status != pgTxIdle {
		t.Errorf("ReadyForQuery status = %c, want %c", status, pgTxIdle)
	}
	w.serverReceivedNothing(t)

	// And the connection is still usable.
	w.query(t, "SELECT 1")
	if m := w.serverReceived(t); m.typ != pgMsgQuery {
		t.Errorf("server received %c, want a Query", m.typ)
	}
}

// pgBind builds a Bind message: unnamed portal and statement, the given
// format codes (one per parameter, or none for all-text), the parameters,
// and no result format codes. A nil parameter is NULL.
func pgBind(formats []int16, params [][]byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0) // portal
	b.WriteByte(0) // statement
	binary.Write(&b, binary.BigEndian, int16(len(formats)))
	for _, f := range formats {
		binary.Write(&b, binary.BigEndian, f)
	}
	binary.Write(&b, binary.BigEndian, int16(len(params)))
	for _, p := range params {
		if p == nil {
			binary.Write(&b, binary.BigEndian, int32(-1))
			continue
		}
		binary.Write(&b, binary.BigEndian, int32(len(p)))
		b.Write(p)
	}
	binary.Write(&b, binary.BigEndian, int16(0))
	return b.Bytes()
}

// lastReceipt returns the most recent receipt with the given method.
func lastReceipt(t *testing.T, g *governor, method string) *receipt.Receipt {
	t.Helper()
	rs := readReceipts(t, g.sink.Name())
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i].Action.Method == method {
			return rs[i]
		}
	}
	t.Fatalf("no receipt with method %q among %d receipts", method, len(rs))
	return nil
}

func componentHealth(r *receipt.Receipt, name string) (receipt.Health, bool) {
	for _, c := range r.Governance.Detector.Components {
		if c.Name == name {
			return c.Health, true
		}
	}
	return "", false
}

// A statement the gateway refuses on its own account — because it already
// told the client the transaction was lost — was never forwarded, and its
// receipt must say so rather than read as allowed.
func TestStatementRefusedInAbortedTransactionIsReceiptedAsBlocked(t *testing.T) {
	g := testGovernorWith(t, governorConfig{policy: blockCards()})
	w := newPGFakeWire(t, g)
	w.sess.observe(pgTxOpen)

	w.query(t, "INSERT INTO cards VALUES ('4111111111111111')")
	w.expectAnswers(t, pgMsgErrorResponse, pgMsgReadyForQuery)

	w.query(t, "INSERT INTO audit VALUES (1)")
	w.expectAnswers(t, pgMsgErrorResponse, pgMsgReadyForQuery)
	w.serverReceivedNothing(t)

	r := lastReceipt(t, g, "INSERT")
	if r.Content.Bytes != int64(len("INSERT INTO audit VALUES (1)")) {
		t.Fatalf("the last INSERT receipt covers %d bytes, not the refused statement", r.Content.Bytes)
	}
	if r.Governance.Decision != receipt.DecisionBlock {
		t.Errorf("decision = %q for a statement that was never forwarded", r.Governance.Decision)
	}
	if r.Governance.Refusal == "" {
		t.Error("the block is not explained: governance.refusal is empty")
	}
	if r.Content.OutputDigest != "" {
		t.Errorf("output digest %q claims something was released", r.Content.OutputDigest)
	}

	// The same holds for a Bind sent into the failed transaction.
	w.send(t, 'B', pgBind(nil, [][]byte{[]byte("alice@example.com")}))
	w.expectAnswers(t, pgMsgErrorResponse)
	w.send(t, 'E', []byte("\x00\x00\x00\x00\x00"))
	w.send(t, pgMsgSync, nil)
	msgs := w.expectAnswers(t, pgMsgReadyForQuery)
	if msgs[0].payload[0] != pgTxFailed {
		t.Errorf("ReadyForQuery status = %c, want %c", msgs[0].payload[0], pgTxFailed)
	}
	w.serverReceivedNothing(t)
	r = lastReceipt(t, g, "BIND")
	if r.Governance.Decision != receipt.DecisionBlock || r.Governance.Refusal == "" {
		t.Errorf("refused Bind receipted as %q with refusal %q", r.Governance.Decision, r.Governance.Refusal)
	}
}

// In the extended protocol the values travel in Bind, not in the SQL. A
// card that never appears in the Parse must still be found.
func TestBindParametersAreGoverned(t *testing.T) {
	g := testGovernor(t)
	w := newPGFakeWire(t, g)

	bind := pgBind(nil, [][]byte{[]byte("4111111111111111"), nil, []byte("alice@example.com")})
	w.send(t, 'B', bind)
	if m := w.serverReceived(t); m.typ != 'B' || !bytes.Equal(m.payload, bind) {
		t.Fatalf("server received %c %q, want the Bind unchanged", m.typ, m.payload)
	}

	r := lastReceipt(t, g, "BIND")
	if r.Action.Direction != receipt.DirectionRequest {
		t.Errorf("direction = %q, want request", r.Action.Direction)
	}
	if !hasFinding(r.Governance.Findings, "pci.card_number") || !hasFinding(r.Governance.Findings, "pii.email") {
		t.Errorf("findings = %v, want the card and the email", r.Governance.Findings)
	}
	if r.Governance.Decision != receipt.DecisionLogOnly {
		t.Errorf("decision = %q, want log_only: the Bind was forwarded as it arrived", r.Governance.Decision)
	}
	if r.Governance.Mode != receipt.ModeFull {
		t.Errorf("mode = %q for a Bind whose every parameter was text", r.Governance.Mode)
	}
	if h, ok := componentHealth(r, "bind-parameters"); !ok || h != receipt.HealthHealthy {
		t.Errorf("a text-only Bind should list bind-parameters as healthy: components = %v", r.Governance.Detector.Components)
	}
}

// A refused Bind is answered the way a refused Parse is: the error now,
// the Execute and Sync that follow discarded, ReadyForQuery after the Sync.
func TestRefusedBindDiscardsThroughSync(t *testing.T) {
	g := testGovernorWith(t, governorConfig{policy: blockCards()})
	w := newPGFakeWire(t, g)

	w.send(t, 'B', pgBind(nil, [][]byte{[]byte("4111111111111111")}))
	w.expectAnswers(t, pgMsgErrorResponse)
	w.send(t, 'E', []byte("\x00\x00\x00\x00\x00"))
	w.send(t, pgMsgSync, nil)
	msgs := w.expectAnswers(t, pgMsgReadyForQuery)
	if msgs[0].payload[0] != pgTxIdle {
		t.Errorf("ReadyForQuery status = %c, want %c", msgs[0].payload[0], pgTxIdle)
	}
	w.serverReceivedNothing(t)

	if r := lastReceipt(t, g, "BIND"); r.Governance.Decision != receipt.DecisionBlock {
		t.Errorf("decision = %q, want block", r.Governance.Decision)
	}

	w.query(t, "SELECT 1")
	if m := w.serverReceived(t); m.typ != pgMsgQuery {
		t.Errorf("server received %c, want the SELECT", m.typ)
	}
}

// A binary-format parameter cannot be read as text. The receipt for a Bind
// carrying one must not read as a full examination.
func TestBindWithBinaryParametersIsNotClaimedFullyExamined(t *testing.T) {
	g := testGovernor(t)
	w := newPGFakeWire(t, g)

	// One text, one binary: the text one is examined, the other is not.
	w.send(t, 'B', pgBind([]int16{0, 1}, [][]byte{[]byte("alice@example.com"), {0, 0, 0, 7}}))
	w.serverReceived(t)
	r := lastReceipt(t, g, "BIND")
	if !hasFinding(r.Governance.Findings, "pii.email") {
		t.Errorf("the text parameter was not examined: findings = %v", r.Governance.Findings)
	}
	if r.Governance.Mode != receipt.ModeDegraded {
		t.Errorf("mode = %q, want degraded: one parameter could not be read", r.Governance.Mode)
	}
	if h, ok := componentHealth(r, "bind-parameters"); !ok || h != receipt.HealthDegraded {
		t.Errorf("no component says the binary parameter went unread: components = %v", r.Governance.Detector.Components)
	}
	for _, c := range r.Governance.Detector.Components {
		if c.Name == "bind-parameters" && c.Detail == "" {
			t.Error("the bind-parameters component gives no detail of what went unread")
		}
	}

	// All binary: nothing in the Bind was examined.
	w.send(t, 'B', pgBind([]int16{1}, [][]byte{{0, 0, 0, 7}}))
	w.serverReceived(t)
	r = lastReceipt(t, g, "BIND")
	if r.Governance.Mode != receipt.ModeDegraded {
		t.Errorf("mode = %q, want degraded", r.Governance.Mode)
	}
	if h, _ := componentHealth(r, "bind-parameters"); h != receipt.HealthUnavailable {
		t.Errorf("bind-parameters health = %q, want unavailable when no parameter could be read", h)
	}

	// A Query afterwards is a full examination with no parameter
	// component at all: it had no parameters for one to describe.
	w.query(t, "SELECT 1")
	w.serverReceived(t)
	r = lastReceipt(t, g, "SELECT")
	if r.Governance.Mode != receipt.ModeFull {
		t.Errorf("mode = %q for a plain query after a binary Bind", r.Governance.Mode)
	}
	if _, ok := componentHealth(r, "bind-parameters"); ok {
		t.Errorf("a Query receipt lists bind-parameters: components = %v", r.Governance.Detector.Components)
	}
}
