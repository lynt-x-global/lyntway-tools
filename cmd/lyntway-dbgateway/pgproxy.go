package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// PostgreSQL wire protocol proxy.
//
// Message format after startup:
//   1 byte  — message type
//   4 bytes — length (includes itself, excludes the type byte)
//   N bytes — payload (length - 4)
//
// StartupMessage (no type byte):
//   4 bytes — length
//   4 bytes — protocol version (196608 = 3.0)
//   pairs of null-terminated key=value strings, terminated by \0
//
// SSLRequest:
//   4 bytes — length (8)
//   4 bytes — code (80877103)

const (
	pgVersionMajor = 3
	pgVersionMinor = 0
	pgVersion      = pgVersionMajor<<16 | pgVersionMinor // 196608
	pgSSLRequest   = 80877103
)

// PostgreSQL message types.
const (
	pgMsgQuery          byte = 'Q'
	pgMsgParse          byte = 'P'
	pgMsgBind           byte = 'B'
	pgMsgSync           byte = 'S'
	pgMsgDataRow        byte = 'D'
	pgMsgErrorResponse  byte = 'E'
	pgMsgReadyForQuery  byte = 'Z'
	pgMsgAuthentication byte = 'R'
)

// Transaction status bytes carried by ReadyForQuery.
const (
	pgTxIdle   byte = 'I'
	pgTxOpen   byte = 'T'
	pgTxFailed byte = 'E'
)

// pgSession is what the two relay goroutines share about one connection.
//
// A refused query is answered by the gateway, not the server, and the
// answer has to end the way the server's would: with ReadyForQuery and
// the transaction status the client should now believe. The server's last
// ReadyForQuery is the only source of that, and it passes through the
// other goroutine.
type pgSession struct {
	mu     sync.Mutex
	status byte

	// aborted records that the gateway told the client its transaction
	// had failed while the server still believes it is open. Until the
	// client ends the block, the gateway keeps answering the way the
	// server would in a failed transaction — otherwise a statement sent
	// after the refusal would run, and a COMMIT would commit, inside a
	// transaction the client was told was already lost.
	aborted bool
}

func newPGSession() *pgSession { return &pgSession{status: pgTxIdle} }

func (s *pgSession) observe(status byte) {
	s.mu.Lock()
	s.status = status
	s.mu.Unlock()
}

// refuse returns the status a locally generated ReadyForQuery must carry,
// and remembers when that status diverges from the server's.
//
// Idle stays idle: nothing reached the server, so nothing changed. Inside
// a transaction an error aborts it — that is what the client's driver
// expects after an ErrorResponse, and answering 'T' would tell it the
// block was healthy when one of its statements had just been refused.
func (s *pgSession) refuse() byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status == pgTxIdle {
		return pgTxIdle
	}
	s.aborted = true
	return pgTxFailed
}

func (s *pgSession) isAborted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.aborted
}

func (s *pgSession) endTransaction() {
	s.mu.Lock()
	s.aborted = false
	s.mu.Unlock()
}

type pgProxy struct{}

func (p *pgProxy) Name() string                { return "postgresql" }
func (p *pgProxy) DefaultUpstreamPort() string { return "5432" }

func (p *pgProxy) Handle(client net.Conn, upstreams []dbUpstream, g *governor) {
	if len(upstreams) == 0 {
		return
	}

	// Read the first client message — could be SSLRequest or StartupMessage.
	msg, err := pgReadStartup(client)
	if err != nil {
		log.Printf("lyntway-dbgateway: pg: reading startup: %v", err)
		return
	}

	// Handle SSLRequest: reply N (no SSL from the proxy) and read again.
	if len(msg) == 8 && binary.BigEndian.Uint32(msg[4:8]) == pgSSLRequest {
		if _, err := client.Write([]byte{'N'}); err != nil {
			return
		}
		msg, err = pgReadStartup(client)
		if err != nil {
			log.Printf("lyntway-dbgateway: pg: reading startup after SSL: %v", err)
			return
		}
	}

	// Resolve the upstream from the database name in the StartupMessage.
	dbName := pgStartupParam(msg, "database")
	upstream := pgResolveUpstream(upstreams, dbName)

	server, err := pgDialUpstream(upstream)
	if err != nil {
		pgSendError(client, fmt.Sprintf("cannot reach upstream %s: %v", upstream.Host, err))
		return
	}
	defer server.Close()

	// Forward the startup message.
	if _, err := server.Write(msg); err != nil {
		pgSendError(client, "upstream write failed")
		return
	}

	// Relay authentication exchange until ReadyForQuery.
	if err := pgRelayUntilReady(client, server); err != nil {
		log.Printf("lyntway-dbgateway: pg: auth relay: %v", err)
		return
	}

	// Main proxy loop: bidirectional, with governance on queries and data.
	done := make(chan struct{}, 2)
	sess := newPGSession()

	// Client to server.
	go func() {
		defer func() { done <- struct{}{} }()
		pgRelayClientToServer(client, server, g, upstream.Name, sess)
	}()

	// Server to client.
	go func() {
		defer func() { done <- struct{}{} }()
		pgRelayServerToClient(server, client, g, upstream.Name, sess)
	}()

	// Wait for either direction to finish.
	<-done
}

// pgResolveUpstream picks the right upstream for a client connection.
//
// The client's "database" startup parameter is matched against:
//  1. The upstream's stored Database name (from the URL path, e.g. "neondb")
//  2. The upstream's registered Name (e.g. "neon")
//
// Falls back to the first upstream when there is only one or no match.
func pgResolveUpstream(upstreams []dbUpstream, clientDB string) dbUpstream {
	if len(upstreams) == 1 || clientDB == "" {
		return upstreams[0]
	}

	// Match by stored database name (from the URL path).
	for _, u := range upstreams {
		if u.Database != "" && u.Database == clientDB {
			return u
		}
	}

	// Match by registered upstream name.
	for _, u := range upstreams {
		if u.Name == clientDB {
			return u
		}
	}

	log.Printf("lyntway-dbgateway: pg: no upstream matches database=%q, using %s", clientDB, upstreams[0].Name)
	return upstreams[0]
}

// pgDialUpstream connects to a PostgreSQL upstream using the STARTTLS
// protocol that PostgreSQL requires.
//
// Unlike HTTP(S), PostgreSQL does not use direct TLS on port 5432.
// Instead, the client sends an SSLRequest message, the server responds
// with 'S' (willing) or 'N' (not willing), and then the TLS handshake
// happens. Only after TLS is established does the client send its
// StartupMessage.
//
// Neon's pooler happens to accept direct TLS (SNI routing), but
// Supabase's direct endpoint and standard PostgreSQL follow the
// SSLRequest protocol. Using STARTTLS works for both.
func pgDialUpstream(u dbUpstream) (net.Conn, error) {
	dialHost := u.DialHost
	if dialHost == "" {
		dialHost = u.Host
	}
	addr := net.JoinHostPort(dialHost, u.Port)

	tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	if !u.TLS {
		return tcpConn, nil
	}

	// PostgreSQL STARTTLS: send SSLRequest, wait for 'S'.
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], pgSSLRequest)
	if _, err := tcpConn.Write(sslReq); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("writing SSLRequest: %w", err)
	}

	var resp [1]byte
	if _, err := io.ReadFull(tcpConn, resp[:]); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("reading SSL response: %w", err)
	}
	if resp[0] != 'S' {
		tcpConn.Close()
		return nil, fmt.Errorf("upstream refused SSL (responded %q)", resp[0])
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tlsConn := tls.Client(tcpConn, tlsConfigFor(u))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, explainTLSError(u, err)
	}
	return tlsConn, nil
}

// pgReadStartup reads a length-prefixed startup message (no type byte).
func pgReadStartup(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < 4 || length > 10<<20 {
		return nil, fmt.Errorf("invalid startup length: %d", length)
	}
	msg := make([]byte, length)
	copy(msg[:4], lenBuf[:])
	if _, err := io.ReadFull(r, msg[4:]); err != nil {
		return nil, err
	}
	return msg, nil
}

// pgStartupParam extracts a named parameter from a StartupMessage.
func pgStartupParam(msg []byte, key string) string {
	if len(msg) < 8 {
		return ""
	}
	// Skip length (4) + version (4).
	data := msg[8:]
	for len(data) > 1 {
		// Find the end of the key.
		keyEnd := 0
		for keyEnd < len(data) && data[keyEnd] != 0 {
			keyEnd++
		}
		if keyEnd >= len(data) {
			break
		}
		k := string(data[:keyEnd])
		data = data[keyEnd+1:]

		// Find the end of the value.
		valEnd := 0
		for valEnd < len(data) && data[valEnd] != 0 {
			valEnd++
		}
		if valEnd >= len(data) {
			break
		}
		v := string(data[:valEnd])
		data = data[valEnd+1:]

		if k == key {
			return v
		}
	}
	return ""
}

// pgReadMessage reads a typed PostgreSQL message (type + 4-byte length + payload).
func pgReadMessage(r io.Reader) (msgType byte, payload []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	msgType = hdr[0]
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 {
		return 0, nil, fmt.Errorf("invalid message length: %d", length)
	}
	payloadLen := length - 4
	if payloadLen > 64<<20 {
		return 0, nil, fmt.Errorf("message too large: %d", payloadLen)
	}
	payload = make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return msgType, payload, nil
}

// pgWriteMessage writes a typed PostgreSQL message.
func pgWriteMessage(w io.Writer, msgType byte, payload []byte) error {
	length := uint32(len(payload) + 4)
	hdr := [5]byte{msgType}
	binary.BigEndian.PutUint32(hdr[1:], length)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// pgRelayUntilReady relays messages from server to client until
// ReadyForQuery, handling the authentication exchange transparently.
//
// SCRAM-SHA-256 (used by Neon, Supabase, RDS, etc.) requires multiple
// round-trips:
//
//	AuthenticationSASL (10)         → SASLInitialResponse ('p')
//	AuthenticationSASLContinue (11) → SASLResponse ('p')
//	AuthenticationSASLFinal (12)    — no client response needed
//	AuthenticationOk (0)            — no client response needed
//
// Other auth types (MD5, cleartext) have a single round-trip. The
// relay handles all of them by reading a client response after every
// auth message that expects one.
func pgRelayUntilReady(client, server net.Conn) error {
	for {
		msgType, payload, err := pgReadMessage(server)
		if err != nil {
			return err
		}
		if err := pgWriteMessage(client, msgType, payload); err != nil {
			return err
		}

		if msgType == pgMsgReadyForQuery {
			return nil
		}

		if msgType == pgMsgErrorResponse {
			return fmt.Errorf("authentication failed")
		}

		// Authentication messages that expect a client response.
		if msgType == pgMsgAuthentication && len(payload) >= 4 {
			authType := binary.BigEndian.Uint32(payload[:4])
			switch authType {
			case 0:
				// AuthenticationOk — no response needed, continue
				// reading ParameterStatus etc. until ReadyForQuery.
			case 12:
				// AuthenticationSASLFinal — server sends its proof,
				// no client response expected. AuthenticationOk follows.
			default:
				// All other auth types (3=cleartext, 5=MD5,
				// 10=SASL, 11=SASLContinue) need a client response.
				cType, cPayload, err := pgReadMessage(client)
				if err != nil {
					return err
				}
				if err := pgWriteMessage(server, cType, cPayload); err != nil {
					return err
				}
			}
		}
	}
}

// pgRelayClientToServer reads client messages, governs queries, and
// forwards to the server.
//
// A refused statement is answered here in full. The server's answer to any
// statement ends with ReadyForQuery, and a driver waits for it before
// sending the next; an ErrorResponse on its own left psql hanging until it
// was killed, with the second statement never sent.
func pgRelayClientToServer(client, server net.Conn, g *governor, dbName string, sess *pgSession) {
	for {
		msgType, payload, err := pgReadMessage(client)
		if err != nil {
			return
		}

		switch msgType {
		case pgMsgQuery:
			// Simple query: payload is the SQL string, null-terminated.
			sql := pgNullTermString(payload)
			verb := sqlVerb(sql)
			if sess.isAborted() && !pgEndsTransaction(verb) {
				pgRefuseQuery(client, g, dbName, sql, verb, abortedRefusal)
				continue
			}
			res, err := g.governQuery(dbName, sql, verb)
			if err != nil {
				log.Printf("lyntway-dbgateway: pg: govern error: %v", err)
			}
			if res != nil && res.Content == nil {
				pgSendError(client, "query blocked by governance policy")
				pgSendReady(client, sess.refuse())
				continue
			}
			if sess.isAborted() {
				if verb == "COMMIT" || verb == "END" {
					// What the server does with COMMIT in a failed
					// transaction: rolls back and says so in the command
					// tag. Forwarding COMMIT would commit the statements
					// that ran before the refusal.
					payload = []byte("ROLLBACK\x00")
				}
				sess.endTransaction()
			}

		case pgMsgParse:
			// Extended query: name (null-term) + query (null-term) + param types.
			sql := pgParseStatement(payload)
			verb := sqlVerb(sql)
			if sess.isAborted() && !pgEndsTransaction(verb) {
				if _, err := g.governRefused(dbName, sql, verb, abortedRefusal); err != nil {
					log.Printf("lyntway-dbgateway: pg: govern error: %v", err)
				}
				if err := pgRefuseExtended(client, abortedMessage, pgTxFailed); err != nil {
					return
				}
				continue
			}
			res, err := g.governQuery(dbName, sql, verb)
			if err != nil {
				log.Printf("lyntway-dbgateway: pg: govern error: %v", err)
			}
			if res != nil && res.Content == nil {
				// The server answers a failed Parse the same way: the
				// error at once, then nothing until the client's Sync,
				// then ReadyForQuery. The Bind and Execute that follow
				// belong to the refused statement and carry its parameter
				// values, so they are discarded here rather than forwarded
				// to a server that never saw the Parse.
				if err := pgRefuseExtended(client, "query blocked by governance policy", sess.refuse()); err != nil {
					return
				}
				continue
			}
			if sess.isAborted() {
				if verb == "COMMIT" || verb == "END" {
					payload = pgReplaceParseQuery(payload, "ROLLBACK")
				}
				sess.endTransaction()
			}

		case pgMsgBind:
			// The values of a prepared statement travel here, not in the
			// SQL the Parse carried. A card that never appears in the
			// statement text appears in its parameters.
			params, ok := pgBindParameters(payload)
			if !ok || params.total == 0 {
				break
			}
			if sess.isAborted() {
				if _, err := g.governBind(dbName, params.text, params.component(), abortedRefusal); err != nil {
					log.Printf("lyntway-dbgateway: pg: govern error: %v", err)
				}
				if err := pgRefuseExtended(client, abortedMessage, pgTxFailed); err != nil {
					return
				}
				continue
			}
			res, err := g.governBind(dbName, params.text, params.component(), "")
			if err != nil {
				log.Printf("lyntway-dbgateway: pg: govern error: %v", err)
			}
			if res != nil && res.Content == nil {
				if err := pgRefuseExtended(client, "parameters blocked by governance policy", sess.refuse()); err != nil {
					return
				}
				continue
			}
		}

		// Forward the message as it arrived. Governance here produces
		// receipts and refusals; it does not rewrite wire-protocol binary,
		// and the receipts say so.
		if err := pgWriteMessage(server, msgType, payload); err != nil {
			return
		}
	}
}

// abortedRefusal is the reason on the receipt of a statement refused
// because the gateway had already told the client its transaction failed.
const abortedRefusal = "transaction aborted by an earlier refusal; not forwarded"

// abortedMessage is what the server itself says in the same situation.
const abortedMessage = "current transaction is aborted, commands ignored until end of transaction block"

func pgEndsTransaction(verb string) bool {
	switch verb {
	case "ROLLBACK", "ABORT", "COMMIT", "END":
		return true
	}
	return false
}

// pgRefuseQuery answers a simple-protocol statement the gateway refuses on
// its own account, and receipts it as the block it is.
func pgRefuseQuery(client net.Conn, g *governor, dbName, sql, verb, reason string) {
	if _, err := g.governRefused(dbName, sql, verb, reason); err != nil {
		log.Printf("lyntway-dbgateway: pg: govern error: %v", err)
	}
	pgSendError(client, abortedMessage)
	pgSendReady(client, pgTxFailed)
}

// pgRefuseExtended answers a refused extended-protocol message the way the
// server would: the error now, the rest of the pipeline discarded through
// Sync, then ReadyForQuery.
func pgRefuseExtended(client net.Conn, message string, status byte) error {
	pgSendError(client, message)
	if err := pgDiscardUntilSync(client); err != nil {
		return err
	}
	pgSendReady(client, status)
	return nil
}

// pgBindParams is what a Bind message carries that detection can see.
type pgBindParams struct {
	// text holds the text-format parameter values, one per line, so a
	// value cannot run into its neighbour and a card beside an id is not
	// read as one long number.
	text []byte

	total  int // parameters carried, NULLs included
	binary int // of which binary-format, which cannot be read as text
}

// component is what the receipt says about how much of this Bind could
// be read: every value, some of them, or none.
func (p pgBindParams) component() receipt.Component {
	c := receipt.Component{Name: componentBindParameters}
	switch {
	case p.binary == 0:
		c.Health = receipt.HealthHealthy
		c.Detail = fmt.Sprintf("%d of %d parameters text-format and examined", p.total, p.total)
	case p.binary == p.total:
		c.Health = receipt.HealthUnavailable
		c.Detail = fmt.Sprintf("all %d parameters binary-format; none could be read as text", p.total)
	default:
		c.Health = receipt.HealthDegraded
		c.Detail = fmt.Sprintf("%d of %d parameters binary-format and not read as text", p.binary, p.total)
	}
	return c
}

// pgBindParameters parses a Bind message.
//
// Format: portal\0 statement\0, int16 format-code count and codes (none
// means all text, one applies to every parameter, otherwise one each),
// int16 parameter count, then per parameter int32 length (-1 = NULL) and
// bytes, then the result format codes, which do not matter here.
func pgBindParameters(payload []byte) (pgBindParams, bool) {
	var p pgBindParams
	i := 0
	for n := 0; n < 2; n++ { // portal, then statement
		for i < len(payload) && payload[i] != 0 {
			i++
		}
		if i >= len(payload) {
			return p, false
		}
		i++
	}
	if i+2 > len(payload) {
		return p, false
	}
	nformats := int(binary.BigEndian.Uint16(payload[i:]))
	i += 2
	if i+2*nformats > len(payload) {
		return p, false
	}
	formats := make([]int16, nformats)
	for f := range formats {
		formats[f] = int16(binary.BigEndian.Uint16(payload[i:]))
		i += 2
	}
	if i+2 > len(payload) {
		return p, false
	}
	p.total = int(binary.BigEndian.Uint16(payload[i:]))
	i += 2
	for n := 0; n < p.total; n++ {
		if i+4 > len(payload) {
			return p, false
		}
		length := int(int32(binary.BigEndian.Uint32(payload[i:])))
		i += 4
		if length < 0 {
			continue // NULL
		}
		if i+length > len(payload) {
			return p, false
		}
		value := payload[i : i+length]
		i += length

		var format int16
		switch {
		case nformats == 1:
			format = formats[0]
		case nformats > 1 && n < nformats:
			format = formats[n]
		}
		if format != 0 {
			p.binary++
			continue
		}
		if len(p.text) > 0 {
			p.text = append(p.text, '\n')
		}
		p.text = append(p.text, value...)
	}
	return p, true
}

// pgRelayServerToClient reads server messages and forwards to the client,
// governing DataRow messages.
func pgRelayServerToClient(server, client net.Conn, g *governor, dbName string, sess *pgSession) {
	for {
		msgType, payload, err := pgReadMessage(server)
		if err != nil {
			return
		}

		switch msgType {
		case pgMsgDataRow:
			text := pgDataRowText(payload)
			if len(text) > 0 {
				if _, err := g.governResponse(dbName, text); err != nil {
					log.Printf("lyntway-dbgateway: pg: govern response error: %v", err)
				}
			}
		case pgMsgReadyForQuery:
			if len(payload) >= 1 {
				sess.observe(payload[0])
			}
		}

		if err := pgWriteMessage(client, msgType, payload); err != nil {
			return
		}
	}
}

// pgDiscardUntilSync reads and drops client messages through the next
// Sync, which is what the server does after an error in the extended
// protocol.
func pgDiscardUntilSync(client io.Reader) error {
	for {
		msgType, _, err := pgReadMessage(client)
		if err != nil {
			return err
		}
		if msgType == pgMsgSync {
			return nil
		}
	}
}

// pgReplaceParseQuery swaps the SQL in a Parse message, keeping the
// statement name and parameter types as the client sent them.
func pgReplaceParseQuery(payload []byte, query string) []byte {
	nameEnd := 0
	for nameEnd < len(payload) && payload[nameEnd] != 0 {
		nameEnd++
	}
	if nameEnd >= len(payload) {
		return payload
	}
	queryEnd := nameEnd + 1
	for queryEnd < len(payload) && payload[queryEnd] != 0 {
		queryEnd++
	}
	out := make([]byte, 0, len(payload)-(queryEnd-nameEnd-1)+len(query))
	out = append(out, payload[:nameEnd+1]...)
	out = append(out, query...)
	out = append(out, payload[queryEnd:]...)
	return out
}

// pgNullTermString returns a string from a null-terminated byte slice.
func pgNullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// pgParseStatement extracts the SQL statement from a Parse message.
// Format: name\0 + query\0 + int16 param count + param OIDs.
func pgParseStatement(payload []byte) string {
	// Skip the statement name.
	i := 0
	for i < len(payload) && payload[i] != 0 {
		i++
	}
	if i >= len(payload) {
		return ""
	}
	i++ // skip null terminator of name

	// The query string follows, also null-terminated.
	start := i
	for i < len(payload) && payload[i] != 0 {
		i++
	}
	return string(payload[start:i])
}

// pgDataRowText concatenates text column values from a DataRow message
// for governance scanning, one column per line.
//
// A line break rather than a space: the card rule accepts spaces between
// digit groups, because that is how people write cards, so an id column
// followed by a card column joined with a space became one seventeen-digit
// candidate that failed its checksum. The card crossed the wire and the
// receipt said nothing was found.
//
// DataRow format: int16 column count, then for each column
// int32 length (-1 = NULL) followed by that many bytes of data.
func pgDataRowText(payload []byte) []byte {
	if len(payload) < 2 {
		return nil
	}
	cols := int(binary.BigEndian.Uint16(payload[:2]))
	offset := 2
	var buf []byte
	for i := 0; i < cols && offset+4 <= len(payload); i++ {
		colLen := int(int32(binary.BigEndian.Uint32(payload[offset : offset+4])))
		offset += 4
		if colLen < 0 {
			continue // NULL
		}
		if offset+colLen > len(payload) {
			break
		}
		if len(buf) > 0 {
			buf = append(buf, '\n')
		}
		buf = append(buf, payload[offset:offset+colLen]...)
		offset += colLen
	}
	return buf
}

// pgSendError sends a PostgreSQL ErrorResponse to the client.
func pgSendError(w io.Writer, message string) {
	// ErrorResponse: series of type-byte + null-terminated string, ended by \0.
	// S = severity, M = message.
	var payload []byte
	payload = append(payload, 'S')
	payload = append(payload, "ERROR\x00"...)
	payload = append(payload, 'M')
	payload = append(payload, message...)
	payload = append(payload, 0)
	payload = append(payload, 0) // terminator
	pgWriteMessage(w, pgMsgErrorResponse, payload)
}

// pgSendReady sends ReadyForQuery with a transaction status byte.
func pgSendReady(w io.Writer, status byte) {
	pgWriteMessage(w, pgMsgReadyForQuery, []byte{status})
}

// sqlVerb extracts the first SQL keyword from a query, skipping whitespace
// and comments.
func sqlVerb(query string) string {
	s := query
	for len(s) > 0 {
		// Skip whitespace.
		if s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r' {
			s = s[1:]
			continue
		}
		// Skip single-line comments.
		if strings.HasPrefix(s, "--") {
			if nl := strings.IndexByte(s, '\n'); nl >= 0 {
				s = s[nl+1:]
			} else {
				return ""
			}
			continue
		}
		// Skip block comments.
		if strings.HasPrefix(s, "/*") {
			if end := strings.Index(s, "*/"); end >= 0 {
				s = s[end+2:]
			} else {
				return ""
			}
			continue
		}
		break
	}
	// Extract the first word.
	end := 0
	for end < len(s) && s[end] != ' ' && s[end] != '\t' && s[end] != '\n' && s[end] != '\r' && s[end] != '(' && s[end] != ';' {
		end++
	}
	return strings.ToUpper(s[:end])
}
