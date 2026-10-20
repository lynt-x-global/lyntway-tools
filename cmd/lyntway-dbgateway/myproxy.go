package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

// MySQL wire protocol proxy.
//
// Packet format: 3-byte length (LE) + 1-byte sequence ID + payload.
//
// Key command bytes in client packets:
//   0x03  COM_QUERY
//   0x16  COM_STMT_PREPARE

const (
	myCOMQuery       byte = 0x03
	myCOMStmtPrepare byte = 0x16
)

type myProxy struct{}

func (p *myProxy) Name() string                { return "mysql" }
func (p *myProxy) DefaultUpstreamPort() string { return "3306" }

func (p *myProxy) Handle(client net.Conn, upstreams []dbUpstream, g *governor) {
	if len(upstreams) == 0 {
		return
	}
	// MySQL requires connecting to the upstream first (server speaks
	// first), so multi-upstream routing is not possible without
	// protocol-level changes. Use the first upstream.
	fallback := upstreams[0]

	server, err := dialUpstream(fallback)
	if err != nil {
		log.Printf("lyntway-dbgateway: mysql: cannot reach %s: %v", fallback.Host, err)
		return
	}
	defer server.Close()

	// Step 1: Read server HandshakeV10, forward to client.
	handshake, err := myReadPacket(server)
	if err != nil {
		log.Printf("lyntway-dbgateway: mysql: reading handshake: %v", err)
		return
	}
	if err := myWritePacket(client, handshake); err != nil {
		return
	}

	// Step 2: Read client HandshakeResponse, forward to server.
	response, err := myReadPacket(client)
	if err != nil {
		log.Printf("lyntway-dbgateway: mysql: reading client handshake: %v", err)
		return
	}
	if err := myWritePacket(server, response); err != nil {
		return
	}

	// Step 3: Relay server OK/ERR + any auth switch, forward to client.
	// The auth exchange may take several round-trips (auth switch, SHA2
	// fast-auth, etc.), so keep relaying until we get OK or ERR with
	// the expected sequence.
	for {
		pkt, err := myReadPacket(server)
		if err != nil {
			return
		}
		if err := myWritePacket(client, pkt); err != nil {
			return
		}
		payload := myPayload(pkt)
		if len(payload) == 0 {
			continue
		}
		// 0x00 = OK, 0xFF = ERR — auth is done either way.
		if payload[0] == 0x00 || payload[0] == 0xFF {
			break
		}
		// 0xFE = auth switch or more data needed — read client response.
		cPkt, err := myReadPacket(client)
		if err != nil {
			return
		}
		if err := myWritePacket(server, cPkt); err != nil {
			return
		}
	}

	// Step 4: Main proxy loop.
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		myRelayClientToServer(client, server, g, fallback.Name)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		myRelayServerToClient(server, client)
	}()

	<-done
}

// myReadPacket reads one MySQL packet (header + payload).
func myReadPacket(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16
	if length > 64<<20 {
		return nil, fmt.Errorf("mysql packet too large: %d", length)
	}
	pkt := make([]byte, 4+length)
	copy(pkt[:4], hdr[:])
	if length > 0 {
		if _, err := io.ReadFull(r, pkt[4:]); err != nil {
			return nil, err
		}
	}
	return pkt, nil
}

// myWritePacket writes a full MySQL packet (header already included).
func myWritePacket(w io.Writer, pkt []byte) error {
	_, err := w.Write(pkt)
	return err
}

// myPayload returns the payload portion of a MySQL packet.
func myPayload(pkt []byte) []byte {
	if len(pkt) <= 4 {
		return nil
	}
	return pkt[4:]
}

// myBuildPacket builds a MySQL packet from sequence ID and payload.
func myBuildPacket(seq byte, payload []byte) []byte {
	length := len(payload)
	pkt := make([]byte, 4+length)
	pkt[0] = byte(length)
	pkt[1] = byte(length >> 8)
	pkt[2] = byte(length >> 16)
	pkt[3] = seq
	copy(pkt[4:], payload)
	return pkt
}

// myRelayClientToServer reads client packets, governs queries, and forwards.
func myRelayClientToServer(client, server net.Conn, g *governor, dbName string) {
	for {
		pkt, err := myReadPacket(client)
		if err != nil {
			return
		}

		payload := myPayload(pkt)
		if len(payload) > 0 {
			cmd := payload[0]
			if cmd == myCOMQuery || cmd == myCOMStmtPrepare {
				sql := string(payload[1:])
				verb := sqlVerb(sql)
				res, err := g.governQueryUninspectedReplies(dbName, sql, verb, "MySQL")
				if err != nil {
					log.Printf("lyntway-dbgateway: mysql: govern error: %v", err)
				}
				if res != nil && res.Content == nil {
					myWriteErrPacket(client, pkt[3]+1, "query blocked by governance policy")
					continue
				}
			}
		}

		if err := myWritePacket(server, pkt); err != nil {
			return
		}
	}
}

// myRelayServerToClient reads server packets and forwards to the client.
func myRelayServerToClient(server, client net.Conn) {
	// Response governance is opt-in for MySQL because result set framing
	// requires tracking the full column-count/column-def/EOF/row/EOF
	// state machine, which is complex for a first version. Queries are
	// governed and receipted on the request side.
	buf := make([]byte, 32<<10)
	io.CopyBuffer(client, server, buf)
}

// myWriteErrPacket sends a MySQL ERR_Packet to the client.
func myWriteErrPacket(w io.Writer, seq byte, message string) {
	// ERR_Packet: 0xFF + 2-byte error code + '#' + 5-byte state + message.
	payload := make([]byte, 0, 9+len(message))
	payload = append(payload, 0xFF)
	// Error code 1045 (access denied) as a generic refusal.
	payload = append(payload, 0x15, 0x04)
	payload = append(payload, '#')
	payload = append(payload, "HY000"...)
	payload = append(payload, message...)
	myWritePacket(w, myBuildPacket(seq, payload))
}

// myExtractSQL extracts the SQL string from a COM_QUERY or COM_STMT_PREPARE
// packet payload (exported for testing).
func myExtractSQL(payload []byte) string {
	if len(payload) < 2 {
		return ""
	}
	cmd := payload[0]
	if cmd != myCOMQuery && cmd != myCOMStmtPrepare {
		return ""
	}
	return string(payload[1:])
}

// myPacketLen returns the declared payload length from a MySQL packet header.
func myPacketLen(pkt []byte) uint32 {
	if len(pkt) < 4 {
		return 0
	}
	return uint32(pkt[0]) | uint32(pkt[1])<<8 | uint32(pkt[2])<<16
}

// myPacketSeq returns the sequence ID from a MySQL packet header.
func myPacketSeq(pkt []byte) byte {
	if len(pkt) < 4 {
		return 0
	}
	return pkt[3]
}

// Ensure binary import is used (for test helpers that need it).
var _ = binary.LittleEndian
