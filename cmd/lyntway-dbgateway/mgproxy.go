package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

// MongoDB wire protocol proxy.
//
// Message format (MsgHeader):
//   4 bytes — total message length (LE, includes itself)
//   4 bytes — requestID
//   4 bytes — responseTo
//   4 bytes — opCode
//
// OP_MSG (opCode 2013):
//   4 bytes — flags
//   sections...
//
// Section kind 0 (body):
//   1 byte  — kind (0)
//   BSON document
//
// The command name is the first key in the body document. The database
// is the $db field.

const (
	mgOpMsg     int32 = 2013
	mgHeaderLen       = 16
)

type mgProxy struct{}

func (p *mgProxy) Name() string                { return "mongodb" }
func (p *mgProxy) DefaultUpstreamPort() string { return "27017" }

func (p *mgProxy) Handle(client net.Conn, upstreams []dbUpstream, g *governor) {
	if len(upstreams) == 0 {
		return
	}
	// MongoDB establishes a TCP connection before any command arrives,
	// so multi-upstream routing would require per-command multiplexing.
	// Use the first upstream.
	fallback := upstreams[0]

	server, err := dialUpstream(fallback)
	if err != nil {
		log.Printf("lyntway-dbgateway: mongodb: cannot reach %s: %v", fallback.Host, err)
		return
	}
	defer server.Close()

	done := make(chan struct{}, 2)

	// Client to server.
	go func() {
		defer func() { done <- struct{}{} }()
		mgRelayClientToServer(client, server, g, fallback.Name)
	}()

	// Server to client — forwarded transparently.
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32<<10)
		io.CopyBuffer(client, server, buf)
	}()

	<-done
}

// mgRelayClientToServer reads MongoDB messages from the client, governs
// OP_MSG commands, and forwards to the server.
func mgRelayClientToServer(client, server net.Conn, g *governor, dbName string) {
	for {
		msg, err := mgReadMessage(client)
		if err != nil {
			return
		}

		if len(msg) >= mgHeaderLen {
			opCode := int32(binary.LittleEndian.Uint32(msg[12:16]))
			if opCode == mgOpMsg && len(msg) > mgHeaderLen+4+1 {
				// Skip flags (4 bytes), read section kind.
				sectionStart := mgHeaderLen + 4
				if sectionStart < len(msg) && msg[sectionStart] == 0 {
					// Kind 0: body BSON document starts after the kind byte.
					bsonStart := sectionStart + 1
					if bsonStart+4 <= len(msg) {
						cmd, collection, db := mgExtractCommand(msg[bsonStart:])
						if cmd != "" {
							verb := strings.ToUpper(cmd)
							target := db
							if collection != "" {
								target = db + "." + collection
							}
							_ = target
							res, err := g.governQueryUninspectedReplies(dbName, cmd+" "+collection, verb, "MongoDB")
							if err != nil {
								log.Printf("lyntway-dbgateway: mongodb: govern error: %v", err)
							}
							if res != nil && res.Content == nil {
								mgSendError(client, msg, "query blocked by governance policy")
								continue
							}
						}
					}
				}
			}
		}

		if _, err := server.Write(msg); err != nil {
			return
		}
	}
}

// mgReadMessage reads a complete MongoDB wire protocol message.
func mgReadMessage(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := int(binary.LittleEndian.Uint32(hdr[:]))
	if length < mgHeaderLen || length > 48<<20 {
		return nil, fmt.Errorf("invalid mongodb message length: %d", length)
	}
	msg := make([]byte, length)
	copy(msg[:4], hdr[:])
	if _, err := io.ReadFull(r, msg[4:]); err != nil {
		return nil, err
	}
	return msg, nil
}

// mgExtractCommand extracts the command name, collection, and $db from
// a BSON document. Uses minimal BSON parsing — only reads string (0x02)
// and int32 (0x10) values for the fields we need.
//
// BSON document: 4-byte LE length, then elements, then 0x00 terminator.
// Each element: 1-byte type, null-terminated key, type-dependent value.
func mgExtractCommand(bson []byte) (command, collection, db string) {
	if len(bson) < 5 {
		return
	}
	docLen := int(binary.LittleEndian.Uint32(bson[:4]))
	if docLen < 5 || docLen > len(bson) {
		return
	}
	doc := bson[:docLen]

	pos := 4
	firstKey := true
	for pos < len(doc)-1 {
		if doc[pos] == 0 {
			break // document terminator
		}
		elemType := doc[pos]
		pos++

		// Read key (null-terminated).
		keyStart := pos
		for pos < len(doc) && doc[pos] != 0 {
			pos++
		}
		if pos >= len(doc) {
			break
		}
		key := string(doc[keyStart:pos])
		pos++ // skip null terminator

		// The first key is always the command name.
		if firstKey {
			command = key
			firstKey = false
		}

		// Read value based on type.
		switch elemType {
		case 0x02: // string: int32 length + bytes + \0
			if pos+4 > len(doc) {
				return
			}
			strLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			pos += 4
			if strLen < 1 || pos+strLen > len(doc) {
				return
			}
			val := string(doc[pos : pos+strLen-1]) // exclude null terminator
			pos += strLen

			if firstKey || key == command {
				// The first key's value is the collection name (for
				// commands like find, insert, etc.).
			}
			if key == command && command != "" {
				collection = val
			}
			if key == "$db" {
				db = val
			}

		case 0x10: // int32
			if pos+4 > len(doc) {
				return
			}
			pos += 4

		case 0x12: // int64
			if pos+8 > len(doc) {
				return
			}
			pos += 8

		case 0x01: // double (float64)
			if pos+8 > len(doc) {
				return
			}
			pos += 8

		case 0x08: // boolean
			pos++

		case 0x03, 0x04: // embedded document or array
			if pos+4 > len(doc) {
				return
			}
			subLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			if subLen < 5 || pos+subLen > len(doc) {
				return
			}
			pos += subLen

		case 0x07: // ObjectId (12 bytes)
			pos += 12

		case 0x09: // UTC datetime (int64)
			pos += 8

		case 0x0A: // null
			// no value bytes

		case 0x05: // binary
			if pos+5 > len(doc) {
				return
			}
			binLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			pos += 4 + 1 + binLen // length + subtype + data

		default:
			// Unknown type — stop parsing to avoid misreading.
			return
		}
	}
	return
}

// mgSendError sends an OP_MSG error reply to the client.
func mgSendError(w io.Writer, request []byte, message string) {
	// Build a minimal BSON error document: { ok: 0, errmsg: "..." }
	errmsgKey := "errmsg\x00"
	okKey := "ok\x00"

	// errmsg string value (type 0x02): int32 len + string + \0
	msgBytes := message + "\x00"
	msgLen := len(msgBytes)

	// Document: 4-byte len + elements + \0
	docLen := 4 + // doc length
		1 + len(okKey) + 8 + // double ok = 0.0
		1 + len(errmsgKey) + 4 + msgLen + // string errmsg
		1 // terminator

	doc := make([]byte, docLen)
	binary.LittleEndian.PutUint32(doc[0:4], uint32(docLen))
	pos := 4

	// ok: 0.0 (double)
	doc[pos] = 0x01
	pos++
	copy(doc[pos:], okKey)
	pos += len(okKey)
	// 0.0 as float64 is all zeros, already there
	pos += 8

	// errmsg: string
	doc[pos] = 0x02
	pos++
	copy(doc[pos:], errmsgKey)
	pos += len(errmsgKey)
	binary.LittleEndian.PutUint32(doc[pos:pos+4], uint32(msgLen))
	pos += 4
	copy(doc[pos:], msgBytes)
	pos += msgLen

	doc[pos] = 0 // document terminator

	// Build OP_MSG reply.
	totalLen := mgHeaderLen + 4 + 1 + docLen // header + flags + kind + doc
	msg := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))
	// requestID = 0
	if len(request) >= 8 {
		// responseTo = request's requestID
		copy(msg[8:12], request[4:8])
	}
	binary.LittleEndian.PutUint32(msg[12:16], uint32(mgOpMsg))
	// flags = 0
	msg[mgHeaderLen+4] = 0 // section kind 0
	copy(msg[mgHeaderLen+5:], doc)

	w.Write(msg)
}
