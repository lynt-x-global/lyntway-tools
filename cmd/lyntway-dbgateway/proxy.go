package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// ProtocolProxy handles connections for one wire protocol.
type ProtocolProxy interface {
	Name() string
	DefaultUpstreamPort() string
	Handle(client net.Conn, upstreams []dbUpstream, g *governor)
}

// acceptLoop accepts connections and dispatches them to the proxy handler.
//
// Each connection selects its upstream from the map at accept time. For
// PostgreSQL, the upstream is resolved from the database name in the
// startup message — which requires reading from the connection first — so
// acceptLoop passes the full list and lets Handle resolve it.
func acceptLoop(ln net.Listener, proxy ProtocolProxy, upstreams *UpstreamMap, g *governor) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed during shutdown.
			return
		}
		go handleConnection(conn, proxy, upstreams, g)
	}
}

func handleConnection(client net.Conn, proxy ProtocolProxy, upstreams *UpstreamMap, g *governor) {
	defer client.Close()

	all := upstreams.allForProtocol(proxy.Name())
	if len(all) == 0 {
		log.Printf("lyntway-dbgateway: %s connection from %s but no upstreams registered", proxy.Name(), client.RemoteAddr())
		return
	}

	proxy.Handle(client, all, g)
}

// resolveUpstream finds a database upstream by name within a list.
func resolveUpstream(all []dbUpstream, name string) (dbUpstream, bool) {
	for _, u := range all {
		if u.Name == name {
			return u, true
		}
	}
	return dbUpstream{}, false
}

// dialUpstream connects to a database upstream, using TLS when required.
func dialUpstream(u dbUpstream) (net.Conn, error) {
	dialHost := u.DialHost
	if dialHost == "" {
		dialHost = u.Host
	}

	if !u.TLS {
		addr := net.JoinHostPort(dialHost, u.Port)
		return net.DialTimeout("tcp", addr, 10*time.Second)
	}

	// Connect to the resolved IP, then TLS with the hostname as SNI and as
	// the name the certificate must carry. Verified unless the upstream's
	// URL opted out; see tlspolicy.go for why that is the default.
	realAddr := net.JoinHostPort(dialHost, u.Port)

	tcpConn, err := net.DialTimeout("tcp", realAddr, 10*time.Second)
	if err != nil {
		return nil, err
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

// resolveSRV looks up _mongodb._tcp.<host> SRV records for a
// mongodb+srv:// connection. Returns the target host and port from the
// first SRV record. The hosts file does not affect SRV records, so
// net.LookupSRV is safe here even on Windows.
func resolveSRV(host string) (string, string, error) {
	_, addrs, err := net.LookupSRV("mongodb", "tcp", host)
	if err != nil {
		return "", "", err
	}
	if len(addrs) == 0 {
		return "", "", fmt.Errorf("no SRV records for _mongodb._tcp.%s", host)
	}
	target := strings.TrimSuffix(addrs[0].Target, ".")
	port := fmt.Sprintf("%d", addrs[0].Port)
	return target, port, nil
}

// resolveBypassingHosts resolves a hostname via public DNS (8.8.8.8),
// ignoring the system hosts file. Falls back to the hostname itself
// if DNS fails.
//
// On Windows, Go's resolver reads the hosts file even with PreferGo
// and a custom Dial function. When the hosts file redirects a database
// hostname to localhost (the Lyntway CLI does this), the Go resolver
// returns 127.0.0.x successfully — so we cannot rely on it and go
// straight to a raw UDP query against 8.8.8.8.
func resolveBypassingHosts(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}

	// Try the manual DNS query up to 3 times. UDP is unreliable and
	// Neon's pooler sits behind a CNAME chain that occasionally needs
	// a second attempt.
	for attempt := 0; attempt < 3; attempt++ {
		ip, err := manualDNSLookup(host)
		if err == nil {
			return ip
		}
	}

	// Do NOT fall back to Go's resolver on Windows. It reads the hosts
	// file even with PreferGo, so it returns 127.0.0.x when the
	// Lyntway CLI has redirected the hostname — which is worse than
	// returning the hostname unresolved.
	return host
}

// manualDNSLookup sends a raw DNS query to 8.8.8.8 as a fallback
// when Go's resolver does not bypass the hosts file.
func manualDNSLookup(host string) (string, error) {
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Build a minimal DNS A-record query.
	txID := uint16(0xABCD)
	query := buildDNSQuery(txID, host)

	if _, err := conn.Write(query); err != nil {
		return "", err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}

	return parseDNSResponse(buf[:n], txID)
}

// buildDNSQuery constructs a minimal DNS A-record query packet.
func buildDNSQuery(txID uint16, host string) []byte {
	var pkt []byte
	// Header: ID, flags (standard query), 1 question, 0 answers.
	pkt = append(pkt, byte(txID>>8), byte(txID))
	pkt = append(pkt, 0x01, 0x00) // flags: RD=1
	pkt = append(pkt, 0x00, 0x01) // 1 question
	pkt = append(pkt, 0x00, 0x00) // 0 answers
	pkt = append(pkt, 0x00, 0x00) // 0 authority
	pkt = append(pkt, 0x00, 0x00) // 0 additional

	// Question: labels.
	for _, label := range splitDNSLabels(host) {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, label...)
	}
	pkt = append(pkt, 0x00)       // root label
	pkt = append(pkt, 0x00, 0x01) // type A
	pkt = append(pkt, 0x00, 0x01) // class IN
	return pkt
}

func splitDNSLabels(host string) []string {
	// Remove trailing dot.
	host = strings.TrimSuffix(host, ".")
	return strings.Split(host, ".")
}

// parseDNSResponse extracts the first A record from a DNS response.
func parseDNSResponse(pkt []byte, txID uint16) (string, error) {
	if len(pkt) < 12 {
		return "", fmt.Errorf("dns response too short")
	}
	respID := uint16(pkt[0])<<8 | uint16(pkt[1])
	if respID != txID {
		return "", fmt.Errorf("dns txid mismatch")
	}
	anCount := int(pkt[6])<<8 | int(pkt[7])
	if anCount == 0 {
		return "", fmt.Errorf("no dns answers")
	}

	// Skip the question section.
	offset := 12
	// Skip QNAME.
	for offset < len(pkt) {
		l := int(pkt[offset])
		if l == 0 {
			offset++
			break
		}
		if l >= 0xC0 {
			offset += 2
			break
		}
		offset += 1 + l
	}
	offset += 4 // QTYPE + QCLASS

	// Read answer records.
	for i := 0; i < anCount && offset < len(pkt); i++ {
		// Skip NAME (may be a pointer).
		if offset < len(pkt) && pkt[offset] >= 0xC0 {
			offset += 2
		} else {
			for offset < len(pkt) {
				l := int(pkt[offset])
				if l == 0 {
					offset++
					break
				}
				offset += 1 + l
			}
		}
		if offset+10 > len(pkt) {
			break
		}
		rType := uint16(pkt[offset])<<8 | uint16(pkt[offset+1])
		rdLen := int(pkt[offset+8])<<8 | int(pkt[offset+9])
		offset += 10
		if rType == 1 && rdLen == 4 && offset+4 <= len(pkt) {
			return fmt.Sprintf("%d.%d.%d.%d", pkt[offset], pkt[offset+1], pkt[offset+2], pkt[offset+3]), nil
		}
		offset += rdLen
	}
	return "", fmt.Errorf("no A record found")
}
